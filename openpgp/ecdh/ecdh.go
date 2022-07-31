// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ecdh implements ECDH encryption, suitable for OpenPGP,
// as specified in RFC 6637, section 8.
package ecdh

import (
	"bytes"
	"errors"
	"io"
	"math/big"

	"github.com/ProtonMail/go-crypto/openpgp/aes/keywrap"
	"github.com/ProtonMail/go-crypto/openpgp/internal/algorithm"
	"github.com/ProtonMail/go-crypto/openpgp/internal/ecc"
)

type KDF struct {
	Hash   algorithm.Hash
	Cipher algorithm.Cipher
}

type PublicKey struct {
	Curve ecc.ECDHCurve
	X, Y *big.Int
	KDF
}

type PrivateKey struct {
	PublicKey
	D []byte
}

func GenerateKey(rand io.Reader, c ecc.ECDHCurve, kdf KDF) (priv *PrivateKey, err error) {
	priv = new(PrivateKey)
	priv.PublicKey.Curve = c
	priv.PublicKey.KDF = kdf
	priv.PublicKey.X, priv.PublicKey.Y, priv.D, err = c.GenerateECDH(rand)
	return
}

func Encrypt(random io.Reader, pub *PublicKey, msg, curveOID, fingerprint []byte) (vsG, c []byte, err error) {
	if len(msg) > 40 {
		return nil, nil, errors.New("ecdh: message too long")
	}
	// the sender MAY use 21, 13, and 5 bytes of padding for AES-128,
	// AES-192, and AES-256, respectively, to provide the same number of
	// octets, 40 total, as an input to the key wrapping method.
	padding := make([]byte, 40-len(msg))
	for i := range padding {
		padding[i] = byte(40 - len(msg))
	}
	m := append(msg, padding...)

	vsG, zb, err := pub.Curve.Encaps(pub.X, pub.Y, random)
	if err != nil {
		return nil, nil, err
	}

	z, err := buildKey(pub, zb, curveOID, fingerprint, false, false)
	if err != nil {
		return nil, nil, err
	}

	if c, err = keywrap.Wrap(z, m); err != nil {
		return nil, nil, err
	}

	return vsG, c, nil

}

func Decrypt(priv *PrivateKey, vsG, c, curveOID, fingerprint []byte) (msg []byte, err error) {
	var m []byte
	zb, err := priv.PublicKey.Curve.Decaps(vsG, priv.D)

	for i := 0; i < priv.PublicKey.Curve.GetBuildKeyAttempts(); i++ {
		// RFC6637 §8: "Compute Z = KDF( S, Z_len, Param );"
		// Try buildKey three times for compat, see comments in buildKey.
		z, err := buildKey(&priv.PublicKey, zb, curveOID, fingerprint, i == 1, i == 2)
		if err != nil {
			return nil, err
		}

		// RFC6637 §8: "Compute C = AESKeyWrap( Z, c ) as per [RFC3394]"
		m, err = keywrap.Unwrap(z, c)
		if err == nil {
			break
		}
	}

	// Only return an error after we've tried all variants of buildKey.
	if err != nil {
		return nil, err
	}

	// RFC6637 §8: "m = symm_alg_ID || session key || checksum || pkcs5_padding"
	// The last byte should be the length of the padding, as per PKCS5; strip it off.
	return m[:len(m)-int(m[len(m)-1])], nil
}

func buildKey(pub *PublicKey, zb []byte, curveOID, fingerprint []byte, stripLeading, stripTrailing bool) ([]byte, error) {
	// Param = curve_OID_len || curve_OID || public_key_alg_ID || 03
	//         || 01 || KDF_hash_ID || KEK_alg_ID for AESKeyWrap
	//         || "Anonymous Sender    " || recipient_fingerprint;
	param := new(bytes.Buffer)
	if _, err := param.Write(curveOID); err != nil {
		return nil, err
	}
	algKDF := []byte{18, 3, 1, pub.KDF.Hash.Id(), pub.KDF.Cipher.Id()}
	if _, err := param.Write(algKDF); err != nil {
		return nil, err
	}
	if _, err := param.Write([]byte("Anonymous Sender    ")); err != nil {
		return nil, err
	}
	// For v5 keys, the 20 leftmost octets of the fingerprint are used.
	if _, err := param.Write(fingerprint[:20]); err != nil {
		return nil, err
	}
	if param.Len() - len(curveOID) != 45 {
		return nil, errors.New("ecdh: malformed KDF Param")
	}

	// MB = Hash ( 00 || 00 || 00 || 01 || ZB || Param );
	h := pub.KDF.Hash.New()
	if _, err := h.Write([]byte{0x0, 0x0, 0x0, 0x1}); err != nil {
		return nil, err
	}
	zbLen := len(zb)
	i := 0
	j := zbLen - 1
	if stripLeading {
		// Work around old go crypto bug where the leading zeros are missing.
		for ; i < zbLen && zb[i] == 0; i++ {}
	}
	if stripTrailing {
		// Work around old OpenPGP.js bug where insignificant trailing zeros in
		// this little-endian number are missing.
		// (See https://github.com/openpgpjs/openpgpjs/pull/853.)
		for ; j >= 0 && zb[j] == 0; j-- {}
	}
	if _, err := h.Write(zb[i:j+1]); err != nil {
		return nil, err
	}
	if _, err := h.Write(param.Bytes()); err != nil {
		return nil, err
	}
	mb := h.Sum(nil)

	return mb[:pub.KDF.Cipher.KeySize()], nil // return oBits leftmost bits of MB.

}

func Validate(priv *PrivateKey) error {
	return priv.Curve.Validate(priv.X, priv.Y, priv.D)
}