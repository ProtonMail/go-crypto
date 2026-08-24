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

	"github.com/ProtonMail/go-crypto/openpgp/aes/keywrap"
	"github.com/ProtonMail/go-crypto/openpgp/internal/algorithm"
	"github.com/ProtonMail/go-crypto/openpgp/internal/ecc"
)

type KDF struct {
	Hash   algorithm.Hash
	Cipher algorithm.Cipher
}

type PublicKey struct {
	curve ecc.ECDHCurve
	Point []byte
	KDF
}

type PrivateKey struct {
	PublicKey
	D []byte
}

func NewPublicKey(curve ecc.ECDHCurve, kdfHash algorithm.Hash, kdfCipher algorithm.Cipher) *PublicKey {
	return &PublicKey{
		curve: curve,
		KDF: KDF{
			Hash:   kdfHash,
			Cipher: kdfCipher,
		},
	}
}

func NewPrivateKey(key PublicKey) *PrivateKey {
	return &PrivateKey{
		PublicKey: key,
	}
}

func (pk *PublicKey) GetCurve() ecc.ECDHCurve {
	return pk.curve
}

func (pk *PublicKey) MarshalPoint() []byte {
	return pk.curve.MarshalBytePoint(pk.Point)
}

func (pk *PublicKey) UnmarshalPoint(p []byte) error {
	pk.Point = pk.curve.UnmarshalBytePoint(p)
	if pk.Point == nil {
		return errors.New("ecdh: failed to parse EC point")
	}
	return nil
}

func (sk *PrivateKey) MarshalByteSecret() []byte {
	return sk.curve.MarshalByteSecret(sk.D)
}

func (sk *PrivateKey) UnmarshalByteSecret(d []byte) error {
	sk.D = sk.curve.UnmarshalByteSecret(d)

	if sk.D == nil {
		return errors.New("ecdh: failed to parse scalar")
	}
	return nil
}

func GenerateKey(rand io.Reader, c ecc.ECDHCurve, kdf KDF) (priv *PrivateKey, err error) {
	priv = new(PrivateKey)
	priv.PublicKey.curve = c
	priv.PublicKey.KDF = kdf
	priv.PublicKey.Point, priv.D, err = c.GenerateECDH(rand)
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

	ephemeral, zb, err := pub.curve.Encaps(random, pub.Point)
	if err != nil {
		return nil, nil, err
	}

	vsG = pub.curve.MarshalBytePoint(ephemeral)

	z, err := buildKey(pub, zb, curveOID, fingerprint, false, false)
	if err != nil {
		return nil, nil, err
	}

	if c, err = keywrap.Wrap(z, m); err != nil {
		return nil, nil, err
	}

	return vsG, c, nil

}

// Decapsulator allows ECDH decapsulation to be performed by an external
// implementation, such as a hardware token (YubiKey, OpenPGP smartcard).
// The library calls Decaps during session key decryption; implementations
// perform the ECDH key agreement and return the raw shared secret.
// The library handles KDF and AES key unwrap internally.
type Decapsulator interface {
	// Decaps performs ECDH key agreement using the given ephemeral
	// public key point and returns the raw shared secret.
	Decaps(ephemeral []byte) (sharedSecret []byte, err error)
}

func Decrypt(priv *PrivateKey, vsG, c, curveOID, fingerprint []byte) (msg []byte, err error) {
	zb, err := priv.PublicKey.curve.Decaps(priv.curve.UnmarshalBytePoint(vsG), priv.D)
	if err != nil {
		return nil, err
	}

	return decryptWithSharedSecret(&priv.PublicKey, zb, c, curveOID, fingerprint)
}

// DecryptWithDecapsulator decrypts an ECDH-encrypted session key using an
// external Decapsulator to perform the key agreement step. This supports
// hardware tokens (YubiKey, OpenPGP smartcard) that perform ECDH internally
// and return only the raw shared secret, without exposing the private key.
//
// The Decapsulator is called with the unmarshalled ephemeral public key
// point from the PKESK packet. The KDF (RFC 6637 §8) and AES key unwrap
// (RFC 3394) steps are handled internally by this function.
func DecryptWithDecapsulator(decapsulator Decapsulator, pub *PublicKey, vsG, c, curveOID, fingerprint []byte) (msg []byte, err error) {
	ephemeral := pub.curve.UnmarshalBytePoint(vsG)
	if len(ephemeral) == 0 {
		return nil, errors.New("ecdh: invalid ephemeral public key point")
	}
	zb, err := decapsulator.Decaps(ephemeral)
	if err != nil {
		return nil, err
	}

	return decryptWithSharedSecret(pub, zb, c, curveOID, fingerprint)
}

// decryptWithSharedSecret completes ECDH decryption given a pre-computed
// shared secret, performing KDF and AES key unwrap.
func decryptWithSharedSecret(pub *PublicKey, zb, c, curveOID, fingerprint []byte) ([]byte, error) {
	var m []byte
	var err error

	// Try buildKey three times to workaround an old bug, see comments in buildKey.
	for i := 0; i < 3; i++ {
		var z []byte
		// RFC6637 §8: "Compute Z = KDF( S, Z_len, Param );"
		z, err = buildKey(pub, zb, curveOID, fingerprint, i == 1, i == 2)
		if err != nil {
			return nil, err
		}

		// RFC6637 §8: "Compute C = AESKeyWrap( Z, c ) as per [RFC3394]"
		m, err = keywrap.Unwrap(z, c)
		if err == nil {
			break
		}
	}

	// Only return an error after we've tried all (required) variants of buildKey.
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
	if _, err := param.Write(fingerprint[:]); err != nil {
		return nil, err
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
		for i < zbLen && zb[i] == 0 {
			i++
		}
	}
	if stripTrailing {
		// Work around old OpenPGP.js bug where insignificant trailing zeros in
		// this little-endian number are missing.
		// (See https://github.com/openpgpjs/openpgpjs/pull/853.)
		for j >= 0 && zb[j] == 0 {
			j--
		}
	}
	if _, err := h.Write(zb[i : j+1]); err != nil {
		return nil, err
	}
	if _, err := h.Write(param.Bytes()); err != nil {
		return nil, err
	}
	mb := h.Sum(nil)

	return mb[:pub.KDF.Cipher.KeySize()], nil // return oBits leftmost bits of MB.

}

func Validate(priv *PrivateKey) error {
	return priv.curve.ValidateECDH(priv.Point, priv.D)
}
