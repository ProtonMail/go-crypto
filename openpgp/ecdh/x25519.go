// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ecdh implements ECDH encryption, suitable for OpenPGP,
// as specified in RFC 6637, section 8.
package ecdh

import (
	"errors"
	"io"
	"math/big"

	"github.com/ProtonMail/go-crypto/openpgp/aes/keywrap"
	"github.com/ProtonMail/go-crypto/openpgp/internal/ecc"
	"github.com/cloudflare/circl/dh/x25519"
)

// Generates a private-public key-pair.
// 'priv' is a private key; a little-endian scalar belonging to the set
// 2^{254} + 8 * [0, 2^{251}), in order to avoid the small subgroup of the
// curve. 'pub' is simply 'priv' * G where G is the base point.
// See https://cr.yp.to/ecdh.html and RFC7748, sec 5.
func x25519GenerateKeyPairBytes(rand io.Reader) (priv x25519.Key, pub x25519.Key, err error) {
	_, err = io.ReadFull(rand, priv[:])
	if err != nil {
		return
	}

	// The following ensures that the private key is a number of the form
	// 2^{254} + 8 * [0, 2^{251}), in order to avoid the small subgroup of
	// of the curve.
	//
	// This masking is done internally to KeyGen and so is unnecessary
	// for security, but OpenPGP implementations require that private keys be
	// pre-masked.
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	x25519.KeyGen(&pub, &priv)
	return
}

// X25519GenerateKey samples the key pair according to the correct distribution.
// It also sets the given key-derivation function and returns the *PrivateKey
// object along with an error.
func X25519GenerateKey(rand io.Reader, kdf KDF) (priv *PrivateKey, err error) {
	ci := ecc.FindByName("Curve25519")
	priv = new(PrivateKey)
	priv.PublicKey.Curve = ci.Curve
	d, pubKey, err := x25519GenerateKeyPairBytes(rand)
	if err != nil {
		return nil, err
	}
	priv.PublicKey.KDF = kdf
	priv.D = make([]byte, 32)
	copyReversed(priv.D, d[:])
	priv.PublicKey.CurveType = ci.CurveType
	priv.PublicKey.Curve = ci.Curve
	/*
	 * Note that ECPoint.point differs from the definition of public keys in
	 * [Curve25519] in two ways: (1) the byte-ordering is big-endian, which is
	 * more uniform with how big integers are represented in TLS, and (2) there
	 * is an additional length byte (so ECpoint.point is actually 33 bytes),
	 * again for uniformity (and extensibility).
	 */
	var encodedKey = make([]byte, 33)
	encodedKey[0] = 0x40
	copy(encodedKey[1:], pubKey[:])
	priv.PublicKey.X = new(big.Int).SetBytes(encodedKey[:])
	priv.PublicKey.Y = new(big.Int)
	return priv, nil
}

func X25519Encrypt(random io.Reader, pub *PublicKey, msg, curveOID, fingerprint []byte) (vsG, c []byte, err error) {
	// RFC6637 §8: "Generate an ephemeral key pair {v, V=vG}"
	// ephemeralPrivate corresponds to `v`.
	// ephemeralPublic corresponds to `V`.
	ephemeralPrivate, ephemeralPublic, err := x25519GenerateKeyPairBytes(random)
	if err != nil {
		return nil, nil, err
	}

	// RFC6637 §8: "Obtain the authenticated recipient public key R"
	// pubKey corresponds to `R`.
	var pubKey x25519.Key
	if pub.X.BitLen() > 33*264 {
		return nil, nil, errors.New("ecdh: invalid key")
	}
	copy(pubKey[:], pub.X.Bytes()[1:])

	// RFC6637 §8: "Compute the shared point S = vR"
	// pubKey corresponds to `S`.
	var sharedPoint x25519.Key
	x25519.Shared(&sharedPoint, &ephemeralPrivate, &pubKey)

	// RFC6637 §8: "Compute Z = KDF( S, Z_len, Param )"
	z, err := buildKey(pub, sharedPoint[:], curveOID, fingerprint, false, false)
	if err != nil {
		return nil, nil, err
	}
	// RFC6637 §8: "Compute C = AESKeyWrap( Z, m ) as per [RFC3394]"
	if c, err = keywrap.Wrap(z, msg); err != nil {
		return nil, nil, err
	}

	// RFC6637 §8: "VB = convert point V to the octet string"
	// vsg corresponds to `VB`
	var vsg [33]byte
	// This is in "Prefixed Native EC Point Wire Format", defined in
	// draft-ietf-openpgp-crypto-refresh-05 §13.2.2 as 0x40 || bytes
	// which ensures a bit in the first octet for later MPI encoding
	vsg[0] = 0x40
	copy(vsg[1:], ephemeralPublic[:])

	// RFC6637 §8: "Output (MPI(VB) || len(C) || C)."
	return vsg[:], c, nil
}

func X25519Decrypt(priv *PrivateKey, vsG, c, curveOID, fingerprint []byte) (msg []byte, err error) {
	// RFC6637 §8: "The decryption is the inverse of the method given."
	// All quoted descriptions in comments below describe encryption, and
	// the reverse is performed.

	// vsG corresponds to `VB` in RFC6637 §8 .
	// ephemeralPublic corresponds to `V`.
	var ephemeralPublic x25519.Key
	// Insist that vsG is an elliptic curve point in "Prefixed Native
	// EC Point Wire Format", defined in draft-ietf-openpgp-crypto-refresh-05
	// §13.2.2 as 0x40 || bytes
	if len(vsG) != 33 || vsG[0] != 0x40 {
		return nil, errors.New("ecdh: invalid key")
	}
	// RFC6637 §8: "VB = convert point V to the octet string"
	copy(ephemeralPublic[:], vsG[1:33])

	// decodedPrivate corresponds to `r` in RFC6637 §8 .
	var decodedPrivate x25519.Key
	copyReversed(decodedPrivate[:], priv.D)

	// RFC6637 §8: "Note that the recipient obtains the shared secret by calculating
	//   S = rV = rvG, where (r,R) is the recipient's key pair."
	// sharedPoint corresponds to `S`.
	var sharedPoint x25519.Key
	x25519.Shared(&sharedPoint, &decodedPrivate, &ephemeralPublic)

	var m []byte

	for i := 0; i < 3; i++ {
		// RFC6637 §8: "Compute Z = KDF( S, Z_len, Param );"
		// Try buildKey three times for compat, see comments in buildKey.
		z, err := buildKey(&priv.PublicKey, sharedPoint[:], curveOID, fingerprint, i == 1, i == 2)
		if err != nil {
			return nil, err
		}

		// RFC6637 §8: "Compute C = AESKeyWrap( Z, m ) as per [RFC3394]"
		m, err = keywrap.Unwrap(z, c)
		if i == 2 && err != nil {
			// Only return an error after we've tried all variants of buildKey.
			return nil, err
		}

		if err == nil {
			break
		}
	}

	// RFC6637 §8: "m = symm_alg_ID || session key || checksum || pkcs5_padding"
	// The last byte should be the length of the padding, as per PKCS5; strip it off.
	return m[:len(m)-int(m[len(m)-1])], nil
}

func copyReversed(out []byte, in []byte) {
	l := len(in)
	for i := 0; i < l; i++ {
		out[i] = in[l-i-1]
	}
}
