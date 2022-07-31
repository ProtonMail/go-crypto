// Package ecc implements a generic interface for ECDH, ECDSA, and EdDSA.
package ecc

import (
	"crypto/subtle"
	goerrors "errors"
	"io"
	"math/big"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
	x25519lib "github.com/cloudflare/circl/dh/x25519"
)

type curve25519 struct {}

func NewCurve25519() *curve25519 {
	return &curve25519{}
}

func (c *curve25519) GetCurveType() CurveType {
	return Curve25519
}

func (c *curve25519) GetCurveName() string {
	return "curve25519"
}

func (c *curve25519) GetBuildKeyAttempts() int {
	return 3
}

func (c *curve25519) Marshal(x, y *big.Int) []byte {
	return x.Bytes()
}

func (c *curve25519) Unmarshal(point []byte) (x, y *big.Int) {
	x = new(big.Int)
	x.SetBytes(point)
	return
}

// generateKeyPairBytes Generates a private-public key-pair.
// 'priv' is a private key; a little-endian scalar belonging to the set
// 2^{254} + 8 * [0, 2^{251}), in order to avoid the small subgroup of the
// curve. 'pub' is simply 'priv' * G where G is the base point.
// See https://cr.yp.to/ecdh.html and RFC7748, sec 5.
func (c *curve25519) generateKeyPairBytes(rand io.Reader) (priv, pub x25519lib.Key, err error) {
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

	x25519lib.KeyGen(&pub, &priv)
	return
}

func (c *curve25519) GenerateECDH(rand io.Reader) (x, y *big.Int, secret []byte, err error) {
	priv, pub, err := c.generateKeyPairBytes(rand)
	secret = make([]byte, x25519lib.Size)
	if err != nil {
		return
	}

	/*
	 * Note that ECPoint.point differs from the definition of public keys in
	 * [Curve25519] in two ways: (1) the byte-ordering is big-endian, which is
	 * more uniform with how big integers are represented in TLS, and (2) there
	 * is an additional length byte (so ECpoint.point is actually 33 bytes),
	 * again for uniformity (and extensibility).
	 */
	copyReversed(secret, priv[:])

	var encodedKey = make([]byte, 33)
	encodedKey[0] = 0x40
	copy(encodedKey[1:], pub[:])
	x = new(big.Int).SetBytes(encodedKey[:])
	y = new(big.Int)

	return
}

func (c *curve25519) Encaps(x, y *big.Int, rand io.Reader) (ephemeral, sharedSecret []byte, err error) {
	// RFC6637 §8: "Generate an ephemeral key pair {v, V=vG}"
	// ephemeralPrivate corresponds to `v`.
	// ephemeralPublic corresponds to `V`.
	ephemeralPrivate, ephemeralPublic, err := c.generateKeyPairBytes(rand)
	if err != nil {
		return nil, nil, err
	}

	// RFC6637 §8: "Obtain the authenticated recipient public key R"
	// pubKey corresponds to `R`.
	var pubKey x25519lib.Key
	if x.BitLen() > 33*264 {
		return nil, nil, goerrors.New("ecc: invalid curve25519 public point")
	}
	copy(pubKey[:], x.Bytes()[1:])

	// RFC6637 §8: "Compute the shared point S = vR"
	// pubKey corresponds to `S`.
	var sharedPoint x25519lib.Key
	x25519lib.Shared(&sharedPoint, &ephemeralPrivate, &pubKey)

	// RFC6637 §8: "VB = convert point V to the octet string"
	// vsg corresponds to `VB`
	var vsg [33]byte
	// This is in "Prefixed Native EC Point Wire Format", defined in
	// draft-ietf-openpgp-crypto-refresh-05 §13.2.2 as 0x40 || bytes
	// which ensures a bit in the first octet for later MPI encoding
	vsg[0] = 0x40
	copy(vsg[1:], ephemeralPublic[:])

	return vsg[:], sharedPoint[:], nil
}

func (c *curve25519) Decaps(vsG, secret []byte) (sharedSecret []byte, err error) {
	var decodedPrivate, sharedPoint x25519lib.Key
	// RFC6637 §8: "The decryption is the inverse of the method given."
	// All quoted descriptions in comments below describe encryption, and
	// the reverse is performed.

	// vsG corresponds to `VB` in RFC6637 §8 .
	// ephemeralPublic corresponds to `V`.
	var ephemeralPublic x25519lib.Key

	// Insist that vsG is an elliptic curve point in "Prefixed Native
	// EC Point Wire Format", defined in draft-ietf-openpgp-crypto-refresh-05
	// §13.2.2 as 0x40 || bytes
	if len(vsG) != 33 || vsG[0] != 0x40 {
		return nil, goerrors.New("ecc: invalid key")
	}
	// RFC6637 §8: "VB = convert point V to the octet string"
	copy(ephemeralPublic[:], vsG[1:33])

	// decodedPrivate corresponds to `r` in RFC6637 §8 .
	copyReversed(decodedPrivate[:], secret)

	// RFC6637 §8: "Note that the recipient obtains the shared secret by calculating
	//   S = rV = rvG, where (r,R) is the recipient's key pair."
	// sharedPoint corresponds to `S`.
	x25519lib.Shared(&sharedPoint, &decodedPrivate, &ephemeralPublic)

	return sharedPoint[:], nil
}

func (c *curve25519) Validate(x, y *big.Int, secret []byte) (err error) {
	var pk, sk x25519lib.Key
	publicPoint := x.Bytes()[1:]

	copyReversed(sk[:], secret)
	x25519lib.KeyGen(&pk, &sk)

	if subtle.ConstantTimeCompare(publicPoint, pk[:]) == 0 {
		return errors.KeyInvalidError("ecc: invalid curve25519 public point")
	}

	return nil
}

func copyReversed(out []byte, in []byte) {
	l := len(in)
	for i := 0; i < l; i++ {
		out[i] = in[l-i-1]
	}
}
