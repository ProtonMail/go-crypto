// Package ecc implements a generic interface for ECDH, ECDSA, and EdDSA.
package ecc

import (
	"crypto/subtle"
	"github.com/ProtonMail/go-crypto/openpgp/errors"
	ed25519lib "golang.org/x/crypto/ed25519"
	"io"
)

type ed25519 struct {}

func NewEd25519() *ed25519 {
	return &ed25519{}
}

func (c *ed25519) GetCurveType() CurveType {
	return Ed25519
}

func (c *ed25519) GetCurveName() string {
	return "ed25519"
}

func (c *ed25519) MarshalPoint(x []byte) []byte {
	return append([]byte{0x40}, x...)
}

func (c *ed25519) UnmarshalPoint(point []byte) (x []byte) {
	// Handle stripped leading zeroes
	x = make([]byte, 32)
	copy(x[33 - len(point):], point[1:])
	return
}

func (c *ed25519) MarshalInteger(d []byte) []byte {
	return d
}

func (c *ed25519) UnmarshalInteger(point []byte) (d []byte) {
	// Handle stripped leading zeroes
	d = make([]byte, 32)
	copy(d[32 - len(point):], point)
	return
}

func (c *ed25519) GenerateEdDSA(rand io.Reader) (pub, priv []byte, err error) {
	pk, sk, err := ed25519lib.GenerateKey(rand)

	if err != nil {
		return nil, nil, err
	}

	return pk, sk[:32], nil
}

func getSk(publicKey, privateKey []byte) ed25519lib.PrivateKey {
	return append(privateKey, publicKey...)
}

func (c *ed25519) Sign(publicKey, privateKey, message []byte) (r, s []byte, err error) {
	sig := ed25519lib.Sign(getSk(publicKey, privateKey), message)
	return sig[:32], sig[32:], nil
}

func (c *ed25519) Verify(publicKey, message, r, s []byte) bool {
	signature := make([]byte, ed25519lib.SignatureSize)
	copy(signature[32-len(r):32], r)
	copy(signature[64-len(s):], s)

	return ed25519lib.Verify(publicKey, message, signature)
}

func (c *ed25519) Validate(publicKey, privateKey []byte) (err error) {
	priv := getSk(publicKey, privateKey)
	expectedPriv := ed25519lib.NewKeyFromSeed(priv.Seed())
	if subtle.ConstantTimeCompare(priv, expectedPriv) == 0 {
		return errors.KeyInvalidError("ecc: invalid ed25519 secret")
	}
	return nil
}
