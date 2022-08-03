// Package ecc implements a generic interface for ECDH, ECDSA, and EdDSA.
package ecc

import (
	"crypto/subtle"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
	ed25519lib "github.com/cloudflare/circl/sign/ed25519"
)

const ed25519Size = 32
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
	// Check size draft-ietf-openpgp-crypto-refresh-06#section-9.2.1
	if len(point) != ed25519lib.PublicKeySize + 1 {
		return nil
	}

	// Return unprefixed
	return point[1:]
}

func (c *ed25519) MarshalByteSecret(d []byte) []byte {
	return d
}

func (c *ed25519) UnmarshalByteSecret(s []byte) (d []byte) {
	if len(s) > ed25519lib.SeedSize {
		return nil
	}

	// Handle stripped leading zeroes draft-ietf-openpgp-crypto-refresh-06#section-9.2.1
	d = make([]byte, ed25519lib.SeedSize)
	copy(d[ed25519lib.SeedSize - len(s):], s)
	return
}

func (c *ed25519) GenerateEdDSA(rand io.Reader) (pub, priv []byte, err error) {
	pk, sk, err := ed25519lib.GenerateKey(rand)

	if err != nil {
		return nil, nil, err
	}

	return pk, sk[:ed25519lib.SeedSize], nil
}

func getEd25519Sk(publicKey, privateKey []byte) ed25519lib.PrivateKey {
	return append(privateKey, publicKey...)
}

func (c *ed25519) Sign(publicKey, privateKey, message []byte) (r, s []byte, err error) {
	sig := ed25519lib.Sign(getEd25519Sk(publicKey, privateKey), message)
	return sig[:ed25519Size], sig[ed25519Size:], nil
}

func (c *ed25519) Verify(publicKey, message, r, s []byte) bool {
	signature := make([]byte, ed25519lib.SignatureSize)

	// Handle stripped leading zeroes draft-ietf-openpgp-crypto-refresh-06#section-9.2.1
	copy(signature[ed25519Size-len(r):ed25519Size], r)
	copy(signature[ed25519lib.SignatureSize-len(s):], s)

	return ed25519lib.Verify(publicKey, message, signature)
}

func (c *ed25519) Validate(publicKey, privateKey []byte) (err error) {
	priv := getEd25519Sk(publicKey, privateKey)
	expectedPriv := ed25519lib.NewKeyFromSeed(priv.Seed())
	if subtle.ConstantTimeCompare(priv, expectedPriv) == 0 {
		return errors.KeyInvalidError("ecc: invalid ed25519 secret")
	}
	return nil
}
