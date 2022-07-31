// Package eddsa implements EdDSA signature, suitable for OpenPGP,
// as specified in ...
package eddsa

import (
	"github.com/ProtonMail/go-crypto/openpgp/internal/ecc"
	"io"
)

type PublicKey struct {
	X []byte
	Curve ecc.EdDSACurve
}

type PrivateKey struct {
	PublicKey
	D []byte
}

func GenerateKey(rand io.Reader, c ecc.EdDSACurve) (priv *PrivateKey, err error) {
	priv = new(PrivateKey)
	priv.PublicKey.Curve = c
	priv.PublicKey.X, priv.D, err = c.GenerateEdDSA(rand)
	return
}

func Sign(priv *PrivateKey, message []byte) (r, s []byte, err error) {
	return priv.PublicKey.Curve.Sign(priv.PublicKey.X, priv.D, message)
}

func Verify(pub *PublicKey, message, r, s []byte) bool {
	return pub.Curve.Verify(pub.X, message, r, s)
}

func Validate(priv *PrivateKey) error {
	return priv.Curve.Validate(priv.PublicKey.X, priv.D)
}
