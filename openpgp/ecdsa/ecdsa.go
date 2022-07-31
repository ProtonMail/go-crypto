// Package ecdsa implements ECDSA signature, suitable for OpenPGP,
// as specified in RFC 6637, section 5.
package ecdsa

import (
	"github.com/ProtonMail/go-crypto/openpgp/internal/ecc"
	"io"
	"math/big"
)

type PublicKey struct {
	X, Y *big.Int
	Curve ecc.ECDSACurve
}

type PrivateKey struct {
	PublicKey
	D *big.Int
}

func GenerateKey(rand io.Reader, c ecc.ECDSACurve) (priv *PrivateKey, err error) {
	priv = new(PrivateKey)
	priv.PublicKey.Curve = c
	priv.PublicKey.X, priv.PublicKey.Y, priv.D, err = c.GenerateECDSA(rand)
	return
}

func Sign(rand io.Reader, priv *PrivateKey, hash []byte) (r, s *big.Int, err error) {
	return priv.PublicKey.Curve.Sign(rand, priv.X, priv.Y, priv.D, hash)
}

func Verify(pub *PublicKey, hash []byte, r, s *big.Int) bool {
	return pub.Curve.Verify(pub.X, pub.Y, hash, r, s)
}

func Validate(priv *PrivateKey) error {
	return priv.Curve.Validate(priv.X, priv.Y, priv.D.Bytes())
}