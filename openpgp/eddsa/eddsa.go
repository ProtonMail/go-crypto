// Package eddsa implements EdDSA signature, suitable for OpenPGP, as specified in
// https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-crypto-refresh-06#section-13.7
package eddsa

import (
	"errors"
	"github.com/ProtonMail/go-crypto/openpgp/internal/ecc"
	"io"
)

type PublicKey struct {
	X []byte
	curve ecc.EdDSACurve
}

type PrivateKey struct {
	PublicKey
	D []byte
}

func NewPublicKey(curve ecc.EdDSACurve) *PublicKey {
	return &PublicKey{
		curve: curve,
	}
}

func NewPrivateKey(key PublicKey) *PrivateKey {
	return &PrivateKey{
		PublicKey: key,
	}
}

func (pk *PublicKey) GetCurve() ecc.EdDSACurve {
	return pk.curve
}

func (pk *PublicKey) MarshalPoint() []byte {
	return pk.curve.MarshalBytePoint(pk.X)
}

func (pk *PublicKey) UnmarshalPoint(x []byte) error {
	pk.X = pk.curve.UnmarshalBytePoint(x)

	if pk.X == nil {
		return errors.New("eddsa: failed to parse EC point")
	}
	return nil
}

func (sk *PrivateKey) MarshalByteSecret() []byte {
	return sk.curve.MarshalByteSecret(sk.D)
}

func (sk *PrivateKey) UnmarshalByteSecret(d []byte) error {
	sk.D = sk.curve.UnmarshalByteSecret(d)

	if sk.D == nil {
		return errors.New("eddsa: failed to parse scalar")
	}
	return nil
}

func GenerateKey(rand io.Reader, c ecc.EdDSACurve) (priv *PrivateKey, err error) {
	priv = new(PrivateKey)
	priv.PublicKey.curve = c
	priv.PublicKey.X, priv.D, err = c.GenerateEdDSA(rand)
	return
}

func Sign(priv *PrivateKey, message []byte) (r, s []byte, err error) {
	return priv.PublicKey.curve.Sign(priv.PublicKey.X, priv.D, message)
}

func Verify(pub *PublicKey, message, r, s []byte) bool {
	return pub.curve.Verify(pub.X, message, r, s)
}

func Validate(priv *PrivateKey) error {
	return priv.curve.ValidateEdDSA(priv.PublicKey.X, priv.D)
}
