// Package ecdsa implements ECDSA signature, suitable for OpenPGP,
// as specified in RFC 6637, section 5.
package ecdsa

import (
	goecdsa "crypto/ecdsa"
	"errors"
	"github.com/ProtonMail/go-crypto/openpgp/internal/ecc"
	"io"
	"math/big"
)

type PublicKey struct {
	X, Y  *big.Int
	curve ecc.ECDSACurve
}

type PrivateKey struct {
	PublicKey
	D *big.Int
}

func NewPublicKey(curve ecc.ECDSACurve) *PublicKey {
	return &PublicKey{
		curve: curve,
	}
}

// NewPublicKeyFromStd converts a crypto/ecdsa public key into the
// representation used by this package. It returns an error if the curve
// is not one supported by OpenPGP.
func NewPublicKeyFromStd(pub *goecdsa.PublicKey) (*PublicKey, error) {
	if pub == nil || pub.Curve == nil || pub.X == nil || pub.Y == nil {
		return nil, errors.New("ecdsa: invalid public key")
	}
	curveInfo := ecc.FindByCurve(ecc.NewGenericCurve(pub.Curve))
	if curveInfo == nil {
		return nil, errors.New("ecdsa: unsupported curve " + pub.Curve.Params().Name)
	}
	curve, ok := curveInfo.Curve.(ecc.ECDSACurve)
	if !ok {
		return nil, errors.New("ecdsa: curve " + pub.Curve.Params().Name + " cannot be used with ECDSA")
	}
	return &PublicKey{
		X:     new(big.Int).Set(pub.X),
		Y:     new(big.Int).Set(pub.Y),
		curve: curve,
	}, nil
}

func NewPrivateKey(key PublicKey) *PrivateKey {
	return &PrivateKey{
		PublicKey: key,
	}
}

func (pk *PublicKey) GetCurve() ecc.ECDSACurve {
	return pk.curve
}

func (pk *PublicKey) MarshalPoint() []byte {
	return pk.curve.MarshalIntegerPoint(pk.X, pk.Y)
}

func (pk *PublicKey) UnmarshalPoint(p []byte) error {
	pk.X, pk.Y = pk.curve.UnmarshalIntegerPoint(p)
	if pk.X == nil {
		return errors.New("ecdsa: failed to parse EC point")
	}
	return nil
}

func (sk *PrivateKey) MarshalIntegerSecret() []byte {
	return sk.curve.MarshalIntegerSecret(sk.D)
}

func (sk *PrivateKey) UnmarshalIntegerSecret(d []byte) error {
	sk.D = sk.curve.UnmarshalIntegerSecret(d)

	if sk.D == nil {
		return errors.New("ecdsa: failed to parse scalar")
	}
	return nil
}

func GenerateKey(rand io.Reader, c ecc.ECDSACurve) (priv *PrivateKey, err error) {
	priv = new(PrivateKey)
	priv.PublicKey.curve = c
	priv.PublicKey.X, priv.PublicKey.Y, priv.D, err = c.GenerateECDSA(rand)
	return
}

func Sign(rand io.Reader, priv *PrivateKey, hash []byte) (r, s *big.Int, err error) {
	return priv.PublicKey.curve.Sign(rand, priv.X, priv.Y, priv.D, hash)
}

func Verify(pub *PublicKey, hash []byte, r, s *big.Int) bool {
	return pub.curve.Verify(pub.X, pub.Y, hash, r, s)
}

func Validate(priv *PrivateKey) error {
	return priv.curve.ValidateECDSA(priv.X, priv.Y, priv.D.Bytes())
}
