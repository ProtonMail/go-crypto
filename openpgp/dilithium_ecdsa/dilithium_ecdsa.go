// Package dilithium_ecdsa implements hybrid Dilithium + ECDSA encryption, suitable for OpenPGP, experimental.
// It follows the specs https://www.ietf.org/archive/id/draft-wussler-openpgp-pqc-00.html#name-composite-signature-schemes-3
package dilithium_ecdsa

import (
	"crypto/subtle"
	goerrors "errors"
	"github.com/cloudflare/circl/sign/dilithium"
	"io"
	"math/big"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/internal/ecc"
)

type PublicKey struct {
	AlgId uint8
	Curve ecc.ECDSACurve
	Dilithium dilithium.Mode
	X, Y *big.Int
	PublicDilithium dilithium.PublicKey
}

type PrivateKey struct {
	PublicKey
	SecretEC *big.Int
	SecretDilithium dilithium.PrivateKey
}

func (pk *PublicKey) MarshalPoint() []byte {
	return pk.Curve.MarshalIntegerPoint(pk.X, pk.Y)
}

func (pk *PublicKey) UnmarshalPoint(p []byte) error {
	pk.X, pk.Y = pk.Curve.UnmarshalIntegerPoint(p)
	if pk.X == nil {
		return goerrors.New("dilithium_ecdsa: failed to parse EC point")
	}
	return nil
}

func (sk *PrivateKey) MarshalIntegerSecret() []byte {
	return sk.Curve.MarshalFieldInteger(sk.SecretEC)
}

func (sk *PrivateKey) UnmarshalIntegerSecret(d []byte) error {
	sk.SecretEC = sk.Curve.UnmarshalFieldInteger(d)

	if sk.SecretEC == nil {
		return goerrors.New("dilithium_ecdsa: failed to parse scalar")
	}
	return nil
}

func GenerateKey(rand io.Reader, algId uint8, c ecc.ECDSACurve, d dilithium.Mode) (priv *PrivateKey, err error) {
	priv = new(PrivateKey)

	priv.PublicKey.AlgId = algId
	priv.PublicKey.Curve = c
	priv.PublicKey.Dilithium = d

	priv.PublicKey.X, priv.PublicKey.Y, priv.SecretEC, err = c.GenerateECDSA(rand)
	if err != nil {
		return nil, err
	}

	priv.PublicKey.PublicDilithium, priv.SecretDilithium, err = priv.PublicKey.Dilithium.GenerateKey(rand)
	return
}

// Sign generates a Dilithium + ECDSA composite signature as specified in
// https://www.ietf.org/archive/id/draft-wussler-openpgp-pqc-00.html#section-5.2.2
func Sign(rand io.Reader, priv *PrivateKey, message []byte) (dSig, ecR, ecS []byte, err error) {
	r, s, err := priv.PublicKey.Curve.Sign(rand, priv.PublicKey.X, priv.PublicKey.Y, priv.SecretEC, message)
	if err != nil {
		return nil, nil, nil, err
	}

	ecR = priv.PublicKey.Curve.MarshalFieldInteger(r)
	ecS = priv.PublicKey.Curve.MarshalFieldInteger(s)

	dSig = priv.PublicKey.Dilithium.Sign(priv.SecretDilithium, message)
	if dSig == nil {
		return nil, nil, nil, goerrors.New("dilithium_eddsa: unable to sign with dilithium")
	}

	return
}

// Verify verifies a Dilithium + ECDSA composite signature as specified in
// https://www.ietf.org/archive/id/draft-wussler-openpgp-pqc-00.html#section-5.2.3
func Verify(pub *PublicKey, message, dSig, ecR, ecS []byte) bool {
	r := pub.Curve.UnmarshalFieldInteger(ecR)
	s := pub.Curve.UnmarshalFieldInteger(ecS)

	return pub.Curve.Verify(pub.X, pub.Y, message, r, s) && pub.Dilithium.Verify(pub.PublicDilithium, message, dSig)
}

// Validate checks that the public key corresponds to the private key
func Validate(priv *PrivateKey) (err error) {
	if err = priv.PublicKey.Curve.ValidateECDSA(priv.PublicKey.X, priv.PublicKey.Y, priv.SecretEC.Bytes()); err != nil {
		return err
	}

	pub := priv.SecretDilithium.Public()
	casted, ok := pub.(dilithium.PublicKey)
	if !ok {
		return errors.KeyInvalidError("dilithium_ecdsa: invalid public key")
	}

	if subtle.ConstantTimeCompare(priv.PublicDilithium.Bytes(), casted.Bytes()) == 0 {
		return errors.KeyInvalidError("dilithium_ecdsa: invalid public key")
	}

	return
}