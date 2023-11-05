// Package mldsa_ecdsa implements hybrid ML-DSA + ECDSA encryption, suitable for OpenPGP, experimental.
// It follows the specs https://www.ietf.org/archive/id/draft-wussler-openpgp-pqc-03.html#name-composite-signature-schemes
package mldsa_ecdsa

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
	Mldsa dilithium.Mode
	X, Y  *big.Int
	PublicMldsa dilithium.PublicKey
}

type PrivateKey struct {
	PublicKey
	SecretEc *big.Int
	SecretMldsa dilithium.PrivateKey
}

func (pk *PublicKey) MarshalPoint() []byte {
	return pk.Curve.MarshalIntegerPoint(pk.X, pk.Y)
}

func (pk *PublicKey) UnmarshalPoint(p []byte) error {
	pk.X, pk.Y = pk.Curve.UnmarshalIntegerPoint(p)
	if pk.X == nil {
		return goerrors.New("mldsa_ecdsa: failed to parse EC point")
	}
	return nil
}

func (sk *PrivateKey) MarshalIntegerSecret() []byte {
	return sk.Curve.MarshalFieldInteger(sk.SecretEc)
}

func (sk *PrivateKey) UnmarshalIntegerSecret(d []byte) error {
	sk.SecretEc = sk.Curve.UnmarshalFieldInteger(d)

	if sk.SecretEc == nil {
		return goerrors.New("mldsa_ecdsa: failed to parse scalar")
	}
	return nil
}

// GenerateKey generates a ML-DSA + ECDSA composite key as specified in
// https://www.ietf.org/archive/id/draft-wussler-openpgp-pqc-03.html#name-key-generation-procedure-2
func GenerateKey(rand io.Reader, algId uint8, c ecc.ECDSACurve, d dilithium.Mode) (priv *PrivateKey, err error) {
	priv = new(PrivateKey)

	priv.PublicKey.AlgId = algId
	priv.PublicKey.Curve = c
	priv.PublicKey.Mldsa = d

	priv.PublicKey.X, priv.PublicKey.Y, priv.SecretEc, err = c.GenerateECDSA(rand)
	if err != nil {
		return nil, err
	}

	priv.PublicKey.PublicMldsa, priv.SecretMldsa, err = priv.PublicKey.Mldsa.GenerateKey(rand)
	return
}

// Sign generates a ML-DSA + ECDSA composite signature as specified in
// https://www.ietf.org/archive/id/draft-wussler-openpgp-pqc-03.html#name-signature-generation
func Sign(rand io.Reader, priv *PrivateKey, message []byte) (dSig, ecR, ecS []byte, err error) {
	r, s, err := priv.PublicKey.Curve.Sign(rand, priv.PublicKey.X, priv.PublicKey.Y, priv.SecretEc, message)
	if err != nil {
		return nil, nil, nil, err
	}

	ecR = priv.PublicKey.Curve.MarshalFieldInteger(r)
	ecS = priv.PublicKey.Curve.MarshalFieldInteger(s)

	dSig = priv.PublicKey.Mldsa.Sign(priv.SecretMldsa, message)
	if dSig == nil {
		return nil, nil, nil, goerrors.New("mldsa_eddsa: unable to sign with ML-DSA")
	}

	return
}

// Verify verifies a ML-DSA + ECDSA composite signature as specified in
// https://www.ietf.org/archive/id/draft-wussler-openpgp-pqc-03.html#name-signature-verification
func Verify(pub *PublicKey, message, dSig, ecR, ecS []byte) bool {
	r := pub.Curve.UnmarshalFieldInteger(ecR)
	s := pub.Curve.UnmarshalFieldInteger(ecS)

	return pub.Curve.Verify(pub.X, pub.Y, message, r, s) && pub.Mldsa.Verify(pub.PublicMldsa, message, dSig)
}

// Validate checks that the public key corresponds to the private key
func Validate(priv *PrivateKey) (err error) {
	if err = priv.PublicKey.Curve.ValidateECDSA(priv.PublicKey.X, priv.PublicKey.Y, priv.SecretEc.Bytes()); err != nil {
		return err
	}

	pub := priv.SecretMldsa.Public()
	casted, ok := pub.(dilithium.PublicKey)
	if !ok {
		return errors.KeyInvalidError("mldsa_ecdsa: invalid public key")
	}

	if subtle.ConstantTimeCompare(priv.PublicMldsa.Bytes(), casted.Bytes()) == 0 {
		return errors.KeyInvalidError("mldsa_ecdsa: invalid public key")
	}

	return
}