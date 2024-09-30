// Package mldsa_eddsa implements hybrid ML-DSA + EdDSA encryption, suitable for OpenPGP, experimental.
// It follows the specs https://www.ietf.org/archive/id/draft-wussler-openpgp-pqc-03.html#name-composite-signature-schemes
package mldsa_eddsa

import (
	"crypto/subtle"
	goerrors "errors"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/internal/ecc"
	"github.com/cloudflare/circl/sign/dilithium"
)

type PublicKey struct {
	AlgId uint8
	Curve       ecc.EdDSACurve
	Mldsa       dilithium.Mode
	PublicPoint []byte
	PublicMldsa dilithium.PublicKey
}

type PrivateKey struct {
	PublicKey
	SecretEc []byte
	SecretMldsa dilithium.PrivateKey
}

// GenerateKey generates a ML-DSA + EdDSA composite key as specified in
// https://www.ietf.org/archive/id/draft-wussler-openpgp-pqc-03.html#name-key-generation-procedure-2
func GenerateKey(rand io.Reader, algId uint8, c ecc.EdDSACurve, d dilithium.Mode) (priv *PrivateKey, err error) {
	priv = new(PrivateKey)

	priv.PublicKey.AlgId = algId
	priv.PublicKey.Curve = c
	priv.PublicKey.Mldsa = d

	priv.PublicKey.PublicPoint, priv.SecretEc, err = c.GenerateEdDSA(rand)
	if err != nil {
		return nil, err
	}

	priv.PublicKey.PublicMldsa, priv.SecretMldsa, err = priv.PublicKey.Mldsa.GenerateKey(rand)
	return
}

// Sign generates a ML-DSA + EdDSA composite signature as specified in
// https://www.ietf.org/archive/id/draft-wussler-openpgp-pqc-03.html#name-signature-generation
func Sign(priv *PrivateKey, message []byte) (dSig, ecSig []byte, err error) {
	ecSig, err = priv.PublicKey.Curve.Sign(priv.PublicKey.PublicPoint, priv.SecretEc, message)
	if err != nil {
		return nil, nil, err
	}

	dSig = priv.PublicKey.Mldsa.Sign(priv.SecretMldsa, message)
	if dSig == nil {
		return nil, nil, goerrors.New("mldsa_eddsa: unable to sign with ML-DSA")
	}

	return
}

// Verify verifies a ML-DSA + EdDSA composite signature as specified in
// https://www.ietf.org/archive/id/draft-wussler-openpgp-pqc-03.html#name-signature-verification
func Verify(pub *PublicKey, message, dSig, ecSig []byte) bool {
	return pub.Curve.Verify(pub.PublicPoint, message, ecSig) && pub.Mldsa.Verify(pub.PublicMldsa, message, dSig)
}

// Validate checks that the public key corresponds to the private key
func Validate(priv *PrivateKey) (err error) {
	if err = priv.PublicKey.Curve.ValidateEdDSA(priv.PublicKey.PublicPoint, priv.SecretEc); err != nil {
		return err
	}

	pub := priv.SecretMldsa.Public()
	casted, ok := pub.(dilithium.PublicKey)
	if !ok {
		return errors.KeyInvalidError("mldsa_eddsa: invalid public key")
	}

	if subtle.ConstantTimeCompare(priv.PublicMldsa.Bytes(), casted.Bytes()) == 0 {
		return errors.KeyInvalidError("mldsa_eddsa: invalid public key")
	}
	return
}