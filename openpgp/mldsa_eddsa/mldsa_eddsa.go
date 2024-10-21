// Package mldsa_eddsa implements hybrid ML-DSA + EdDSA encryption, suitable for OpenPGP, experimental.
// It follows the specs https://www.ietf.org/archive/id/draft-ietf-openpgp-pqc-05.html#name-composite-signature-schemes
package mldsa_eddsa

import (
	goerrors "errors"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/internal/ecc"
	"github.com/cloudflare/circl/sign"
)

const (
	MlDsaSeedLen = 32
)

type PublicKey struct {
	AlgId       uint8
	Curve       ecc.EdDSACurve
	Mldsa       sign.Scheme
	PublicPoint []byte
	PublicMldsa sign.PublicKey
}

type PrivateKey struct {
	PublicKey
	SecretEc        []byte
	SecretMldsa     sign.PrivateKey
	SecretMldsaSeed []byte
}

// GenerateKey generates a ML-DSA + EdDSA composite key as specified in
// https://www.ietf.org/archive/id/draft-ietf-openpgp-pqc-05.html#name-key-generation-procedure-2
func GenerateKey(rand io.Reader, algId uint8, c ecc.EdDSACurve, d sign.Scheme) (priv *PrivateKey, err error) {
	priv = new(PrivateKey)

	priv.PublicKey.AlgId = algId
	priv.PublicKey.Curve = c
	priv.PublicKey.Mldsa = d

	priv.PublicKey.PublicPoint, priv.SecretEc, err = c.GenerateEdDSA(rand)
	if err != nil {
		return nil, err
	}

	keySeed := make([]byte, d.SeedSize())
	if _, err = rand.Read(keySeed); err != nil {
		return nil, err
	}

	if err := priv.DeriveMlDsaKeys(keySeed, true); err != nil {
		return nil, err
	}
	return priv, nil
}

// DeriveMlDsaKeys derives the ML-DSA keys from the provided seed and stores them inside priv.
func (priv *PrivateKey) DeriveMlDsaKeys(seed []byte, overridePublicKey bool) (err error) {
	if len(seed) != MlDsaSeedLen {
		return goerrors.New("mldsa_eddsa: ml-dsa secret seed has the wrong length")
	}
	priv.SecretMldsaSeed = seed
	publicKey, privateKey := priv.PublicKey.Mldsa.DeriveKey(priv.SecretMldsaSeed)
	if overridePublicKey {
		priv.PublicKey.PublicMldsa = publicKey
	}
	priv.SecretMldsa = privateKey
	return nil
}

// Sign generates a ML-DSA + EdDSA composite signature as specified in
// https://www.ietf.org/archive/id/draft-ietf-openpgp-pqc-05.html#name-signature-generation
func Sign(priv *PrivateKey, message []byte) (dSig, ecSig []byte, err error) {
	ecSig, err = priv.PublicKey.Curve.Sign(priv.PublicKey.PublicPoint, priv.SecretEc, message)
	if err != nil {
		return nil, nil, err
	}

	dSig = priv.PublicKey.Mldsa.Sign(priv.SecretMldsa, message, nil)
	if dSig == nil {
		return nil, nil, goerrors.New("mldsa_eddsa: unable to sign with ML-DSA")
	}

	return dSig, ecSig, nil
}

// Verify verifies a ML-DSA + EdDSA composite signature as specified in
// https://www.ietf.org/archive/id/draft-ietf-openpgp-pqc-05.html#name-signature-verification
func Verify(pub *PublicKey, message, dSig, ecSig []byte) bool {
	return pub.Curve.Verify(pub.PublicPoint, message, ecSig) && pub.Mldsa.Verify(pub.PublicMldsa, message, dSig, nil)
}

// Validate checks that the public key corresponds to the private key
func Validate(priv *PrivateKey) (err error) {
	if err = priv.PublicKey.Curve.ValidateEdDSA(priv.PublicKey.PublicPoint, priv.SecretEc); err != nil {
		return err
	}

	if !priv.PublicMldsa.Equal(priv.SecretMldsa.Public()) {
		return errors.KeyInvalidError("mldsa_eddsa: invalid public key")
	}

	return nil
}
