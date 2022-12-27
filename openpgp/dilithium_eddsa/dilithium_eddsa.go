// Package dilithium_eddsa implements hybrid Dilithium + EdDSA encryption, suitable for OpenPGP, experimental.
package dilithium_eddsa

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
	Curve ecc.EdDSACurve
	Dilithium dilithium.Mode
	PublicPoint []byte
	PublicDilithium dilithium.PublicKey
}

type PrivateKey struct {
	PublicKey
	SecretEC []byte
	SecretDilithium dilithium.PrivateKey
}

func GenerateKey(rand io.Reader, algId uint8, c ecc.EdDSACurve, d dilithium.Mode) (priv *PrivateKey, err error) {
	priv = new(PrivateKey)

	priv.PublicKey.AlgId = algId
	priv.PublicKey.Curve = c
	priv.PublicKey.Dilithium = d

	priv.PublicKey.PublicPoint, priv.SecretEC, err = c.GenerateEdDSA(rand)
	if err != nil {
		return nil, err
	}

	priv.PublicKey.PublicDilithium, priv.SecretDilithium, err = priv.PublicKey.Dilithium.GenerateKey(rand)
	return
}

func Sign(priv *PrivateKey, message []byte) (dSig, ecSig []byte, err error) {
	ecSig, err = priv.PublicKey.Curve.Sign(priv.PublicKey.PublicPoint, priv.SecretEC, message)
	if err != nil {
		return nil, nil, err
	}

	dSig = priv.PublicKey.Dilithium.Sign(priv.SecretDilithium, message)
	if dSig == nil {
		return nil, nil, goerrors.New("dilithium_eddsa: unable to sign with dilithium")
	}

	return
}

func Verify(pub *PublicKey, message, dSig, ecSig []byte) bool {
	return pub.Curve.Verify(pub.PublicPoint, message, ecSig) && pub.Dilithium.Verify(pub.PublicDilithium, message, dSig)
}

func Validate(priv *PrivateKey) (err error) {
	if err = priv.PublicKey.Curve.ValidateEdDSA(priv.PublicKey.PublicPoint, priv.SecretEC); err != nil {
		return err
	}

	pub := priv.SecretDilithium.Public()
	casted, ok := pub.(dilithium.PublicKey)
	if !ok {
		return errors.KeyInvalidError("dilithium_eddsa: invalid public key")
	}

	if subtle.ConstantTimeCompare(priv.PublicDilithium.Bytes(), casted.Bytes()) == 0 {
		return errors.KeyInvalidError("dilithium_eddsa: invalid public key")
	}
	return
}