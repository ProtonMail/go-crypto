// Package dilithium_eddsa implements hybrid Dilithium + EdDSA encryption, suitable for OpenPGP, experimental.
package dilithium_eddsa

import (
	"crypto/subtle"
	goerrors "errors"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/internal/dilithium"
	"github.com/ProtonMail/go-crypto/openpgp/internal/ecc"
	libdilithium "github.com/kudelskisecurity/crystals-go/crystals-dilithium"
	"golang.org/x/crypto/sha3"
)

type PublicKey struct {
	AlgId uint8
	ParamId dilithium.ParameterSetId
	Curve ecc.EdDSACurve
	Dilithium *libdilithium.Dilithium
	PublicPoint, PublicDilithium []byte
}

type PrivateKey struct {
	PublicKey
	SecretEC    []byte
	SecretDilithium []byte
}

func GenerateKey(rand io.Reader, algId uint8, c ecc.EdDSACurve, paramId dilithium.ParameterSetId) (priv *PrivateKey, err error) {
	priv = new(PrivateKey)

	priv.PublicKey.AlgId = algId
	priv.PublicKey.Curve = c
	priv.PublicKey.ParamId = paramId
	priv.PublicKey.Dilithium = paramId.GetDilithium()

	priv.PublicKey.PublicPoint, priv.SecretEC, err = c.GenerateEdDSA(rand)
	if err != nil {
		return nil, err
	}

	dilithiumSeed := make([]byte, libdilithium.SEEDBYTES)
	_, err = rand.Read(dilithiumSeed)
	if err != nil {
		return nil, err
	}

	priv.PublicKey.PublicDilithium, priv.SecretDilithium = priv.PublicKey.Dilithium.KeyGen(dilithiumSeed)
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
	var tr [libdilithium.SEEDBYTES]byte

	if err = priv.PublicKey.Curve.ValidateEdDSA(priv.PublicKey.PublicPoint, priv.SecretEC); err != nil {
		return err
	}

	state := sha3.NewShake256()

	state.Write(priv.PublicKey.PublicDilithium)
	state.Read(tr[:])
	kSk := priv.PublicKey.Dilithium.UnpackSK(priv.SecretDilithium)
	if subtle.ConstantTimeCompare(kSk.Tr[:], tr[:]) == 0 {
		return errors.KeyInvalidError("dilithium_eddsa: invalid public key")
	}

	return
}