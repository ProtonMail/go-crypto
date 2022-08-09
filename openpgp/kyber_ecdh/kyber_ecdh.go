// Package kyber_ecdh implements hybrid Kyber + ECDH encryption, suitable for OpenPGP, experimental.
package kyber_ecdh

import (
	"crypto/subtle"
	goerrors "errors"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/internal/algorithm"
	"github.com/ProtonMail/go-crypto/openpgp/internal/ecc"
	aeskeywrap "github.com/google/tink/go/kwp/subtle"
	kyber "github.com/kudelskisecurity/crystals-go/crystals-kyber"
	"golang.org/x/crypto/sha3"
)

type PublicKey struct {
	AlgId uint8
	Curve ecc.ECDHCurve
	Kyber *kyber.Kyber
	PublicPoint, PublicKyber []byte
}

type PrivateKey struct {
	PublicKey
	SecretEC    []byte
	SecretKyber []byte
}

func GenerateKey(rand io.Reader, algId uint8, c ecc.ECDHCurve, k *kyber.Kyber) (priv *PrivateKey, err error) {
	priv = new(PrivateKey)

	priv.PublicKey.AlgId = algId
	priv.PublicKey.Curve = c
	priv.PublicKey.Kyber = k

	priv.PublicKey.PublicPoint, priv.SecretEC, err = c.GenerateECDH(rand)
	if err != nil {
		return nil, err
	}

	kyberSeed := make([]byte, kyber.SIZEZ + kyber.SEEDBYTES)
	_, err = rand.Read(kyberSeed)
	if err != nil {
		return nil, err
	}

	priv.PublicKey.PublicKyber, priv.SecretKyber = priv.PublicKey.Kyber.KeyGen(kyberSeed)
	return
}

func Encrypt(rand io.Reader, pub *PublicKey, msg, fingerprint []byte) (kEphemeral, ecEphemeral, ciphertext []byte, err error) {
	var kwp *aeskeywrap.KWP

	if len(msg) > 64 {
		return nil, nil, nil, goerrors.New("kyber_ecdh: message too long")
	}

	// EC shared secret derivation
	ecEphemeral, ecSS, err := pub.Curve.Encaps(rand, pub.PublicPoint)
	if err != nil {
		return nil, nil, nil, err
	}

	// Kyber shared secret derivation
	kyberSeed := make([]byte, kyber.SEEDBYTES)
	_, err = rand.Read(kyberSeed)
	if err != nil {
		return nil, nil, nil, err
	}

	kEphemeral, kSS := pub.Kyber.Encaps(pub.PublicKyber, kyberSeed)

	z, err := buildKey(pub, kSS, ecSS, fingerprint)
	if err != nil {
		return nil, nil, nil, err
	}

	if kwp, err = aeskeywrap.NewKWP(z); err != nil {
		return nil, nil, nil, err
	}

	if ciphertext, err = kwp.Wrap(msg); err != nil {
		return nil, nil, nil, err
	}

	return kEphemeral, ecEphemeral, ciphertext, nil
}

func Decrypt(priv *PrivateKey, kEphemeral, ecEphemeral, ciphertext, fingerprint []byte) (msg []byte, err error) {
	var kwp *aeskeywrap.KWP

	// EC shared secret derivation
	ecSS, err := priv.PublicKey.Curve.Decaps(ecEphemeral, priv.SecretEC)
	if err != nil {
		return nil, err
	}

	// Kyber shared secret derivation
	kSS := priv.PublicKey.Kyber.Decaps(priv.SecretKyber, kEphemeral)

	z, err := buildKey(&priv.PublicKey, kSS, ecSS, fingerprint)
	if err != nil {
		return nil, err
	}

	if kwp, err = aeskeywrap.NewKWP(z); err != nil {
		return nil, err
	}

	if msg, err = kwp.Unwrap(ciphertext); err != nil {
		return nil, err
	}

	return msg, nil
}

func buildKey(pub *PublicKey, sK, zb, fingerprint []byte) ([]byte, error) {
	// MB = Hash ( ID || Fprint || sK || sEC );
	h := sha3.New512()

	// Hash never returns error
	_, _ = h.Write([]byte{pub.AlgId})
	_, _ = h.Write(fingerprint)
	_, _ = h.Write(sK)
	_, _ = h.Write(zb)

	mb := h.Sum(nil)

	return mb[:algorithm.AES256.KeySize()], nil // return oBits leftmost bits of MB.
}


func Validate(priv *PrivateKey) (err error) {
	if err = priv.PublicKey.Curve.ValidateECDH(priv.PublicKey.PublicPoint, priv.SecretEC); err != nil {
		return err
	}

	kSk := priv.PublicKey.Kyber.UnpackSK(priv.SecretKyber)
	if subtle.ConstantTimeCompare(kSk.Pk, priv.PublicKey.PublicKyber) == 0 {
		return errors.KeyInvalidError("kyber_ecdh: invalid public key")
	}

	return
}