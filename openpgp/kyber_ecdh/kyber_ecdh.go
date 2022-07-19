// Package kyber_ecdh implements hybrid Kyber + ECDH encryption, suitable for OpenPGP, experimental.
package kyber_ecdh

import (
	goerrors "errors"
	"io"

	"github.com/ProtonMail/go-crypto/internal/kmac"
	"github.com/ProtonMail/go-crypto/openpgp/aes/keywrap"
	"github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/internal/algorithm"
	"github.com/ProtonMail/go-crypto/openpgp/internal/ecc"
	"github.com/cloudflare/circl/kem"
)

type PublicKey struct {
	AlgId uint8
	Curve ecc.ECDHCurve
	Kyber kem.Scheme
	PublicKyber kem.PublicKey
	PublicPoint []byte
}

type PrivateKey struct {
	PublicKey
	SecretEC    []byte
	SecretKyber kem.PrivateKey
}

func GenerateKey(rand io.Reader, algId uint8, c ecc.ECDHCurve, k kem.Scheme) (priv *PrivateKey, err error) {
	priv = new(PrivateKey)

	priv.PublicKey.AlgId = algId
	priv.PublicKey.Curve = c
	priv.PublicKey.Kyber = k

	priv.PublicKey.PublicPoint, priv.SecretEC, err = c.GenerateECDH(rand)
	if err != nil {
		return nil, err
	}

	kyberSeed := make([]byte, k.SeedSize())
	_, err = rand.Read(kyberSeed)
	if err != nil {
		return nil, err
	}

	priv.PublicKey.PublicKyber, priv.SecretKyber = priv.PublicKey.Kyber.DeriveKeyPair(kyberSeed)
	return
}

// Encrypt implements Kyber + ECC encryption as specified in
// https://www.ietf.org/archive/id/draft-wussler-openpgp-pqc-00.html#section-4.2.3
func Encrypt(rand io.Reader, pub *PublicKey, msg, publicKeyHash []byte) (kEphemeral, ecEphemeral, ciphertext []byte, err error) {
	if len(msg) > 64 {
		return nil, nil, nil, goerrors.New("kyber_ecdh: session key too long")
	}

	if len(msg) % 8 != 0 {
		return nil, nil, nil, goerrors.New("kyber_ecdh: session key not a multiple of 8")
	}

	// EC shared secret derivation
	ecEphemeral, ecSS, err := pub.Curve.Encaps(rand, pub.PublicPoint)
	if err != nil {
		return nil, nil, nil, err
	}

	// Kyber shared secret derivation
	kyberSeed := make([]byte, pub.Kyber.EncapsulationSeedSize())
	_, err = rand.Read(kyberSeed)
	if err != nil {
		return nil, nil, nil, err
	}

	kEphemeral, kSS, err := pub.Kyber.EncapsulateDeterministically(pub.PublicKyber, kyberSeed)
	if err != nil {
		return nil, nil, nil, err
	}

	z, err := buildKey(pub, ecSS, kSS, publicKeyHash)
	if err != nil {
		return nil, nil, nil, err
	}

	if ciphertext, err = keywrap.Wrap(z, msg); err != nil {
		return nil, nil, nil, err
	}

	return kEphemeral, ecEphemeral, ciphertext, nil
}

// Decrypt implements Kyber + ECC decryption as specified in
// https://www.ietf.org/archive/id/draft-wussler-openpgp-pqc-00.html#section-4.2.4
func Decrypt(priv *PrivateKey, kEphemeral, ecEphemeral, ciphertext, publicKeyHash []byte) (msg []byte, err error) {
	// EC shared secret derivation
	ecSS, err := priv.PublicKey.Curve.Decaps(ecEphemeral, priv.SecretEC)
	if err != nil {
		return nil, err
	}

	// Kyber shared secret derivation
	kSS, err := priv.PublicKey.Kyber.Decapsulate(priv.SecretKyber, kEphemeral)
	if err != nil {
		return nil, err
	}

	z, err := buildKey(&priv.PublicKey, ecSS, kSS, publicKeyHash)
	if err != nil {
		return nil, err
	}

	msg, err = keywrap.Unwrap(z, ciphertext)

	return msg, nil
}

// buildKey implements the composite KDF as specified in
// https://www.ietf.org/archive/id/draft-wussler-openpgp-pqc-00.html#section-4.2.2
// Note: the domain separation has been already updated
func buildKey(pub *PublicKey, eccKeyShare, kyberKeyShare, publicKeyHash []byte) ([]byte, error) {
	// fixedInfo = algID || SHA3-256(publicKey)
	// encKeyShares = counter || eccKeyShare || kyberKeyShare || fixedInfo
	// MB = KMAC256(domSeparation, encKeyShares, oBits, customizationString)
	k := kmac.NewKMAC256([]byte("OpenPGPKyberCompositeKeyDerivation"), algorithm.AES256.KeySize(), []byte("KDF"))

	// KMAC never returns error
	_, _ = k.Write([]byte{0x00, 0x00, 0x00, 0x01})
	_, _ = k.Write(eccKeyShare)
	_, _ = k.Write(kyberKeyShare)
	_, _ = k.Write([]byte{pub.AlgId})
	_, _ = k.Write(publicKeyHash)

	return k.Sum(nil), nil
}


func Validate(priv *PrivateKey) (err error) {
	if err = priv.PublicKey.Curve.ValidateECDH(priv.PublicKey.PublicPoint, priv.SecretEC); err != nil {
		return err
	}

	if !priv.PublicKey.PublicKyber.Equal(priv.SecretKyber.Public()) {
		return errors.KeyInvalidError("kyber_ecdh: invalid public key")
	}

	return
}