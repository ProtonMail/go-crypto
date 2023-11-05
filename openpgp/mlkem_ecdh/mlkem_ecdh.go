// Package mlkem_ecdh implements hybrid ML-KEM + ECDH encryption, suitable for OpenPGP, experimental.
// It follows the spec https://www.ietf.org/archive/id/draft-wussler-openpgp-pqc-03.html#name-composite-kem-schemes
package mlkem_ecdh

import (
	goerrors "errors"
	"golang.org/x/crypto/sha3"
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
	Mlkem kem.Scheme
	PublicMlkem kem.PublicKey
	PublicPoint []byte
}

type PrivateKey struct {
	PublicKey
	SecretEc    []byte
	SecretMlkem kem.PrivateKey
}

// GenerateKey implements ML-KEM + ECC key generation as specified in
// https://www.ietf.org/archive/id/draft-wussler-openpgp-pqc-03.html#name-key-generation-procedure
func GenerateKey(rand io.Reader, algId uint8, c ecc.ECDHCurve, k kem.Scheme) (priv *PrivateKey, err error) {
	priv = new(PrivateKey)

	priv.PublicKey.AlgId = algId
	priv.PublicKey.Curve = c
	priv.PublicKey.Mlkem = k

	priv.PublicKey.PublicPoint, priv.SecretEc, err = c.GenerateECDH(rand)
	if err != nil {
		return nil, err
	}

	kyberSeed := make([]byte, k.SeedSize())
	_, err = rand.Read(kyberSeed)
	if err != nil {
		return nil, err
	}

	priv.PublicKey.PublicMlkem, priv.SecretMlkem = priv.PublicKey.Mlkem.DeriveKeyPair(kyberSeed)
	return
}

// Encrypt implements ML-KEM + ECC encryption as specified in
// https://www.ietf.org/archive/id/draft-wussler-openpgp-pqc-03.html#name-encryption-procedure
func Encrypt(rand io.Reader, pub *PublicKey, msg []byte) (kEphemeral, ecEphemeral, ciphertext []byte, err error) {
	if len(msg) > 64 {
		return nil, nil, nil, goerrors.New("mlkem_ecdh: session key too long")
	}

	if len(msg) % 8 != 0 {
		return nil, nil, nil, goerrors.New("mlkem_ecdh: session key not a multiple of 8")
	}

	// EC shared secret derivation
	ecEphemeral, ecSS, err := pub.Curve.Encaps(rand, pub.PublicPoint)
	if err != nil {
		return nil, nil, nil, err
	}

	// ML-KEM shared secret derivation
	kyberSeed := make([]byte, pub.Mlkem.EncapsulationSeedSize())
	_, err = rand.Read(kyberSeed)
	if err != nil {
		return nil, nil, nil, err
	}

	kEphemeral, kSS, err := pub.Mlkem.EncapsulateDeterministically(pub.PublicMlkem, kyberSeed)
	if err != nil {
		return nil, nil, nil, err
	}

	kek, err := buildKey(pub, ecSS, ecEphemeral, pub.PublicPoint, kSS, kEphemeral)
	if err != nil {
		return nil, nil, nil, err
	}

	if ciphertext, err = keywrap.Wrap(kek, msg); err != nil {
		return nil, nil, nil, err
	}

	return kEphemeral, ecEphemeral, ciphertext, nil
}

// Decrypt implements ML-KEM + ECC decryption as specified in
// https://www.ietf.org/archive/id/draft-wussler-openpgp-pqc-03.html#name-decryption-procedure
func Decrypt(priv *PrivateKey, kEphemeral, ecEphemeral, ciphertext []byte) (msg []byte, err error) {
	// EC shared secret derivation
	ecSS, err := priv.PublicKey.Curve.Decaps(ecEphemeral, priv.SecretEc)
	if err != nil {
		return nil, err
	}

	// ML-KEM shared secret derivation
	kSS, err := priv.PublicKey.Mlkem.Decapsulate(priv.SecretMlkem, kEphemeral)
	if err != nil {
		return nil, err
	}

	kek, err := buildKey(&priv.PublicKey, ecSS, ecEphemeral, priv.PublicPoint, kSS, kEphemeral)
	if err != nil {
		return nil, err
	}

	msg, err = keywrap.Unwrap(kek, ciphertext)

	return msg, err
}

// buildKey implements the composite KDF as specified in
// https://www.ietf.org/archive/id/draft-wussler-openpgp-pqc-03.html#name-key-combiner
func buildKey(pub *PublicKey, eccSecretPoint, eccEphemeral, eccPublicKey, kyberKeyShare, kyberEphemeral []byte) ([]byte, error) {
	h := sha3.New256()

	// SHA3 never returns error
	_, _ = h.Write(eccSecretPoint)
	_, _ = h.Write(eccEphemeral)
	_, _ = h.Write(eccPublicKey)
	eccKeyShare := h.Sum(nil)

	// eccData = eccKeyShare || eccCipherText
	// mlkemData = mlkemKeyShare || mlkemCipherText
	// encData = counter || eccData || mlkemData || fixedInfo
	k := kmac.NewKMAC256([]byte("OpenPGPCompositeKeyDerivationFunction"), algorithm.AES256.KeySize(), []byte("KDF"))

	// KMAC never returns error
	_, _ = k.Write([]byte{0x00, 0x00, 0x00, 0x01})
	_, _ = k.Write(eccKeyShare)
	_, _ = k.Write(eccEphemeral)
	_, _ = k.Write(kyberKeyShare)
	_, _ = k.Write(kyberEphemeral)
	_, _ = k.Write([]byte{pub.AlgId})

	return k.Sum(nil), nil
}

// Validate checks that the public key corresponds to the private key
func Validate(priv *PrivateKey) (err error) {
	if err = priv.PublicKey.Curve.ValidateECDH(priv.PublicKey.PublicPoint, priv.SecretEc); err != nil {
		return err
	}

	if !priv.PublicKey.PublicMlkem.Equal(priv.SecretMlkem.Public()) {
		return errors.KeyInvalidError("mlkem_ecdh: invalid public key")
	}

	return
}