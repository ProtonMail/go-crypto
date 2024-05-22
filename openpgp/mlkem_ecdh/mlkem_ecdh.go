// Package mlkem_ecdh implements hybrid ML-KEM + ECDH encryption, suitable for OpenPGP, experimental.
// It follows the spec https://www.ietf.org/archive/id/draft-wussler-openpgp-pqc-03.html#name-composite-kem-schemes
package mlkem_ecdh

import (
	goerrors "errors"
	"fmt"
	"github.com/ProtonMail/go-crypto/openpgp/internal/encoding"
	"golang.org/x/crypto/sha3"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/aes/keywrap"
	"github.com/ProtonMail/go-crypto/openpgp/errors"
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

	kek, err := buildKey(pub, ecSS, ecEphemeral, pub.PublicPoint, kSS, kEphemeral, pub.PublicMlkem)
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

	kek, err := buildKey(&priv.PublicKey, ecSS, ecEphemeral, priv.PublicPoint, kSS, kEphemeral, priv.PublicMlkem)
	if err != nil {
		return nil, err
	}

	msg, err = keywrap.Unwrap(kek, ciphertext)

	fmt.Printf("kek:%x\nsk:%x\n", kek, msg)

	return msg, err
}

// buildKey implements the composite KDF as specified in
// https://www.ietf.org/archive/id/draft-wussler-openpgp-pqc-03.html#name-key-combiner
func buildKey(pub *PublicKey, eccSecretPoint, eccEphemeral, eccPublicKey, mlkemKeyShare, mlkemEphemeral []byte, mlkemPublicKey kem.PublicKey) ([]byte, error) {
	h := sha3.New256()

	// SHA3 never returns error
	_, _ = h.Write(eccSecretPoint)
	_, _ = h.Write(eccEphemeral)
	_, _ = h.Write(eccPublicKey)
	eccKeyShare := h.Sum(nil)

	serializedMlkemKey, err := mlkemPublicKey.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// eccData = eccKeyShare || eccCipherText
	// mlkemData = mlkemKeyShare || mlkemCipherText
	// encData = counter || eccData || mlkemData || fixedInfo
	k := sha3.New256()

	// SHA3 never returns error
	_, _ = k.Write([]byte{0x00, 0x00, 0x00, 0x01})
	_, _ = k.Write(eccKeyShare)
	_, _ = k.Write(eccEphemeral)
	_, _ = k.Write(eccPublicKey)
	_, _ = k.Write(mlkemKeyShare)
	_, _ = k.Write(mlkemEphemeral)
	_, _ = k.Write(serializedMlkemKey)
	_, _ = k.Write([]byte{pub.AlgId})
	_, _ = k.Write([]byte("OpenPGPCompositeKDFv1"))

	fmt.Printf("ecc:%x\nkyber:%x\n", eccKeyShare, mlkemKeyShare)

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

// EncodeFields encodes an ML-KEM + ECDH session key encryption fields as
// ephemeral ECDH public key | ML-KEM ciphertext | follow byte length | cipherFunction (v3 only) | encryptedSessionKey
// and writes it to writer.
func EncodeFields(w io.Writer, ec, ml, encryptedSessionKey []byte, cipherFunction byte, v6 bool) (err error) {
	if _, err = w.Write(ec); err != nil {
		return err
	}

	if _, err = w.Write(ml); err != nil {
		return err
	}

	lenAlgorithm := 0
	if !v6 {
		lenAlgorithm = 1
	}

	if _, err = w.Write([]byte{byte(len(encryptedSessionKey) + lenAlgorithm)}); err != nil {
		return err
	}

	if !v6 {
		if _, err = w.Write([]byte{cipherFunction}); err != nil {
			return err
		}
	}

	_, err = w.Write(encryptedSessionKey)
	return err
}

// DecodeFields decodes an ML-KEM + ECDH session key encryption fields as
// ephemeral ECDH public key | ML-KEM ciphertext | follow byte length | cipherFunction (v3 only) | encryptedSessionKey.
func DecodeFields(r io.Reader, lenEcc, lenMlkem int, v6 bool) (encryptedMPI1, encryptedMPI2, encryptedMPI3 encoding.Field, cipherFunction byte, err error) {
	var buf [1]byte

	encryptedMPI1 = encoding.NewEmptyOctetArray(lenEcc)
	if _, err = encryptedMPI1.ReadFrom(r); err != nil {
		return
	}

	encryptedMPI2 = encoding.NewEmptyOctetArray(lenMlkem)
	if _, err = encryptedMPI2.ReadFrom(r); err != nil {
		return
	}

	// A one-octet size of the following fields.
	if _, err = io.ReadFull(r, buf[:]); err != nil {
		return
	}

	followingLen := buf[0]
	// The one-octet algorithm identifier, if it was passed (in the case of a v3 PKESK packet).
	if !v6 {
		if _, err = io.ReadFull(r, buf[:]); err != nil {
			return
		}
		cipherFunction = buf[0]
		followingLen -= 1
	}

	// The encrypted session key.
	encryptedMPI3 = encoding.NewEmptyOctetArray(int(followingLen))
	if _, err = encryptedMPI3.ReadFrom(r); err != nil {
		return
	}

	return
}