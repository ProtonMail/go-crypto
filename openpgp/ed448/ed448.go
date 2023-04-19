// Package ed448 implements the ed448 signature algorithm for OpenPGP
// as defined in the Open PGP crypto refresh.
package ed448

import (
	"crypto/subtle"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
	ed448lib "github.com/cloudflare/circl/sign/ed448"
)

const PointSize = 57
const PrivateKeySize = 114
const SignatureSize = 114

type PublicKey struct {
	Point []byte
}

type PrivateKey struct {
	PublicKey
	Key []byte // encoded as seed | pub key point
}

func NewPublicKey() *PublicKey {
	return &PublicKey{}
}

func NewPrivateKey(key PublicKey) *PrivateKey {
	return &PrivateKey{
		PublicKey: key,
	}
}

func (pk *PrivateKey) Seed() []byte {
	return pk.Key[:PointSize]
}

// MarshalByteSecret returns the underlying 32 byte seed of the private key
func (pk *PrivateKey) MarshalByteSecret() []byte {
	return pk.Seed()
}

// UnmarshalByteSecret computes the private key from the secret seed
// and stores it in the private key object.
func (sk *PrivateKey) UnmarshalByteSecret(seed []byte) error {
	sk.Key = ed448lib.NewKeyFromSeed(seed)
	return nil
}

func GenerateKey(rand io.Reader) (*PrivateKey, error) {
	publicKey, privateKey, err := ed448lib.GenerateKey(rand)
	if err != nil {
		return nil, err
	}
	privateKeyOut := new(PrivateKey)
	privateKeyOut.PublicKey.Point = publicKey[:]
	privateKeyOut.Key = privateKey[:]
	return privateKeyOut, nil
}

// Sign signs a message with the ed448 algorithm.
func Sign(priv *PrivateKey, message []byte) ([]byte, error) {
	// Ed448 is used with the empty string as a context string.
	// See https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-crypto-refresh-08#section-13.7
	return ed448lib.Sign(priv.Key, message, ""), nil
}

// Verify verifies a ed448 signature
func Verify(pub *PublicKey, message []byte, signature []byte) bool {
	// Ed448 is used with the empty string as a context string.
	// See https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-crypto-refresh-08#section-13.7
	return ed448lib.Verify(pub.Point, message, signature, "")
}

// Validate checks if the ed448 private key is valid
func Validate(priv *PrivateKey) error {
	expectedPrivateKey := ed448lib.NewKeyFromSeed(priv.Seed())
	if subtle.ConstantTimeCompare(priv.Key, expectedPrivateKey) == 0 {
		return errors.KeyInvalidError("ed448: invalid ed448 secret")
	}
	if subtle.ConstantTimeCompare(priv.PublicKey.Point, expectedPrivateKey[PointSize:]) == 0 {
		return errors.KeyInvalidError("ed448: invalid ed448 public key")
	}
	return nil
}

// ENCODING/DECODING signature:

func WriteSignature(writer io.Writer, signature []byte) error {
	_, err := writer.Write(signature)
	return err
}

func ReadSignature(reader io.Reader) ([]byte, error) {
	signature := make([]byte, SignatureSize)
	if _, err := io.ReadFull(reader, signature); err != nil {
		return nil, err
	}
	return signature, nil
}
