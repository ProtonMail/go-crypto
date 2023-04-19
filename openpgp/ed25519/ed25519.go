// Package ed25519 implements the ed25519 signature algorithm for OpenPGP
// as defined in the Open PGP crypto refresh.
package ed25519

import (
	"crypto/subtle"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
	ed25519lib "github.com/cloudflare/circl/sign/ed25519"
)

const PointSize = 32
const PrivateKeySize = 64
const SignatureSize = 64

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
	sk.Key = ed25519lib.NewKeyFromSeed(seed)
	return nil
}

func GenerateKey(rand io.Reader) (*PrivateKey, error) {
	publicKey, privateKey, err := ed25519lib.GenerateKey(rand)
	if err != nil {
		return nil, err
	}
	privateKeyOut := new(PrivateKey)
	privateKeyOut.PublicKey.Point = publicKey[:]
	privateKeyOut.Key = privateKey[:]
	return privateKeyOut, nil
}

// Sign signs a message with the ed25519 algorithm.
func Sign(priv *PrivateKey, message []byte) ([]byte, error) {
	return ed25519lib.Sign(priv.Key, message), nil
}

// Verify verifies a ed25519 signature
func Verify(pub *PublicKey, message []byte, signature []byte) bool {
	return ed25519lib.Verify(pub.Point, message, signature)
}

// Validate checks if the ed25519 private key is valid
func Validate(priv *PrivateKey) error {
	expectedPrivateKey := ed25519lib.NewKeyFromSeed(priv.Seed())
	if subtle.ConstantTimeCompare(priv.Key, expectedPrivateKey) == 0 {
		return errors.KeyInvalidError("ed25519: invalid ed25519 secret")
	}
	if subtle.ConstantTimeCompare(priv.PublicKey.Point, expectedPrivateKey[PointSize:]) == 0 {
		return errors.KeyInvalidError("ed25519: invalid ed25519 public key")
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
