package x448

import (
	"crypto/sha512"
	"crypto/subtle"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/aes/keywrap"
	"github.com/ProtonMail/go-crypto/openpgp/errors"
	x448lib "github.com/cloudflare/circl/dh/x448"
	"golang.org/x/crypto/hkdf"
)

const hkdfInfo = "OpenPGP X448"
const aesKeySize = 32
const PointSize = 56

type PublicKey struct {
	Point []byte
}

type PrivateKey struct {
	PublicKey
	Secret []byte
}

func NewPrivateKey(key PublicKey) *PrivateKey {
	return &PrivateKey{
		PublicKey: key,
	}
}

// Validate validates that the provided public key matches
// the private key.
func Validate(pk *PrivateKey) (err error) {
	var expectedPublicKey, privateKey x448lib.Key
	subtle.ConstantTimeCopy(1, privateKey[:], pk.Secret)
	x448lib.KeyGen(&expectedPublicKey, &privateKey)
	if subtle.ConstantTimeCompare(expectedPublicKey[:], pk.PublicKey.Point) == 0 {
		return errors.KeyInvalidError("x448: invalid key")
	}
	return nil
}

// GenerateKey generates a new x448 key pair
func GenerateKey(rand io.Reader) (*PrivateKey, error) {
	var privateKey, publicKey x448lib.Key
	privateKeyOut := new(PrivateKey)
	err := generateKey(rand, &privateKey, &publicKey)
	if err != nil {
		return nil, err
	}
	privateKeyOut.PublicKey.Point = publicKey[:]
	privateKeyOut.Secret = privateKey[:]
	return privateKeyOut, nil
}

func generateKey(rand io.Reader, privateKey *x448lib.Key, publicKey *x448lib.Key) error {
	maxRounds := 10
	isZero := true
	for round := 0; isZero; round++  {
		if round == maxRounds {
			return errors.InvalidArgumentError("x448: zero keys only, randomness source might be corrupt")
		}
		_, err := io.ReadFull(rand, privateKey[:])
		if err != nil {
			return err
		}
		isZero = constantTimeIsZero(privateKey[:])
	}
	x448lib.KeyGen(publicKey, privateKey)
	return nil
}

// Encrypt encrpyts a sessionKey with x448 according to 
// the OpenPGP crypto refresh specification section 5.1.6. The function assumes that the
// sessionKey has the correct format and padding according to the specification.
func Encrypt(rand io.Reader, publicKey *PublicKey, sessionKey []byte) (ephemeralPublicKey *PublicKey, encryptedSessionKey []byte,  err error) {
	var ephemeralPrivate, ephemeralPublic, staticPublic, shared x448lib.Key
	// Check that the input static public key has 32 bytes
	if len(publicKey.Point) != PointSize {
		err = errors.KeyInvalidError("x448: the public key has the wrong size")
		return
	}
	copy(staticPublic[:], publicKey.Point)
	// Generate ephemeral keyPair
	err = generateKey(rand, &ephemeralPrivate, &ephemeralPublic)
	if err != nil {
		return
	}
	// Compute shared key
	ok := x448lib.Shared(&shared, &ephemeralPrivate, &staticPublic)
	if !ok {
		err = errors.KeyInvalidError("x448: the public key is a low order point")
		return
	}
	// Derive the encryption key from the shared secret
	encryptionKey := applyHKDF(shared[:])
	ephemeralPublicKey = &PublicKey{
		Point: ephemeralPublic[:],
	}
	// Encrypt the sessionKey with aes key wrapping
	encryptedSessionKey, err = keywrap.Wrap(encryptionKey, sessionKey)
	return
}

// Decrypt decrypts a session key stored in ciphertext with the provided x448
// private key and ephemeral public key
func Decrypt(privateKey *PrivateKey, ephemeralPublicKey *PublicKey, ciphertext []byte) (encodedSessionKey []byte, err error) {
	var ephemeralPublic, staticPrivate, shared x448lib.Key
	// Check that the input ephemeral public key has 32 bytes
	if len(ephemeralPublicKey.Point) != PointSize {
		err = errors.KeyInvalidError("x448: the public key has the wrong size")
		return
	}
	copy(ephemeralPublic[:], ephemeralPublicKey.Point)
	subtle.ConstantTimeCopy(1, staticPrivate[:], privateKey.Secret)
	// Compute shared key
	ok := x448lib.Shared(&shared, &staticPrivate, &ephemeralPublic)
	if !ok {
		err = errors.KeyInvalidError("x448: the ephemeral public key is a low order point")
		return
	}
	// Derive the encryption key from the shared secret
	encryptionKey := applyHKDF(shared[:])
	// Decrypt the session key with aes key wrapping
	encodedSessionKey, err = keywrap.Unwrap(encryptionKey, ciphertext)
	return
}

func applyHKDF(inputKey []byte) []byte {
	hkdfReader := hkdf.New(sha512.New, inputKey, []byte{}, []byte(hkdfInfo))
	encryptionKey := make([]byte, aesKeySize)
	_, _ = io.ReadFull(hkdfReader, encryptionKey)
	return encryptionKey
}

func constantTimeIsZero(bytes []byte) bool {
	isZero := byte(0)
	for _, b := range bytes {
		isZero |= b
	}
	return isZero == 0
}

// ENCODING/DECODING ciphertexts:

// EncodeFieldsLength returns the length of the ciphertext encoding
// given the encrpyted session key.
func EncodedFieldsLength(encryptedSessionKey []byte) int {
	return PointSize + 1 + len(encryptedSessionKey)
}

// EncodeField encodes x448 session key encryption as
// ephemeral x448 public key | encryptedSessionKey length | encryptedSessionKey
// and writes it to writer
func EncodeFields(writer io.Writer, ephemeralPublicKey *PublicKey, encryptedSessionKey []byte) (err error) {
	if _, err = writer.Write(ephemeralPublicKey.Point); err != nil {
		return
	}
	if _, err = writer.Write([]byte{byte(len(encryptedSessionKey))}); err != nil {
		return
	}
	_, err = writer.Write(encryptedSessionKey)
	return 
}

// DecodeField decodes a x448 session key encryption as
// ephemeral x448 public key | encryptedSessionKey length | encryptedSessionKey
func DecodeFields(reader io.Reader) (ephemeralPublicKey *PublicKey, encryptedSessionKey []byte, err error) {
	var buf [1]byte
	ephemeralPublicKey = &PublicKey{
		Point: make([]byte, PointSize),
	}
	_, err = io.ReadFull(reader, ephemeralPublicKey.Point)
	if err != nil {
		return
	}
	_, err = io.ReadFull(reader, buf[:])
	if err != nil {
		return
	}
	encryptedSessionKey = make([]byte, buf[0])
	_, err = io.ReadFull(reader, encryptedSessionKey)
	return
}
