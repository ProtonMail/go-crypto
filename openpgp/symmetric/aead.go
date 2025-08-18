package symmetric

import (
	"github.com/ProtonMail/go-crypto/openpgp/internal/algorithm"
	"io"
)

type AEADPublicKey struct {
	Cipher      algorithm.CipherFunction
	AEADMode    algorithm.AEADMode
	FpSeed      [32]byte
	// While this is a "public" key, the symmetric key needs to be present here.
	// Symmetric cryptographic operations use the same key material for
	// signing and verifying, and go-crypto assumes that a public key type will
	// be used for encryption. Thus, this `Key` field must never be exported
	// publicly.
	Key         []byte
}

type AEADPrivateKey struct {
	PublicKey AEADPublicKey
	Key       []byte
}

func AEADGenerateKey(rand io.Reader, cipher algorithm.CipherFunction, aead algorithm.AEADMode) (priv *AEADPrivateKey, err error) {
	priv, err = generatePrivatePartAEAD(rand, cipher)
	if err != nil {
		return
	}

	priv.generatePublicPartAEAD(rand, cipher, aead)
	return
}

func generatePrivatePartAEAD(rand io.Reader, cipher algorithm.CipherFunction) (priv *AEADPrivateKey, err error) {
	priv = new(AEADPrivateKey)
	key := make([]byte, cipher.KeySize())
	_, err = rand.Read(key)
	if err != nil {
		return
	}
	priv.Key = key
	return
}

func (priv *AEADPrivateKey) generatePublicPartAEAD(rand io.Reader, cipher algorithm.CipherFunction, aead algorithm.AEADMode) (err error) {
	priv.PublicKey.Cipher = cipher
	priv.PublicKey.AEADMode = aead

	var seed [32]byte
	_, err = rand.Read(seed[:])
	if err != nil {
		return
	}

	priv.PublicKey.Key = make([]byte, len(priv.Key))
	copy(priv.PublicKey.Key, priv.Key)
	copy(priv.PublicKey.FpSeed[:], seed[:])
	return
}

func (pub *AEADPublicKey) Encrypt(rand io.Reader, data []byte, mode algorithm.AEADMode) (nonce []byte, ciphertext []byte, err error) {
	block := pub.Cipher.New(pub.Key)
	aead := mode.New(block)
	nonce = make([]byte, aead.NonceSize())
	rand.Read(nonce)
	ciphertext = aead.Seal(nil, nonce, data, nil)
	return
}

func (priv *AEADPrivateKey) Decrypt(ivAndCiphertext []byte, mode algorithm.AEADMode) (message []byte, err error) {
	nonceLength := mode.NonceLength()
	iv := ivAndCiphertext[:nonceLength]
	ciphertext := ivAndCiphertext[nonceLength:]
	block := priv.PublicKey.Cipher.New(priv.Key)
	aead := mode.New(block)
	message, err = aead.Open(nil, iv, ciphertext, nil)
	return
}
