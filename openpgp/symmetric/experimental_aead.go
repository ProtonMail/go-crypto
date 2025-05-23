package symmetric

import (
	"github.com/ProtonMail/go-crypto/openpgp/internal/algorithm"
	"io"
)

type ExperimentalAEADPublicKey struct {
	Cipher      algorithm.CipherFunction
	BindingHash [32]byte
	Key         []byte
}

type ExperimentalAEADPrivateKey struct {
	PublicKey ExperimentalAEADPublicKey
	HashSeed  [32]byte
	Key       []byte
}

func ExperimentalAEADGenerateKey(rand io.Reader, cipher algorithm.CipherFunction) (priv *ExperimentalAEADPrivateKey, err error) {
	priv, err = generatePrivatePartExperimentalAEAD(rand, cipher)
	if err != nil {
		return
	}

	priv.generatePublicPartExperimentalAEAD(cipher)
	return
}

func generatePrivatePartExperimentalAEAD(rand io.Reader, cipher algorithm.CipherFunction) (priv *ExperimentalAEADPrivateKey, err error) {
	priv = new(ExperimentalAEADPrivateKey)
	var seed [32]byte
	_, err = rand.Read(seed[:])
	if err != nil {
		return
	}

	key := make([]byte, cipher.KeySize())
	_, err = rand.Read(key)
	if err != nil {
		return
	}

	priv.HashSeed = seed
	priv.Key = key
	return
}

func (priv *ExperimentalAEADPrivateKey) generatePublicPartExperimentalAEAD(cipher algorithm.CipherFunction) (err error) {
	priv.PublicKey.Cipher = cipher

	bindingHash := ComputeBindingHash(priv.HashSeed)

	priv.PublicKey.Key = make([]byte, len(priv.Key))
	copy(priv.PublicKey.Key, priv.Key)
	copy(priv.PublicKey.BindingHash[:], bindingHash)
	return
}

func (pub *ExperimentalAEADPublicKey) Encrypt(rand io.Reader, data []byte, mode algorithm.AEADMode) (nonce []byte, ciphertext []byte, err error) {
	block := pub.Cipher.New(pub.Key)
	aead := mode.New(block)
	nonce = make([]byte, aead.NonceSize())
	rand.Read(nonce)
	ciphertext = aead.Seal(nil, nonce, data, nil)
	return
}

func (priv *ExperimentalAEADPrivateKey) Decrypt(nonce []byte, ciphertext []byte, mode algorithm.AEADMode) (message []byte, err error) {

	block := priv.PublicKey.Cipher.New(priv.Key)
	aead := mode.New(block)
	message, err = aead.Open(nil, nonce, ciphertext, nil)
	return
}
