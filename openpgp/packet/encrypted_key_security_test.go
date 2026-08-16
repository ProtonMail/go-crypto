package packet

import (
	"crypto"
	"crypto/rsa"
	"io"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/internal/encoding"
)

type emptySessionKeyDecrypter struct {
	pub *rsa.PublicKey
}

func (d emptySessionKeyDecrypter) Public() crypto.PublicKey {
	return d.pub
}

func (d emptySessionKeyDecrypter) Decrypt(io.Reader, []byte, crypto.DecrypterOpts) ([]byte, error) {
	return []byte{}, nil
}

func TestDecryptEmptySessionKeyNoPanic(t *testing.T) {
	pub := &encryptedKeyPub
	priv := &PrivateKey{
		PublicKey: PublicKey{
			PubKeyAlgo: PubKeyAlgoRSA,
			KeyId:      0,
		},
		PrivateKey: emptySessionKeyDecrypter{pub},
	}

	e := &EncryptedKey{
		Version:       3,
		KeyId:         0,
		Algo:          PubKeyAlgoRSA,
		encryptedMPI1: encoding.NewMPI(pub.N.Bytes()),
	}

	err := e.Decrypt(priv, nil)
	if err == nil {
		t.Fatal("expected an error for empty decrypted session key, got nil")
	}
}
