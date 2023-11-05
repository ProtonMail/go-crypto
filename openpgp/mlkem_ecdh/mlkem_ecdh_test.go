// Package mlkem_ecdh_test tests the implementation of hybrid ML-KEM + ECDH encryption, suitable for OpenPGP, experimental.
package mlkem_ecdh_test

import (
	"bytes"
	"crypto/rand"
	"github.com/ProtonMail/go-crypto/openpgp/internal/algorithm"
	"github.com/ProtonMail/go-crypto/openpgp/mlkem_ecdh"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	asymmAlgos := map[string] packet.PublicKeyAlgorithm {
		"Mlkem768_X25519": packet.PubKeyAlgoMlkem768X25519,
		"Mlkem1024_X448": packet.PubKeyAlgoMlkem1024X448,
		"Mlkem768_P256": packet.PubKeyAlgoMlkem768P256,
		"Mlkem1024_P384":packet.PubKeyAlgoMlkem1024P384,
		"Mlkem768_Brainpool256": packet.PubKeyAlgoMlkem768Brainpool256,
		"Mlkem1024_Brainpool384":packet.PubKeyAlgoMlkem1024Brainpool384,
	}

	symmAlgos := map[string] algorithm.Cipher {
		"AES-128": algorithm.AES128,
		"AES-192": algorithm.AES192,
		"AES-256": algorithm.AES256,
	}

	for asymmName, asymmAlgo := range asymmAlgos {
		t.Run(asymmName, func(t *testing.T) {
			key := testGenerateKeyAlgo(t, asymmAlgo)
			for symmName, symmAlgo := range symmAlgos {
				t.Run(symmName, func(t *testing.T) {
					testEncryptDecryptAlgo(t, key, symmAlgo)
				})
			}
			testvalidateAlgo(t, asymmAlgo)
		})
	}
}

func testvalidateAlgo(t *testing.T, algId packet.PublicKeyAlgorithm) {
	var err error
	key := testGenerateKeyAlgo(t, algId)
	if err := mlkem_ecdh.Validate(key); err != nil {
		t.Fatalf("valid key marked as invalid: %s", err)
	}

	bin, _ := key.PublicMlkem.MarshalBinary()
	bin[5] ^= 1
	key.PublicMlkem, err = key.Mlkem.UnmarshalBinaryPublicKey(bin)
	if err != nil {
		t.Fatal("unable to corrupt key")
	}

	if err := mlkem_ecdh.Validate(key); err == nil {
		t.Fatalf("failed to detect invalid key")
	}

	// Generate fresh key
	key = testGenerateKeyAlgo(t, algId)
	if err := mlkem_ecdh.Validate(key); err != nil {
		t.Fatalf("valid key marked as invalid: %s", err)
	}
	
	key.PublicPoint[5] ^= 1
	if err := mlkem_ecdh.Validate(key); err == nil {
		t.Fatalf("failed to detect invalid key")
	}
}

func testGenerateKeyAlgo(t *testing.T, algId packet.PublicKeyAlgorithm) *mlkem_ecdh.PrivateKey {
	curveObj, err := packet.GetECDHCurveFromAlgID(algId)
	if err != nil {
		t.Errorf("error getting curve: %s", err)
	}

	kyberObj, err := packet.GetMlkemFromAlgID(algId)
	if err != nil {
		t.Errorf("error getting kyber: %s", err)
	}

	priv, err := mlkem_ecdh.GenerateKey(rand.Reader, uint8(algId), curveObj, kyberObj)
	if err != nil {
		t.Fatal(err)
	}
	
	return priv
}

func testEncryptDecryptAlgo(t *testing.T, priv *mlkem_ecdh.PrivateKey, kdfCipher algorithm.Cipher) {
	expectedMessage := make([]byte, kdfCipher.KeySize()) // encryption algo + checksum
	rand.Read(expectedMessage)

	kE, ecE, c, err := mlkem_ecdh.Encrypt(rand.Reader, &priv.PublicKey, expectedMessage)
	if err != nil {
		t.Errorf("error encrypting: %s", err)
	}

	decryptedMessage, err := mlkem_ecdh.Decrypt(priv, kE, ecE, c)
	if err != nil {
		t.Errorf("error decrypting: %s", err)
	}
	if !bytes.Equal(decryptedMessage, expectedMessage) {
		t.Errorf("decryption failed, got: %x, want: %x", decryptedMessage, expectedMessage)
	}
}
