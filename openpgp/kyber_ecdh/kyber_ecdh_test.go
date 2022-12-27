// Package kyber_ecdh_test tests the implementation of hybrid Kyber + ECDH encryption, suitable for OpenPGP, experimental.
package kyber_ecdh_test

import (
	"bytes"
	"crypto/rand"
	"github.com/ProtonMail/go-crypto/openpgp/internal/algorithm"
	"github.com/ProtonMail/go-crypto/openpgp/kyber_ecdh"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	randomData := make([]byte, 32)
	rand.Read(randomData)

	asymmAlgos := map[string] packet.PublicKeyAlgorithm {
		"Kyber768_X25519": packet.PubKeyAlgoKyber768X25519,
		"Kyber1024_X448": packet.PubKeyAlgoKyber1024X448,
		"Kyber768_P256": packet.PubKeyAlgoKyber768P256,
		"Kyber1024_P384":packet.PubKeyAlgoKyber1024P384,
		"Kyber768_Brainpool256": packet.PubKeyAlgoKyber768Brainpool256,
		"Kyber1024_Brainpool384":packet.PubKeyAlgoKyber1024Brainpool384,
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
					testEncryptDecryptAlgo(t, key, randomData, symmAlgo)
				})
			}
			testvalidateAlgo(t, asymmAlgo)
		})
	}
}

func testvalidateAlgo(t *testing.T, algId packet.PublicKeyAlgorithm) {
	var err error
	key := testGenerateKeyAlgo(t, algId)
	if err := kyber_ecdh.Validate(key); err != nil {
		t.Fatalf("valid key marked as invalid: %s", err)
	}

	bin, _ := key.PublicKyber.MarshalBinary()
	bin[5] ^= 1
	key.PublicKyber, err = key.Kyber.UnmarshalBinaryPublicKey(bin)
	if err != nil {
		t.Fatal("unable to corrupt key")
	}

	if err := kyber_ecdh.Validate(key); err == nil {
		t.Fatalf("failed to detect invalid key")
	}

	// Generate fresh key
	key = testGenerateKeyAlgo(t, algId)
	if err := kyber_ecdh.Validate(key); err != nil {
		t.Fatalf("valid key marked as invalid: %s", err)
	}
	
	key.PublicPoint[5] ^= 1
	if err := kyber_ecdh.Validate(key); err == nil {
		t.Fatalf("failed to detect invalid key")
	}
}

func testGenerateKeyAlgo(t *testing.T, algId packet.PublicKeyAlgorithm) *kyber_ecdh.PrivateKey {
	curveObj, err := packet.GetECDHCurveFromAlgID(algId)
	if err != nil {
		t.Errorf("error getting curve: %s", err)
	}

	kyberObj, err := packet.GetKyberFromAlgID(algId)
	if err != nil {
		t.Errorf("error getting kyber: %s", err)
	}

	priv, err := kyber_ecdh.GenerateKey(rand.Reader, uint8(algId), curveObj, kyberObj)
	if err != nil {
		t.Fatal(err)
	}
	
	return priv
}

func testEncryptDecryptAlgo(t *testing.T, priv *kyber_ecdh.PrivateKey, publicKeyHash []byte, kdfCipher algorithm.Cipher) {
	expectedMessage := make([]byte, kdfCipher.KeySize()) // encryption algo + checksum
	rand.Read(expectedMessage)

	kE, ecE, c, err := kyber_ecdh.Encrypt(rand.Reader, &priv.PublicKey, expectedMessage, publicKeyHash)
	if err != nil {
		t.Errorf("error encrypting: %s", err)
	}

	decryptedMessage, err := kyber_ecdh.Decrypt(priv, kE, ecE, c, publicKeyHash)
	if err != nil {
		t.Errorf("error decrypting: %s", err)
	}
	if !bytes.Equal(decryptedMessage, expectedMessage) {
		t.Errorf("decryption failed, got: %x, want: %x", decryptedMessage, expectedMessage)
	}
}
