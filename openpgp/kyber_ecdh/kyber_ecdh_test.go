// Package kyber_ecdh_test tests the implementation of hybrid Kyber + ECDH encryption, suitable for OpenPGP, experimental.
package kyber_ecdh_test

import (
	"bytes"
	"crypto/rand"
	"github.com/ProtonMail/go-crypto/openpgp/internal/algorithm"
	"github.com/ProtonMail/go-crypto/openpgp/internal/kyber"
	"github.com/ProtonMail/go-crypto/openpgp/kyber_ecdh"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	testFingerprint := make([]byte, 32)
	rand.Read(testFingerprint)

	asymmAlgos := map[string] packet.PublicKeyAlgorithm {
		"Kyber512_X25519": packet.PubKeyAlgoKyberX25519,
		"Kyber1024_X448": packet.PubKeyAlgoKyberX448,
		"Kyber768_P384": packet.PubKeyAlgoKyberP384,
		"Kyber1024_P521":packet.PubKeyAlgoKyberP521,
		"Kyber768_Brainpool384": packet.PubKeyAlgoKyberBrainpool384,
		"Kyber1024_Brainpool521":packet.PubKeyAlgoKyberBrainpool512,
	}

	symmAlgos := map[string] algorithm.Cipher {
		"AES-128": algorithm.AES128,
		"AES-192": algorithm.AES192,
		"AES-256": algorithm.AES256,
	}

	kyberParamIds := map[string] kyber.ParameterSetId {
		"ParamID_1": kyber.Parameter1,
		"ParamID_2": kyber.Parameter2,
		"ParamID_3": kyber.Parameter3,
	}

	for asymmName, asymmAlgo := range asymmAlgos {
		t.Run(asymmName, func(t *testing.T) {
			for paramIdName, paramId := range kyberParamIds {
				t.Run(paramIdName, func(t *testing.T) {
					key := testGenerateKeyAlgo(t, asymmAlgo, paramId)
					for symmName, symmAlgo := range symmAlgos {
						t.Run(symmName, func(t *testing.T) {
							testEncryptDecryptAlgo(t, key, testFingerprint, symmAlgo)
						})
					}
					testvalidateAlgo(t, asymmAlgo, paramId)
				})
			}
		})
	}
}

func testvalidateAlgo(t *testing.T, algId packet.PublicKeyAlgorithm, paramId kyber.ParameterSetId) {
	key := testGenerateKeyAlgo(t, algId, paramId)
	if err := kyber_ecdh.Validate(key); err != nil {
		t.Fatalf("valid key marked as invalid: %s", err)
	}

	key.PublicKyber[5] ^= 1
	if err := kyber_ecdh.Validate(key); err == nil {
		t.Fatalf("failed to detect invalid key")
	}

	// Generate fresh key
	key = testGenerateKeyAlgo(t, algId, paramId)
	if err := kyber_ecdh.Validate(key); err != nil {
		t.Fatalf("valid key marked as invalid: %s", err)
	}
	
	key.PublicPoint[5] ^= 1
	if err := kyber_ecdh.Validate(key); err == nil {
		t.Fatalf("failed to detect invalid key")
	}
}

func testGenerateKeyAlgo(t *testing.T, algId packet.PublicKeyAlgorithm, paramId kyber.ParameterSetId) *kyber_ecdh.PrivateKey {
	curveObj, err := packet.GetECDHCurveFromAlgID(algId)
	if err != nil {
		t.Errorf("error getting curve: %s", err)
	}

	priv, err := kyber_ecdh.GenerateKey(rand.Reader, uint8(algId), curveObj, paramId)
	if err != nil {
		t.Fatal(err)
	}
	
	return priv
}

func testEncryptDecryptAlgo(t *testing.T, priv *kyber_ecdh.PrivateKey, testFingerprint []byte, kdfCipher algorithm.Cipher) {
	expectedMessage := make([]byte, kdfCipher.KeySize() + 3) // encryption algo + checksum
	rand.Read(expectedMessage)

	kE, ecE, c, err := kyber_ecdh.Encrypt(rand.Reader, &priv.PublicKey, expectedMessage, testFingerprint)
	if err != nil {
		t.Errorf("error encrypting: %s", err)
	}

	decryptedMessage, err := kyber_ecdh.Decrypt(priv, kE, ecE, c, testFingerprint)
	if err != nil {
		t.Errorf("error decrypting: %s", err)
	}
	if !bytes.Equal(decryptedMessage, expectedMessage) {
		t.Errorf("decryption failed, got: %x, want: %x", decryptedMessage, expectedMessage)
	}
}
