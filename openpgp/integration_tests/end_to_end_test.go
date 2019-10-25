// Copyright (C) 2019 ProtonTech AG

package integrationtests

import (
	"bytes"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"io"
	"io/ioutil"
	"strings"
	"testing"
	"time"
)

/////////////////////////////////////////////////////////////////////////////
// TODO:
//
// - Mock config for tests (implement randomConfig)
// - Mock line endings (implement randomLineEnding)
// - See why 'rsa' foreign key is failing to decrypt
//
/////////////////////////////////////////////////////////////////////////////

// Takes a set of different keys (some external, some generated here) and test
// interactions between them: encrypt, sign, decrypt, verify random messages.
func TestEndToEnd(t *testing.T) {
	// Generate random test vectors with the given key settings.
	freshTestVectors, err := generateFreshTestVectors(keySettings)
	if err != nil {
		t.Fatal("Cannot proceed without generated keys: " + err.Error())
	}

	// Append them to the list of foreign test vectors.
	testVectors := append(foreignTestVectors, freshTestVectors...)

	// Run interactions tests
	testInteractions(t, testVectors)
}

// For each testVector in testVectors, (1) Decrypt an already existing message,
// (2) Sign and verify random messages, and (3) Encrypt random messages for
// each of the other keys and then decrypt on the other end.
func testInteractions(t *testing.T, testVectors []testVector) {
	for _, from := range testVectors {
		skFrom := readArmoredSk(t, from.privateKey, from.password)
		pkFrom := readArmoredPk(t, from.publicKey)
		t.Run(from.name, func(t *testing.T) {

			// 1. Decrypt the encryptedSignedMessage of the given testSet
			t.Run("DecryptPreparedMessage",
				func(t *testing.T) {
					decryptionTest(t, from, skFrom)
				})
			// 2. Sign a message and verify signature.
			t.Run("signVerify", func(t *testing.T) {
				t.Run("binary", func(t *testing.T) {
					signVerifyTest(t, from, skFrom, pkFrom, true)
				})
				t.Run("text", func(t *testing.T) {
					signVerifyTest(t, from, skFrom, pkFrom, false)
				})
			})
			// 3. Encrypt, decrypt and verify a random message for
			// every other key.
			t.Run("encryptDecrypt",
				func(t *testing.T) {
					encDecTest(t, from, testVectors)
				})
		})
	}
}

func readArmoredPk(t *testing.T, publicKey string) openpgp.EntityList {
	keys, err := openpgp.ReadArmoredKeyRing(bytes.NewBufferString(publicKey))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) < 1 {
		t.Errorf("Failed to read key with good cross signature, %d", len(keys))
	}
	if len(keys[0].Subkeys) < 1 {
		t.Errorf("Failed to read good subkey, %d", len(keys[0].Subkeys))
	}
	return keys
}

func readArmoredSk(t *testing.T, sk string, pass string) openpgp.EntityList {
	keys, err := openpgp.ReadArmoredKeyRing(bytes.NewBufferString(sk))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Errorf("Failed to read key with good cross signature, %d", len(keys))
	}
	if len(keys[0].Subkeys) != 1 {
		t.Errorf("Failed to read good subkey, %d", len(keys[0].Subkeys))
	}
	var keyObject = keys[0].PrivateKey
	if pass != "" {
		corruptPassword := corrupt(pass)
		if err := keyObject.Decrypt([]byte(corruptPassword)); err == nil {
			t.Fatal("Decrypted key with invalid password")
		}
	}
	return keys
}

// This subtest decrypts the existing encrypted and signed message of each
// testVector.
func decryptionTest(t *testing.T, vector testVector, sk openpgp.EntityList) {
	if vector.encryptedSignedMessage == "" {
		return
	}
	var prompt = func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		err := keys[0].PrivateKey.Decrypt([]byte(vector.password))
		if err != nil {
			t.Errorf("prompt: error decrypting key: %s", err)
			return nil, err
		}
		return nil, nil
	}
	sig, err := armor.Decode(strings.NewReader(vector.encryptedSignedMessage))
	if err != nil {
		t.Error(err)
		return
	}
	md, err := openpgp.ReadMessage(sig.Body, sk, prompt, nil)
	if err != nil {
		t.Error(err)
		return
	}

	body, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Error(err)
		return
	}

	var stringBody = string(body)
	if stringBody != vector.message {
		t.Fatal("Decrypted body did not match expected body")
	}

	// We'll see a sig error here after reading in the UnverifiedBody above,
	// if there was one to see.
	if err = md.SignatureError; err != nil {
		t.Error(err)
		return
	}

	if md.SignatureV3 != nil {
		t.Errorf("Did not expect a signature V3 back")
		return
	}
	if md.Signature == nil {
		t.Errorf("Expected a signature to be set")
		return
	}
	return
}

// Given a testVector, encrypts random messages for all given testVectors
// (including self) and verifies on the other end.
func encDecTest(t *testing.T, from testVector, testVectors []testVector) {
	skFrom := readArmoredSk(t, from.privateKey, from.password)
	pkFrom := readArmoredPk(t, from.publicKey)
	for _, to := range testVectors {
		t.Run(to.name, func(t *testing.T) {
			pkTo := readArmoredPk(t, to.publicKey)
			skTo := readArmoredSk(t, to.privateKey, to.password)
			message := randomMessage()

			// Encrypt message
			signed := skFrom[0]
			errDec := signed.PrivateKey.Decrypt([]byte(from.password))
			if errDec != nil {
				t.Error(errDec)
			}
			buf := new(bytes.Buffer)
			w, err := openpgp.Encrypt(buf, pkTo[:1], signed, nil, nil)
			if err != nil {
				t.Fatalf("Error in Encrypt: %s", err)
			}
			_, err = w.Write([]byte(message))
			if err != nil {
				t.Fatalf("Error writing plaintext: %s", err)
			}
			err = w.Close()
			if err != nil {
				t.Fatalf("Error closing WriteCloser: %s", err)
			}

			// -----------------
			// On the other end:
			// -----------------

			// Decrypt recipient key
			var prompt = func(keys []openpgp.Key, symm bool) ([]byte, error) {
				err := keys[0].PrivateKey.Decrypt([]byte(to.password))
				if err != nil {
					t.Errorf("Prompt: error decrypting key: %s", err)
					return nil, err
				}
				return nil, nil
			}

			// Read message with recipient key
			keyring := append(skTo, pkFrom[:]...)
			md, err := openpgp.ReadMessage(buf, keyring, prompt, nil)
			if err != nil {
				t.Fatalf("Error reading message: %s", err)
			}

			// Test message details
			if !md.IsEncrypted {
				t.Fatal("The message should be encrypted")
			}
			signKey, _ := signed.SigningKey(time.Now())
			expectedKeyID := signKey.PublicKey.KeyId
			if md.SignedByKeyId != expectedKeyID {
				t.Fatalf(
					"Message signed by wrong key id, got: %v, want: %v",
					*md.SignedBy, expectedKeyID)
			}
			if md.SignedBy == nil {
				t.Fatalf("Failed to find the signing Entity")
			}

			plaintext, err := ioutil.ReadAll(md.UnverifiedBody)
			if err != nil {
				t.Fatalf("Error reading encrypted contents: %s", err)
			}

			encryptKey, _ := pkTo[0].EncryptionKey(time.Now())
			expectedEncKeyID := encryptKey.PublicKey.KeyId
			if len(md.EncryptedToKeyIds) != 1 ||
				md.EncryptedToKeyIds[0] != expectedEncKeyID {
				t.Errorf("Expected message to be encrypted to %v, but got %#v",
				expectedKeyID, md.EncryptedToKeyIds)
			}

			// Test decrypted message
			if string(plaintext) != message {
				t.Errorf("got: %s, want: %s", string(plaintext), message)
			}

			if md.SignatureError != nil {
				t.Errorf("Signature error: %s", md.SignatureError)
			}
			if md.Signature == nil {
				t.Error("Signature missing")
			}
		})
	}
}

// Sign a random message and verify signature against the original message,
// another message with same body but different line endings, and a corrupt
// message.
func signVerifyTest(
	t *testing.T,
	from testVector,
	skFrom, pkFrom openpgp.EntityList,
	binary bool,
) {
	signed := skFrom[0]
	if err := signed.PrivateKey.Decrypt([]byte(from.password)); err != nil {
		t.Error(err)
	}

	messageBody := randomMessage()
	lineEnding := "\r\n \n \r\n"
	otherLineEnding := "\n \r\n \n"
	// Add line endings to test whether the non-binary version of this
	// signature normalizes the final line endings, see RFC4880bis, sec 5.2.1.

	message := bytes.NewReader([]byte(messageBody + lineEnding))
	otherMessage := bytes.NewReader([]byte(messageBody + otherLineEnding))

	corruptMessage := bytes.NewReader([]byte(corrupt(messageBody) + lineEnding))

	// Sign the message
	buf := new(bytes.Buffer)
	var errSign error
	if binary {
		errSign = openpgp.ArmoredDetachSign(buf, signed, message, nil)
	} else {
		errSign = openpgp.ArmoredDetachSignText(buf, signed, message, nil)
	}
	if errSign != nil {
		t.Error(errSign)
	}

	// Verify the signature against the corrupt message first
	signatureReader := bytes.NewReader(buf.Bytes())
	wrongsigner, err := openpgp.CheckArmoredDetachedSignature(
		pkFrom, corruptMessage, signatureReader, nil)
	if err == nil || wrongsigner != nil {
		t.Fatal("Expected the signature to not verify")
		return
	}

	// Reset the reader and verify against the message with different line
	// endings (should pass in the non-binary case)
	var errSeek error
	_, errSeek = signatureReader.Seek(0, io.SeekStart)
	if errSeek != nil {
		t.Error(errSeek)
	}

	otherSigner, err := openpgp.CheckArmoredDetachedSignature(
		pkFrom, otherMessage, signatureReader, nil)

	if binary {
		if err == nil || otherSigner != nil {
			t.Fatal("Expected the signature to not verify")
			return
		}
	} else {
		if err != nil {
			t.Errorf("signature error: %s", err)
			return
		}
		if otherSigner == nil {
			t.Errorf("signer is nil")
			return
		}
		if otherSigner.PrimaryKey.KeyId != signed.PrimaryKey.KeyId {
			t.Errorf(
				"wrong signer got:%x want:%x", otherSigner.PrimaryKey.KeyId, 0)
		}
	}

	// Reset the readers and verify against the exact first message.
	_, errSeek = message.Seek(0, io.SeekStart)
	if errSeek != nil {
		t.Error(errSeek)
	}
	_, errSeek = signatureReader.Seek(0, io.SeekStart)
	if errSeek != nil {
		t.Error(errSeek)
	}

	signer, err := openpgp.CheckArmoredDetachedSignature(
		pkFrom, message, signatureReader, nil)

	if err != nil {
		t.Errorf("signature error: %s", err)
		return
	}
	if signer == nil {
		t.Errorf("signer is nil")
		return
	}
	if signer.PrimaryKey.KeyId != signed.PrimaryKey.KeyId {
		t.Errorf("wrong signer got:%x want:%x", signer.PrimaryKey.KeyId, 0)
	}

	return
}
