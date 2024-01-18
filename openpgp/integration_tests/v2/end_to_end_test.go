// Copyright (C) 2019 ProtonTech AG

package v2

import (
	"bytes"
	"crypto"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
)

/////////////////////////////////////////////////////////////////////////////
// TODO:
//
// - Move signature line endings test to packet unit tests.
//
/////////////////////////////////////////////////////////////////////////////

type testVector struct {
	Message                string
	Name                   string
	PrivateKey             string
	PublicKey              string
	Password               string
	EncryptedSignedMessage string
	config                 *packet.Config
}

var allowAllAlgorithmsConfig = packet.Config{
	RejectMessageHashAlgorithms: map[crypto.Hash]bool{},
	RejectPublicKeyAlgorithms:   map[packet.PublicKeyAlgorithm]bool{},
	RejectCurves:                map[packet.Curve]bool{},
	MinRSABits:                  512,
}

// Takes a set of different keys (some external, some generated here) and test
// interactions between them: encrypt, sign, decrypt, verify random messages.
func TestEndToEnd(t *testing.T) {
	// Fetch foreign test vectors from JSON file
	file, err := os.Open("testdata/test_vectors.json")
	if err != nil {
		panic(err)
	}
	raw, err := io.ReadAll(file)
	if err != nil {
		panic(err)
	}
	var foreignTestVectors []testVector
	err = json.Unmarshal(raw, &foreignTestVectors)
	if err != nil {
		panic(err)
	}

	for i := 0; i < len(foreignTestVectors); i++ {
		foreignTestVectors[i].Name += "_foreign"
		config := allowAllAlgorithmsConfig
		foreignTestVectors[i].config = &config
	}

	// Generate random test vectors
	freshTestVectors, err := generateFreshTestVectors(20)
	if err != nil {
		t.Fatal("Cannot proceed without generated keys: " + err.Error())
	}
	testVectors := append(foreignTestVectors, freshTestVectors...)

	// For each testVector in testVectors, (1) Decrypt an already existing message,
	// (2) Sign and verify random messages, and (3) Encrypt random messages for
	// each of the other keys and then decrypt on the other end.
	for _, from := range testVectors {
		skFrom := readArmoredSk(t, from.PrivateKey, from.Password)
		pkFrom := readArmoredPk(t, from.PublicKey)
		t.Run(from.Name, func(t *testing.T) {

			// 1. Decrypt the existing message of the given test vector
			t.Run("DecryptPreparedMessage",
				func(t *testing.T) {
					decryptionTest(t, from, skFrom)
				})
			// 2. Sign a message and verify the signature.
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

// This subtest decrypts the existing encrypted and signed message of each
// testVector.
func decryptionTest(t *testing.T, vector testVector, sk openpgp.EntityList) {
	if vector.EncryptedSignedMessage == "" {
		return
	}
	prompt := func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		err := keys[0].PrivateKey.Decrypt([]byte(vector.Password))
		if err != nil {
			t.Errorf("prompt: error decrypting key: %s", err)
			return nil, err
		}
		return nil, nil
	}
	sig, err := armor.Decode(strings.NewReader(vector.EncryptedSignedMessage))
	if err != nil {
		t.Fatal(err)
	}
	md, err := openpgp.ReadMessage(sig.Body, sk, prompt, vector.config)
	if err != nil {
		t.Fatal(err)
	}

	body, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Fatal(err)
	}
	if !md.IsVerified {
		t.Errorf("not verified despite all data read")
	}

	stringBody := string(body)
	if stringBody != vector.Message {
		t.Fatal("Decrypted body did not match expected body")
	}

	// We'll see a sig error here after reading in the UnverifiedBody above,
	// if there was one to see.
	if err = md.SignatureError; err != nil {
		t.Fatal(err)
	}

	if md.Signature == nil {
		t.Fatal("Expected a signature to be valid")
	}
}

// Given a testVector, encrypts random messages for all given testVectors
// (including self) and verifies on the other end.
func encDecTest(t *testing.T, from testVector, testVectors []testVector) {
	skFrom := readArmoredSk(t, from.PrivateKey, from.Password)
	// Decrypt private key if necessary
	for _, entity := range skFrom {
		if err := entity.DecryptPrivateKeys([]byte(from.Password)); err != nil {
			t.Error(err)
		}
	}
	pkFrom := readArmoredPk(t, from.PublicKey)
	for _, to := range testVectors {
		t.Run(to.Name, func(t *testing.T) {
			pkTo := readArmoredPk(t, to.PublicKey)
			skTo := readArmoredSk(t, to.PrivateKey, to.Password)
			message := randMessage()
			hints := randFileHints()

			// Encrypt message
			signer := skFrom[0]
			errDec := signer.PrivateKey.Decrypt([]byte(from.Password))
			if errDec != nil {
				t.Error(errDec)
			}
			buf := new(bytes.Buffer)
			w, err := openpgp.Encrypt(buf, pkTo[:1], nil, []*openpgp.Entity{signer}, hints, from.config)
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
			prompt := func(keys []openpgp.Key, symm bool) ([]byte, error) {
				err := keys[0].PrivateKey.Decrypt([]byte(to.Password))
				if err != nil {
					t.Errorf("Prompt: error decrypting key: %s", err)
					return nil, err
				}
				return nil, nil
			}

			// Read message with recipient key
			keyring := append(skTo, pkFrom[:]...)
			md, err := openpgp.ReadMessage(buf, keyring, prompt, to.config)
			if err != nil {
				t.Fatalf("Error reading message: %s", err)
			}

			// Test message details
			if !md.IsEncrypted {
				t.Fatal("The message should be encrypted")
			}
			signKey, _ := signer.SigningKey(time.Now(), &allowAllAlgorithmsConfig)
			expectedKeyID := signKey.PublicKey.KeyId
			expectedFingerprint := signKey.PublicKey.Fingerprint
			if len(md.SignatureCandidates) != 1 {
				t.Fatal("No signature candidate found")
			}
			if signKey.PublicKey.Version != 6 && md.SignatureCandidates[0].IssuerKeyId != expectedKeyID {
				t.Fatalf(
					"Message signed by wrong key id, got: %v, want: %v",
					*md.SignatureCandidates[0].SignedBy, expectedKeyID)
			}
			if signKey.PublicKey.Version == 6 && !bytes.Equal(md.SignatureCandidates[0].IssuerFingerprint, expectedFingerprint) {
				t.Fatalf(
					"Message signed by wrong key id, got: %x, want: %x",
					md.SignatureCandidates[0].IssuerFingerprint, expectedFingerprint)
			}
			if md.SignatureCandidates[0] == nil {
				t.Fatalf("Failed to find the signing Entity")
			}

			plaintext, err := io.ReadAll(md.UnverifiedBody)
			if err != nil {
				t.Fatalf("Error reading encrypted contents: %s", err)
			}
			if !md.IsVerified {
				t.Errorf("not verified despite all data read")
			}
			encryptKey, _ := pkTo[0].EncryptionKey(time.Now(), &allowAllAlgorithmsConfig)
			expectedEncKeyID := encryptKey.PublicKey.KeyId
			if len(md.EncryptedToKeyIds) != 1 ||
				md.EncryptedToKeyIds[0] != expectedEncKeyID {
				t.Errorf("Expected message to be encrypted to %v, but got %#v",
					expectedKeyID, md.EncryptedToKeyIds)
			}
			// Test decrypted message
			if string(plaintext) != message {
				t.Error("decrypted and expected message do not match")
			}

			if md.SignatureError != nil {
				t.Fatalf("Signature error: %s", md.SignatureError)
			}
			if md.Signature == nil {
				t.Error("Expected valid signature")
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
	if err := skFrom[0].PrivateKey.Decrypt([]byte(from.Password)); err != nil {
		t.Error(err)
	}

	messageBody := randMessage()

	// ================================================
	// TODO: Move the line ending checks to unit tests
	// ================================================
	// Add line endings to test whether the non-binary version of this
	// signature normalizes the final line endings, see RFC4880bis, sec 5.2.1.
	lineEnding := " \r\n \n \r\n"
	otherLineEnding := " \n \r\n \n"
	message := bytes.NewReader([]byte(messageBody + lineEnding))
	otherMessage := bytes.NewReader([]byte(messageBody + otherLineEnding))

	corruptMessage := bytes.NewReader([]byte(corrupt(messageBody) + lineEnding))

	// Sign the message
	buf := new(bytes.Buffer)
	errSign := openpgp.ArmoredDetachSign(buf, skFrom[:1], message, &openpgp.SignParams{
		TextSig: !binary,
		Config:  &allowAllAlgorithmsConfig,
	})
	if errSign != nil {
		t.Error(errSign)
	}

	// Verify the signature against the corrupt message first
	signatureReader := bytes.NewReader(buf.Bytes())
	_, wrongsigner, err := openpgp.VerifyArmoredDetachedSignature(
		pkFrom, corruptMessage, signatureReader, &allowAllAlgorithmsConfig)
	if err == nil || wrongsigner != nil {
		t.Fatal("Expected the signature to not verify")
	}

	// Reset the reader and verify against the message with different line
	// endings (should pass in the non-binary case)
	var errSeek error
	_, errSeek = signatureReader.Seek(0, io.SeekStart)
	if errSeek != nil {
		t.Error(errSeek)
	}

	_, otherSigner, err := openpgp.VerifyArmoredDetachedSignature(
		pkFrom, otherMessage, signatureReader, &allowAllAlgorithmsConfig)
	if binary {
		if err == nil || otherSigner != nil {
			t.Fatal("Expected the signature to not verify")
			return
		}
	} else {
		if err != nil {
			t.Fatalf("signature error: %s", err)
		}
		if otherSigner == nil {
			t.Fatalf("signer is nil")
		}
		if otherSigner.PrimaryKey.KeyId != skFrom[0].PrimaryKey.KeyId {
			t.Errorf(
				"wrong signer: got %x, expected %x", otherSigner.PrimaryKey.KeyId, 0)
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

	_, otherSigner, err = openpgp.VerifyArmoredDetachedSignature(
		pkFrom, message, signatureReader, &allowAllAlgorithmsConfig)

	if err != nil {
		t.Fatalf("signature error: %s", err)
	}
	if otherSigner == nil {
		t.Fatalf("signer is nil")
	}
	if otherSigner.PrimaryKey.KeyId != skFrom[0].PrimaryKey.KeyId {
		t.Errorf(
			"wrong signer: got %x, expected %x",
			skFrom[0].PrimaryKey.KeyId,
			skFrom[0].PrimaryKey.KeyId,
		)
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
	if len(keys[0].Subkeys) < 1 {
		t.Errorf("Failed to read good subkey, %d", len(keys[0].Subkeys))
	}
	keyObject := keys[0].PrivateKey
	if pass != "" {
		corruptPassword := corrupt(pass)
		if err := keyObject.Decrypt([]byte(corruptPassword)); err == nil {
			t.Fatal("Decrypted key with invalid password")
		}
	}
	return keys
}
