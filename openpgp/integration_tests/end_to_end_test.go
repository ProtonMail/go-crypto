// Copyright (C) 2019 ProtonTech AG

package integrationTests

import (
	"bytes"
	"crypto/rand"
	mathrand "math/rand"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"io"
	"io/ioutil"
	"strings"
	"testing"
	"time"
)

// Takes a set of different keys (some external, some generated here) and test
// interactions between them: encrypt, sign, decrypt, verify random messages.
func TestEndToEnd(t *testing.T) {
	// Generate random test vectors with the given key settings.
	freshTestVectors, err := generateFreshTestVectors(keySettings)
	if err != nil {
		t.Fatal("Cannot proceed without generated keys: " + err.Error())
	}

	// Append them to the list of foreign test vectors.
	testVectors = append(testVectors, freshTestVectors...)

	for _, testSet := range testVectors {
		t.Run(
			testSet.name,
			func(t *testing.T) {
				testInteractions(t, testSet)
			},
		)
	}
}

// Given the 'from' testVector, (1) Decrypt an already existing message, (2)
// Encrypt a message for each of the other keys ('to' testSet) and then decrypt
// on the other end, and (3) sign TODO
func testInteractions(t *testing.T, from testVector) {
	var privateKeyFrom = readArmoredPrivateKey(t, from.privateKey, from.password)
	var publicKeyFrom = readArmoredPublicKey(t, from.publicKey)

	// 1. Decrypt the encryptedSignedMessage of the given testSet
	t.Run("DecryptPreparedMessage",
		func(t *testing.T) {
			decryptionTest(t, from, privateKeyFrom)
		})
	// 2. Compose a message for every other key.
	t.Run("encryptDecrypt", func(t *testing.T) {
		for _, to := range testVectors {
			var publicKeyTo = readArmoredPublicKey(t, to.publicKey)
			var privateKeyTo = readArmoredPrivateKey(t, to.privateKey, to.password)
			t.Run(to.name,
				func(t *testing.T) {
					encryptDecryptTest(t, from, to, privateKeyFrom, publicKeyFrom, publicKeyTo, privateKeyTo)
				})
		}
	})
	// 3. Sign a message and verify signature.
	t.Run("signVerify", func(t *testing.T) {
		t.Run("binary", func(t *testing.T) {
			signVerifyTest(t, from, privateKeyFrom, publicKeyFrom, true)
		})
		t.Run("text", func(t *testing.T) {
			signVerifyTest(t, from, privateKeyFrom, publicKeyFrom, false)
		})
	})
}

func readArmoredPublicKey(t *testing.T, publicKey string) openpgp.EntityList {
	keys, err := openpgp.ReadArmoredKeyRing(bytes.NewBufferString(publicKey))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Errorf("Failed to accept key with good cross signature, %d", len(keys))
	}
	if len(keys[0].Subkeys) != 1 {
		t.Errorf("Failed to accept good subkey, %d", len(keys[0].Subkeys))
	}
	return keys
}

func readArmoredPrivateKey(t *testing.T, privateKey string, password string) openpgp.EntityList {
	keys, err := openpgp.ReadArmoredKeyRing(bytes.NewBufferString(privateKey))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Errorf("Failed to accept key with good cross signature, %d", len(keys))
	}
	if len(keys[0].Subkeys) != 1 {
		t.Errorf("Failed to accept good subkey, %d", len(keys[0].Subkeys))
	}
	var keyObject = keys[0].PrivateKey
	if password != "" {
		if err := keyObject.Decrypt([]byte("invalid password")); err == nil {
			t.Fatal("It should not be possible to decrypt with an invalid password")
		}
	}
	return keys
}

// This subtest decrypts the existing encryoted and signed of each testSet.
func decryptionTest(t *testing.T, testSet testVector, privateKey openpgp.EntityList) {
	if testSet.encryptedSignedMessage == "" {
		return
	}
	var prompt = func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		err := keys[0].PrivateKey.Decrypt([]byte(testSet.password))
		if err != nil {
			t.Errorf("prompt: error decrypting key: %s", err)
			return nil, err
		}
		return nil, nil
	}
	sig, err := armor.Decode(strings.NewReader(testSet.encryptedSignedMessage))
	if err != nil {
		t.Error(err)
		return
	}
	md, err := openpgp.ReadMessage(sig.Body, privateKey, prompt, nil)
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
	if stringBody != testSet.message {
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

// Encrypts a random message and tests decryption with recipients' key.
func encryptDecryptTest(
	t *testing.T,
	from, to testVector,
	privateKeyFrom, publicKeyFrom, publicKeyTo, privateKeyTo openpgp.EntityList,
) {
	// Sample random message to encrypt
	rawMessage := make([]byte, mathrand.Intn(maxMessageLength))
	if _, err := rand.Read(rawMessage); err != nil {
		panic(err)
	}
	message := string(rawMessage)

	// Encrypt message
	signed := privateKeyFrom[0]
	signed.PrivateKey.Decrypt([]byte(from.password))
	buf := new(bytes.Buffer)
	w, err := openpgp.Encrypt(buf, publicKeyTo[:1], signed, nil /* no hints */, nil)
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

	// Decrypt recipient key
	var prompt = func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		err := keys[0].PrivateKey.Decrypt([]byte(to.password))
		if err != nil {
			t.Errorf("Prompt: error decrypting key: %s", err)
			return nil, err
		}
		return nil, nil
	}

	// Read message with recipient key
	// TODO: Parse this
	md, err := openpgp.ReadMessage(buf, append(privateKeyTo, publicKeyFrom[0]), prompt, nil)
	if err != nil {
		t.Fatalf("Error reading message: %s", err)
	}

	// Test message details
	if !md.IsEncrypted {
		t.Fatal("The message should be encrypted")
	}
	signKey, _ := signed.SigningKey(time.Now())
	expectedKeyId := signKey.PublicKey.KeyId
	if md.SignedByKeyId != expectedKeyId {
		t.Fatalf("Message signed by wrong key id, got: %v, want: %v", *md.SignedBy, expectedKeyId)
	}
	if md.SignedBy == nil {
		t.Fatalf("Failed to find the signing Entity")
	}

	plaintext, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Fatalf("Error reading encrypted contents: %s", err)
	}

	encryptKey, _ := publicKeyTo[0].EncryptionKey(time.Now())
	expectedEncKeyId := encryptKey.PublicKey.KeyId
	if len(md.EncryptedToKeyIds) != 1 || md.EncryptedToKeyIds[0] != expectedEncKeyId {
		t.Errorf("Expected message to be encrypted to %v, but got %#v", expectedKeyId, md.EncryptedToKeyIds)
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
}

// TODO: Describe
func signVerifyTest(
	t *testing.T,
	from testVector,
	privateKeyFrom, publicKeyFrom openpgp.EntityList,
	binary bool,
) {
	signed := privateKeyFrom[0]
	signed.PrivateKey.Decrypt([]byte(from.password))

	message := bytes.NewReader(bytes.NewBufferString("testing 漢字 \r\n \n \r\n").Bytes())

	// TODO:
	// Sample random message to encrypt
	// rawMessage := make([]byte, mathrand.Intn(maxMessageLength))
	// if _, err := rand.Read(rawMessage); err != nil {
	// 	panic(err)
	// }
	// message := bytes.NewReader(rawMessage)
	buf := new(bytes.Buffer)
	if binary {
		openpgp.ArmoredDetachSign(buf, signed, message, nil)
	} else {
		openpgp.ArmoredDetachSignText(buf, signed, message, nil)
	}

	signatureReader := bytes.NewReader(buf.Bytes())

	wrongmessage := bytes.NewReader(bytes.NewBufferString("testing 漢字").Bytes())
	wrongsigner, err := openpgp.CheckArmoredDetachedSignature(publicKeyFrom, wrongmessage, signatureReader, nil)

	if err == nil || wrongsigner != nil {
		t.Fatal("Expected the signature to not verify")
		return
	}

	message.Seek(0, io.SeekStart)
	signatureReader.Seek(0, io.SeekStart)

	wronglineendings := bytes.NewReader(bytes.NewBufferString("testing 漢字 \n \r\n \n").Bytes())
	wronglinesigner, err := openpgp.CheckArmoredDetachedSignature(publicKeyFrom, wronglineendings, signatureReader, nil)

	if binary {
		if err == nil || wronglinesigner != nil {
			t.Fatal("Expected the signature to not verify")
			return
		}
	} else {
		if err != nil {
			t.Errorf("signature error: %s", err)
			return
		}
		if wronglinesigner == nil {
			t.Errorf("signer is nil")
			return
		}
		if wronglinesigner.PrimaryKey.KeyId != signed.PrimaryKey.KeyId {
			t.Errorf("wrong signer got:%x want:%x", wronglinesigner.PrimaryKey.KeyId, 0)
		}
	}

	message.Seek(0, io.SeekStart)
	signatureReader.Seek(0, io.SeekStart)

	signer, err := openpgp.CheckArmoredDetachedSignature(publicKeyFrom, message, signatureReader, nil)

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
