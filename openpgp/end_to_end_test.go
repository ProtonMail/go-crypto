// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package openpgp

import (
	"bytes"
	"fmt"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"io"
	"io/ioutil"
	"strings"
	"testing"
	"time"
)

type algorithmSet struct {
	message                string
	name                   string
	privateKey             string
	publicKey              string
	password               string
	encryptedSignedMessage string
}

type keySet struct {
	name string
	cfg  *packet.Config
}

// TODO: Explain what this test actually does.
func TestEndToEnd(t *testing.T) {
	keyGenTestSets, err := makeKeyGenTestSets()
	if err != nil {
		fmt.Println(err.Error())
		panic("Cannot proceed without generated keys")
	}
	testSets = append(testSets, keyGenTestSets...)

	for _, testSet := range testSets {
		t.Run(testSet.name,
			func(t *testing.T) {
				algorithmTest(t, testSet)
			})
	}
}

// TODO: Explain what this function (test, really) actually does.
func algorithmTest(t *testing.T, testSet algorithmSet) {
	var privateKeyFrom = readArmoredPrivateKey(t, testSet.privateKey, testSet.password)
	var publicKeyFrom = readArmoredPublicKey(t, testSet.publicKey)
	t.Run(fmt.Sprintf("DecryptPreparedMessage"),
		func(t *testing.T) {
			decryptionTest(t, testSet, privateKeyFrom)
		})
	t.Run("encryptDecrypt", func(t *testing.T) {
		for _, testSetTo := range testSets {
			t.Run(testSetTo.name,
				func(t *testing.T) {
					var publicKeyTo = readArmoredPublicKey(t, testSetTo.publicKey)
					var privateKeyTo = readArmoredPrivateKey(t, testSetTo.privateKey, testSetTo.password)
					encryptDecryptTest(t, testSet, testSetTo, privateKeyFrom, publicKeyFrom, publicKeyTo, privateKeyTo)
				})
		}
	})
	t.Run("signVerify", func(t *testing.T) {
		t.Run("binary", func(t *testing.T) {
			signVerifyTest(t, testSet, privateKeyFrom, publicKeyFrom, true)
		})
		t.Run("text", func(t *testing.T) {
			signVerifyTest(t, testSet, privateKeyFrom, publicKeyFrom, false)
		})
	})
}

func readArmoredPublicKey(t *testing.T, publicKey string) EntityList {
	keys, err := ReadArmoredKeyRing(bytes.NewBufferString(publicKey))
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

func readArmoredPrivateKey(t *testing.T, privateKey string, password string) EntityList {
	keys, err := ReadArmoredKeyRing(bytes.NewBufferString(privateKey))
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

func decryptionTest(t *testing.T, testSet algorithmSet, privateKey EntityList) {
	if testSet.encryptedSignedMessage == "" {
		return
	}
	var prompt = func(keys []Key, symmetric bool) ([]byte, error) {
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
	md, err := ReadMessage(sig.Body, privateKey, prompt, nil)
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

func encryptDecryptTest(t *testing.T, testSetFrom algorithmSet, testSetTo algorithmSet, privateKeyFrom EntityList, publicKeyFrom EntityList, publicKeyTo EntityList, privateKeyTo EntityList) {
	var signed *Entity
	var prompt = func(keys []Key, symmetric bool) ([]byte, error) {
		err := keys[0].PrivateKey.Decrypt([]byte(testSetTo.password))
		if err != nil {
			t.Errorf("Prompt: error decrypting key: %s", err)
			return nil, err
		}
		return nil, nil
	}
	signed = privateKeyFrom[0]
	signed.PrivateKey.Decrypt([]byte(testSetFrom.password))

	buf := new(bytes.Buffer)
	w, err := Encrypt(buf, publicKeyTo[:1], signed, nil /* no hints */, nil)
	if err != nil {
		t.Fatalf("Error in Encrypt: %s", err)
	}

	const message = "testing"
	_, err = w.Write([]byte(message))
	if err != nil {
		t.Fatalf("Error writing plaintext: %s", err)
	}
	err = w.Close()
	if err != nil {
		t.Fatalf("Error closing WriteCloser: %s", err)
	}

	md, err := ReadMessage(buf, append(privateKeyTo, publicKeyFrom[0]), prompt, nil)
	if err != nil {
		t.Fatalf("Error reading message: %s", err)
	}

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

func signVerifyTest(t *testing.T, testSetFrom algorithmSet, privateKeyFrom EntityList, publicKeyFrom EntityList, binary bool) {
	var signed *Entity
	signed = privateKeyFrom[0]
	signed.PrivateKey.Decrypt([]byte(testSetFrom.password))

	buf := new(bytes.Buffer)
	message := bytes.NewReader(bytes.NewBufferString("testing 漢字 \r\n \n \r\n").Bytes())
	if binary {
		ArmoredDetachSign(buf, signed, message, nil)
	} else {
		ArmoredDetachSignText(buf, signed, message, nil)
	}

	signatureReader := bytes.NewReader(buf.Bytes())

	wrongmessage := bytes.NewReader(bytes.NewBufferString("testing 漢字").Bytes())
	wrongsigner, err := CheckArmoredDetachedSignature(publicKeyFrom, wrongmessage, signatureReader, nil)

	if err == nil || wrongsigner != nil {
		t.Fatal("Expected the signature to not verify")
		return
	}

	message.Seek(0, io.SeekStart)
	signatureReader.Seek(0, io.SeekStart)

	wronglineendings := bytes.NewReader(bytes.NewBufferString("testing 漢字 \n \r\n \n").Bytes())
	wronglinesigner, err := CheckArmoredDetachedSignature(publicKeyFrom, wronglineendings, signatureReader, nil)

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

	signer, err := CheckArmoredDetachedSignature(publicKeyFrom, message, signatureReader, nil)

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
