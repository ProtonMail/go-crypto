package x25519

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestGenerate(t *testing.T) {
	privateKey, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(privateKey.Secret) != KeySize {
		t.Fatal("key has the wrong size")
	}
	if len(privateKey.PublicKey.Point) != KeySize {
		t.Fatal("key has the wrong size")
	}
}

func TestValidate(t *testing.T) {
	privateKey, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	err = Validate(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateKey.PublicKey.Point[0] = privateKey.PublicKey.Point[0] + byte(1)
	err = Validate(privateKey)
	if err == nil {
		t.Fatal("validation failed")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	sessionKey := []byte("session.........")
	privateKey, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ephemeralPublic, ctxt, err := Encrypt(rand.Reader, &privateKey.PublicKey, sessionKey)
	if err != nil {
		t.Errorf("error encrypting: %s", err)
	}

	sessionKeyAfter, err := Decrypt(privateKey, ephemeralPublic, ctxt)
	if err != nil {
		t.Errorf("error decrypting: %s", err)
	}

	if !bytes.Equal(sessionKeyAfter, sessionKey) {
		t.Errorf("decryption failed, got: %x, want: %x", sessionKeyAfter, sessionKey)
	}
}
