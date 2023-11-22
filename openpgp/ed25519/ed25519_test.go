package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"testing"
)

const messageDigestSize = 32

func TestGenerate(t *testing.T) {
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(priv.Key) != ed25519.SeedSize+ed25519.PublicKeySize && len(priv.Point) != ed25519.PublicKeySize {
		t.Error("generated wrong key sizes")
	}
}

func TestSignVerify(t *testing.T) {
	digest := make([]byte, messageDigestSize)
	_, err := io.ReadFull(rand.Reader, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signature, err := Sign(priv, digest)
	if err != nil {
		t.Errorf("error signing: %s", err)
	}

	result := Verify(&priv.PublicKey, digest, signature)

	if !result {
		t.Error("unable to verify message")
	}

	digest[0] += 1
	result = Verify(&priv.PublicKey, digest, signature)

	if result {
		t.Error("signature should be invalid")
	}
}

func TestValidation(t *testing.T) {
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(priv); err != nil {
		t.Fatalf("valid key marked as invalid: %s", err)
	}

	priv.Key[0] += 1
	if err := Validate(priv); err == nil {
		t.Fatal("failed to detect invalid key")
	}
}
