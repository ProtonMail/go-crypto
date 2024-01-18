package ed448

import (
	"crypto/rand"
	"io"
	"testing"
)

func TestGenerate(t *testing.T) {
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(priv.Key) != SeedSize+PublicKeySize && len(priv.Point) != PublicKeySize {
		t.Error("gnerated wrong key sizes")
	}
}

func TestSignVerify(t *testing.T) {
	digest := make([]byte, 32)
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
