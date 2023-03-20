// Copyright 2019 ProtonTech AG.

// Package ecc implements a generic interface for ECDH, ECDSA, and EdDSA.
package ecc

import (
	"crypto/rand"
	"testing"
)

// Some OpenPGP implementations, such as gpg 2.2.12, do not accept ECDH private
// keys if they're not masked. This is because they're not of the proper form,
// cryptographically, and they don't mask input keys during crypto operations.
// This test checks if the keys that this library stores or outputs are
// properly masked.
func TestGenerateMaskedPrivateKeyX25519(t *testing.T) {
	c := NewCurve25519()
	_, secret, err := c.GenerateECDH(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	encoded := c.MarshalByteSecret(secret)
	decoded := c.UnmarshalByteSecret(encoded)
	if decoded == nil {
		t.Fatal(err)
	}

	// Check masking
	// 3 lsb are 0
	if decoded[0]<<5 != 0 {
		t.Fatalf("Priv. key is not masked (3 lsb should be unset): %X", decoded)
	}
	// MSB is 0
	if decoded[31]>>7 != 0 {
		t.Fatalf("Priv. key is not masked (MSB should be unset): %X", decoded)
	}
	// Second-MSB is 1
	if decoded[31]>>6 != 1 {
		t.Fatalf("Priv. key is not masked (second MSB should be set): %X", decoded)
	}
}
