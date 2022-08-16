// Package ecc implements a generic interface for ECDH, ECDSA, and EdDSA.
package ecc

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

// Test correct zero padding
func TestEd25519MarshalUnmarshal(t *testing.T) {
	c := NewEd25519()

	x := make([]byte, ed25519Size)
	_, err := io.ReadFull(rand.Reader, x)
	if err != nil {
		t.Fatal(err)
	}

	x[0] = 0

	encoded := c.MarshalBytePoint(x)
	parsed := c.UnmarshalBytePoint(encoded)

	if !bytes.Equal(x, parsed) {
		t.Fatal("failed to marshal/unmarshal point correctly")
	}

	encoded = c.MarshalByteSecret(x)
	parsed = c.UnmarshalByteSecret(encoded)

	if !bytes.Equal(x, parsed) {
		t.Fatal("failed to marshal/unmarshal secret correctly")
	}
}
