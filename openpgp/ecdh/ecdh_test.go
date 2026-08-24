// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ecdh implements ECDH encryption, suitable for OpenPGP,
// as specified in RFC 6637, section 8.
package ecdh

import (
	"bytes"
	"crypto/rand"
	"github.com/ProtonMail/go-crypto/openpgp/internal/ecc"
	"io"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/internal/algorithm"
)

func TestCurves(t *testing.T) {
	for _, curve := range ecc.Curves {
		ECDHCurve, ok := curve.Curve.(ecc.ECDHCurve)
		if !ok {
			continue
		}

		t.Run(ECDHCurve.GetCurveName(), func(t *testing.T) {
			testFingerprint := make([]byte, 20)
			_, err := io.ReadFull(rand.Reader, testFingerprint[:])
			if err != nil {
				t.Fatal(err)
			}

			priv := testGenerate(t, ECDHCurve)
			testEncryptDecrypt(t, priv, curve.Oid.Bytes(), testFingerprint)
			testDecryptWithDecapsulator(t, priv, curve.Oid.Bytes(), testFingerprint)
			testValidation(t, priv)

			// Needs fresh key
			priv = testGenerate(t, ECDHCurve)
			testMarshalUnmarshal(t, priv)
		})
	}
}

func testGenerate(t *testing.T, curve ecc.ECDHCurve) *PrivateKey {
	kdf := KDF{
		Hash:   algorithm.SHA512,
		Cipher: algorithm.AES256,
	}

	priv, err := GenerateKey(rand.Reader, curve, kdf)
	if err != nil {
		t.Fatal(err)
	}

	return priv
}

func testEncryptDecrypt(t *testing.T, priv *PrivateKey, oid, fingerprint []byte) {
	message := []byte("hello world")

	vsG, m, err := Encrypt(rand.Reader, &priv.PublicKey, message, oid, fingerprint)
	if err != nil {
		t.Errorf("error encrypting: %s", err)
	}

	message2, err := Decrypt(priv, vsG, m, oid, fingerprint)
	if err != nil {
		t.Errorf("error decrypting: %s", err)
	}

	if !bytes.Equal(message2, message) {
		t.Errorf("decryption failed, got: %x, want: %x", message2, message)
	}
}

// testDecapsulator wraps a real private key, simulating a hardware token
// that performs ECDH key agreement internally without exposing the scalar.
type testDecapsulator struct {
	priv        *PrivateKey
	decapsCount int
}

func (d *testDecapsulator) Decaps(ephemeral []byte) ([]byte, error) {
	d.decapsCount++
	return d.priv.PublicKey.GetCurve().Decaps(ephemeral, d.priv.D)
}

// testDecryptWithDecapsulator simulates the hardware token flow:
// 1. Encrypt a message normally
// 2. Decrypt via a Decapsulator (simulating what a hardware token does)
// 3. Verify the decrypted message matches the original
func testDecryptWithDecapsulator(t *testing.T, priv *PrivateKey, oid, fingerprint []byte) {
	message := []byte("hello world")

	vsG, wrappedKey, err := Encrypt(rand.Reader, &priv.PublicKey, message, oid, fingerprint)
	if err != nil {
		t.Fatalf("error encrypting: %s", err)
	}

	decapsulator := &testDecapsulator{priv: priv}

	decrypted, err := DecryptWithDecapsulator(decapsulator, &priv.PublicKey, vsG, wrappedKey, oid, fingerprint)
	if err != nil {
		t.Fatalf("error in DecryptWithDecapsulator: %s", err)
	}

	if !bytes.Equal(decrypted, message) {
		t.Errorf("DecryptWithDecapsulator failed, got: %x, want: %x", decrypted, message)
	}

	if decapsulator.decapsCount != 1 {
		t.Errorf("expected Decaps to be called once, got %d", decapsulator.decapsCount)
	}
}

func testValidation(t *testing.T, priv *PrivateKey) {
	if err := Validate(priv); err != nil {
		t.Fatalf("valid key marked as invalid: %s", err)
	}

	priv.D[5] ^= 1
	if err := Validate(priv); err == nil {
		t.Fatalf("failed to detect invalid key")
	}
}

func testMarshalUnmarshal(t *testing.T, priv *PrivateKey) {
	p := priv.MarshalPoint()
	d := priv.MarshalByteSecret()

	parsed := NewPrivateKey(*NewPublicKey(priv.GetCurve(), priv.KDF.Hash, priv.KDF.Cipher))

	if err := parsed.UnmarshalPoint(p); err != nil {
		t.Fatalf("unable to unmarshal point: %s", err)
	}

	if err := parsed.UnmarshalByteSecret(d); err != nil {
		t.Fatalf("unable to unmarshal integer: %s", err)
	}

	expectedD := make([]byte, len(priv.D))
	copy(expectedD, priv.D)

	// Curve25519 expects keys to be saved clamped
	if priv.curve.GetCurveName() == "curve25519" {
		expectedD[0] &= 248
		expectedD[31] &= 127
		expectedD[31] |= 64
	}

	if !bytes.Equal(priv.Point, parsed.Point) || !bytes.Equal(expectedD, parsed.D) {
		t.Fatal("failed to marshal/unmarshal correctly")
	}
}
