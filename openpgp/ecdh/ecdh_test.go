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
			testValidation(t, priv)

			// Needs fresh key
			priv = testGenerate(t, ECDHCurve)
			testMarshalUnmarshal(t, priv)
		})
	}
}

func testGenerate(t *testing.T, curve ecc.ECDHCurve) *PrivateKey {
	kdf := KDF {
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

	parsed := NewPrivateKey(*NewPublicKey(priv.GetCurve(), priv.KDF))

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

func TestKDFParamsWrite(t *testing.T) {
	kdf := KDF{
		Hash:   algorithm.SHA512,
		Cipher: algorithm.AES256,
	}
	byteBuffer := new(bytes.Buffer)

	testFingerprint := make([]byte, 20)

	expectBytesV1 := []byte{3, 1, kdf.Hash.Id(), kdf.Cipher.Id()}
	kdf.Serialize(byteBuffer)
	gotBytes := byteBuffer.Bytes()
	if !bytes.Equal(gotBytes, expectBytesV1) {
		t.Errorf("error serializing KDF params, got %x, want: %x", gotBytes, expectBytesV1)
	}
	byteBuffer.Reset()

	kdfV2 := KDF{
		Version:                KDFVersionForwarding,
		Hash:                   algorithm.SHA512,
		Cipher:                 algorithm.AES256,
		ReplacementFingerprint: testFingerprint,
	}
	expectBytesV2 := []byte{23, 0xFF, kdfV2.Hash.Id(), kdfV2.Cipher.Id()}
	expectBytesV2 = append(expectBytesV2, testFingerprint...)

	kdfV2.Serialize(byteBuffer)
	gotBytes = byteBuffer.Bytes()
	if !bytes.Equal(gotBytes, expectBytesV2) {
		t.Errorf("error serializing KDF params v2, got %x, want: %x", gotBytes, expectBytesV2)
	}
	byteBuffer.Reset()
}
