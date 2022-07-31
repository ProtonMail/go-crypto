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
	"math/big"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/internal/algorithm"
)

func TestCurves(t *testing.T) {
	for _, curve := range ecc.Curves {
		ECDHCurve, ok := curve.Curve.(ecc.ECDHCurve)
		if !ok {
			continue
		}

		t.Run(curve.Name, func(t *testing.T) {
			testFingerprint := make([]byte, 20)
			_, err := io.ReadFull(rand.Reader, testFingerprint[:])
			if err != nil {
				t.Fatal(err)
			}

			priv := testGenerate(t, ECDHCurve)
			testEncryptDecrypt(t, priv, curve.Oid.Bytes(), testFingerprint)
			testValidation(t, priv)
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


func testValidation(t *testing.T, priv *PrivateKey) {
	if err := Validate(priv); err != nil {
		t.Fatalf("valid key marked as invalid: %s", err)
	}

	priv.X.Sub(priv.X, big.NewInt(1))
	if err := Validate(priv); err == nil {
		t.Fatalf("failed to detect invalid key")
	}
}