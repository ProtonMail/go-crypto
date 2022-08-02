// Package eddsa implements EdDSA signature, suitable for OpenPGP,
// as specified in draft-ietf-openpgp-crypto-refresh-06 section 13.7
package eddsa

import (
	"crypto/rand"
	"io"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/internal/ecc"
)

func TestCurves(t *testing.T) {
	for _, curve := range ecc.Curves {
		EdDSACurve, ok := curve.Curve.(ecc.EdDSACurve)
		if !ok {
			continue
		}

		t.Run(curve.Name, func(t *testing.T) {
			testFingerprint := make([]byte, 20)
			_, err := io.ReadFull(rand.Reader, testFingerprint[:])
			if err != nil {
				t.Fatal(err)
			}

			priv := testGenerate(t, EdDSACurve)
			testSignVerify(t, priv)
			testValidation(t, priv)
		})
	}
}

func testGenerate(t *testing.T, curve ecc.EdDSACurve) *PrivateKey {
	priv, err := GenerateKey(rand.Reader, curve)
	if err != nil {
		t.Fatal(err)
	}

	return priv
}

func testSignVerify(t *testing.T, priv *PrivateKey) {
	digest := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	r, s, err := Sign(priv, digest)
	if err != nil {
		t.Errorf("error signing: %s", err)
	}

	result := Verify(&priv.PublicKey, digest, r, s)

	if !result {
		t.Error("unable to verify message")
	}
}

func testValidation(t *testing.T, priv *PrivateKey) {
	if err := Validate(priv); err != nil {
		t.Fatalf("valid key marked as invalid: %s", err)
	}

	priv.D[5] ^= 1
	if err := Validate(priv); err == nil {
		t.Fatal("failed to detect invalid key")
	}
}
