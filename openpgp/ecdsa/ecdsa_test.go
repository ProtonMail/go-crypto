// Package ecdsa implements ECDSA signature, suitable for OpenPGP,
// as specified in RFC 6637, section 5.
package ecdsa

import (
	"bytes"
	goecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"math/big"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/internal/ecc"
)

func TestCurves(t *testing.T) {
	for _, curve := range ecc.Curves {
		ECDSACurve, ok := curve.Curve.(ecc.ECDSACurve)
		if !ok {
			continue
		}

		t.Run(ECDSACurve.GetCurveName(), func(t *testing.T) {
			testFingerprint := make([]byte, 20)
			_, err := io.ReadFull(rand.Reader, testFingerprint[:])
			if err != nil {
				t.Fatal(err)
			}

			priv := testGenerate(t, ECDSACurve)
			testSignVerify(t, priv)
			testValidation(t, priv)

			// Needs fresh key
			priv = testGenerate(t, ECDSACurve)
			testMarshalUnmarshal(t, priv)
		})
	}
}

func testGenerate(t *testing.T, curve ecc.ECDSACurve) *PrivateKey {
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

	r, s, err := Sign(rand.Reader, priv, digest)
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

	priv.X.Sub(priv.X, big.NewInt(1))
	if err := Validate(priv); err == nil {
		t.Fatal("failed to detect invalid key")
	}
}

func testMarshalUnmarshal(t *testing.T, priv *PrivateKey) {
	p := priv.MarshalPoint()
	d := priv.MarshalIntegerSecret()

	parsed := NewPrivateKey(*NewPublicKey(priv.GetCurve()))

	if err := parsed.UnmarshalPoint(p); err != nil {
		t.Fatalf("unable to unmarshal point: %s", err)
	}

	if err := parsed.UnmarshalIntegerSecret(d); err != nil {
		t.Fatalf("unable to unmarshal integer: %s", err)
	}

	if priv.X.Cmp(parsed.X) != 0 || priv.Y.Cmp(parsed.Y) != 0 || priv.D.Cmp(parsed.D) != 0 {
		t.Fatal("failed to marshal/unmarshal correctly")
	}
}

func TestNewPublicKeyFromStd(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			stdPriv, err := goecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			pub, err := NewPublicKeyFromStd(&stdPriv.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			want := elliptic.Marshal(curve, stdPriv.X, stdPriv.Y)
			if got := pub.MarshalPoint(); !bytes.Equal(got, want) {
				t.Fatalf("got point %x, want %x", got, want)
			}

			hash := make([]byte, 32)
			if _, err := io.ReadFull(rand.Reader, hash); err != nil {
				t.Fatal(err)
			}
			r, s, err := goecdsa.Sign(rand.Reader, stdPriv, hash)
			if err != nil {
				t.Fatal(err)
			}
			if !Verify(pub, hash, r, s) {
				t.Fatal("signature made with the crypto/ecdsa key did not verify")
			}
		})
	}
}

func TestNewPublicKeyFromStdInvalid(t *testing.T) {
	stdPriv, err := goecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewPublicKeyFromStd(&stdPriv.PublicKey); err == nil {
		t.Error("expected an error for the unsupported P-224 curve")
	}
	if _, err := NewPublicKeyFromStd(nil); err == nil {
		t.Error("expected an error for a nil key")
	}
	if _, err := NewPublicKeyFromStd(&goecdsa.PublicKey{}); err == nil {
		t.Error("expected an error for an empty key")
	}
}
