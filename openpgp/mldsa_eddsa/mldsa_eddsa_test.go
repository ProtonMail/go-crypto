// Package mldsa_eddsa_test tests the implementation of hybrid ML-DSA + EdDSA encryption, suitable for OpenPGP, experimental.
package mldsa_eddsa_test

import (
	"crypto/rand"
	"io"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/mldsa_eddsa"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func TestSignVerify(t *testing.T) {
	asymmAlgos := map[string] packet.PublicKeyAlgorithm {
		"ML-DSA3_Ed25519": packet.PubKeyAlgoMldsa65Ed25519,
		"ML-DSA5_Ed448": packet.PubKeyAlgoMldsa87Ed448,
	}

	for asymmName, asymmAlgo := range asymmAlgos {
		t.Run(asymmName, func(t *testing.T) {
			key := testGenerateKeyAlgo(t, asymmAlgo)
			testSignVerifyAlgo(t, key)
			testvalidateAlgo(t, asymmAlgo)
		})
	}
}

func testvalidateAlgo(t *testing.T, algId packet.PublicKeyAlgorithm) {
	key := testGenerateKeyAlgo(t, algId)
	if err := mldsa_eddsa.Validate(key); err != nil {
		t.Fatalf("valid key marked as invalid: %s", err)
	}

	bin := key.PublicMldsa.Bytes()
	bin[5] ^= 1
	key.PublicMldsa = key.Mldsa.PublicKeyFromBytes(bin)

	if err := mldsa_eddsa.Validate(key); err == nil {
		t.Fatalf("failed to detect invalid key")
	}

	// Generate fresh key
	key = testGenerateKeyAlgo(t, algId)
	if err := mldsa_eddsa.Validate(key); err != nil {
		t.Fatalf("valid key marked as invalid: %s", err)
	}

	key.PublicPoint[5] ^= 1
	if err := mldsa_eddsa.Validate(key); err == nil {
		t.Fatalf("failed to detect invalid key")
	}
}

func testGenerateKeyAlgo(t *testing.T, algId packet.PublicKeyAlgorithm) *mldsa_eddsa.PrivateKey {
	curveObj, err := packet.GetEdDSACurveFromAlgID(algId)
	if err != nil {
		t.Errorf("error getting curve: %s", err)
	}

	kyberObj, err := packet.GetMldsaFromAlgID(algId)
	if err != nil {
		t.Errorf("error getting ML-DSA: %s", err)
	}

	priv, err := mldsa_eddsa.GenerateKey(rand.Reader, uint8(algId), curveObj, kyberObj)
	if err != nil {
		t.Fatal(err)
	}

	return priv
}


func testSignVerifyAlgo(t *testing.T, priv *mldsa_eddsa.PrivateKey) {
	digest := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	dSig, ecSig, err := mldsa_eddsa.Sign(priv, digest)
	if err != nil {
		t.Errorf("error encrypting: %s", err)
	}

	result := mldsa_eddsa.Verify(&priv.PublicKey, digest, dSig, ecSig)
	if !result {
		t.Error("unable to verify message")
	}
}
