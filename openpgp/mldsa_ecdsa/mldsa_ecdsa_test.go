// Package mldsa_ecdsa_test tests the implementation of hybrid ML-DSA + ECDSA encryption, suitable for OpenPGP, experimental.
package mldsa_ecdsa_test

import (
	"crypto/rand"
	"io"
	"math/big"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/mldsa_ecdsa"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func TestSignVerify(t *testing.T) {
	asymmAlgos := map[string] packet.PublicKeyAlgorithm {
		"ML-DSA3_P256": packet.PubKeyAlgoMldsa65p256,
		"ML-DSA5_P384": packet.PubKeyAlgoMldsa87p384,
		"ML-DSA3_Brainpool256": packet.PubKeyAlgoMldsa65Brainpool256,
		"ML-DSA5_Brainpool384": packet.PubKeyAlgoMldsa87Brainpool384,
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
	if err := mldsa_ecdsa.Validate(key); err != nil {
		t.Fatalf("valid key marked as invalid: %s", err)
	}

	bin := key.PublicMldsa.Bytes()
	bin[5] ^= 1
	key.PublicMldsa = key.Mldsa.PublicKeyFromBytes(bin)

	if err := mldsa_ecdsa.Validate(key); err == nil {
		t.Fatalf("failed to detect invalid key")
	}

	// Generate fresh key
	key = testGenerateKeyAlgo(t, algId)
	if err := mldsa_ecdsa.Validate(key); err != nil {
		t.Fatalf("valid key marked as invalid: %s", err)
	}

	key.X.Sub(key.X, big.NewInt(1))
	if err := mldsa_ecdsa.Validate(key); err == nil {
		t.Fatalf("failed to detect invalid key")
	}
}

func testGenerateKeyAlgo(t *testing.T, algId packet.PublicKeyAlgorithm) *mldsa_ecdsa.PrivateKey {
	curveObj, err := packet.GetEcdsaCurveFromAlgID(algId)
	if err != nil {
		t.Errorf("error getting curve: %s", err)
	}

	kyberObj, err := packet.GetMldsaFromAlgID(algId)
	if err != nil {
		t.Errorf("error getting ML-DSA: %s", err)
	}

	priv, err := mldsa_ecdsa.GenerateKey(rand.Reader, uint8(algId), curveObj, kyberObj)
	if err != nil {
		t.Fatal(err)
	}

	return priv
}


func testSignVerifyAlgo(t *testing.T, priv *mldsa_ecdsa.PrivateKey) {
	digest := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	dSig, ecR, ecS, err := mldsa_ecdsa.Sign(rand.Reader, priv, digest)
	if err != nil {
		t.Errorf("error encrypting: %s", err)
	}

	result := mldsa_ecdsa.Verify(&priv.PublicKey, digest, dSig, ecR, ecS)
	if !result {
		t.Error("unable to verify message")
	}
}
