// Package dilithium_ecdsa_test tests the implementation of hybrid Dilithium + ECDSA encryption, suitable for OpenPGP, experimental.
package dilithium_ecdsa_test

import (
	"crypto/rand"
	"io"
	"math/big"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/dilithium_ecdsa"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func TestSignVerify(t *testing.T) {
	asymmAlgos := map[string] packet.PublicKeyAlgorithm {
		"Dilithium3_P256": packet.PubKeyAlgoDilithium3p256,
		"Dilithium5_P384": packet.PubKeyAlgoDilithium5p384,
		"Dilithium3_Brainpool256": packet.PubKeyAlgoDilithium3Brainpool256,
		"Dilithium5_Brainpool384": packet.PubKeyAlgoDilithium5Brainpool384,
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
	if err := dilithium_ecdsa.Validate(key); err != nil {
		t.Fatalf("valid key marked as invalid: %s", err)
	}

	bin := key.PublicDilithium.Bytes()
	bin[5] ^= 1
	key.PublicDilithium = key.Dilithium.PublicKeyFromBytes(bin)

	if err := dilithium_ecdsa.Validate(key); err == nil {
		t.Fatalf("failed to detect invalid key")
	}

	// Generate fresh key
	key = testGenerateKeyAlgo(t, algId)
	if err := dilithium_ecdsa.Validate(key); err != nil {
		t.Fatalf("valid key marked as invalid: %s", err)
	}

	key.X.Sub(key.X, big.NewInt(1))
	if err := dilithium_ecdsa.Validate(key); err == nil {
		t.Fatalf("failed to detect invalid key")
	}
}

func testGenerateKeyAlgo(t *testing.T, algId packet.PublicKeyAlgorithm) *dilithium_ecdsa.PrivateKey {
	curveObj, err := packet.GetECDSACurveFromAlgID(algId)
	if err != nil {
		t.Errorf("error getting curve: %s", err)
	}

	kyberObj, err := packet.GetDilithiumFromAlgID(algId)
	if err != nil {
		t.Errorf("error getting dilithium: %s", err)
	}

	priv, err := dilithium_ecdsa.GenerateKey(rand.Reader, uint8(algId), curveObj, kyberObj)
	if err != nil {
		t.Fatal(err)
	}

	return priv
}


func testSignVerifyAlgo(t *testing.T, priv *dilithium_ecdsa.PrivateKey) {
	digest := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	dSig, ecR, ecS, err := dilithium_ecdsa.Sign(rand.Reader, priv, digest)
	if err != nil {
		t.Errorf("error encrypting: %s", err)
	}

	result := dilithium_ecdsa.Verify(&priv.PublicKey, digest, dSig, ecR, ecS)
	if !result {
		t.Error("unable to verify message")
	}
}
