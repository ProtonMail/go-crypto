// Package dilithium_eddsa_test tests the implementation of hybrid Dilithium + EdDSA encryption, suitable for OpenPGP, experimental.
package dilithium_eddsa_test

import (
	"crypto/rand"
	"io"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/dilithium_eddsa"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func TestSignVerify(t *testing.T) {
	asymmAlgos := map[string] packet.PublicKeyAlgorithm {
		"Dilithium3_Ed25519": packet.PubKeyAlgoDilithium3Ed25519,
		"Dilithium5_Ed448": packet.PubKeyAlgoDilithium5Ed448,
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
	if err := dilithium_eddsa.Validate(key); err != nil {
		t.Fatalf("valid key marked as invalid: %s", err)
	}

	bin := key.PublicDilithium.Bytes()
	bin[5] ^= 1
	key.PublicDilithium = key.Dilithium.PublicKeyFromBytes(bin)

	if err := dilithium_eddsa.Validate(key); err == nil {
		t.Fatalf("failed to detect invalid key")
	}

	// Generate fresh key
	key = testGenerateKeyAlgo(t, algId)
	if err := dilithium_eddsa.Validate(key); err != nil {
		t.Fatalf("valid key marked as invalid: %s", err)
	}

	key.PublicPoint[5] ^= 1
	if err := dilithium_eddsa.Validate(key); err == nil {
		t.Fatalf("failed to detect invalid key")
	}
}

func testGenerateKeyAlgo(t *testing.T, algId packet.PublicKeyAlgorithm) *dilithium_eddsa.PrivateKey {
	curveObj, err := packet.GetEdDSACurveFromAlgID(algId)
	if err != nil {
		t.Errorf("error getting curve: %s", err)
	}

	kyberObj, err := packet.GetDilithiumFromAlgID(algId)
	if err != nil {
		t.Errorf("error getting dilithium: %s", err)
	}

	priv, err := dilithium_eddsa.GenerateKey(rand.Reader, uint8(algId), curveObj, kyberObj)
	if err != nil {
		t.Fatal(err)
	}

	return priv
}


func testSignVerifyAlgo(t *testing.T, priv *dilithium_eddsa.PrivateKey) {
	digest := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	dSig, ecSig, err := dilithium_eddsa.Sign(priv, digest)
	if err != nil {
		t.Errorf("error encrypting: %s", err)
	}

	result := dilithium_eddsa.Verify(&priv.PublicKey, digest, dSig, ecSig)
	if !result {
		t.Error("unable to verify message")
	}
}
