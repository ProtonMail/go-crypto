// Package dilithium_eddsa_test tests the implementation of hybrid Dilithium + EdDSA encryption, suitable for OpenPGP, experimental.
package dilithium_eddsa_test

import (
	"crypto/rand"
	"github.com/ProtonMail/go-crypto/openpgp/internal/dilithium"
	"io"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/dilithium_eddsa"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func TestSignVerify(t *testing.T) {
	asymmAlgos := map[string] packet.PublicKeyAlgorithm {
		"Dilithium_Ed25519": packet.PubKeyAlgoDilithiumEd25519,
		"Dilithium_Ed448": packet.PubKeyAlgoDilithiumEd448,
	}

	dilithiumParamIds := map[string] dilithium.ParameterSetId {
		"ParamID_1": dilithium.Parameter1,
		"ParamID_2": dilithium.Parameter2,
		"ParamID_3": dilithium.Parameter3,
	}

	for asymmName, asymmAlgo := range asymmAlgos {
		t.Run(asymmName, func(t *testing.T) {
			for paramIdName, paramId := range dilithiumParamIds {
				t.Run(paramIdName, func(t *testing.T) {
					key := testGenerateKeyAlgo(t, asymmAlgo, paramId)
					testSignVerifyAlgo(t, key)
					testvalidateAlgo(t, asymmAlgo, paramId)
				})
			}
		})
	}
}

func testvalidateAlgo(t *testing.T, algId packet.PublicKeyAlgorithm, paramId dilithium.ParameterSetId) {
	key := testGenerateKeyAlgo(t, algId, paramId)
	if err := dilithium_eddsa.Validate(key); err != nil {
		t.Fatalf("valid key marked as invalid: %s", err)
	}

	key.PublicDilithium[5] ^= 1
	if err := dilithium_eddsa.Validate(key); err == nil {
		t.Fatalf("failed to detect invalid key")
	}

	// Generate fresh key
	key = testGenerateKeyAlgo(t, algId, paramId)
	if err := dilithium_eddsa.Validate(key); err != nil {
		t.Fatalf("valid key marked as invalid: %s", err)
	}

	key.PublicPoint[5] ^= 1
	if err := dilithium_eddsa.Validate(key); err == nil {
		t.Fatalf("failed to detect invalid key")
	}
}

func testGenerateKeyAlgo(t *testing.T, algId packet.PublicKeyAlgorithm, paramId dilithium.ParameterSetId) *dilithium_eddsa.PrivateKey {
	curveObj, err := packet.GetEdDSACurveFromAlgID(algId)
	if err != nil {
		t.Errorf("error getting curve: %s", err)
	}

	priv, err := dilithium_eddsa.GenerateKey(rand.Reader, uint8(algId), curveObj, paramId)
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
