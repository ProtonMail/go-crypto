// Package dilithium_ecdsa_test tests the implementation of hybrid Dilithium + ECDSA encryption, suitable for OpenPGP, experimental.
package dilithium_ecdsa_test

import (
	"crypto/rand"
	"github.com/ProtonMail/go-crypto/openpgp/internal/dilithium"
	"io"
	"math/big"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/dilithium_ecdsa"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func TestSignVerify(t *testing.T) {
	asymmAlgos := map[string] packet.PublicKeyAlgorithm {
		"Dilithium_P384": packet.PubKeyAlgoDilithiumP384,
		"Dilithium_P521": packet.PubKeyAlgoDilithiumP521,
		"Dilithium_Brainpool384": packet.PubKeyAlgoDilithiumBrainpool384,
		"Dilithium_Brainpool512": packet.PubKeyAlgoDilithiumBrainpool512,
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
	if err := dilithium_ecdsa.Validate(key); err != nil {
		t.Fatalf("valid key marked as invalid: %s", err)
	}

	key.PublicDilithium[5] ^= 1
	if err := dilithium_ecdsa.Validate(key); err == nil {
		t.Fatalf("failed to detect invalid key")
	}

	// Generate fresh key
	key = testGenerateKeyAlgo(t, algId, paramId)
	if err := dilithium_ecdsa.Validate(key); err != nil {
		t.Fatalf("valid key marked as invalid: %s", err)
	}

	key.X.Sub(key.X, big.NewInt(1))
	if err := dilithium_ecdsa.Validate(key); err == nil {
		t.Fatalf("failed to detect invalid key")
	}
}

func testGenerateKeyAlgo(t *testing.T, algId packet.PublicKeyAlgorithm, paramId dilithium.ParameterSetId) *dilithium_ecdsa.PrivateKey {
	curveObj, err := packet.GetECDSACurveFromAlgID(algId)
	if err != nil {
		t.Errorf("error getting curve: %s", err)
	}

	priv, err := dilithium_ecdsa.GenerateKey(rand.Reader, uint8(algId), curveObj, paramId)
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
