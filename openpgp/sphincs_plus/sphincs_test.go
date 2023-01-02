// Package sphincs_plus_test tests the implementation of SPHINCS+ signatures, suitable for OpenPGP, experimental.
package sphincs_plus_test

import (
	"crypto/rand"
	"io"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/sphincs_plus"
)

func TestSignVerify(t *testing.T) {
	asymmAlgos := map[string] sphincs_plus.Mode{
		"SHA2-Simple": sphincs_plus.ModeSimpleSHA2,
		"SHAKE-Simple": sphincs_plus.ModeSimpleShake,
	}

	params := map[string] sphincs_plus.ParameterSetId {
		"1": sphincs_plus.Param128s,
		"2": sphincs_plus.Param128f,
		"3": sphincs_plus.Param192s,
		"4": sphincs_plus.Param192f,
		"5": sphincs_plus.Param256s,
		"6": sphincs_plus.Param256f,
	}

	for asymmName, asymmAlgo := range asymmAlgos {
		t.Run(asymmName, func(t *testing.T) {
			for paramName, param := range params {
				t.Run(paramName, func(t *testing.T) {
					key := testGenerateKeyAlgo(t, asymmAlgo, param)
					testSignVerifyAlgo(t, key)
					testvalidateAlgo(t, asymmAlgo, param)
				})
			}
		})
	}
}

func testvalidateAlgo(t *testing.T, mode sphincs_plus.Mode, param sphincs_plus.ParameterSetId) {
	key := testGenerateKeyAlgo(t, mode, param)
	if err := sphincs_plus.Validate(key); err != nil {
		t.Fatalf("valid key marked as invalid: %s", err)
	}

	// Serialize
	pkBin, err := key.SerializePublic()
	if err != nil {
		t.Fatalf("unable to serialize public key")
	}

	skBin, err := key.SerializePrivate()
	if err != nil {
		t.Fatalf("unable to serialize private key")
	}

	// Deserialize
	if err = key.UnmarshalPublic(pkBin); err != nil {
		t.Fatalf("unable to deserialize public key")
	}

	if err = key.UnmarshalPrivate(skBin); err != nil {
		t.Fatalf("unable to deserialize private key")
	}

	if err := sphincs_plus.Validate(key); err != nil {
		t.Fatalf("valid key marked as invalid: %s", err)
	}

	// Corrupt the root of the public key
	key.PublicData.PKroot[1] ^= 1

	if err := sphincs_plus.Validate(key); err == nil {
		t.Fatalf("failed to detect invalid root in key")
	}

	// Re-load the correct public key
	if err = key.UnmarshalPublic(pkBin); err != nil {
		t.Fatalf("unable to deserialize public key")
	}

	if err = key.UnmarshalPrivate(skBin); err != nil {
		t.Fatalf("unable to deserialize private key")
	}

	if err := sphincs_plus.Validate(key); err != nil {
		t.Fatalf("valid key marked as invalid: %s", err)
	}

	// Corrupt the seed of the public key
	key.PublicData.PKseed[1] ^= 1

	if err := sphincs_plus.Validate(key); err == nil {
		t.Fatalf("failed to detect invalid seed in key")
	}
}

func testGenerateKeyAlgo(t *testing.T, mode sphincs_plus.Mode, param sphincs_plus.ParameterSetId) *sphincs_plus.PrivateKey {
	priv, err := sphincs_plus.GenerateKey(rand.Reader, mode, param)
	if err != nil {
		t.Fatal(err)
	}

	return priv
}


func testSignVerifyAlgo(t *testing.T, priv *sphincs_plus.PrivateKey) {
	digest := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	sig, err := sphincs_plus.Sign(priv, digest)
	if err != nil {
		t.Errorf("error encrypting: %s", err)
	}

	result := sphincs_plus.Verify(&priv.PublicKey, digest, sig)
	if !result {
		t.Error("unable to verify message")
	}
}
