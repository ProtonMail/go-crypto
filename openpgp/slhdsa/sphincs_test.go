// Package slh_dsa_test tests the implementation of SLH-DSA signatures, suitable for OpenPGP, experimental.
package slhdsa_test

import (
	"crypto/rand"
	"io"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/slhdsa"
)

func TestSignVerify(t *testing.T) {
	asymmAlgos := map[string] slhdsa.Mode{
		"SHA2-Simple":  slhdsa.ModeSimpleSHA2,
		"SHAKE-Simple": slhdsa.ModeSimpleShake,
	}

	params := map[string] slhdsa.ParameterSetId {
		"1": slhdsa.Param128s,
		"2": slhdsa.Param128f,
		"3": slhdsa.Param192s,
		"4": slhdsa.Param192f,
		"5": slhdsa.Param256s,
		"6": slhdsa.Param256f,
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

func testvalidateAlgo(t *testing.T, mode slhdsa.Mode, param slhdsa.ParameterSetId) {
	key := testGenerateKeyAlgo(t, mode, param)
	if err := slhdsa.Validate(key); err != nil {
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

	if err := slhdsa.Validate(key); err != nil {
		t.Fatalf("valid key marked as invalid: %s", err)
	}

	// Corrupt the root of the public key
	key.PublicData.PKroot[1] ^= 1

	if err := slhdsa.Validate(key); err == nil {
		t.Fatalf("failed to detect invalid root in key")
	}

	// Re-load the correct public key
	if err = key.UnmarshalPublic(pkBin); err != nil {
		t.Fatalf("unable to deserialize public key")
	}

	if err = key.UnmarshalPrivate(skBin); err != nil {
		t.Fatalf("unable to deserialize private key")
	}

	if err := slhdsa.Validate(key); err != nil {
		t.Fatalf("valid key marked as invalid: %s", err)
	}

	// Corrupt the seed of the public key
	key.PublicData.PKseed[1] ^= 1

	if err := slhdsa.Validate(key); err == nil {
		t.Fatalf("failed to detect invalid seed in key")
	}
}

func testGenerateKeyAlgo(t *testing.T, mode slhdsa.Mode, param slhdsa.ParameterSetId) *slhdsa.PrivateKey {
	priv, err := slhdsa.GenerateKey(rand.Reader, mode, param)
	if err != nil {
		t.Fatal(err)
	}

	return priv
}


func testSignVerifyAlgo(t *testing.T, priv *slhdsa.PrivateKey) {
	digest := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	sig, err := slhdsa.Sign(priv, digest)
	if err != nil {
		t.Errorf("error encrypting: %s", err)
	}

	result := slhdsa.Verify(&priv.PublicKey, digest, sig)
	if !result {
		t.Error("unable to verify message")
	}
}
