// Package slhdsa_test tests the SLH-DSA implementation suitable for OpenPGP, experimental.
package slhdsa_test

import (
	"crypto/rand"
	"io"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/go-crypto/openpgp/slhdsa"
)

var algorithms = map[string]packet.PublicKeyAlgorithm{
	"SLH-DSA-SHAKE-128s": packet.PubKeyAlgoSlhdsaShake128s,
	"SLH-DSA-SHAKE-128f": packet.PubKeyAlgoSlhdsaShake128f,
	"SLH-DSA-SHAKE-256s": packet.PubKeyAlgoSlhdsaShake256s,
}

func TestValidate(t *testing.T) {
	for asymmName, asymmAlgo := range algorithms {
		t.Run(asymmName, func(t *testing.T) {
			testValidateAlgo(t, asymmAlgo)
		})
	}
}

func TestSignVerify(t *testing.T) {
	for asymmName, asymmAlgo := range algorithms {
		t.Run(asymmName, func(t *testing.T) {
			key := testGenerateKeyAlgo(t, asymmAlgo)
			testSignVerifyAlgo(t, key)
		})
	}
}

func testValidateAlgo(t *testing.T, algId packet.PublicKeyAlgorithm) {
	key := testGenerateKeyAlgo(t, algId)
	if err := slhdsa.Validate(key); err != nil {
		t.Fatalf("valid key marked as invalid: %s", err)
	}

	bin, err := key.PublicSlhdsa.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	bin[5] ^= 1
	key.PublicSlhdsa, err = key.Slhdsa.UnmarshalBinaryPublicKey(bin) //PublicKeyFromBytes(bin)
	if err != nil {
		t.Fatal(err)
	}

	if err := slhdsa.Validate(key); err == nil {
		t.Fatalf("failed to detect invalid key")
	}
}

func testGenerateKeyAlgo(t *testing.T, algId packet.PublicKeyAlgorithm) *slhdsa.PrivateKey {
	scheme, err := packet.GetSlhdsaSchemeFromAlgID(algId)
	if err != nil {
		t.Errorf("error getting SLH-DSA scheme: %s", err)
	}

	priv, err := slhdsa.GenerateKey(rand.Reader, uint8(algId), scheme)
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

	dSig, err := slhdsa.Sign(priv, digest)
	if err != nil {
		t.Errorf("error encrypting: %s", err)
	}

	result := slhdsa.Verify(&priv.PublicKey, digest, dSig)
	if !result {
		t.Error("unable to verify message")
	}
}
