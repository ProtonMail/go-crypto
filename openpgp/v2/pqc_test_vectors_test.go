package v2

import (
	"bytes"
	"crypto"
	"fmt"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func dumpTestVector(_ *testing.T, filename, vector string) {
	fmt.Printf("Artifact: %s\n%s\n\n", filename, vector)
}

func serializePqSkVector(t *testing.T, filename string, entity *Entity, doChecksum bool) {
	var serializedArmoredPrivate bytes.Buffer
	serializedPrivate, err := armor.EncodeWithChecksumOption(&serializedArmoredPrivate, PrivateKeyType, nil, doChecksum)
	if err != nil {
		t.Fatalf("Failed to init armoring: %s", err)
	}

	if err = entity.SerializePrivate(serializedPrivate, nil); err != nil {
		t.Fatalf("Failed to serialize entity: %s", err)
	}

	if err := serializedPrivate.Close(); err != nil {
		t.Fatalf("Failed to close armoring: %s", err)
	}

	dumpTestVector(t, filename, serializedArmoredPrivate.String())
}

func serializePqPkVector(t *testing.T, filename string, entity *Entity, doChecksum bool) {
	var serializedArmoredPublic bytes.Buffer
	serializedPublic, err := armor.EncodeWithChecksumOption(&serializedArmoredPublic, PublicKeyType, nil, doChecksum)
	if err != nil {
		t.Fatalf("Failed to init armoring: %s", err)
	}

	if err = entity.Serialize(serializedPublic); err != nil {
		t.Fatalf("Failed to serialize entity: %s", err)
	}

	if err := serializedPublic.Close(); err != nil {
		t.Fatalf("Failed to close armoring: %s", err)
	}

	dumpTestVector(t, filename, serializedArmoredPublic.String())
}

func encryptPqcMessageVector(t *testing.T, filename string, entity *Entity, config *packet.Config, doChecksum bool) {
	var serializedArmoredMessage bytes.Buffer
	serializedMessage, err := armor.EncodeWithChecksumOption(&serializedArmoredMessage, MessageType, nil, doChecksum)
	if err != nil {
		t.Fatalf("Failed to init armoring: %s", err)
	}

	w, err := Encrypt(serializedMessage, []*Entity{entity}, nil, []*Entity{entity}, nil /* no hints */, config)
	if err != nil {
		t.Fatalf("Error in Encrypt: %s", err)
	}

	const message = "Testing\n"
	_, err = w.Write([]byte(message))
	if err != nil {
		t.Fatalf("Error writing plaintext: %s", err)
	}

	err = w.Close()
	if err != nil {
		t.Fatalf("Error closing WriteCloser: %s", err)
	}

	err = serializedMessage.Close()
	if err != nil {
		t.Fatalf("Error closing armoring WriteCloser: %s", err)
	}

	dumpTestVector(t, filename, serializedArmoredMessage.String())
}

func TestV6EddsaPqKey(t *testing.T) {
	eddsaConfig := &packet.Config{
		DefaultHash:   crypto.SHA512,
		Algorithm:     packet.PubKeyAlgoEd25519,
		V6Keys:        true,
		DefaultCipher: packet.CipherAES256,
		AEADConfig: &packet.AEADConfig{
			DefaultMode: packet.AEADModeOCB,
		},
		Time: func() time.Time {
			parsed, _ := time.Parse("2006-01-02", "2013-07-01")
			return parsed
		},
	}

	entity, err := NewEntity("PQC user", "Test Key", "pqc-test-key@example.com", eddsaConfig)
	if err != nil {
		t.Fatal(err)
	}

	kyberConfig := &packet.Config{
		DefaultHash: crypto.SHA512,
		Algorithm:   packet.PubKeyAlgoMlkem768X25519,
		V6Keys:      true,
		Time: func() time.Time {
			parsed, _ := time.Parse("2006-01-02", "2013-07-01")
			return parsed
		},
	}

	err = entity.AddEncryptionSubkey(kyberConfig)
	if err != nil {
		t.Fatal(err)
	}

	serializePqSkVector(t, "v6-eddsa-sample-sk.asc", entity, false)
	serializePqPkVector(t, "v6-eddsa-sample-pk.asc", entity, false)

	fmt.Printf("Primary fingerprint: %x\n", entity.PrimaryKey.Fingerprint)
	for i, subkey := range entity.Subkeys {
		fmt.Printf("Sub-key %d fingerprint: %x\n", i, subkey.PublicKey.Fingerprint)
	}

	configV2 := &packet.Config{
		DefaultCipher: packet.CipherAES256,
	}

	encryptPqcMessageVector(t, "v6-eddsa-sample-message-v2.asc", entity, configV2, false)
}

func TestV6MlDsa65PqKey(t *testing.T) {
	eddsaConfig := &packet.Config{
		DefaultHash:   crypto.SHA512,
		Algorithm:     packet.PubKeyAlgoMldsa65Ed25519,
		V6Keys:        true,
		DefaultCipher: packet.CipherAES256,
		AEADConfig: &packet.AEADConfig{
			DefaultMode: packet.AEADModeOCB,
		},
		Time: func() time.Time {
			parsed, _ := time.Parse("2006-01-02", "2013-07-01")
			return parsed
		},
	}

	entity, err := NewEntity("PQC user", "Test Key", "pqc-test-key@example.com", eddsaConfig)
	if err != nil {
		t.Fatal(err)
	}

	serializePqSkVector(t, "v6-mldsa-65-sample-sk.asc", entity, false)
	serializePqPkVector(t, "v6-mldsa-65-sample-pk.asc", entity, false)

	fmt.Printf("Primary fingerprint: %x\n", entity.PrimaryKey.Fingerprint)
	for i, subkey := range entity.Subkeys {
		fmt.Printf("Sub-key %d fingerprint: %x\n", i, subkey.PublicKey.Fingerprint)
	}

	var configV2 = &packet.Config{
		DefaultCipher: packet.CipherAES256,
		AEADConfig: &packet.AEADConfig{
			DefaultMode: packet.AEADModeOCB,
		},
	}

	encryptPqcMessageVector(t, "v6-mldsa-65-sample-message-v2.asc", entity, configV2, false)
}

func TestV6MlDsa87PqKey(t *testing.T) {
	eddsaConfig := &packet.Config{
		DefaultHash:   crypto.SHA512,
		Algorithm:     packet.PubKeyAlgoMldsa87Ed448,
		V6Keys:        true,
		DefaultCipher: packet.CipherAES256,
		AEADConfig: &packet.AEADConfig{
			DefaultMode: packet.AEADModeOCB,
		},
		Time: func() time.Time {
			parsed, _ := time.Parse("2006-01-02", "2013-07-01")
			return parsed
		},
	}

	entity, err := NewEntity("PQC user", "Test Key", "pqc-test-key@example.com", eddsaConfig)
	if err != nil {
		t.Fatal(err)
	}

	serializePqSkVector(t, "v6-mldsa-87-sample-sk.asc", entity, false)
	serializePqPkVector(t, "v6-mldsa-87-sample-pk.asc", entity, false)

	fmt.Printf("Primary fingerprint: %x\n", entity.PrimaryKey.Fingerprint)
	for i, subkey := range entity.Subkeys {
		fmt.Printf("Sub-key %d fingerprint: %x\n", i, subkey.PublicKey.Fingerprint)
	}

	var configV2 = &packet.Config{
		DefaultCipher: packet.CipherAES256,
		AEADConfig: &packet.AEADConfig{
			DefaultMode: packet.AEADModeOCB,
		},
	}

	encryptPqcMessageVector(t, "v6-mldsa-87-sample-message-v2.asc", entity, configV2, false)
}

func TestV6SlhDsa128sPqKey(t *testing.T) {
	eddsaConfig := &packet.Config{
		DefaultHash:   crypto.SHA512,
		Algorithm:     packet.PubKeyAlgoSlhdsaShake128s,
		V6Keys:        true,
		DefaultCipher: packet.CipherAES256,
		AEADConfig: &packet.AEADConfig{
			DefaultMode: packet.AEADModeOCB,
		},
		Time: func() time.Time {
			parsed, _ := time.Parse("2006-01-02", "2013-07-01")
			return parsed
		},
	}

	entity, err := NewEntity("PQC user", "Test Key", "pqc-test-key@example.com", eddsaConfig)
	if err != nil {
		t.Fatal(err)
	}

	serializePqSkVector(t, "v6-slhdsa-128s-sample-sk.asc", entity, false)
	serializePqPkVector(t, "v6-slhdsa-128s-sample-pk.asc", entity, false)

	fmt.Printf("Primary fingerprint: %x\n", entity.PrimaryKey.Fingerprint)
	for i, subkey := range entity.Subkeys {
		fmt.Printf("Sub-key %d fingerprint: %x\n", i, subkey.PublicKey.Fingerprint)
	}

	var configV2 = &packet.Config{
		DefaultCipher: packet.CipherAES256,
		AEADConfig: &packet.AEADConfig{
			DefaultMode: packet.AEADModeOCB,
		},
	}

	encryptPqcMessageVector(t, "v6-slhdsa-128s-sample-message-v2.asc", entity, configV2, false)
}
