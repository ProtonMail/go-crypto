// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build pqc_test_vectors

package openpgp

import (
	"bytes"
	"crypto"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"testing"
	"time"
)

func dumpTestVector(t *testing.T, filename, vector string) {
	t.Logf("Artifact: %s\n%s\n\n", filename, vector)
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

	w, err := Encrypt(serializedMessage, []*Entity{entity},nil, nil /* no hints */, config)
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

func TestV4EddsaPqKey(t *testing.T) {
	eddsaConfig := &packet.Config{
		DefaultHash: crypto.SHA512,
		Algorithm:   packet.PubKeyAlgoEdDSA,
		V6Keys:      false,
		DefaultCipher: packet.CipherAES256,
		AEADConfig: &packet.AEADConfig {
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
		V6Keys:      false,
		Time: func() time.Time {
			parsed, _ := time.Parse("2006-01-02", "2013-07-01")
			return parsed
		},
	}

	err = entity.AddEncryptionSubkey(kyberConfig)
	if err != nil {
		t.Fatal(err)
	}

	serializePqSkVector(t, "v4-eddsa-sample-pk.asc", entity, true)
	serializePqPkVector(t, "v4-eddsa-sample-pk.asc", entity, true)

	t.Logf("Primary fingerprint: %x", entity.PrimaryKey.Fingerprint)
	for i, subkey := range entity.Subkeys {
		t.Logf("Sub-key %d fingerprint: %x", i, subkey.PublicKey.Fingerprint)
	}

	var configV1 = &packet.Config{
		DefaultCipher: packet.CipherAES256,
		AEADConfig: nil,
	}

	encryptPqcMessageVector(t, "v4-eddsa-sample-message-v1.asc", entity, configV1,true)

	var configV2 = &packet.Config{
		DefaultCipher: packet.CipherAES256,
		AEADConfig: &packet.AEADConfig{
			DefaultMode: packet.AEADModeOCB,
		},
	}

	encryptPqcMessageVector(t, "v4-eddsa-sample-message-v2.asc", entity, configV2,false)
}


func TestV6EddsaPqKey(t *testing.T) {
	eddsaConfig := &packet.Config{
		DefaultHash: crypto.SHA512,
		Algorithm:   packet.PubKeyAlgoEd25519,
		V6Keys:      true,
		DefaultCipher: packet.CipherAES256,
		AEADConfig: &packet.AEADConfig {
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

	entity.Subkeys = []Subkey{}
	err = entity.AddEncryptionSubkey(kyberConfig)
	if err != nil {
		t.Fatal(err)
	}

	serializePqSkVector(t, "v6-eddsa-sample-pk.asc", entity, false)
	serializePqPkVector(t, "v6-eddsa-sample-pk.asc", entity, false)

	t.Logf("Primary fingerprint: %x", entity.PrimaryKey.Fingerprint)
	for i, subkey := range entity.Subkeys {
		t.Logf("Sub-key %d fingerprint: %x", i, subkey.PublicKey.Fingerprint)
	}

	var configV2 = &packet.Config{
		DefaultCipher: packet.CipherAES256,
		AEADConfig: &packet.AEADConfig{
			DefaultMode: packet.AEADModeOCB,
		},
	}

	encryptPqcMessageVector(t, "v6-eddsa-sample-message-v2.asc", entity, configV2,false)
}
