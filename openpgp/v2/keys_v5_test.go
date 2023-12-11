package v2

import (
	"bytes"
	"strings"
	"testing"
)

var foreignKeys = []string{
	v5PrivKey,
}

func TestReadPrivateForeignV5Key(t *testing.T) {
	for _, str := range foreignKeys {
		kring, err := ReadArmoredKeyRing(strings.NewReader(str))
		if err != nil {
			t.Fatal(err)
		}
		checkV5Key(t, kring[0])
	}
}

func TestReadPrivateSerializeForeignV5Key(t *testing.T) {
	for _, str := range foreignKeys {
		el, err := ReadArmoredKeyRing(strings.NewReader(str))
		if err != nil {
			t.Fatal(err)
		}
		checkSerializeRead(t, el[0])
	}
}

func checkV5Key(t *testing.T, ent *Entity) {
	key := ent.PrimaryKey
	if key.Version != 5 {
		t.Errorf("wrong key version %d", key.Version)
	}
	if len(key.Fingerprint) != 32 {
		t.Errorf("Wrong fingerprint length: %d", len(key.Fingerprint))
	}
	signatures := ent.Revocations
	for _, id := range ent.Identities {
		signatures = append(signatures, id.SelfCertifications...)
	}
	for _, sig := range signatures {
		if sig == nil {
			continue
		}
		if sig.Packet.Version != 5 {
			t.Errorf("wrong signature version %d", sig.Packet.Version)
		}
		fgptLen := len(sig.Packet.IssuerFingerprint)
		if fgptLen != 32 {
			t.Errorf("Wrong fingerprint length in signature: %d", fgptLen)
		}
	}
}

func checkSerializeRead(t *testing.T, e *Entity) {
	// Entity serialize
	serializedEntity := bytes.NewBuffer(nil)
	err := e.Serialize(serializedEntity)
	if err != nil {
		t.Fatal(err)
	}
	el, err := ReadKeyRing(serializedEntity)
	if err != nil {
		t.Fatal(err)
	}
	checkV5Key(t, el[0])

	// Without signing
	serializedEntity = bytes.NewBuffer(nil)
	err = e.SerializePrivateWithoutSigning(serializedEntity, nil)
	if err != nil {
		t.Fatal(err)
	}
	el, err = ReadKeyRing(serializedEntity)
	if err != nil {
		t.Fatal(err)
	}
	checkV5Key(t, el[0])

	// Private
	serializedEntity = bytes.NewBuffer(nil)
	err = e.SerializePrivate(serializedEntity, nil)
	if err != nil {
		t.Fatal(err)
	}
	el, err = ReadKeyRing(serializedEntity)
	if err != nil {
		t.Fatal(err)
	}
	checkV5Key(t, el[0])
}
