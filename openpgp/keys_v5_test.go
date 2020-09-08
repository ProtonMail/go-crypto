package openpgp

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/crypto/openpgp/packet"
)

func TestReadPrivateV5Key(t *testing.T) {
	// V5 key from
	// mailarchive.ietf.org/arch/msg/openpgp/9SheW_LENE0Kxf7haNllovPyAdY/
	kring, err := ReadArmoredKeyRing(strings.NewReader(v5PrivKey))
	if err != nil {
		t.Error(err)
		return
	}
	checkV5Key(t, kring[0])
}

func testReadPrivateSerializeV5KeyXXX(t *testing.T) {
	el, err := ReadArmoredKeyRing(strings.NewReader(v5PrivKey))
	if err != nil {
		t.Error(err)
		return
	}
	checkSerializeRead(t, el[0])
}

func TestNewEntitySerializeV5Key(t *testing.T) {
	c := &packet.Config{
		V5Keys: true,
	}
	e, err := NewEntity("V5 Key Owner", "V5 Key", "v5@pm.me", c)
	if err != nil {
		t.Fatal(err)
	}
	checkSerializeRead(t, e)
}

func TestNewEntityV5Key(t *testing.T) {
	c := &packet.Config{
		V5Keys: true,
	}
	e, err := NewEntity("V5 Key Owner", "V5 Key", "v5@pm.me", c)
	if err != nil {
		t.Fatal(err)
	}
	checkV5Key(t, e)
}

func checkV5Key(t *testing.T, ent *Entity) {
	key := ent.PrimaryKey
	if key != nil {
		if key.Version() != 5 {
			t.Errorf("wrong key version %d", key.Version())
		}
		if key.ByteCount == 0 {
			t.Errorf("no byte count")
		}
		if len(key.Fingerprint) != 32 {
			t.Errorf("Wrong fingerprint length: %d", len(key.Fingerprint))
		}
	} else {
		println("nil key")
	}
	signatures := ent.Revocations
	for _, id := range ent.Identities {
		signatures = append(signatures, id.SelfSignature)
		signatures = append(signatures, id.Signatures...)
	}
	for _, sig := range signatures {
		if sig == nil {
			continue
		}
		if sig.Version() != 5 {
			t.Errorf("wrong signature version %d", sig.Version())
		}
		if sig.IssuerKeyId != nil {
			t.Error("v5 signature should not have Issuer Key ID subpacket")
		}
		fgptLen := len(sig.IssuerKeyFingerprint)
		if fgptLen!= 32 {
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

