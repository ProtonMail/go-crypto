package openpgp

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/crypto/openpgp/packet"
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

func TestReadPrivateEncryptedV5Key(t *testing.T) {
	c := &packet.Config{V5Keys: true}
	e, err := NewEntity("V5 Key Owner", "V5 Key", "v5@pm.me", c)
	if err != nil {
		t.Fatal(err)
	}
	password := []byte("test v5 key # password")
	// Encrypt private key
	if err = e.PrivateKey.Encrypt(password); err != nil {
		t.Fatal(err)
	}
	// Encrypt subkeys
	for _, sub := range e.Subkeys {
		if err = sub.PrivateKey.Encrypt(password); err != nil {
			t.Fatal(err)
		}
	}
	// Serialize, Read
	serializedEntity := bytes.NewBuffer(nil)
	err = e.SerializePrivateWithoutSigning(serializedEntity, nil)
	if err != nil {
		t.Fatal(err)
	}
	el, err := ReadKeyRing(serializedEntity)
	if err != nil {
		t.Fatal(err)
	}

	// Decrypt
	if el[0].PrivateKey == nil {
		t.Fatal("No private key found")
	}
	if err = el[0].PrivateKey.Decrypt(password); err != nil {
		t.Error(err)
	}

	// Decrypt subkeys
	for _, sub := range e.Subkeys {
		if err = sub.PrivateKey.Decrypt(password); err != nil {
			t.Error(err)
		}
	}

	checkV5Key(t, el[0])
}

// TODO
func testDetachedSignatureV5Key(t *testing.T) {
	// Signature from
	// mailarchive.ietf.org/arch/msg/openpgp/9SheW_LENE0Kxf7haNllovPyAdY/
	kring, err := ReadArmoredKeyRing(strings.NewReader(v5PrivKey))
	if err != nil {
		t.Fatal(err)
	}
	sig := strings.NewReader(v5detachedSig)
	_, err = CheckArmoredDetachedSignature(kring, nil, sig, nil)
	if err != nil {
		t.Fatal(err)
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

func TestNewEntitySerializeV5Key(t *testing.T) {
	c := &packet.Config{V5Keys: true}
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
		if key.Version() != 5 {
			t.Errorf("wrong key version %d", key.Version())
		}
		if key.ByteCount == 0 {
			t.Errorf("no byte count")
		}
		if len(key.Fingerprint) != 32 {
			t.Errorf("Wrong fingerprint length: %d", len(key.Fingerprint))
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
