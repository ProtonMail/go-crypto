package openpgp

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/crypto/openpgp/packet"
)

func TestNewEntityV5Keys (t *testing.T) {
	c := &packet.Config{
		V5Keys: true,
	}
	_, err := NewEntity("V5 Key Owner", "V5 Key", "botvinnik@pm.me", c)
	if err != nil {
		t.Fatal(err)
	}
}

func TestReadPrivateKeyV5(t *testing.T) {
	_, err := ReadArmoredKeyRing(strings.NewReader(v5PrivKey))
	if err != nil {
		t.Error(err)
		return
	}
}

func TestReadPrivateSerializeV5(t *testing.T) {
	el, err := ReadArmoredKeyRing(strings.NewReader(v5PrivKey))
	if err != nil {
		t.Error(err)
		return
	}
	entity := el[0]
	serializedEntity := bytes.NewBuffer(nil)
	err = entity.Serialize(serializedEntity)
	if err != nil {
		t.Fatal(err)
	}
	el, err = ReadKeyRing(serializedEntity)
	if err != nil {
		t.Fatal(err)
	}
}

func TestReadPrivateSerializePrivateWithoutSigningV5(t *testing.T) {
	el, err := ReadArmoredKeyRing(strings.NewReader(v5PrivKey))
	if err != nil {
		t.Error(err)
		return
	}
	entity := el[0]
	serializedEntity := bytes.NewBuffer(nil)
	err = entity.SerializePrivateWithoutSigning(serializedEntity, nil)
	if err != nil {
		t.Fatal(err)
	}
	el, err = ReadKeyRing(serializedEntity)
	if err != nil {
		t.Fatal(err)
	}
}
