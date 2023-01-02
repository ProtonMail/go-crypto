package openpgp

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"github.com/ProtonMail/go-crypto/openpgp/dilithium_ecdsa"
	"github.com/ProtonMail/go-crypto/openpgp/dilithium_eddsa"
	"github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/kyber_ecdh"
	"github.com/ProtonMail/go-crypto/openpgp/sphincs_plus"
	"io/ioutil"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
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

// TODO: Replace message with a correctly generated one.
func testV5ForeignSignedMessage(t *testing.T) {
	kring, err := ReadArmoredKeyRing(strings.NewReader(v5PrivKey))
	if err != nil {
		t.Fatal(err)
	}
	msg := strings.NewReader(v5PrivKeyMsg)
	// Unarmor
	block, err := armor.Decode(msg)
	if err != nil {
		return
	}
	md, err := ReadMessage(block.Body, kring, nil, nil)
	if md.SignedBy == nil {
		t.Fatal("incorrect signer")
	}
	if err != nil {
		t.Fatal(err)
	}
	// Consume UnverifiedBody
	body, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, []byte("test")) {
		t.Fatal("bad body")
	}
	if md.SignatureError != nil {
		t.Fatal(md.SignatureError)
	}
	if err != nil {
		t.Fatal(err)
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
		if key.Version != 5 {
			t.Errorf("wrong key version %d", key.Version)
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
		if sig.Version != 5 {
			t.Errorf("wrong signature version %d", sig.Version)
		}
		fgptLen := len(sig.IssuerFingerprint)
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

func TestGeneratePqKey(t *testing.T) {
	randomPassword := make([]byte, 128)
	_, err := rand.Read(randomPassword)
	if err != nil {
		t.Fatal(err)
	}

	asymmAlgos := map[string] packet.PublicKeyAlgorithm{
		"Dilithium3_Ed25519": packet.PubKeyAlgoDilithium3Ed25519,
		"Dilithium5_Ed448": packet.PubKeyAlgoDilithium5Ed448,
		"Dilithium3_P256": packet.PubKeyAlgoDilithium3p256,
		"Dilithium5_P384":packet.PubKeyAlgoDilithium5p384,
		"Dilithium3_Brainpool256": packet.PubKeyAlgoDilithium3Brainpool256,
		"Dilithium5_Brainpool384":packet.PubKeyAlgoDilithium5Brainpool384,
		"SphincsPlus_simple_SHA2":packet.PubKeyAlgoSphincsPlusSha2,
		"SphincsPlus_simple_SHAKE":packet.PubKeyAlgoSphincsPlusShake,
	}

	for name, algo := range asymmAlgos {
		t.Run(name, func(t *testing.T) {
			config := &packet.Config{
				DefaultHash: crypto.SHA512,
				Algorithm:   algo,
				V5Keys:      true,
				Time: func() time.Time {
					parsed, _ := time.Parse("2006-01-02", "2013-07-01")
					return parsed
				},
			}

			entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", config)
			if err != nil {
				t.Fatal(err)
			}

			serializedEntity := bytes.NewBuffer(nil)
			err = entity.SerializePrivate(serializedEntity, nil)
			if err != nil {
				t.Fatalf("Failed to serialize entity: %s", err)
			}

			read, err := ReadEntity(packet.NewReader(bytes.NewBuffer(serializedEntity.Bytes())))
			if err != nil {
				t.Fatalf("Failed to parse entity: %s", err)
			}

			if read.PrimaryKey.PubKeyAlgo != algo {
				t.Fatalf("Expected subkey algorithm: %v, got: %v", algo, read.PrimaryKey.PubKeyAlgo)
			}

			if err = read.PrivateKey.Encrypt(randomPassword); err != nil {
				t.Fatal(err)
			}

			if err := read.PrivateKey.Decrypt(randomPassword); err != nil {
				t.Fatal("Valid Dilithium key was marked as invalid: ", err)
			}

			if err = read.PrivateKey.Encrypt(randomPassword); err != nil {
				t.Fatal(err)
			}

			// Corrupt public Dilithium in primary key
			if pk, ok := read.PrivateKey.PublicKey.PublicKey.(*dilithium_ecdsa.PublicKey); ok {
				bin := pk.PublicDilithium.Bytes()
				bin[5] ^= 1
				pk.PublicDilithium = pk.Dilithium.PublicKeyFromBytes(bin)
			}

			if pk, ok := read.PrivateKey.PublicKey.PublicKey.(*dilithium_eddsa.PublicKey); ok {
				bin := pk.PublicDilithium.Bytes()
				bin[5] ^= 1
				pk.PublicDilithium = pk.Dilithium.PublicKeyFromBytes(bin)
			}

			if pk, ok := read.PrivateKey.PublicKey.PublicKey.(*sphincs_plus.PublicKey); ok {
				pk.PublicData.PKseed[5] ^= 1
			}

			err = read.PrivateKey.Decrypt(randomPassword)
			if _, ok := err.(errors.KeyInvalidError); !ok {
				t.Fatal("Failed to detect invalid Dilithium key")
			}

			testKyberSubkey(t, read.Subkeys[0], randomPassword)
		})
	}
}

func testKyberSubkey(t *testing.T, subkey Subkey, randomPassword []byte) {
	var err error
	if err = subkey.PrivateKey.Encrypt(randomPassword); err != nil {
		t.Fatal(err)
	}

	if err = subkey.PrivateKey.Decrypt(randomPassword); err != nil {
		t.Fatal("Valid Kyber key was marked as invalid: ", err)
	}

	if err = subkey.PrivateKey.Encrypt(randomPassword); err != nil {
		t.Fatal(err)
	}

	// Corrupt public Kyber in primary key
	if pk, ok := subkey.PublicKey.PublicKey.(*kyber_ecdh.PublicKey); ok {
		bin, _ := pk.PublicKyber.MarshalBinary()
		bin[5] ^= 1
		if pk.PublicKyber, err = pk.Kyber.UnmarshalBinaryPublicKey(bin); err != nil {
			t.Fatal("unable to corrupt key")
		}
	} else {
		t.Fatal("Invalid subkey")
	}

	err = subkey.PrivateKey.Decrypt(randomPassword)
	if _, ok := err.(errors.KeyInvalidError); !ok {
		t.Fatal("Failed to detect invalid kyber key")
	}
}


func TestAddKyberSubkey(t *testing.T) {
	eddsaConfig := &packet.Config{
		DefaultHash: crypto.SHA512,
		Algorithm: packet.PubKeyAlgoEdDSA,
		V5Keys: true,
		Time: func() time.Time {
			parsed, _ := time.Parse("2006-01-02", "2013-07-01")
			return parsed
		},
	}

	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", eddsaConfig)
	if err != nil {
		t.Fatal(err)
	}

	asymmAlgos := map[string] packet.PublicKeyAlgorithm{
		"Kyber768_X25519": packet.PubKeyAlgoKyber768X25519,
		"Kyber1024_X448": packet.PubKeyAlgoKyber1024X448,
		"Kyber768_P256": packet.PubKeyAlgoKyber768P256,
		"Kyber1024_P384":packet.PubKeyAlgoKyber1024P384,
		"Kyber768_Brainpool256": packet.PubKeyAlgoKyber768Brainpool256,
		"Kyber1024_Brainpool384":packet.PubKeyAlgoKyber1024Brainpool384,
	}

	for name, algo := range asymmAlgos {
		// Remove existing subkeys
		entity.Subkeys = []Subkey{}

		t.Run(name, func(t *testing.T) {
			kyberConfig := &packet.Config{
				DefaultHash: crypto.SHA512,
				Algorithm:   algo,
				V5Keys:      true,
				Time: func() time.Time {
					parsed, _ := time.Parse("2006-01-02", "2013-07-01")
					return parsed
				},
			}

			err = entity.AddEncryptionSubkey(kyberConfig)
			if err != nil {
				t.Fatal(err)
			}

			if len(entity.Subkeys) != 1 {
				t.Fatalf("Expected 1 subkey, got %d", len(entity.Subkeys))
			}

			if entity.Subkeys[0].PublicKey.PubKeyAlgo != algo {
				t.Fatalf("Expected subkey algorithm: %v, got: %v", packet.PubKeyAlgoEdDSA,
					entity.Subkeys[0].PublicKey.PubKeyAlgo)
			}

			serializedEntity := bytes.NewBuffer(nil)
			err = entity.SerializePrivate(serializedEntity, nil)
			if err != nil {
				t.Fatalf("Failed to serialize entity: %s", err)
			}

			read, err := ReadEntity(packet.NewReader(bytes.NewBuffer(serializedEntity.Bytes())))
			if err != nil {
				t.Fatal(err)
			}

			if len(read.Subkeys) != 1 {
				t.Fatalf("Expected 1 subkey, got %d", len(entity.Subkeys))
			}

			if read.Subkeys[0].PublicKey.PubKeyAlgo != algo {
				t.Fatalf("Expected subkey algorithm: %v, got: %v", packet.PubKeyAlgoEdDSA,
					entity.Subkeys[0].PublicKey.PubKeyAlgo)
			}
		})
	}
}