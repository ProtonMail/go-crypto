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
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

var foreignKeysV6 = []string{
	v6PrivKey,
	v6ArgonSealedPrivKey,
}

func TestReadPrivateForeignV6Key(t *testing.T) {
	for _, str := range foreignKeysV6 {
		kring, err := ReadArmoredKeyRing(strings.NewReader(str))
		if err != nil {
			t.Fatal(err)
		}
		checkV6Key(t, kring[0])
	}
}

func TestReadPrivateForeignV6KeyAndDecrypt(t *testing.T) {
	password := []byte("correct horse battery staple")
	kring, err := ReadArmoredKeyRing(strings.NewReader(v6ArgonSealedPrivKey))
	if err != nil {
		t.Fatal(err)
	}
	key := kring[0]
	if key.PrivateKey != nil && key.PrivateKey.Encrypted {
		if err := key.PrivateKey.Decrypt(password); err != nil {
			t.Fatal(err)
		}
	}
	for _, sub := range key.Subkeys {
		if sub.PrivateKey != nil && sub.PrivateKey.Encrypted {
			if err := key.PrivateKey.Decrypt(password); err != nil {
				t.Fatal(err)
			}
		}
	}
	checkV6Key(t, kring[0])
}

func TestReadPrivateEncryptedV6Key(t *testing.T) {
	c := &packet.Config{V6Keys: true}
	e, err := NewEntity("V6 Key Owner", "V6 Key", "v6@pm.me", c)
	if err != nil {
		t.Fatal(err)
	}
	password := []byte("test v6 key # password")
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

	checkV6Key(t, el[0])
}

func TestNewEntitySerializeV6Key(t *testing.T) {
	c := &packet.Config{V6Keys: true}
	e, err := NewEntity("V6 Key Owner", "V6 Key", "v6@pm.me", c)
	if err != nil {
		t.Fatal(err)
	}
	checkSerializeReadv6(t, e)
}

func TestNewEntityV6Key(t *testing.T) {
	c := &packet.Config{
		V6Keys: true,
	}
	e, err := NewEntity("V6 Key Owner", "V6 Key", "v6@pm.me", c)
	if err != nil {
		t.Fatal(err)
	}
	checkV6Key(t, e)
}

func checkV6Key(t *testing.T, ent *Entity) {
	key := ent.PrimaryKey
	if key.Version != 6 {
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
		if sig.Version != 6 {
			t.Errorf("wrong signature version %d", sig.Version)
		}
		fgptLen := len(sig.IssuerFingerprint)
		if fgptLen != 32 {
			t.Errorf("Wrong fingerprint length in signature: %d", fgptLen)
		}
	}
}

func checkSerializeReadv6(t *testing.T, e *Entity) {
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
	checkV6Key(t, el[0])

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
	checkV6Key(t, el[0])

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
	checkV6Key(t, el[0])
}

func TestNewEntityWithDefaultHashv6(t *testing.T) {
	for _, hash := range hashes[:5] {
		c := &packet.Config{
			V6Keys:      true,
			DefaultHash: hash,
		}
		entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", c)
		if hash == crypto.SHA1 {
			if err == nil {
				t.Fatal("should fail on SHA1 key creation")
			}
			continue
		}
		prefs := entity.SelfSignature.PreferredHash
		if prefs == nil {
			t.Fatal(err)
		}
	}
}

func TestGenerateDilithiumKey(t *testing.T) {
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
	}

	for name, algo := range asymmAlgos {
		t.Run(name, func(t *testing.T) {
			dilithiumConfig := &packet.Config{
				DefaultHash: crypto.SHA512,
				Algorithm:   algo,
				V6Keys:      true,
				Time: func() time.Time {
					parsed, _ := time.Parse("2006-01-02", "2013-07-01")
					return parsed
				},
			}

			entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", dilithiumConfig)
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
				t.Fatalf("Expected subkey algorithm: %v, got: %v", packet.PubKeyAlgoEdDSA, read.PrimaryKey.PubKeyAlgo)
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

			err = read.PrivateKey.Decrypt(randomPassword)
			if _, ok := err.(errors.KeyInvalidError); !ok {
				t.Fatal("Failed to detect invalid Dilithium key")
			}

			// Kyber subkey
			subkey := read.Subkeys[0]
			if err = subkey.PrivateKey.Encrypt(randomPassword); err != nil {
				t.Fatal(err)
			}

			if err := subkey.PrivateKey.Decrypt(randomPassword); err != nil {
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
				t.Fatal("Failed to detect invalid Dilithium key")
			}
		})
	}
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
				V6Keys:      true,
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
		V6Keys: true,
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
