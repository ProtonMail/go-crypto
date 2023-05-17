package openpgp

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

const benchmarkMessageSize = 1024 // Signed / encrypted message size in bytes

var benchmarkTestSet = map[string] *packet.Config {
	"RSA_1024": {
		Algorithm: packet.PubKeyAlgoRSA,
		RSABits: 1024,
	},
	"RSA_2048": {
		Algorithm: packet.PubKeyAlgoRSA,
		RSABits: 2048,
	},
	"RSA_3072": {
		Algorithm: packet.PubKeyAlgoRSA,
		RSABits: 3072,
	},
	"RSA_4096": {
		Algorithm: packet.PubKeyAlgoRSA,
		RSABits: 4096,
	},
	"Ed25519_X25519": {
		Algorithm: packet.PubKeyAlgoEd25519,
	},
	"Ed448_X448": {
		Algorithm: packet.PubKeyAlgoEd448,
	},
	"P256": {
		Algorithm: packet.PubKeyAlgoECDSA,
		Curve: packet.CurveNistP256,
	},
	"P384": {
		Algorithm: packet.PubKeyAlgoECDSA,
		Curve: packet.CurveNistP384,
	},
	"P521": {
		Algorithm: packet.PubKeyAlgoECDSA,
		Curve: packet.CurveNistP521,
	},
	"Brainpool256": {
		Algorithm: packet.PubKeyAlgoECDSA,
		Curve: packet.CurveBrainpoolP256,
	},
	"Brainpool384": {
		Algorithm: packet.PubKeyAlgoECDSA,
		Curve: packet.CurveBrainpoolP384,
	},
	"Brainpool512": {
		Algorithm: packet.PubKeyAlgoECDSA,
		Curve: packet.CurveBrainpoolP512,
	},
	"Dilithium3Ed25519_Kyber768X25519": {
		Algorithm: packet.PubKeyAlgoDilithium3Ed25519,
	},
	"Dilithium5Ed448_Kyber1024X448": {
		Algorithm: packet.PubKeyAlgoDilithium5Ed448,
	},
	"Dilithium3P256_Kyber768P256": {
		Algorithm: packet.PubKeyAlgoDilithium3p256,
	},
	"Dilithium5P384_Kyber1024P384": {
		Algorithm: packet.PubKeyAlgoDilithium5p384,
	},
	"Dilithium3Brainpool256_Kyber768Brainpool256": {
		Algorithm: packet.PubKeyAlgoDilithium3Brainpool256,
	},
	"Dilithium5Brainpool384_Kyber1024Brainpool384": {
		Algorithm: packet.PubKeyAlgoDilithium5Brainpool384,
	},
	"SphincsPlusSHA2_128s_Kyber1024X448": {
		Algorithm: packet.PubKeyAlgoSphincsPlusSha2,
		SphincsPlusParameterId: 1,
	},
	"SphincsPlusSHA2_128f_Kyber1024X448": {
		Algorithm: packet.PubKeyAlgoSphincsPlusSha2,
		SphincsPlusParameterId: 2,
	},
	"SphincsPlusSHA2_192s_Kyber1024X448": {
		Algorithm: packet.PubKeyAlgoSphincsPlusSha2,
		SphincsPlusParameterId: 3,
	},
	"SphincsPlusSHA2_192f_Kyber1024X448": {
		Algorithm: packet.PubKeyAlgoSphincsPlusSha2,
		SphincsPlusParameterId: 4,
	},
	"SphincsPlusSHA2_256s_Kyber1024X448": {
		Algorithm: packet.PubKeyAlgoSphincsPlusSha2,
		SphincsPlusParameterId: 5,
	},
	"SphincsPlusSHA2_256f_Kyber1024X448": {
		Algorithm: packet.PubKeyAlgoSphincsPlusSha2,
		SphincsPlusParameterId: 6,
	},
	"SphincsPlusSHAKE_128s_Kyber1024X448":{
		Algorithm: packet.PubKeyAlgoSphincsPlusShake,
		SphincsPlusParameterId: 1,
	},
	"SphincsPlusSHAKE_128f_Kyber1024X448":{
		Algorithm: packet.PubKeyAlgoSphincsPlusShake,
		SphincsPlusParameterId: 2,
	},
	"SphincsPlusSHAKE_192s_Kyber1024X448":{
		Algorithm: packet.PubKeyAlgoSphincsPlusShake,
		SphincsPlusParameterId: 3,
	},
	"SphincsPlusSHAKE_192f_Kyber1024X448":{
		Algorithm: packet.PubKeyAlgoSphincsPlusShake,
		SphincsPlusParameterId: 4,
	},
	"SphincsPlusSHAKE_256s_Kyber1024X448":{
		Algorithm: packet.PubKeyAlgoSphincsPlusShake,
		SphincsPlusParameterId: 5,
	},
	"SphincsPlusSHAKE_256f_Kyber1024X448":{
		Algorithm: packet.PubKeyAlgoSphincsPlusShake,
		SphincsPlusParameterId: 6,
	},
}

func benchmarkGenerateKey(b *testing.B, config *packet.Config) [][]byte {
	var serializedEntities [][]byte
	config.V6Keys = true

	config.AEADConfig = &packet.AEADConfig{
		DefaultMode: packet.AEADModeOCB,
	}

	config.Time = func() time.Time {
		parsed, _ := time.Parse("2006-01-02", "2013-07-01")
		return parsed
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", config)
		if err != nil {
			b.Fatal(err)
		}

		serializedEntity := bytes.NewBuffer(nil)
		err = entity.SerializePrivate(serializedEntity, nil)
		if err != nil {
			b.Fatalf("Failed to serialize entity: %s", err)
		}

		serializedEntities = append(serializedEntities, serializedEntity.Bytes())
	}

	return serializedEntities
}

func benchmarkParse(b *testing.B, keys [][]byte) []*Entity {
	var parsedKeys []*Entity

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		keyring, err := ReadKeyRing(bytes.NewReader(keys[n]))
		if err != nil {
			b.Errorf("Failed to initalize encryption: %s", err)
			continue
		}

		parsedKeys = append(parsedKeys, keyring[0])
	}

	return parsedKeys
}

func benchmarkEncrypt(b *testing.B, keys []*Entity, plaintext []byte, sign bool) [][]byte {
	var encryptedMessages [][]byte

	var config = &packet.Config{
		AEADConfig: &packet.AEADConfig{
			DefaultMode: packet.AEADModeOCB,
		},
		V6Keys: true,
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		buf := new(bytes.Buffer)

		var signed *Entity
		if sign {
			signed = keys[n % len(keys)]
		}

		w, err := Encrypt(buf, EntityList{keys[n % len(keys)]}, signed, nil, config)
		if err != nil {
			b.Errorf("Failed to initalize encryption: %s", err)
			continue
		}

		_, err = w.Write(plaintext)
		if err != nil {
			b.Errorf("Error writing plaintext: %s", err)
			continue
		}

		err = w.Close()
		if err != nil {
			b.Errorf("Error closing WriteCloser: %s", err)
			continue
		}

		encryptedMessages = append(encryptedMessages, buf.Bytes())
	}

	return encryptedMessages
}

func benchmarkDecrypt(b *testing.B, keys []*Entity, plaintext []byte, encryptedMessages [][]byte, verify bool) {
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		reader := bytes.NewReader(encryptedMessages[n % len(encryptedMessages)])
		md, err := ReadMessage(reader, EntityList{keys[n % len(keys)]}, nil, nil)
		if err != nil {
			b.Errorf("Error reading message: %s", err)
			continue
		}

		decrypted, err := io.ReadAll(md.UnverifiedBody)
		if err != nil {
			b.Errorf("Error reading encrypted content: %s", err)
			continue
		}

		if !bytes.Equal(decrypted, plaintext) {
			b.Error("Decrypted wrong plaintext")
		}

		if verify {
			if md.SignatureError != nil {
				b.Errorf("Signature error: %s", md.SignatureError)
			}
			if md.Signature == nil {
				b.Error("Signature missing")
			}
		}
	}
}

func benchmarkSign(b *testing.B, keys []*Entity, plaintext []byte) [][]byte {
	var signatures [][]byte

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		buf := new(bytes.Buffer)

		err := DetachSign(buf, keys[n % len(keys)], bytes.NewReader(plaintext), nil)
		if err != nil {
			b.Errorf("Failed to sign: %s", err)
			continue
		}

		signatures = append(signatures, buf.Bytes())
	}

	return signatures
}

func benchmarkVerify(b *testing.B, keys []*Entity, plaintext []byte, signatures [][]byte) {
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		signed := bytes.NewReader(plaintext)
		signature := bytes.NewReader(signatures[n % len(signatures)])

		parsedSignature, signer, signatureError := VerifyDetachedSignature(EntityList{keys[n % len(keys)]}, signed, signature,nil)

		if signatureError != nil {
			b.Errorf("Signature error: %s", signatureError)
		}

		if parsedSignature == nil {
			b.Error("Signature missing")
		}

		if signer == nil {
			b.Error("Signer missing")
		}
	}
}

func BenchmarkV6Keys(b *testing.B) {
	serializedKeys := make(map[string] [][]byte)
	parsedKeys := make(map[string] []*Entity)
	encryptedMessages := make(map[string] [][]byte)
	encryptedSignedMessages := make(map[string] [][]byte)
	signatures := make(map[string] [][]byte)

	var plaintext [benchmarkMessageSize]byte
	_, _ = rand.Read(plaintext[:])

	for name, config := range benchmarkTestSet {
		b.Run("Generate " + name, func(b *testing.B) {
			serializedKeys[name] = benchmarkGenerateKey(b, config)
			b.Logf("Generate %s: %d bytes", name, len(serializedKeys[name][0]))
		})
	}

	for name, keys := range serializedKeys {
		b.Run("Parse_" + name, func(b *testing.B) {
			parsedKeys[name] = benchmarkParse(b, keys)
		})
	}

	for name, keys := range parsedKeys {
		b.Run("Encrypt_" + name, func(b *testing.B) {
			encryptedMessages[name] = benchmarkEncrypt(b, keys, plaintext[:], false)
			b.Logf("Encrypt %s: %d bytes", name, len(encryptedMessages[name][0]))
		})
	}

	for name, keys := range parsedKeys {
		b.Run("Decrypt_" + name, func(b *testing.B) {
			benchmarkDecrypt(b, keys, plaintext[:], encryptedMessages[name], false)
		})
	}

	for name, keys := range parsedKeys {
		b.Run("Encrypt_Sign_" + name, func(b *testing.B) {
			encryptedSignedMessages[name] = benchmarkEncrypt(b, keys, plaintext[:], true)
			b.Logf("Encrypt_Sign %s: %d bytes", name, len(encryptedSignedMessages[name][0]))
		})
	}

	for name, keys := range parsedKeys {
		b.Run("Decrypt_Verify_" + name, func(b *testing.B) {
			benchmarkDecrypt(b, keys, plaintext[:], encryptedSignedMessages[name], true)
		})
	}

	for name, keys := range parsedKeys {
		b.Run("Sign_" + name, func(b *testing.B) {
			signatures[name] = benchmarkSign(b, keys, plaintext[:])
			b.Logf("Sign %s: %d bytes", name, len(signatures[name][0]))
		})
	}

	for name, keys := range parsedKeys {
		b.Run("Verify_" + name, func(b *testing.B) {
			benchmarkVerify(b, keys, plaintext[:], signatures[name])
		})
	}
}
