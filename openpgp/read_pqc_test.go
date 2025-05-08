package openpgp

import (
	"bytes"
	"encoding/hex"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

var pqcDraftVectors = map[string]struct {
	armoredPrivateKeyPath string
	armoredPublicKeyPath  string
	fingerprints          []string
	armoredMessagePaths   []string
}{
	"v6_MlDsa65_MlKem768": {
		"test_data/pqc/v6-mldsa-65-sample-sk.asc",
		"test_data/pqc/v6-mldsa-65-sample-pk.asc",
		[]string{"a3e2e14b6a493ff930fb27321f125e9a6880338be9fb7da3ae065ea65793242f", "7dae8fbce23022607167af72a002e774e0ca379a2d7ae072384e1e8fde3265e4"},
		[]string{"test_data/pqc/v6-mldsa-65-sample-message.asc"},
	},
	"v4_eddsa_MlKem768": {
		"test_data/pqc/v4-eddsa-sample-sk.asc",
		"test_data/pqc/v4-eddsa-sample-pk.asc",
		[]string{"342e5db2de345215cb2c944f7102ffed3b9cf12d", "e51dbfea51936988b5428fffa4f95f985ed61a51"},
		[]string{"test_data/pqc/v4-eddsa-sample-message-v1.asc", "test_data/pqc/v4-eddsa-sample-message-v1.asc"},
	},
	"v6_SlhDsa128s_MlKem768": {
		"test_data/pqc/v6-slhdsa-128s-sample-sk.asc",
		"test_data/pqc/v6-slhdsa-128s-sample-pk.asc",
		[]string{},
		[]string{"test_data/pqc/v6-slhdsa-128s-sample-message.asc"},
	},
}

func TestPqcDraftVectors(t *testing.T) {
	for name, test := range pqcDraftVectors {
		t.Run(name, func(t *testing.T) {
			// Read private key
			privateKeyBytes, err := os.ReadFile(test.armoredPrivateKeyPath)
			if err != nil {
				t.Fatalf("Failed to read private key file: %v", err)
			}

			// Read public key
			publicKeyBytes, err := os.ReadFile(test.armoredPublicKeyPath)
			if err != nil {
				t.Fatalf("Failed to read public key file: %v", err)
			}

			secretKey, err := ReadArmoredKeyRing(bytes.NewReader(privateKeyBytes))
			if err != nil {
				t.Error(err)
				return
			}

			if len(secretKey) != 1 {
				t.Errorf("Expected 1 entity, found %d", len(secretKey))
			}

			if len(test.fingerprints) > 0 && len(secretKey[0].Subkeys) != len(test.fingerprints)-1 {
				t.Errorf("Expected %d subkey, found %d", len(test.fingerprints)-1, len(secretKey[0].Subkeys))
			}

			if len(test.fingerprints) > 0 && hex.EncodeToString(secretKey[0].PrimaryKey.Fingerprint) != test.fingerprints[0] {
				t.Errorf("Expected primary fingerprint %s, got %x", test.fingerprints[0], secretKey[0].PrimaryKey.Fingerprint)
			}

			for i, subkey := range secretKey[0].Subkeys {
				if len(test.fingerprints) > 0 && hex.EncodeToString(subkey.PublicKey.Fingerprint) != test.fingerprints[i+1] {
					t.Errorf("Expected subkey %d fingerprint %s, got %x", i, test.fingerprints[i+1], subkey.PublicKey.Fingerprint)
				}
			}

			var serializedArmoredPublic bytes.Buffer
			serializedPublic, err := armor.EncodeWithChecksumOption(&serializedArmoredPublic, PublicKeyType, nil, false)
			if err != nil {
				t.Fatalf("Failed to init armoring: %s", err)
			}

			if err = secretKey[0].Serialize(serializedPublic); err != nil {
				t.Fatalf("Failed to serialize entity: %s", err)
			}

			if err := serializedPublic.Close(); err != nil {
				t.Fatalf("Failed to close armoring: %s", err)
			}

			if serializedArmoredPublic.String() != strings.Trim(string(publicKeyBytes), "\r\n") {
				t.Error("Wrong serialized public key")
			}

			for i, armoredMessage := range test.armoredMessagePaths {
				t.Run("Decrypt_message_"+strconv.Itoa(i), func(t *testing.T) {
					msgData, err := os.ReadFile(armoredMessage)
					if err != nil {
						t.Fatalf("Failed to read message file: %v", err)
					}
					msgReader, err := armor.Decode(bytes.NewReader(msgData))
					if err != nil {
						t.Error(err)
						return
					}

					md, err := ReadMessage(msgReader.Body, secretKey, nil, nil)
					if err != nil {
						t.Fatalf("Error in reading message: %s", err)
						return
					}
					contents, err := io.ReadAll(md.UnverifiedBody)
					if err != nil {
						t.Fatalf("Error in decrypting message: %s", err)
						return
					}

					if string(contents) != "Testing\n" {
						t.Fatalf("Decrypted message is wrong: %s", contents)
					}
				})
			}
		})
	}
}
