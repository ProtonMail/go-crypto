// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"io/ioutil"
	mathrand "math/rand"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/s2k"
)

const maxPassLen = 64

// Tests against RFC vectors
func TestDecryptSymmetricKeyAndEncryptedDataPacket(t *testing.T) {
	for _, testCase := range keyAndIpePackets {
		// Key
		buf := readerFromHex(testCase.packets)
		packet, err := Read(buf)
		if err != nil {
			t.Fatalf("failed to read SymmetricKeyEncrypted: %s", err)
		}
		ske, ok := packet.(*SymmetricKeyEncrypted)
		if !ok {
			t.Fatal("didn't find SymmetricKeyEncrypted packet")
		}
		// Decrypt key
		key, cipherFunc, err := ske.Decrypt([]byte(testCase.password))
		if err != nil {
			t.Fatal(err)
		}
		packet, err = Read(buf)
		if err != nil {
			t.Fatalf("failed to read SymmetricallyEncrypted: %s", err)
		}
		// Decrypt contents
		var edp EncryptedDataPacket
		switch packet.(type) {
		case *SymmetricallyEncrypted:
			edp, _ = packet.(*SymmetricallyEncrypted)
		case *AEADEncrypted:
			edp, _ = packet.(*AEADEncrypted)
		default:
			t.Fatal("no integrity protected packet")
		}
		r, err := edp.Decrypt(cipherFunc, key)
		if err != nil {
			t.Fatal(err)
		}

		contents, err := ioutil.ReadAll(r)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			t.Fatal(err)
		}

		expectedContents, _ := hex.DecodeString(testCase.contents)
		if !bytes.Equal(expectedContents, contents) {
			t.Errorf("bad contents got:%x want:%x", contents, expectedContents)
		}
	}
}

func TestSerializeSymmetricKeyEncryptedV5RandomizeSlow(t *testing.T) {
	ciphers := map[string]CipherFunction{
		"AES128": CipherAES128,
		"AES192": CipherAES192,
		"AES256": CipherAES256,
	}

	modes := map[string]AEADMode{
		"EAX": AEADModeEAX,
		"OCB": AEADModeOCB,
		"GCM": AEADModeGCM,
	}

	modesS2K := map[string]s2k.Mode{
		"Salted":   s2k.SaltedS2K,
		"Iterated": s2k.IteratedSaltedS2K,
		"Argon2":   s2k.Argon2S2K,
	}

	for cipherName, cipher := range ciphers {
		t.Run(cipherName, func(t *testing.T) {
			for modeName, mode := range modes {
				t.Run(modeName, func(t *testing.T) {
					for s2kName, s2ktype := range modesS2K {
						t.Run(s2kName, func(t *testing.T) {
							var buf bytes.Buffer
							passphrase := randomKey(mathrand.Intn(maxPassLen))

							config := &Config{
								DefaultCipher: cipher,
								AEADConfig:    &AEADConfig{DefaultMode: mode},
								S2KConfig:     &s2k.Config{S2KMode: s2ktype, PassphraseIsHighEntropy: true},
							}

							key, err := SerializeSymmetricKeyEncrypted(&buf, passphrase, config)
							p, err := Read(&buf)
							if err != nil {
								t.Errorf("failed to reparse %s", err)
							}
							ske, ok := p.(*SymmetricKeyEncrypted)
							if !ok {
								t.Errorf("parsed a different packet type: %#v", p)
							}

							parsedKey, _, err := ske.Decrypt(passphrase)
							if err != nil {
								t.Errorf("failed to decrypt reparsed SKE: %s", err)
							}
							if !bytes.Equal(key, parsedKey) {
								t.Errorf("keys don't match after Decrypt: %x (original) vs %x (parsed)", key, parsedKey)
							}
						})
					}
				})
			}
		})
	}
}

func TestSerializeSymmetricKeyEncryptedCiphersV4(t *testing.T) {
	tests := map[string]CipherFunction{
		"AES128": CipherAES128,
		"AES192": CipherAES192,
		"AES256": CipherAES256,
	}

	testS2K := map[string]s2k.Mode{
		"Salted":   s2k.SaltedS2K,
		"Iterated": s2k.IteratedSaltedS2K,
		"Argon2":   s2k.Argon2S2K,
	}

	for cipherName, cipher := range tests {
		t.Run(cipherName, func(t *testing.T) {
			for s2kName, s2ktype := range testS2K {
				t.Run(s2kName, func(t *testing.T) {
					var buf bytes.Buffer
					passphrase := make([]byte, mathrand.Intn(maxPassLen))
					if _, err := rand.Read(passphrase); err != nil {
						panic(err)
					}
					config := &Config{
						DefaultCipher: cipher,
						S2KConfig: &s2k.Config{
							S2KMode: s2ktype,
							PassphraseIsHighEntropy: true,
						},
					}

					key, err := SerializeSymmetricKeyEncrypted(&buf, passphrase, config)
					if err != nil {
						t.Fatalf("failed to serialize: %s", err)
					}

					p, err := Read(&buf)
					if err != nil {
						t.Fatalf("failed to reparse: %s", err)
					}

					ske, ok := p.(*SymmetricKeyEncrypted)
					if !ok {
						t.Fatalf("parsed a different packet type: %#v", p)
					}

					if ske.CipherFunc != config.DefaultCipher {
						t.Fatalf("SKE cipher function is %d (expected %d)", ske.CipherFunc, config.DefaultCipher)
					}
					parsedKey, parsedCipherFunc, err := ske.Decrypt(passphrase)
					if err != nil {
						t.Fatalf("failed to decrypt reparsed SKE: %s", err)
					}
					if !bytes.Equal(key, parsedKey) {
						t.Fatalf("keys don't match after Decrypt: %x (original) vs %x (parsed)", key, parsedKey)
					}
					if parsedCipherFunc != cipher {
						t.Fatalf("cipher function doesn't match after Decrypt: %d (original) vs %d (parsed)",
							cipher, parsedCipherFunc)
					}
				})
			}
		})
	}
}
