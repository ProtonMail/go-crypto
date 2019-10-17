// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"encoding/hex"
	"io"
	"io/ioutil"
	"testing"
)

func TestDecryptKeyAndIntegrityProtectedEncryptedPacket(t *testing.T) {
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

func TestSerializeSymmetricKeyEncryptedCiphers(t *testing.T) {
	tests := [...]struct {
		cipherFunc CipherFunction
		name       string
	}{
		{Cipher3DES, "Cipher3DES"},
		{CipherCAST5, "CipherCAST5"},
		{CipherAES128, "CipherAES128"},
		{CipherAES192, "CipherAES192"},
		{CipherAES256, "CipherAES256"},
	}

	for _, test := range tests {
		var buf bytes.Buffer
		passphrase := []byte("testing")
		config := &Config{
			DefaultCipher: test.cipherFunc,
		}

		key, err := SerializeSymmetricKeyEncrypted(&buf, passphrase, config)
		if err != nil {
			t.Errorf("cipher(%s) failed to serialize: %s", test.name, err)
			continue
		}

		p, err := Read(&buf)
		if err != nil {
			t.Errorf("cipher(%s) failed to reparse: %s", test.name, err)
			continue
		}

		ske, ok := p.(*SymmetricKeyEncrypted)
		if !ok {
			t.Errorf("cipher(%s) parsed a different packet type: %#v", test.name, p)
			continue
		}

		if ske.CipherFunc != config.DefaultCipher {
			t.Errorf("cipher(%s) SKE cipher function is %d (expected %d)", test.name, ske.CipherFunc, config.DefaultCipher)
		}
		parsedKey, parsedCipherFunc, err := ske.Decrypt(passphrase)
		if err != nil {
			t.Errorf("cipher(%s) failed to decrypt reparsed SKE: %s", test.name, err)
			continue
		}
		if !bytes.Equal(key, parsedKey) {
			t.Errorf("cipher(%s) keys don't match after Decrypt: %x (original) vs %x (parsed)", test.name, key, parsedKey)
		}
		if parsedCipherFunc != test.cipherFunc {
			t.Errorf("cipher(%s) cipher function doesn't match after Decrypt: %d (original) vs %d (parsed)",
				test.name, test.cipherFunc, parsedCipherFunc)
		}
	}
}
