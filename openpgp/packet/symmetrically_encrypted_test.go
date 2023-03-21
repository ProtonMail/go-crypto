// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	goerrors "errors"
	"io"
	"io/ioutil"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
)

// TestReader wraps a []byte and returns reads of a specific length.
type testReader struct {
	data   []byte
	stride int
}

func (t *testReader) Read(buf []byte) (n int, err error) {
	n = t.stride
	if n > len(t.data) {
		n = len(t.data)
	}
	if n > len(buf) {
		n = len(buf)
	}

	copy(buf[:n], t.data)
	t.data = t.data[n:]

	if len(t.data) == 0 {
		err = io.EOF
	}

	return
}

const mdcPlaintextHex = "cb1362000000000048656c6c6f2c20776f726c6421d314c23d643f478a9a2098811fcb191e7b24b80966a1"

func TestMDCReader(t *testing.T) {
	mdcPlaintext, _ := hex.DecodeString(mdcPlaintextHex)
	for stride := 1; stride < len(mdcPlaintext)/2; stride++ {
		r := &testReader{data: mdcPlaintext, stride: stride}
		mdcReader := &seMDCReader{in: r, h: sha1.New()}
		body, err := ioutil.ReadAll(mdcReader)
		if err != nil {
			t.Errorf("stride: %d, error: %s", stride, err)
			continue
		}
		if !bytes.Equal(body, mdcPlaintext[:len(mdcPlaintext)-22]) {
			t.Errorf("stride: %d: bad contents %x", stride, body)
			continue
		}

		err = mdcReader.Close()
		if err != nil {
			t.Errorf("stride: %d, error on Close: %s", stride, err)
		}
	}

	mdcPlaintext[15] ^= 80

	r := &testReader{data: mdcPlaintext, stride: 2}
	mdcReader := &seMDCReader{in: r, h: sha1.New()}
	_, err := ioutil.ReadAll(mdcReader)
	if err != nil {
		t.Errorf("corruption test, error: %s", err)
		return
	}
	err = mdcReader.Close()
	if err == nil {
		t.Error("corruption: no error")
	} else if !goerrors.Is(err, errors.ErrMDCHashMismatch) {
		t.Errorf("corruption: expected SignatureError, got: %s", err)
	}
}

func TestSerializeMdc(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	c := CipherAES128
	key := make([]byte, c.KeySize())

	cipherSuite := CipherSuite{
		Cipher: c,
		Mode:   AEADModeOCB,
	}

	w, err := SerializeSymmetricallyEncrypted(buf, c, false, cipherSuite, key, nil)
	if err != nil {
		t.Errorf("error from SerializeSymmetricallyEncrypted: %s", err)
		return
	}

	contents := []byte("hello world\n")

	w.Write(contents)
	w.Close()

	p, err := Read(buf)
	if err != nil {
		t.Errorf("error from Read: %s", err)
		return
	}

	se, ok := p.(*SymmetricallyEncrypted)
	if !ok {
		t.Errorf("didn't read a *SymmetricallyEncrypted")
		return
	}

	r, err := se.Decrypt(c, key)
	if err != nil {
		t.Errorf("error from Decrypt: %s", err)
		return
	}

	contentsCopy := bytes.NewBuffer(nil)
	_, err = io.Copy(contentsCopy, r)
	if err != nil {
		t.Errorf("error from io.Copy: %s", err)
		return
	}
	if !bytes.Equal(contentsCopy.Bytes(), contents) {
		t.Errorf("contents not equal got: %x want: %x", contentsCopy.Bytes(), contents)
	}
}

const aeadHexKey = "1936fc8568980274bb900d8319360c77"
const aeadHexSeipd = "d26902070306fcb94490bcb98bbdc9d106c6090266940f72e89edc21b5596b1576b101ed0f9ffc6fc6d65bbfd24dcd0790966e6d1e85a30053784cb1d8b6a0699ef12155a7b2ad6258531b57651fd7777912fa95e35d9b40216f69a4c248db28ff4331f1632907399e6ff9"
const aeadHexPlainText = "cb1362000000000048656c6c6f2c20776f726c6421d50e1ce2269a9eddef81032172b7ed7c"
const aeadExpectedSalt = "fcb94490bcb98bbdc9d106c6090266940f72e89edc21b5596b1576b101ed0f9f"

func TestAeadRfcVector(t *testing.T) {
	key, err := hex.DecodeString(aeadHexKey)
	if err != nil {
		t.Errorf("error in decoding key: %s", err)
	}

	packet, err := hex.DecodeString(aeadHexSeipd)
	if err != nil {
		t.Errorf("error in decoding packet: %s", err)
	}

	plainText, err := hex.DecodeString(aeadHexPlainText)
	if err != nil {
		t.Errorf("error in decoding plaintext: %s", err)
	}

	expectedSalt, err := hex.DecodeString(aeadExpectedSalt)
	if err != nil {
		t.Errorf("error in decoding salt: %s", err)
	}

	buf := bytes.NewBuffer(packet)
	p, err := Read(buf)
	if err != nil {
		t.Errorf("error from Read: %s", err)
		return
	}

	se, ok := p.(*SymmetricallyEncrypted)
	if !ok {
		t.Errorf("didn't read a *SymmetricallyEncrypted")
		return
	}

	if se.Version != symmetricallyEncryptedVersionAead {
		t.Errorf("found wrong version, want: %d, got: %d", symmetricallyEncryptedVersionAead, se.Version)
	}

	if se.cipher != CipherAES128 {
		t.Errorf("found wrong cipher, want: %d, got: %d", CipherAES128, se.cipher)
	}

	if se.mode != AEADModeGCM {
		t.Errorf("found wrong mode, want: %d, got: %d", AEADModeGCM, se.mode)
	}

	if !bytes.Equal(se.salt[:], expectedSalt) {
		t.Errorf("found wrong salt, want: %x, got: %x", expectedSalt, se.salt)
	}

	if se.chunkSizeByte != 0x06 {
		t.Errorf("found wrong chunk size byte, want: %d, got: %d", 0x06, se.chunkSizeByte)
	}

	aeadReader, err := se.Decrypt(CipherFunction(0), key)
	if err != nil {
		t.Errorf("error from Decrypt: %s", err)
		return
	}

	decrypted, err := ioutil.ReadAll(aeadReader)
	if err != nil {
		t.Errorf("error when reading: %s", err)
		return
	}

	err = aeadReader.Close()
	if err != nil {
		t.Errorf("error when closing reader: %s", err)
		return
	}

	if !bytes.Equal(decrypted, plainText) {
		t.Errorf("contents not equal got: %x want: %x", decrypted, plainText)
	}
}

func TestAeadEncryptDecrypt(t *testing.T) {
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

	for cipherName, cipher := range ciphers {
		t.Run(cipherName, func(t *testing.T) {
			for modeName, mode := range modes {
				t.Run(modeName, func(t *testing.T) {
					testSerializeAead(t, CipherSuite{Cipher: cipher, Mode: mode})
				})
			}
		})
	}
}

func testSerializeAead(t *testing.T, cipherSuite CipherSuite) {
	buf := bytes.NewBuffer(nil)
	key := make([]byte, cipherSuite.Cipher.KeySize())
	_, _ = rand.Read(key)

	w, err := SerializeSymmetricallyEncrypted(buf, CipherFunction(0), true, cipherSuite, key, &Config{AEADConfig: &AEADConfig{}})
	if err != nil {
		t.Errorf("error from SerializeSymmetricallyEncrypted: %s", err)
		return
	}

	contents := []byte("hello world\n")

	w.Write(contents)
	w.Close()

	p, err := Read(buf)
	if err != nil {
		t.Errorf("error from Read: %s", err)
		return
	}

	se, ok := p.(*SymmetricallyEncrypted)
	if !ok {
		t.Errorf("didn't read a *SymmetricallyEncrypted")
		return
	}

	if se.Version != symmetricallyEncryptedVersionAead {
		t.Errorf("found wrong version, want: %d, got: %d", symmetricallyEncryptedVersionAead, se.Version)
	}

	if se.cipher != cipherSuite.Cipher {
		t.Errorf("found wrong cipher, want: %d, got: %d", cipherSuite.Cipher, se.cipher)
	}

	if se.mode != cipherSuite.Mode {
		t.Errorf("found wrong mode, want: %d, got: %d", cipherSuite.Mode, se.mode)
	}

	r, err := se.Decrypt(CipherFunction(0), key)
	if err != nil {
		t.Errorf("error from Decrypt: %s", err)
		return
	}

	contentsCopy := bytes.NewBuffer(nil)
	_, err = io.Copy(contentsCopy, r)
	if err != nil {
		t.Errorf("error from io.Copy: %s", err)
		return
	}
	if !bytes.Equal(contentsCopy.Bytes(), contents) {
		t.Errorf("contents not equal got: %x want: %x", contentsCopy.Bytes(), contents)
	}
}
