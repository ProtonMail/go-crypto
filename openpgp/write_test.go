// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package openpgp

import (
	"bytes"
	"crypto/rand"
	"io"
	"io/ioutil"
	mathrand "math/rand"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/go-crypto/openpgp/s2k"
)

const (
	maxPlaintextLen = 1 << 12
	maxPassLen      = 1 << 6
)

func TestSignDetached(t *testing.T) {
	kring, _ := ReadKeyRing(readerFromHex(testKeys1And2PrivateHex))
	out := bytes.NewBuffer(nil)
	message := bytes.NewBufferString(signedInput)
	err := DetachSign(out, kring[0], message, nil)
	if err != nil {
		t.Error(err)
	}

	testDetachedSignature(t, kring, out, signedInput, "check", testKey1KeyId)
}

func TestSignTextDetached(t *testing.T) {
	kring, _ := ReadKeyRing(readerFromHex(testKeys1And2PrivateHex))
	out := bytes.NewBuffer(nil)
	message := bytes.NewBufferString(signedInput)
	err := DetachSignText(out, kring[0], message, nil)
	if err != nil {
		t.Error(err)
	}

	testDetachedSignature(t, kring, out, signedInput, "check", testKey1KeyId)
}

func TestSignDetachedDSA(t *testing.T) {
	kring, _ := ReadKeyRing(readerFromHex(dsaTestKeyPrivateHex))
	out := bytes.NewBuffer(nil)
	message := bytes.NewBufferString(signedInput)
	err := DetachSign(out, kring[0], message, nil)
	if err != nil {
		t.Error(err)
	}

	testDetachedSignature(t, kring, out, signedInput, "check", testKey3KeyId)
}

func TestSignDetachedP256(t *testing.T) {
	kring, _ := ReadKeyRing(readerFromHex(p256TestKeyPrivateHex))
	kring[0].PrivateKey.Decrypt([]byte("passphrase"))

	out := bytes.NewBuffer(nil)
	message := bytes.NewBufferString(signedInput)
	err := DetachSign(out, kring[0], message, nil)
	if err != nil {
		t.Error(err)
	}

	testDetachedSignature(t, kring, out, signedInput, "check", testKeyP256KeyId)
}

func TestSignDetachedWithNotation(t *testing.T) {
	kring, _ := ReadKeyRing(readerFromHex(testKeys1And2PrivateHex))
	signature := bytes.NewBuffer(nil)
	message := bytes.NewBufferString(signedInput)
	config := &packet.Config{
		SignatureNotations: []*packet.Notation{
			{
				Name:            "test@example.com",
				Value:           []byte("test"),
				IsHumanReadable: true,
			},
		},
	}
	err := DetachSign(signature, kring[0], message, config)
	if err != nil {
		t.Error(err)
	}

	signed := bytes.NewBufferString(signedInput)
	config = &packet.Config{}
	sig, signer, err := VerifyDetachedSignature(kring, signed, signature, config)
	if err != nil {
		t.Errorf("signature error: %s", err)
		return
	}
	if sig == nil {
		t.Errorf("sig is nil")
		return
	}
	if numNotations, numExpected := len(sig.Notations), 1; numNotations != numExpected {
		t.Fatalf("got %d Notation Data subpackets, expected %d", numNotations, numExpected)
	}
	if sig.Notations[0].IsHumanReadable != true {
		t.Fatalf("got false, expected true")
	}
	if sig.Notations[0].Name != "test@example.com" {
		t.Fatalf("got %s, expected test@example.com", sig.Notations[0].Name)
	}
	if string(sig.Notations[0].Value) != "test" {
		t.Fatalf("got %s, expected \"test\"", string(sig.Notations[0].Value))
	}
	if signer == nil {
		t.Errorf("signer is nil")
		return
	}
	if signer.PrimaryKey.KeyId != testKey1KeyId {
		t.Errorf("wrong signer: got %x, expected %x", signer.PrimaryKey.KeyId, testKey1KeyId)
	}
}

func TestSignDetachedWithCriticalNotation(t *testing.T) {
	kring, _ := ReadKeyRing(readerFromHex(testKeys1And2PrivateHex))
	signature := bytes.NewBuffer(nil)
	message := bytes.NewBufferString(signedInput)
	config := &packet.Config{
		SignatureNotations: []*packet.Notation{
			{
				Name:            "test@example.com",
				Value:           []byte("test"),
				IsHumanReadable: true,
				IsCritical:      true,
			},
		},
	}
	err := DetachSign(signature, kring[0], message, config)
	if err != nil {
		t.Error(err)
	}

	signed := bytes.NewBufferString(signedInput)
	config = &packet.Config{
		KnownNotations: map[string]bool{
			"test@example.com": true,
		},
	}
	sig, signer, err := VerifyDetachedSignature(kring, signed, signature, config)
	if err != nil {
		t.Errorf("signature error: %s", err)
		return
	}
	if sig == nil {
		t.Errorf("sig is nil")
		return
	}
	if numNotations, numExpected := len(sig.Notations), 1; numNotations != numExpected {
		t.Fatalf("got %d Notation Data subpackets, expected %d", numNotations, numExpected)
	}
	if sig.Notations[0].IsHumanReadable != true {
		t.Fatalf("got false, expected true")
	}
	if sig.Notations[0].Name != "test@example.com" {
		t.Fatalf("got %s, expected test@example.com", sig.Notations[0].Name)
	}
	if string(sig.Notations[0].Value) != "test" {
		t.Fatalf("got %s, expected \"test\"", string(sig.Notations[0].Value))
	}
	if signer == nil {
		t.Errorf("signer is nil")
		return
	}
	if signer.PrimaryKey.KeyId != testKey1KeyId {
		t.Errorf("wrong signer: got %x, expected %x", signer.PrimaryKey.KeyId, testKey1KeyId)
	}
}

func TestNewEntity(t *testing.T) {

	// Check bit-length with no config.
	e, err := NewEntity("Test User", "test", "test@example.com", nil)
	if err != nil {
		t.Errorf("failed to create entity: %s", err)
		return
	}
	bl, err := e.PrimaryKey.BitLength()
	if err != nil {
		t.Errorf("failed to find bit length: %s", err)
	}
	defaultRSAKeyBits := 2048
	if int(bl) != defaultRSAKeyBits {
		t.Errorf("BitLength %v, expected %v", int(bl), defaultRSAKeyBits)
	}

	// Check bit-length with a config.
	cfg := &packet.Config{RSABits: 1024}
	e, err = NewEntity("Test User", "test", "test@example.com", cfg)
	if err != nil {
		t.Errorf("failed to create entity: %s", err)
		return
	}
	bl, err = e.PrimaryKey.BitLength()
	if err != nil {
		t.Errorf("failed to find bit length: %s", err)
	}
	if int(bl) != cfg.RSABits {
		t.Errorf("BitLength %v, expected %v", bl, cfg.RSABits)
	}

	w := bytes.NewBuffer(nil)
	if err := e.SerializePrivate(w, nil); err != nil {
		t.Errorf("failed to serialize entity: %s", err)
		return
	}
	serialized := w.Bytes()

	el, err := ReadKeyRing(w)
	if err != nil {
		t.Errorf("failed to reparse entity: %s", err)
		return
	}

	if len(el) != 1 {
		t.Errorf("wrong number of entities found, got %d, want 1", len(el))
	}

	w = bytes.NewBuffer(nil)
	if err := e.SerializePrivate(w, nil); err != nil {
		t.Errorf("failed to serialize entity second time: %s", err)
		return
	}

	if !bytes.Equal(w.Bytes(), serialized) {
		t.Errorf("results differed")
	}

	if err := e.PrivateKey.Encrypt([]byte("password")); err != nil {
		t.Errorf("failed to encrypt private key: %s", err)
	}

	if err := e.PrivateKey.Decrypt([]byte("password")); err != nil {
		t.Errorf("failed to decrypt private key: %s", err)
	}

	w = bytes.NewBuffer(nil)
	if err := e.SerializePrivate(w, nil); err != nil {
		t.Errorf("failed to serialize after encryption round: %s", err)
		return
	}

	_, err = ReadKeyRing(w)
	if err != nil {
		t.Errorf("failed to reparse entity after encryption round: %s", err)
		return
	}
}

func TestEncryptWithCompression(t *testing.T) {
	kring, _ := ReadKeyRing(readerFromHex(testKeys1And2PrivateHex))
	passphrase := []byte("passphrase")
	for _, entity := range kring {
		if entity.PrivateKey != nil && entity.PrivateKey.Encrypted {
			err := entity.PrivateKey.Decrypt(passphrase)
			if err != nil {
				t.Errorf("failed to decrypt key: %s", err)
			}
		}
		for _, subkey := range entity.Subkeys {
			if subkey.PrivateKey != nil && subkey.PrivateKey.Encrypted {
				err := subkey.PrivateKey.Decrypt(passphrase)
				if err != nil {
					t.Errorf("failed to decrypt subkey: %s", err)
				}
			}
		}
	}

	buf := new(bytes.Buffer)
	var config = &packet.Config{
		DefaultCompressionAlgo: packet.CompressionZIP,
		CompressionConfig:      &packet.CompressionConfig{-1},
	}
	w, err := Encrypt(buf, kring[:1], nil, nil /* no hints */, config)
	if err != nil {
		t.Errorf("error in encrypting plaintext: %s", err)
		return
	}
	message := []byte("hello world")
	_, err = w.Write(message)

	if err != nil {
		t.Errorf("error writing plaintext: %s", err)
		return
	}
	err = w.Close()
	if err != nil {
		t.Errorf("error closing WriteCloser: %s", err)
		return
	}
	err = checkCompression(buf, kring[:1])
	if err != nil {
		t.Errorf("compression check failed: %s", err)
	}
}

func TestSymmetricEncryption(t *testing.T) {
	modesS2K := map[string]s2k.Mode{
		"Iterated": s2k.IteratedSaltedS2K,
		"Argon2":   s2k.Argon2S2K,
	}
	for s2kName, s2ktype := range modesS2K {
		t.Run(s2kName, func(t *testing.T) {
			config := &packet.Config{
				S2KConfig: &s2k.Config{S2KMode: s2ktype},
			}
			buf := new(bytes.Buffer)
			plaintext, err := SymmetricallyEncrypt(buf, []byte("testing"), nil, config)
			if err != nil {
				t.Errorf("error writing headers: %s", err)
				return
			}
			message := []byte("hello world\n")
			_, err = plaintext.Write(message)
			if err != nil {
				t.Errorf("error writing to plaintext writer: %s", err)
			}
			err = plaintext.Close()
			if err != nil {
				t.Errorf("error closing plaintext writer: %s", err)
			}

			md, err := ReadMessage(buf, nil, func(keys []Key, symmetric bool) ([]byte, error) {
				return []byte("testing"), nil
			}, nil)
			if err != nil {
				t.Errorf("error rereading message: %s", err)
			}
			messageBuf := bytes.NewBuffer(nil)
			_, err = io.Copy(messageBuf, md.UnverifiedBody)
			if err != nil {
				t.Errorf("error rereading message: %s", err)
			}
			if !bytes.Equal(message, messageBuf.Bytes()) {
				t.Errorf("recovered message incorrect got '%s', want '%s'", messageBuf.Bytes(), message)
			}
		})
	}
}

func TestSymmetricEncryptionV5RandomizeSlow(t *testing.T) {
	modesS2K := map[int]s2k.Mode{
		0: s2k.IteratedSaltedS2K,
		1: s2k.Argon2S2K,
	}
	aeadConf := packet.AEADConfig{
		DefaultMode: aeadModes[mathrand.Intn(len(aeadModes))],
	}
	config := &packet.Config{AEADConfig: &aeadConf, S2KConfig: &s2k.Config{S2KMode: modesS2K[mathrand.Intn(2)]}}
	buf := new(bytes.Buffer)
	passphrase := make([]byte, mathrand.Intn(maxPassLen))
	_, err := rand.Read(passphrase)
	if err != nil {
		panic(err)
	}
	plaintext, err := SymmetricallyEncrypt(buf, passphrase, nil, config)
	if err != nil {
		t.Errorf("error writing headers: %s", err)
		return
	}
	message := make([]byte, mathrand.Intn(maxPlaintextLen))
	_, errR := rand.Read(message)
	if errR != nil {
		panic(errR)
	}
	_, err = plaintext.Write(message)
	if err != nil {
		t.Errorf("error writing to plaintext writer: %s", err)
	}
	err = plaintext.Close()
	if err != nil {
		t.Errorf("error closing plaintext writer: %s", err)
	}

	// Check if the packet is AEADEncrypted
	copiedCiph := make([]byte, len(buf.Bytes()))
	copy(copiedCiph, buf.Bytes())
	copiedBuf := bytes.NewBuffer(copiedCiph)
	packets := packet.NewReader(copiedBuf)
	// First a SymmetricKeyEncrypted packet
	p, err := packets.Next()
	switch tp := p.(type) {
	case *packet.SymmetricKeyEncrypted:
	default:
		t.Errorf("Didn't find a SymmetricKeyEncrypted packet (found %T instead)", tp)
	}
	// Then an SymmetricallyEncrypted packet version 2
	p, err = packets.Next()
	switch tp := p.(type) {
	case *packet.SymmetricallyEncrypted:
		if tp.Version != 2 {
			t.Errorf("Wrong packet version, expected 2, found %d", tp.Version)
		}
	default:
		t.Errorf("Didn't find an SymmetricallyEncrypted packet (found %T instead)", tp)
	}

	promptFunc := func(keys []Key, symmetric bool) ([]byte, error) {
		return passphrase, nil
	}
	md, err := ReadMessage(buf, nil, promptFunc, config)
	if err != nil {
		t.Errorf("error rereading message: %s", err)
	}
	messageBuf := bytes.NewBuffer(nil)
	_, err = io.Copy(messageBuf, md.UnverifiedBody)
	if err != nil {
		t.Errorf("error rereading message: %s", err)
	}
	if !bytes.Equal(message, messageBuf.Bytes()) {
		t.Errorf("recovered message incorrect got '%s', want '%s'",
			messageBuf.Bytes(), message)
	}
}

var testEncryptionTests = []struct {
	keyRingHex string
	isSigned   bool
}{
	{
		testKeys1And2PrivateHex,
		false,
	},
	{
		testKeys1And2PrivateHex,
		true,
	},
	{
		dsaElGamalTestKeysHex,
		false,
	},
	{
		dsaElGamalTestKeysHex,
		true,
	},
}

func TestEncryption(t *testing.T) {
	for i, test := range testEncryptionTests {
		kring, _ := ReadKeyRing(readerFromHex(test.keyRingHex))

		passphrase := []byte("passphrase")
		for _, entity := range kring {
			if entity.PrivateKey != nil && entity.PrivateKey.Encrypted {
				err := entity.PrivateKey.Decrypt(passphrase)
				if err != nil {
					t.Errorf("#%d: failed to decrypt key", i)
				}
			}
			for _, subkey := range entity.Subkeys {
				if subkey.PrivateKey != nil && subkey.PrivateKey.Encrypted {
					err := subkey.PrivateKey.Decrypt(passphrase)
					if err != nil {
						t.Errorf("#%d: failed to decrypt subkey", i)
					}
				}
			}
		}

		var signed *Entity
		if test.isSigned {
			signed = kring[0]
		}

		buf := new(bytes.Buffer)
		// randomized compression test
		compAlgos := []packet.CompressionAlgo{
			packet.CompressionNone,
			packet.CompressionZIP,
			packet.CompressionZLIB,
		}
		compAlgo := compAlgos[mathrand.Intn(len(compAlgos))]
		level := mathrand.Intn(11) - 1
		compConf := &packet.CompressionConfig{level}
		var config = &packet.Config{
			DefaultCompressionAlgo: compAlgo,
			CompressionConfig:      compConf,
		}

		// Flip coin to enable AEAD mode
		if mathrand.Int()%2 == 0 {
			aeadConf := packet.AEADConfig{
				DefaultMode: aeadModes[mathrand.Intn(len(aeadModes))],
			}
			config.AEADConfig = &aeadConf
		}

		w, err := Encrypt(buf, kring[:1], signed, nil /* no hints */, config)
		if err != nil {
			t.Errorf("#%d: error in Encrypt: %s", i, err)
			continue
		}

		const message = "testing"
		_, err = w.Write([]byte(message))
		if err != nil {
			t.Errorf("#%d: error writing plaintext: %s", i, err)
			continue
		}
		err = w.Close()
		if err != nil {
			t.Errorf("#%d: error closing WriteCloser: %s", i, err)
			continue
		}

		md, err := ReadMessage(buf, kring, nil /* no prompt */, config)
		if err != nil {
			t.Errorf("#%d: error reading message: %s", i, err)
			continue
		}

		testTime, _ := time.Parse("2006-01-02", "2013-07-01")
		if test.isSigned {
			signKey, _ := kring[0].SigningKey(testTime)
			expectedKeyId := signKey.PublicKey.KeyId
			if md.SignedByKeyId != expectedKeyId {
				t.Errorf("#%d: message signed by wrong key id, got: %v, want: %v", i, *md.SignedBy, expectedKeyId)
			}
			if md.SignedBy == nil {
				t.Errorf("#%d: failed to find the signing Entity", i)
			}
		}

		plaintext, err := ioutil.ReadAll(md.UnverifiedBody)
		if err != nil {
			t.Errorf("#%d: error reading encrypted contents: %s", i, err)
			continue
		}

		encryptKey, _ := kring[0].EncryptionKey(testTime)
		expectedKeyId := encryptKey.PublicKey.KeyId
		if len(md.EncryptedToKeyIds) != 1 || md.EncryptedToKeyIds[0] != expectedKeyId {
			t.Errorf("#%d: expected message to be encrypted to %v, but got %#v", i, expectedKeyId, md.EncryptedToKeyIds)
		}

		if string(plaintext) != message {
			t.Errorf("#%d: got: %s, want: %s", i, string(plaintext), message)
		}

		if test.isSigned {
			if md.SignatureError != nil {
				t.Errorf("#%d: signature error: %s", i, md.SignatureError)
			}
			if md.Signature == nil {
				t.Error("signature missing")
			}
		}
	}
}

var testSigningTests = []struct {
	keyRingHex string
}{
	{
		testKeys1And2PrivateHex,
	},
	{
		dsaElGamalTestKeysHex,
	},
}

func TestSigning(t *testing.T) {
	for i, test := range testSigningTests {
		kring, _ := ReadKeyRing(readerFromHex(test.keyRingHex))

		passphrase := []byte("passphrase")
		for _, entity := range kring {
			if entity.PrivateKey != nil && entity.PrivateKey.Encrypted {
				err := entity.PrivateKey.Decrypt(passphrase)
				if err != nil {
					t.Errorf("#%d: failed to decrypt key", i)
				}
			}
			for _, subkey := range entity.Subkeys {
				if subkey.PrivateKey != nil && subkey.PrivateKey.Encrypted {
					err := subkey.PrivateKey.Decrypt(passphrase)
					if err != nil {
						t.Errorf("#%d: failed to decrypt subkey", i)
					}
				}
			}
		}

		signed := kring[0]

		buf := new(bytes.Buffer)
		w, err := Sign(buf, signed, nil /* no hints */, nil)
		if err != nil {
			t.Errorf("#%d: error in Sign: %s", i, err)
			continue
		}

		const message = "testing"
		_, err = w.Write([]byte(message))
		if err != nil {
			t.Errorf("#%d: error writing plaintext: %s", i, err)
			continue
		}
		err = w.Close()
		if err != nil {
			t.Errorf("#%d: error closing WriteCloser: %s", i, err)
			continue
		}

		md, err := ReadMessage(buf, kring, nil /* no prompt */, nil)
		if err != nil {
			t.Errorf("#%d: error reading message: %s", i, err)
			continue
		}

		testTime, _ := time.Parse("2006-01-02", "2013-07-01")
		signKey, _ := kring[0].SigningKey(testTime)
		expectedKeyId := signKey.PublicKey.KeyId
		if md.SignedByKeyId != expectedKeyId {
			t.Errorf("#%d: message signed by wrong key id, got: %v, want: %v", i, *md.SignedBy, expectedKeyId)
		}
		if md.SignedBy == nil {
			t.Errorf("#%d: failed to find the signing Entity", i)
		}

		plaintext, err := ioutil.ReadAll(md.UnverifiedBody)
		if err != nil {
			t.Errorf("#%d: error reading contents: %v", i, err)
			continue
		}

		if string(plaintext) != message {
			t.Errorf("#%d: got: %q, want: %q", i, plaintext, message)
		}

		if md.SignatureError != nil {
			t.Errorf("#%d: signature error: %q", i, md.SignatureError)
		}
		if md.Signature == nil {
			t.Error("signature missing")
		}
	}
}

func checkCompression(r io.Reader, keyring KeyRing) (err error) {
	var p packet.Packet

	var symKeys []*packet.SymmetricKeyEncrypted
	var pubKeys []keyEnvelopePair
	// Integrity protected encrypted packet: SymmetricallyEncrypted or AEADEncrypted
	var edp packet.EncryptedDataPacket

	packets := packet.NewReader(r)
	config := &packet.Config{}

	// The message, if encrypted, starts with a number of packets
	// containing an encrypted decryption key. The decryption key is either
	// encrypted to a public key, or with a passphrase. This loop
	// collects these packets.
ParsePackets:
	for {
		p, err = packets.Next()
		if err != nil {
			return err
		}
		switch p := p.(type) {
		case *packet.EncryptedKey:
			// This packet contains the decryption key encrypted to a public key.
			switch p.Algo {
			case packet.PubKeyAlgoRSA, packet.PubKeyAlgoRSAEncryptOnly, packet.PubKeyAlgoElGamal, packet.PubKeyAlgoECDH:
				break
			default:
				continue
			}
			var keys []Key
			if p.KeyId == 0 {
				keys = keyring.DecryptionKeys()
			} else {
				keys = keyring.KeysById(p.KeyId)
			}
			for _, k := range keys {
				pubKeys = append(pubKeys, keyEnvelopePair{k, p})
			}
		case *packet.SymmetricallyEncrypted, *packet.AEADEncrypted:
			edp = p.(packet.EncryptedDataPacket)
			break ParsePackets
		case *packet.Compressed, *packet.LiteralData, *packet.OnePassSignature:
			// This message isn't encrypted.
			return errors.StructuralError("message not encrypted")
		}
	}

	var candidates []Key
	var decrypted io.ReadCloser

	// Now that we have the list of encrypted keys we need to decrypt at
	// least one of them or, if we cannot, we need to call the prompt
	// function so that it can decrypt a key or give us a passphrase.
FindKey:
	for {
		// See if any of the keys already have a private key available
		candidates = candidates[:0]
		candidateFingerprints := make(map[string]bool)

		for _, pk := range pubKeys {
			if pk.key.PrivateKey == nil {
				continue
			}
			if !pk.key.PrivateKey.Encrypted {
				if len(pk.encryptedKey.Key) == 0 {
					errDec := pk.encryptedKey.Decrypt(pk.key.PrivateKey, config)
					if errDec != nil {
						continue
					}
				}
				// Try to decrypt symmetrically encrypted
				decrypted, err = edp.Decrypt(pk.encryptedKey.CipherFunc, pk.encryptedKey.Key)
				if err != nil && err != errors.ErrKeyIncorrect {
					return err
				}
				if decrypted != nil {
					break FindKey
				}
			} else {
				fpr := string(pk.key.PublicKey.Fingerprint[:])
				if v := candidateFingerprints[fpr]; v {
					continue
				}
				candidates = append(candidates, pk.key)
				candidateFingerprints[fpr] = true
			}
		}

		if len(candidates) == 0 && len(symKeys) == 0 {
			return errors.ErrKeyIncorrect
		}
	}

	decPackets, err := packet.Read(decrypted)
	_, ok := decPackets.(*packet.Compressed)
	if !ok {
		return errors.InvalidArgumentError("No compressed packets found")
	}
	return nil
}
