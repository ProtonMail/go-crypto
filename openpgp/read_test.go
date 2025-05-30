// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package openpgp

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"io"
	"io/ioutil"
	"math/bits"
	"os"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func readerFromHex(s string) io.Reader {
	data, err := hex.DecodeString(s)
	if err != nil {
		panic("readerFromHex: bad input")
	}
	return bytes.NewBuffer(data)
}

func TestReadKeyRing(t *testing.T) {
	kring, err := ReadKeyRing(readerFromHex(testKeys1And2Hex))
	if err != nil {
		t.Error(err)
		return
	}
	if len(kring) != 2 || uint32(kring[0].PrimaryKey.KeyId) != 0xC20C31BB || uint32(kring[1].PrimaryKey.KeyId) != 0x1E35246B {
		t.Errorf("bad keyring: %#v", kring)
	}
}

func TestRereadKeyRing(t *testing.T) {
	kring, err := ReadKeyRing(readerFromHex(testKeys1And2Hex))
	if err != nil {
		t.Errorf("error in initial parse: %s", err)
		return
	}
	out := new(bytes.Buffer)
	err = kring[0].Serialize(out)
	if err != nil {
		t.Errorf("error in serialization: %s", err)
		return
	}
	kring, err = ReadKeyRing(out)
	if err != nil {
		t.Errorf("error in second parse: %s", err)
		return
	}

	if len(kring) != 1 || uint32(kring[0].PrimaryKey.KeyId) != 0xC20C31BB {
		t.Errorf("bad keyring: %#v", kring)
	}
}

func TestReadPrivateKeyRing(t *testing.T) {
	kring, err := ReadKeyRing(readerFromHex(testKeys1And2PrivateHex))
	if err != nil {
		t.Error(err)
		return
	}
	if len(kring) != 2 || uint32(kring[0].PrimaryKey.KeyId) != 0xC20C31BB || uint32(kring[1].PrimaryKey.KeyId) != 0x1E35246B || kring[0].PrimaryKey == nil {
		t.Errorf("bad keyring: %#v", kring)
	}
}

func TestReadDSAKey(t *testing.T) {
	kring, err := ReadKeyRing(readerFromHex(dsaTestKeyHex))
	if err != nil {
		t.Error(err)
		return
	}
	if len(kring) != 1 || uint32(kring[0].PrimaryKey.KeyId) != 0x0CCC0360 {
		t.Errorf("bad parse: %#v", kring)
	}
}

func TestReadP256Key(t *testing.T) {
	kring, err := ReadKeyRing(readerFromHex(p256TestKeyHex))
	if err != nil {
		t.Error(err)
		return
	}
	if len(kring) != 1 || uint32(kring[0].PrimaryKey.KeyId) != 0x5918513E {
		t.Errorf("bad parse: %#v", kring)
	}
}

func TestDSAHashTruncatation(t *testing.T) {
	// dsaKeyWithSHA512 was generated with GnuPG and --cert-digest-algo
	// SHA512 in order to require DSA hash truncation to verify correctly.
	_, err := ReadKeyRing(readerFromHex(dsaKeyWithSHA512))
	if err != nil {
		t.Error(err)
	}
}

func TestGetKeyById(t *testing.T) {
	kring, _ := ReadKeyRing(readerFromHex(testKeys1And2Hex))

	keys := kring.KeysById(0xa34d7e18c20c31bb)
	if len(keys) != 1 || keys[0].Entity != kring[0] {
		t.Errorf("bad result for 0xa34d7e18c20c31bb: %#v", keys)
	}

	keys = kring.KeysById(0xfd94408d4543314f)
	if len(keys) != 1 || keys[0].Entity != kring[0] {
		t.Errorf("bad result for 0xa34d7e18c20c31bb: %#v", keys)
	}
}

func checkSignedMessage(t *testing.T, signedHex, expected string) {
	kring, _ := ReadKeyRing(readerFromHex(testKeys1And2Hex))

	md, err := ReadMessage(readerFromHex(signedHex), kring, nil, nil)
	if err != nil {
		t.Error(err)
		return
	}

	if !md.IsSigned || md.SignedByKeyId != 0xa34d7e18c20c31bb || md.SignedBy == nil || md.IsEncrypted || md.IsSymmetricallyEncrypted || len(md.EncryptedToKeyIds) != 0 || md.DecryptedWith.Entity != nil {
		t.Errorf("bad MessageDetails: %#v", md)
	}

	contents, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Errorf("error reading UnverifiedBody: %s", err)
	}
	if string(contents) != expected {
		t.Errorf("bad UnverifiedBody got:%s want:%s", string(contents), expected)
	}
	if md.SignatureError != nil || md.Signature == nil {
		t.Errorf("failed to validate: %s", md.SignatureError)
	}
}

func TestSignedMessage(t *testing.T) {
	checkSignedMessage(t, signedMessageHex, signedInput)
}

func TestTextSignedMessage(t *testing.T) {
	checkSignedMessage(t, signedTextMessageHex, signedTextInput)
}

// The reader should detect "compressed quines", which are compressed
// packets that expand into themselves and cause an infinite recursive
// parsing loop.
// The packet in this test case comes from Taylor R. Campbell at
// http://mumble.net/~campbell/misc/pgp-quine/
func TestCampbellQuine(t *testing.T) {
	md, err := ReadMessage(readerFromHex(campbellQuine), nil, nil, nil)
	if md != nil {
		t.Errorf("Reading a compressed quine should not return any data: %#v", md)
	}
	structural, ok := err.(errors.StructuralError)
	if !ok {
		t.Fatalf("Unexpected class of error: %T", err)
	}
	if !strings.Contains(string(structural), "too many layers of packets") {
		t.Fatalf("Unexpected error: %s", err)
	}
}

func TestSignedEncryptedMessage(t *testing.T) {
	var signedEncryptedMessageTests = []struct {
		keyRingHex       string
		messageHex       string
		signedByKeyId    uint64
		encryptedToKeyId uint64
		verifiedSigHex   string
		unverifiedSigHex string
	}{
		{
			testKeys1And2PrivateHex,
			signedEncryptedMessageHex,
			0xa34d7e18c20c31bb,
			0x2a67d68660df41c7,
			verifiedSignatureEncryptedMessageHex,
			unverifiedSignatureEncryptedMessageHex,
		},
		{
			dsaElGamalTestKeysHex,
			signedEncryptedMessage2Hex,
			0x33af447ccd759b09,
			0xcf6a7abcd43e3673,
			signatureEncryptedMessage2Hex,
			"",
		},
	}
	for i, test := range signedEncryptedMessageTests {
		expected := "Signed and encrypted message\n"
		kring, _ := ReadKeyRing(readerFromHex(test.keyRingHex))
		prompt := func(keys []Key, symmetric bool) ([]byte, error) {
			if symmetric {
				t.Errorf("prompt: message was marked as symmetrically encrypted")
				return nil, errors.ErrKeyIncorrect
			}

			if len(keys) == 0 {
				t.Error("prompt: no keys requested")
				return nil, errors.ErrKeyIncorrect
			}

			err := keys[0].PrivateKey.Decrypt([]byte("passphrase"))
			if err != nil {
				t.Errorf("prompt: error decrypting key: %s", err)
				return nil, errors.ErrKeyIncorrect
			}

			return nil, nil
		}

		md, err := ReadMessage(readerFromHex(test.messageHex), kring, prompt, nil)
		if err != nil {
			t.Errorf("#%d: error reading message: %s", i, err)
			return
		}

		if !md.IsSigned || md.SignedByKeyId != test.signedByKeyId || md.SignedBy == nil || !md.IsEncrypted || md.IsSymmetricallyEncrypted || len(md.EncryptedToKeyIds) == 0 || md.EncryptedToKeyIds[0] != test.encryptedToKeyId {
			t.Errorf("#%d: bad MessageDetails: %#v", i, md)
		}

		contents, err := io.ReadAll(md.UnverifiedBody)
		if err != nil {
			t.Errorf("#%d: error reading UnverifiedBody: %s", i, err)
		}
		if string(contents) != expected {
			t.Errorf("#%d: bad UnverifiedBody got:%s want:%s", i, string(contents), expected)
		}

		if md.SignatureError != nil || md.Signature == nil {
			t.Errorf("#%d: failed to validate: %s", i, md.SignatureError)
		}

		if test.verifiedSigHex != "" {
			var sig bytes.Buffer
			err = md.Signature.Serialize(&sig)
			if err != nil {
				t.Errorf("#%d: error serializing verified signature: %s", i, err)
			}

			sigData, err := io.ReadAll(&sig)
			if err != nil {
				t.Errorf("#%d: error reading verified signature: %s", i, err)
			}

			if hex.EncodeToString(sigData) != test.verifiedSigHex {
				t.Errorf("#%d: verified signature does not match: %s, %s", i, hex.EncodeToString(sigData), test.verifiedSigHex)
			}
		}

		if test.unverifiedSigHex != "" {
			var sig bytes.Buffer
			for i := range md.UnverifiedSignatures {
				err = md.Signature.Serialize(&sig)
				if err != nil {
					t.Errorf("#%d: error serializing unverified signature: %s", i, err)
				}
			}

			sigData, err := io.ReadAll(&sig)
			if err != nil {
				t.Errorf("#%d: error reading unverified signature: %s", i, err)
			}

			if hex.EncodeToString(sigData) != test.verifiedSigHex {
				t.Errorf("#%d: unverified signature does not match: %s, %s", i, hex.EncodeToString(sigData), test.verifiedSigHex)
			}
		}
	}
}

func TestUnspecifiedRecipient(t *testing.T) {
	expected := "Recipient unspecified\n"
	kring, _ := ReadKeyRing(readerFromHex(testKeys1And2PrivateHex))

	md, err := ReadMessage(readerFromHex(recipientUnspecifiedHex), kring, nil, nil)
	if err != nil {
		t.Errorf("error reading message: %s", err)
		return
	}

	contents, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Errorf("error reading UnverifiedBody: %s", err)
	}
	if string(contents) != expected {
		t.Errorf("bad UnverifiedBody got:%s want:%s", string(contents), expected)
	}
}

func TestSymmetricallyEncrypted(t *testing.T) {
	firstTimeCalled := true

	prompt := func(keys []Key, symmetric bool) ([]byte, error) {
		if len(keys) != 0 {
			t.Errorf("prompt: len(keys) = %d (want 0)", len(keys))
		}

		if !symmetric {
			t.Errorf("symmetric is not set")
		}

		if firstTimeCalled {
			firstTimeCalled = false
			return []byte("wrongpassword"), nil
		}

		return []byte("password"), nil
	}

	md, err := ReadMessage(readerFromHex(symmetricallyEncryptedCompressedHex), nil, prompt, nil)
	if err != nil {
		t.Errorf("ReadMessage: %s", err)
		return
	}

	contents, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Errorf("ReadAll: %s", err)
	}

	expectedCreationTime := uint32(1555107469)
	if md.LiteralData.Time != expectedCreationTime {
		t.Errorf("LiteralData.Time is %d, want %d", md.LiteralData.Time, expectedCreationTime)
	}

	const expected = "Symmetrically encrypted.\r\n"
	if string(contents) != expected {
		t.Errorf("contents got: %s want: %s", string(contents), expected)
	}
}

func testDetachedSignature(t *testing.T, kring KeyRing, signature io.Reader, sigInput, tag string, expectedSignerKeyId uint64) {
	signed := bytes.NewBufferString(sigInput)
	config := &packet.Config{}
	signer, err := CheckDetachedSignature(kring, signed, signature, config)
	if err != nil {
		t.Errorf("%s: signature error: %s", tag, err)
		return
	}
	if signer == nil {
		t.Errorf("%s: signer is nil", tag)
		return
	}
	if signer.PrimaryKey.KeyId != expectedSignerKeyId {
		t.Errorf("%s: wrong signer: got %x, expected %x", tag, signer.PrimaryKey.KeyId, expectedSignerKeyId)
	}
}

func TestDetachedSignature(t *testing.T) {
	kring, _ := ReadKeyRing(readerFromHex(testKeys1And2Hex))
	testDetachedSignature(t, kring, readerFromHex(detachedSignatureHex), signedInput, "binary", testKey1KeyId)
	testDetachedSignature(t, kring, readerFromHex(detachedSignatureTextHex), signedInput, "text", testKey1KeyId)

	incorrectSignedInput := signedInput + "X"
	config := &packet.Config{}
	_, err := CheckDetachedSignature(kring, bytes.NewBufferString(incorrectSignedInput), readerFromHex(detachedSignatureHex), config)
	if err == nil {
		t.Fatal("CheckDetachedSignature returned without error for bad signature")
	}
	if err == errors.ErrUnknownIssuer {
		t.Fatal("CheckDetachedSignature returned ErrUnknownIssuer when the signer was known, but the signature invalid")
	}
}

func TestDetachedSignatureDSA(t *testing.T) {
	kring, _ := ReadKeyRing(readerFromHex(dsaTestKeyHex))
	testDetachedSignature(t, kring, readerFromHex(detachedSignatureDSAHex), signedInput, "binary", testKey3KeyId)
}

func TestMultipleSignaturePacketsDSA(t *testing.T) {
	kring, _ := ReadKeyRing(readerFromHex(dsaTestKeyHex))
	testDetachedSignature(t, kring, readerFromHex(missingHashFunctionHex+detachedSignatureDSAHex), signedInput, "binary", testKey3KeyId)
}

func TestDetachedSignatureP256(t *testing.T) {
	kring, _ := ReadKeyRing(readerFromHex(p256TestKeyHex))
	testDetachedSignature(t, kring, readerFromHex(detachedSignatureP256Hex), signedInput, "binary", testKeyP256KeyId)
}

func testHashFunctionError(t *testing.T, signatureHex string) {
	kring, _ := ReadKeyRing(readerFromHex(testKeys1And2Hex))
	config := &packet.Config{}
	_, err := CheckDetachedSignature(kring, nil, readerFromHex(signatureHex), config)
	if err == nil {
		t.Fatal("Packet with bad hash type was correctly parsed")
	}
	if err != errors.ErrUnknownIssuer {
		t.Fatalf("Unexpected class of error: %s", err)
	}
}

func TestUnknownHashFunction(t *testing.T) {
	// unknownHashFunctionHex contains a signature packet with hash function type
	// 153 (which isn't a real hash function id). Since that's the only signature
	// packet we don't find any suitable packets and end up with ErrUnknownIssuer.
	testHashFunctionError(t, unknownHashFunctionHex)
}

func TestMissingHashFunction(t *testing.T) {
	// missingHashFunctionHex contains a signature packet that uses RIPEMD160,
	// which isn't compiled in. Since that's the only signature packet we don't
	// find any suitable packets and end up with ErrUnknownIssuer.
	testHashFunctionError(t, missingHashFunctionHex)
}

func TestRSASignatureBadMPILength(t *testing.T) {
	kring, _ := ReadKeyRing(readerFromHex(testKeys1And2Hex))
	config := &packet.Config{}
	_, err := CheckDetachedSignature(kring, nil, readerFromHex(rsaSignatureBadMPIlength), config)
	if err == nil {
		t.Fatal("RSA Signature with malformed MPI was correctly parsed")
	}
}

func TestDetachedSignatureExpiredCrossSig(t *testing.T) {
	kring, _ := ReadArmoredKeyRing(bytes.NewBufferString(keyWithExpiredCrossSig))
	config := &packet.Config{}
	_, err := CheckArmoredDetachedSignature(kring, bytes.NewBufferString("Hello World :)"), bytes.NewBufferString(sigFromKeyWithExpiredCrossSig), config)
	if err == nil {
		t.Fatal("Signature from key with expired subkey binding embedded signature was accepted")
	}
	if err != errors.ErrSignatureExpired {
		t.Fatalf("Unexpected class of error: %s", err)
	}
}

func TestSignatureUnknownNotation(t *testing.T) {
	el, err := ReadArmoredKeyRing(bytes.NewBufferString(criticalNotationSigner))
	if err != nil {
		t.Error(err)
	}
	raw, err := armor.Decode(strings.NewReader(signedMessageWithCriticalNotation))
	if err != nil {
		t.Error(err)
		return
	}
	md, err := ReadMessage(raw.Body, el, nil, nil)
	if err != nil {
		t.Error(err)
		return
	}
	_, err = io.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Error(err)
		return
	}
	const expectedErr string = "openpgp: invalid signature: unknown critical notation: test@example.com"
	if md.SignatureError == nil || md.SignatureError.Error() != expectedErr {
		t.Errorf("Expected error '%s', but got error '%s'", expectedErr, md.SignatureError)
	}
}

func TestSignatureKnownNotation(t *testing.T) {
	el, err := ReadArmoredKeyRing(bytes.NewBufferString(criticalNotationSigner))
	if err != nil {
		t.Error(err)
	}
	raw, err := armor.Decode(strings.NewReader(signedMessageWithCriticalNotation))
	if err != nil {
		t.Error(err)
		return
	}
	config := &packet.Config{
		KnownNotations: map[string]bool{
			"test@example.com": true,
		},
	}
	md, err := ReadMessage(raw.Body, el, nil, config)
	if err != nil {
		t.Error(err)
		return
	}
	_, err = io.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Error(err)
		return
	}
	if md.SignatureError != nil {
		t.Error(md.SignatureError)
		return
	}
}

func TestReadingArmoredPrivateKey(t *testing.T) {
	el, err := ReadArmoredKeyRing(bytes.NewBufferString(armoredPrivateKeyBlock))
	if err != nil {
		t.Error(err)
	}
	if len(el) != 1 {
		t.Errorf("got %d entities, wanted 1\n", len(el))
	}
}

func TestReadingArmoredPublicKey(t *testing.T) {
	el, err := ReadArmoredKeyRing(bytes.NewBufferString(e2ePublicKey))
	if err != nil {
		t.Error(err)
	}
	if len(el) != 1 {
		t.Errorf("didn't get a valid entity")
	}
}

func TestNoArmoredData(t *testing.T) {
	_, err := ReadArmoredKeyRing(bytes.NewBufferString("foo"))
	if _, ok := err.(errors.InvalidArgumentError); !ok {
		t.Errorf("error was not an InvalidArgumentError: %s", err)
	}
}

func testReadMessageError(t *testing.T, messageHex string) {
	buf, err := hex.DecodeString(messageHex)
	if err != nil {
		t.Errorf("hex.DecodeString(): %v", err)
	}

	kr, err := ReadKeyRing(new(bytes.Buffer))
	if err != nil {
		t.Errorf("ReadKeyring(): %v", err)
	}

	_, err = ReadMessage(bytes.NewBuffer(buf), kr,
		func([]Key, bool) ([]byte, error) {
			return []byte("insecure"), nil
		}, nil)

	if err == nil {
		t.Errorf("ReadMessage(): Unexpected nil error")
	}
}

func TestIssue11503(t *testing.T) {
	testReadMessageError(t, "8c040402000aa430aa8228b9248b01fc899a91197130303030")
}

func TestIssue11504(t *testing.T) {
	testReadMessageError(t, "9303000130303030303030303030983002303030303030030000000130")
}

// TestSignatureV3Message tests the verification of V3 signature, generated
// with a modern V4-style key.  Some people have their clients set to generate
// V3 signatures, so it's useful to be able to verify them.
func TestSignatureV3Message(t *testing.T) {
	sig, err := armor.Decode(strings.NewReader(signedMessageV3))
	if err != nil {
		t.Error(err)
		return
	}
	key, err := ReadArmoredKeyRing(strings.NewReader(keyV4forVerifyingSignedMessageV3))
	if err != nil {
		t.Error(err)
		return
	}
	md, err := ReadMessage(sig.Body, key, nil, nil)
	if err != nil {
		t.Error(err)
		return
	}

	_, err = io.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Error(err)
		return
	}

	// We'll see a sig error here after reading in the UnverifiedBody above,
	// if there was one to see.
	if err = md.SignatureError; err == nil {
		t.Errorf("Expected a signature error")
		return
	}

	if md.Signature != nil {
		t.Errorf("Did not expect a signature V4 back")
		return
	}
}

func TestReadV6Messages(t *testing.T) {
	key, err := ReadArmoredKeyRing(strings.NewReader(v6PrivKey))
	if err != nil {
		t.Error(err)
		return
	}
	msgReader, err := armor.Decode(strings.NewReader(v6PrivKeyMsg))
	if err != nil {
		t.Error(err)
		return
	}
	md, err := ReadMessage(msgReader.Body, key, nil, nil)
	if err != nil {
		t.Error(err)
		return
	}
	contents, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Error(err)
		return
	}
	if string(contents) != "Hello, world!" {
		t.Errorf("decrypted message is wrong: %s", contents)
	}

	msgReader, err = armor.Decode(strings.NewReader(v6PrivKeyInlineSignMsg))
	if err != nil {
		t.Error(err)
		return
	}
	md, err = ReadMessage(msgReader.Body, key, nil, nil)
	if err != nil {
		t.Error(err)
		return
	}
	contents, err = io.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Error(err)
		return
	}
	if md.SignatureError != nil {
		t.Error("expected no signature error, got:", md.SignatureError)
	}
	if string(contents) != "Hello, world!" {
		t.Errorf("inline message is wrong: %s", contents)
	}
}
func TestSymmetricDecryptionArgon2(t *testing.T) {
	if bits.UintSize == 32 {
		// 32-bit platforms cannot allocate 2GiB of RAM
		// required by the test vector.
		t.Skip()
	}
	// Appendix IETF OpenPGP crypto refresh draft v08 A.8.1
	file, err := os.Open("test_data/argon2-sym-message.asc")
	if err != nil {
		t.Fatal(err)
	}
	armoredEncryptedMessage, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	testSymmetricDecryptionArgon2Run(t, armoredEncryptedMessage)
}

func TestSymmetricDecryptionArgon2LessMemory(t *testing.T) {
	armoredEncryptedMessage := []byte(`-----BEGIN PGP MESSAGE-----

w0gGJgcCFATa3KMW/4/9RsPME+un+MBqAwQQljCpv3dPfmVTFJAcqn+YRcIFrbY4
iiVOkxM5uAKScyYn/T2su2j2fu+uPl/HpgLSWQIHAgx/1caHYWvwl7tyjJ/tSYwK
m8OMKQHidSWi7UM88mN17ltnLCV/Wa3bLDIyAgJr9XKubHXeUK6/FqmtPxepd4y/
SXkqZq0XEafMIbynK2gH6JHjctFX
-----END PGP MESSAGE-----`)
	testSymmetricDecryptionArgon2Run(t, armoredEncryptedMessage)
}

func testSymmetricDecryptionArgon2Run(t *testing.T, armoredEncryptedMessage []byte) {
	passphrase := []byte("password")
	// Unarmor string
	raw, err := armor.Decode(strings.NewReader(string(armoredEncryptedMessage)))
	if err != nil {
		t.Error(err)
		return
	}
	// Mock passphrase prompt
	promptFunc := func(keys []Key, symmetric bool) ([]byte, error) {
		return passphrase, nil
	}
	// Decrypt message
	md, err := ReadMessage(raw.Body, nil, promptFunc, nil)
	if err != nil {
		t.Error(err)
		return
	}
	contents, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Errorf("error reading UnverifiedBody: %s", err)
	}

	if string(contents) != "Hello, world!" {
		t.Fatal("Did not decrypt Argon message correctly")
	}
}

func TestAsymmestricAeadOcbOpenPGPjsCompressedMessage(t *testing.T) {
	if packet.V5Disabled {
		t.Skip()
	}
	// Read key from file
	armored, err := os.Open("test_data/aead-ocb-asym-key.asc")
	if err != nil {
		t.Fatal(err)
	}
	el, err := ReadArmoredKeyRing(armored)
	if err != nil {
		t.Fatal(err)
	}
	// Read ciphertext from file
	ciphertext, err := os.Open("test_data/aead-ocb-asym-message.asc")
	if err != nil {
		t.Fatal(err)
	}
	armoredEncryptedMessage, err := io.ReadAll(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	// Unarmor string
	raw, err := armor.Decode(strings.NewReader(string(armoredEncryptedMessage)))
	if err != nil {
		t.Error(err)
		return
	}
	// Decrypt message
	md, err := ReadMessage(raw.Body, el, nil, nil)
	if err != nil {
		t.Error(err)
		return
	}
	// Read contents
	contents, err := io.ReadAll(md.UnverifiedBody)
	if err != nil && err != io.ErrUnexpectedEOF {
		t.Errorf("error reading UnverifiedBody: %s", err)
	}

	wantHash := modestProposalSha512
	gotHashRaw := sha512.Sum512(contents)
	gotHash := base64.StdEncoding.EncodeToString(gotHashRaw[:])

	if wantHash != gotHash {
		t.Fatal("Did not decrypt OpenPGPjs message correctly")
	}
}

func TestSymmetricAeadEaxOpenPGPJsMessage(t *testing.T) {
	if packet.V5Disabled {
		t.Skip()
	}
	key := []byte{79, 41, 206, 112, 224, 133, 140, 223, 27, 61, 227, 57, 114,
		118, 64, 60, 177, 26, 42, 174, 151, 5, 186, 74, 226, 97, 214, 63, 114, 77,
		215, 121}

	file, err := os.Open("test_data/aead-eax-packet.b64")
	if err != nil {
		t.Fatal(err)
	}
	fileBytes, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	// Decode from base 64
	raw, err := base64.StdEncoding.DecodeString(string(fileBytes))
	if err != nil {
		t.Fatal(err)
	}
	r := bytes.NewBuffer(raw)
	// Read packet
	p, err := packet.Read(r)
	if err != nil {
		panic(err)
	}

	// Decrypt with key
	var edp = p.(*packet.AEADEncrypted)
	rc, err := edp.Decrypt(packet.CipherFunction(0), key)
	if err != nil {
		panic(err)
	}
	// Read literal data packet
	p, err = packet.Read(rc)
	if err != nil {
		t.Fatal(err)
	}
	ld := p.(*packet.LiteralData)

	// Read contents
	contents, err := io.ReadAll(ld.Body)
	if err != nil && err != io.ErrUnexpectedEOF {
		t.Errorf("error reading UnverifiedBody: %s", err)
	}

	wantHash := modestProposalSha512
	gotHashRaw := sha512.Sum512(contents)
	gotHash := base64.StdEncoding.EncodeToString(gotHashRaw[:])

	if wantHash != gotHash {
		t.Fatal("Did not decrypt OpenPGPjs message correctly")
	}
}

func TestCorruptedMessageInvalidSigHeader(t *testing.T) {
	// Decrypt message with corrupted MDC and invalid one-pass-signature header
	// Expect parsing errors over unverified decrypted data to be opaque
	passphrase := []byte("password")
	file, err := os.Open("test_data/sym-corrupted-message-invalid-sig-header.asc")
	if err != nil {
		t.Fatal(err)
	}
	armoredEncryptedMessage, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	// Unarmor string
	raw, err := armor.Decode(strings.NewReader(string(armoredEncryptedMessage)))
	if err != nil {
		t.Error(err)
		return
	}
	// Mock passphrase prompt
	promptFunc := func(keys []Key, symmetric bool) ([]byte, error) {
		return passphrase, nil
	}
	const expectedErr string = "openpgp: decryption with session key failed: parsing error"
	_, observedErr := ReadMessage(raw.Body, nil, promptFunc, nil)
	if observedErr.Error() != expectedErr {
		t.Errorf("Expected error '%s', but got error '%s'", expectedErr, observedErr)
	}
}

func TestCorruptedMessageWrongLength(t *testing.T) {
	// Decrypt message with wrong length in Literal packet header (length too long)
	// Expect parsing errors over unverified decrypted data to be opaque
	passphrase := []byte("password")
	promptFunc := func(keys []Key, symmetric bool) ([]byte, error) {
		return passphrase, nil
	}
	const expectedErr string = "openpgp: decryption with session key failed: parsing error"

	file, err := os.Open("test_data/sym-corrupted-message-long-length.asc")
	if err != nil {
		t.Fatal(err)
	}
	armoredEncryptedMessage, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := armor.Decode(strings.NewReader(string(armoredEncryptedMessage)))
	if err != nil {
		t.Error(err)
		return
	}
	md, err := ReadMessage(raw.Body, nil, promptFunc, nil)
	if err != nil {
		t.Error(err)
		return
	}
	_, err = io.ReadAll(md.UnverifiedBody)
	if err == nil {
		t.Fatal("Parsing error expected")
	}
	if err.Error() != expectedErr {
		t.Errorf("Expected error '%s', but got error '%s'", expectedErr, err)
	}
}

func TestMessageWithoutMdc(t *testing.T) {
	armored, err := os.Open("test_data/aead-ocb-asym-key.asc")
	if err != nil {
		t.Fatal(err)
	}
	defer armored.Close()

	el, err := ReadArmoredKeyRing(armored)
	if err != nil {
		t.Fatal(err)
	}

	armoredMessageWithoutMdc, err := ioutil.ReadFile("test_data/sym-message-without-mdc.asc")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("fails with InsecureAllowUnauthenticatedMessages disabled", func(t *testing.T) {
		messageWithoutMdc, err := armor.Decode(bytes.NewReader(armoredMessageWithoutMdc))
		if err != nil {
			t.Fatal(err)
		}

		_, err = ReadMessage(messageWithoutMdc.Body, el, nil, nil)
		if err == nil {
			t.Fatal("reading the message should have failed")
		}
	})

	t.Run("succeeds with InsecureAllowUnauthenticatedMessages enabled", func(t *testing.T) {
		messageWithoutMdc, err := armor.Decode(bytes.NewReader(armoredMessageWithoutMdc))
		if err != nil {
			t.Fatal(err)
		}

		md, err := ReadMessage(messageWithoutMdc.Body, el, nil, &packet.Config{
			InsecureAllowUnauthenticatedMessages: true,
		})
		if err != nil {
			t.Fatal("reading the message should have worked")
		}

		b, err := io.ReadAll(md.UnverifiedBody)
		if err != nil {
			t.Fatal("reading the message should have worked")
		}

		if !bytes.Equal(b, []byte("message without mdc\n")) {
			t.Error("unexpected message content")
		}
	})
}

func TestReadV5Messages(t *testing.T) {
	if packet.V5Disabled {
		t.Skip()
	}
	key, err := ReadArmoredKeyRing(strings.NewReader(keyv5Test))
	if err != nil {
		t.Error(err)
		return
	}
	keyVer, err := ReadArmoredKeyRing(strings.NewReader(certv5Test))
	if err != nil {
		t.Error(err)
		return
	}
	keys := append(key, keyVer...)
	msgReader, err := armor.Decode(strings.NewReader(msgv5Test))
	if err != nil {
		t.Error(err)
		return
	}
	md, err := ReadMessage(msgReader.Body, keys, nil, nil)
	if err != nil {
		t.Error(err)
		return
	}
	contents, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Error(err)
		return
	}
	if string(contents) != "Hello World :)" {
		t.Errorf("decrypted message is wrong: %s", contents)
	}
	if md.SignatureError != nil {
		t.Error("expected no signature error, got:", md.SignatureError)
	}
}
