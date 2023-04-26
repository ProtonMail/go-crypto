// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package s2k

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/hex"
	"testing"

	_ "golang.org/x/crypto/ripemd160"
	_ "golang.org/x/crypto/sha3"
)

var saltedTests = []struct {
	in, out string
}{
	{"hello", "10295ac1"},
	{"world", "ac587a5e"},
	{"foo", "4dda8077"},
	{"bar", "bd8aac6b9ea9cae04eae6a91c6133b58b5d9a61c14f355516ed9370456"},
	{"x", "f1d3f289"},
	{"xxxxxxxxxxxxxxxxxxxxxxx", "e00d7b45"},
}

func TestSalted(t *testing.T) {
	h := sha1.New()
	salt := [4]byte{1, 2, 3, 4}

	for i, test := range saltedTests {
		expected, _ := hex.DecodeString(test.out)
		out := make([]byte, len(expected))
		Salted(out, h, []byte(test.in), salt[:])
		if !bytes.Equal(expected, out) {
			t.Errorf("#%d, got: %x want: %x", i, out, expected)
		}
	}
}

var argon2EncodeTest = []struct {
	in uint32
	out uint8
}{
	{64*1024, 16},
	{64*1024+1, 17},
	{2147483647, 31},
	{2147483649, 31},
	{1, 3},
}

func TestArgon2EncodeTest(t *testing.T) {

	for i, tests := range argon2EncodeTest {
		conf  := &Argon2Config {
			Memory: tests.in,
			DegreeOfParallelism: 1,
		}
		out := conf.EncodedMemory()
		if out != tests.out {
			t.Errorf("#%d, got: %x want: %x", i, out, tests.out)
		}
	}
}


var iteratedTests = []struct {
	in, out string
}{
	{"hello", "83126105"},
	{"world", "6fa317f9"},
	{"foo", "8fbc35b9"},
	{"bar", "2af5a99b54f093789fd657f19bd245af7604d0f6ae06f66602a46a08ae"},
	{"x", "5a684dfe"},
	{"xxxxxxxxxxxxxxxxxxxxxxx", "18955174"},
}

func TestIterated(t *testing.T) {
	h := sha1.New()
	salt := [4]byte{4, 3, 2, 1}

	for i, test := range iteratedTests {
		expected, _ := hex.DecodeString(test.out)
		out := make([]byte, len(expected))
		Iterated(out, h, []byte(test.in), salt[:], 31)
		if !bytes.Equal(expected, out) {
			t.Errorf("#%d, got: %x want: %x", i, out, expected)
		}
	}
}

var argonTestSalt = "12345678"
var argon2DeriveTests = []struct {
	in, out string
}{
	{"hello", "bf69293d2961bbbebe4c64c745cf44d4"},
	{"world", "dc1bb06234b61c9542d8cf73e2e279d3"},
	{"foo", "7f6baa1c21f0e7eec16cf8fde866775d"},
	{"bar", "2826332c8e62d0cf97cc08f243c5cc9135654bf3a8e46d6a4b4637e42eda2fa0"},
	{"x", "89e5b79435132b98bbcad321532ae7e09f87ac96deca272d6012d367e6350b7d"},
	{"xxxxxxxxxxxxxxxxxxxxxxx", "de0f978013283457e29f0682e0078ad654e7c21bc72886c914c012e56fd5dc91"},
}

func TestArgon2Derive(t *testing.T) {
	salt := []byte(argonTestSalt)

	for i, test := range argon2DeriveTests {
		expected, _ := hex.DecodeString(test.out)
		out := make([]byte, len(expected))
		Argon2(out, []byte(test.in), salt[:], 3, 4, 16)
		if !bytes.Equal(expected, out) {
			t.Errorf("#%d, got: %x want: %x", i, out, expected)
		}
	}
}

var parseTests = []struct {
	spec, in, out string
	dummyKey      bool
	params        Params
}{
	/* Simple with SHA1 */
	{"0002", "hello", "aaf4c61d", false,
		Params{SimpleS2K, 0x02, [16]byte{}, 0, 0, 0, 0}},
	/* Salted with SHA1 */
	{"01020102030405060708", "hello", "f4f7d67e", false,
		Params{SaltedS2K, 0x02, [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 0, 0, 0, 0}},
	/* Iterated with SHA1 */
	{"03020102030405060708f1", "hello", "f2a57b7c", false,
		Params{IteratedSaltedS2K, 0x02, [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 0xf1, 0, 0, 0}},
	/* Argon2 */
	{"0401020304050607080102030405060708030416", "hello", "c7745927", false,
		Params{Argon2S2K, 0x00, [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, 0, 0x03, 0x04, 0x16}},
	/* GNU dummy S2K */
	{"6502474e5501", "", "", true,
		Params{GnuS2K, 0x02, [16]byte{}, 0, 0, 0, 0}},
}

func TestParseIntoParams(t *testing.T) {
	for i, test := range parseTests {
		spec, _ := hex.DecodeString(test.spec)
		buf := bytes.NewBuffer(spec)
		params, err := ParseIntoParams(buf)
		if err != nil {
			t.Errorf("%d: ParseIntoParams returned error: %s", i, err)
			continue
		}

		if test.params.mode != params.mode || test.params.hashId != params.hashId || test.params.countByte != params.countByte ||
			!bytes.Equal(test.params.salt(), params.salt()) {
			t.Errorf("%d: Wrong config, got: %+v want: %+v", i, params, test.params)
		}

		if params.Dummy() != test.dummyKey {
			t.Errorf("%d: Got GNU dummy %v, expected %v", i, params.Dummy(), test.dummyKey)
		}

		if !test.dummyKey {
			expectedHash, _ := hex.DecodeString(test.out)
			out := make([]byte, len(expectedHash))

			f, err := params.Function()
			if err != nil {
				t.Errorf("%d: params.Function() returned error: %s", i, err)
				continue
			}
			f(out, []byte(test.in))
			if !bytes.Equal(out, expectedHash) {
				t.Errorf("%d: Wrong output got: %x want: %x", i, out, expectedHash)
			}
		}

		var reserialized bytes.Buffer
		err = params.Serialize(&reserialized)
		if err != nil {
			t.Errorf("%d: params.Serialize() returned error: %s", i, err)
			continue
		}
		if !bytes.Equal(reserialized.Bytes(), spec) {
			t.Errorf("%d: Wrong reserialized got: %x want: %x", i, reserialized.Bytes(), spec)
		}
		if testing.Short() {
			break
		}
	}
}

func TestSerializeSaltedOK(t *testing.T) {
	hashes := []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512, crypto.SHA224, crypto.SHA3_256,
		crypto.SHA3_512}
	for _, h := range hashes {
		params := testSerializeConfigOK(t, &Config{S2KMode: SaltedS2K, Hash: h, PassphraseIsHighEntropy: true})

		if params.mode != SaltedS2K {
			t.Fatalf("Wrong mode, expected %d got %d", SaltedS2K, params.mode)
		}
	}
}

func TestSerializeSaltedLowEntropy(t *testing.T) {
	hashes := []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512, crypto.SHA224, crypto.SHA3_256,
		crypto.SHA3_512}
	for _, h := range hashes {
		params := testSerializeConfigOK(t, &Config{S2KMode: SaltedS2K, Hash: h})

		if params.mode != IteratedSaltedS2K {
			t.Fatalf("Wrong mode, expected %d got %d", IteratedSaltedS2K, params.mode)
		}

		if params.countByte != 224 { // The default case. Corresponding to 16777216
			t.Fatalf("Wrong count byte, expected %d got %d", 224, params.countByte)
		}
	}
}

func TestSerializeSaltedIteratedOK(t *testing.T) {
	hashes := []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512, crypto.SHA224, crypto.SHA3_256,
		crypto.SHA3_512}
	// {input, expected}
	testCounts := [][]int{{-1, 96}, {0, 224}, {1024, 96}, {65536, 96}, {4063232, 191}, {65011712, 255}}
	for _, h := range hashes {
		for _, c := range testCounts {
			params := testSerializeConfigOK(t, &Config{Hash: h, S2KCount: c[0]})

			if params.mode != IteratedSaltedS2K {
				t.Fatalf("Wrong mode, expected %d got %d", IteratedSaltedS2K, params.mode)
			}

			if int(params.countByte) != c[1] {
				t.Fatalf("Wrong count byte, expected %d got %d", c[1], params.countByte)
			}
		}
	}
}

func TestSerializeOKArgon(t *testing.T) {
	config := &Config{
		S2KMode: Argon2S2K,
		Argon2Config: &Argon2Config{NumberOfPasses: 3, DegreeOfParallelism: 4, Memory: 64*1024},
	}

	params := testSerializeConfigOK(t, config)

	if params.mode != Argon2S2K {
		t.Fatalf("Wrong mode, expected %d got %d", Argon2S2K, params.mode)
	}
}

func testSerializeConfigOK(t *testing.T, c *Config) *Params {
	buf := bytes.NewBuffer(nil)
	key := make([]byte, 16)
	passphrase := []byte("testing")
	err := Serialize(buf, key, rand.Reader, passphrase, c)
	if err != nil {
		t.Fatalf("failed to serialize with config %+v: %s", c, err)
	}

	f, err := Parse(bytes.NewBuffer(buf.Bytes()))
	if err != nil {
		t.Fatalf("failed to reparse: %s", err)
	}
	key2 := make([]byte, len(key))
	f(key2, passphrase)
	if !bytes.Equal(key2, key) {
		t.Errorf("keys don't match: %x (serialied) vs %x (parsed)", key, key2)
	}

	params, err := ParseIntoParams(bytes.NewBuffer(buf.Bytes()))
	if err != nil {
		t.Fatalf("failed to parse params: %s", err)
	}

	return params
}
