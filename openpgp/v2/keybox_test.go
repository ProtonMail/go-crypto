package v2

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	goerrors "errors"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
)

// kbxHeaderBlob builds a valid keybox header blob (type 1, with "KBXf" magic
// at offset 8.
func kbxHeaderBlob() []byte {
	blob := make([]byte, 20)
	blob[4] = KBXBlobTypeHeader
	blob[5] = 1 // version
	copy(blob[8:12], []byte("KBXf"))
	binary.BigEndian.PutUint32(blob[0:4], uint32(len(blob)))
	return blob
}

// kbxOpenPGPBlob builds a type-2 (OpenPGP) blob embedding keyblock. lead is the
// number of filler bytes placed between the 16-byte blob header and the
// keyblock (so the parser must skip forward to reach it); trail is the number
// of trailing bytes after the keyblock (reserved space / padding / checksum).
func kbxOpenPGPBlob(keyblock []byte, lead, trail int) []byte {
	dataOffset := 16 + lead
	total := dataOffset + len(keyblock) + trail
	blob := make([]byte, total)
	blob[4] = KBXBlobTypeOpenPGP
	blob[5] = 1 // version
	binary.BigEndian.PutUint32(blob[8:12], uint32(dataOffset))
	binary.BigEndian.PutUint32(blob[12:16], uint32(len(keyblock)))
	copy(blob[dataOffset:], keyblock)
	binary.BigEndian.PutUint32(blob[0:4], uint32(total))
	return blob
}

// kbxRawBlob builds an opaque blob of the given type and total length, with all
// bytes beyond the framing left zero. Used for empty / X.509 / unknown blobs
// that the parser is expected to skip.
func kbxRawBlob(blobType byte, length int) []byte {
	blob := make([]byte, length)
	blob[4] = blobType
	binary.BigEndian.PutUint32(blob[0:4], uint32(length))
	return blob
}

// kbxFile concatenates blobs into a single keybox byte stream.
func kbxFile(blobs ...[]byte) []byte {
	var out []byte
	for _, b := range blobs {
		out = append(out, b...)
	}
	return out
}

// bytesFromHex decodes a hex test fixture, panicking on malformed input.
func bytesFromHex(s string) []byte {
	data, err := hex.DecodeString(s)
	if err != nil {
		panic("bytesFromHex: bad input")
	}
	return data
}

// keyIds returns the lower-64-bit key IDs of an entity list's primary keys.
func keyIds(el EntityList) []uint64 {
	ids := make([]uint64, len(el))
	for i, e := range el {
		ids[i] = e.PrimaryKey.KeyId
	}
	return ids
}

// The keybox parser (ReadKeyBoxKeyRing) only cares about a blob's framing and
// then hands the embedded keyblock straight to ReadKeyRing, so the synthesized
// blobs below wrap the *real* key bytes already defined in
// read_write_test_data.go (testKeys1And2Hex, dsaTestKeyHex, p256TestKeyHex).
// This exercises every branch deterministically without external fixtures.

func TestReadKeyBoxKeyRing(t *testing.T) {
	// A header, then two OpenPGP blobs (the first carrying the two keys from
	// testKeys1And2Hex, the second the single P-256 key), with empty and X.509
	// blobs interleaved to confirm they are skipped.
	kbx := kbxFile(
		kbxHeaderBlob(),
		kbxRawBlob(KBXBlobTypeEmpty, 8),
		kbxOpenPGPBlob(bytesFromHex(testKeys1And2Hex), 0, 0),
		kbxRawBlob(KBXBlobTypeX509, 24),
		kbxOpenPGPBlob(bytesFromHex(p256TestKeyHex), 0, 0),
	)

	el, err := ReadKeyBoxKeyRing(bytes.NewReader(kbx))
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(el) != 3 {
		t.Fatalf("got %d entities, want 3", len(el))
	}
	if uint32(el[0].PrimaryKey.KeyId) != 0xC20C31BB ||
		uint32(el[1].PrimaryKey.KeyId) != 0x1E35246B ||
		el[2].PrimaryKey.KeyId != testKeyP256KeyId {
		t.Errorf("bad keyring: %v", keyIds(el))
	}
}

func TestReadKeyBoxKeyRingLeadingAndTrailing(t *testing.T) {
	// The keyblock is not flush against the blob header (lead) and the blob has
	// reserved trailing bytes (trail); both must be skipped cleanly.
	kbx := kbxFile(
		kbxHeaderBlob(),
		kbxOpenPGPBlob(bytesFromHex(dsaTestKeyHex), 12, 20),
	)

	el, err := ReadKeyBoxKeyRing(bytes.NewReader(kbx))
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(el) != 1 || el[0].PrimaryKey.KeyId != testKey3KeyId {
		t.Errorf("bad keyring: %v", keyIds(el))
	}
}

func TestReadKeyBoxKeyRingSkipsNonOpenPGP(t *testing.T) {
	// A keybox with only a header plus non-OpenPGP blobs yields no entities.
	kbx := kbxFile(
		kbxHeaderBlob(),
		kbxRawBlob(KBXBlobTypeX509, 32),
		kbxRawBlob(KBXBlobTypeEmpty, 16),
		kbxRawBlob(99, 10), // unknown type
	)

	el, err := ReadKeyBoxKeyRing(bytes.NewReader(kbx))
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(el) != 0 {
		t.Errorf("got %d entities, want 0", len(el))
	}
}

func TestReadKeyBoxKeyRingEmptyInput(t *testing.T) {
	// A clean EOF on the very first length read is the normal end-of-file.
	el, err := ReadKeyBoxKeyRing(bytes.NewReader(nil))
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(el) != 0 {
		t.Errorf("got %d entities, want 0", len(el))
	}
}

func TestReadKeyBoxKeyRingNotAKeybox(t *testing.T) {
	// First blob is well-framed and long enough, but lacks the KBXf magic.
	bad := kbxHeaderBlob()
	copy(bad[8:12], []byte("XXXX"))

	_, err := ReadKeyBoxKeyRing(bytes.NewReader(bad))
	assertInvalidArgument(t, err)
}

func TestReadKeyBoxKeyRingWrongHeaderType(t *testing.T) {
	// Correct magic but the first blob is not a header-type blob.
	bad := kbxHeaderBlob()
	bad[4] = KBXBlobTypeOpenPGP

	_, err := ReadKeyBoxKeyRing(bytes.NewReader(bad))
	assertInvalidArgument(t, err)
}

func TestReadKeyBoxKeyRingHeaderTooShort(t *testing.T) {
	// First blob is shorter than the 12 bytes needed to hold the magic.
	bad := kbxRawBlob(KBXBlobTypeHeader, 8)

	_, err := ReadKeyBoxKeyRing(bytes.NewReader(bad))
	assertInvalidArgument(t, err)
}

func TestReadKeyBoxKeyRingInvalidLength(t *testing.T) {
	// A blob length below the 5-byte framing minimum is structurally invalid.
	bad := []byte{0x00, 0x00, 0x00, 0x03}

	_, err := ReadKeyBoxKeyRing(bytes.NewReader(bad))
	assertStructural(t, err)
}

func TestReadKeyBoxKeyRingTruncatedLength(t *testing.T) {
	// A partial length prefix (fewer than 4 bytes) means a truncated file.
	_, err := ReadKeyBoxKeyRing(bytes.NewReader([]byte{0x00, 0x00}))
	assertStructural(t, err)
}

func TestReadKeyBoxKeyRingTruncatedBlob(t *testing.T) {
	// A valid header followed by an OpenPGP blob whose declared length runs
	// past the available bytes.
	good := kbxFile(
		kbxHeaderBlob(),
		kbxOpenPGPBlob(bytesFromHex(p256TestKeyHex), 0, 0),
	)
	truncated := good[:len(good)-10]

	_, err := ReadKeyBoxKeyRing(bytes.NewReader(truncated))
	assertStructural(t, err)
}

func TestReadKeyBoxKeyRingKeyblockOutOfBounds(t *testing.T) {
	// A keyblock length that exceeds the blob's own bounds must be rejected
	// rather than read past the blob.
	blob := kbxOpenPGPBlob(bytesFromHex(p256TestKeyHex), 0, 0)
	binary.BigEndian.PutUint32(blob[12:16], 0xFFFFFFFF)
	kbx := kbxFile(kbxHeaderBlob(), blob)

	_, err := ReadKeyBoxKeyRing(bytes.NewReader(kbx))
	assertStructural(t, err)
}

func TestReadKeyBoxKeyRingZeroKeyblockLength(t *testing.T) {
	blob := kbxOpenPGPBlob(bytesFromHex(p256TestKeyHex), 0, 0)
	binary.BigEndian.PutUint32(blob[12:16], 0) // zero keyblock length
	kbx := kbxFile(kbxHeaderBlob(), blob)

	_, err := ReadKeyBoxKeyRing(bytes.NewReader(kbx))
	assertStructural(t, err)
}

func TestIsKeyBox(t *testing.T) {
	keybox := kbxFile(kbxHeaderBlob(), kbxOpenPGPBlob(bytesFromHex(p256TestKeyHex), 0, 0))

	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"keybox", keybox, true},
		{"plain keyring", bytesFromHex(testKeys1And2Hex), false},
		{"too short", []byte{0x00, 0x00, 0x00, 0x14, 0x01}, false},
		{"empty", nil, false},
		{"wrong magic", func() []byte { b := kbxHeaderBlob(); copy(b[8:12], "d3ad"); return b }(), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IsKeyBox(bytes.NewReader(tt.data))
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if got != tt.want {
				t.Errorf("IsKeyBox = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsKeyBoxPreservesPosition(t *testing.T) {
	// IsKeyBox must rewind the reader so it can be handed straight to
	// ReadKeyBoxKeyRing afterwards.
	keybox := kbxFile(kbxHeaderBlob(), kbxOpenPGPBlob(bytesFromHex(testKeys1And2Hex), 0, 0))
	r := bytes.NewReader(keybox)

	ok, err := IsKeyBox(r)
	if err != nil || !ok {
		t.Fatalf("IsKeyBox = %v, %v; want true, nil", ok, err)
	}

	el, err := ReadKeyBoxKeyRing(r)
	if err != nil {
		t.Fatalf("ReadKeyBoxKeyRing after IsKeyBox: %s", err)
	}
	if len(el) != 2 {
		t.Errorf("got %d entities after IsKeyBox, want 2", len(el))
	}
}

// TestReadKeyBoxKeyRingRealKeyBox parses a real GnuPG-generated keybox
func TestReadKeyBoxKeyRingRealKeyBox(t *testing.T) {
	if keyBoxHex == "" {
		t.Skip("keyboxRealHex not populated; see keybox_test_data.go")
	}

	el, err := ReadKeyBoxKeyRing(bytes.NewReader(bytesFromHex(keyBoxHex)))
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(el) != len(keyBoxKeyIds) {
		t.Fatalf("got %d entities, want %d", len(el), len(keyBoxKeyIds))
	}
	for i, want := range keyBoxKeyIds {
		if el[i].PrimaryKey.KeyId != want {
			t.Errorf("entity %d: key ID = %016X, want %016X", i, el[i].PrimaryKey.KeyId, want)
		}
	}
}

func assertStructural(t *testing.T, err error) {
	t.Helper()
	var se errors.StructuralError
	if !goerrors.As(err, &se) {
		t.Fatalf("got error %v (%T), want errors.StructuralError", err, err)
	}
}

func assertInvalidArgument(t *testing.T, err error) {
	t.Helper()
	var ie errors.InvalidArgumentError
	if !goerrors.As(err, &ie) {
		t.Fatalf("got error %v (%T), want errors.InvalidArgumentError", err, err)
	}
}
