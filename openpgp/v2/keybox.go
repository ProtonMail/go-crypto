package v2

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
)

// Keybox blob types (byte at offset 4 of every blob).
const (
	KBXBlobTypeEmpty   = 0
	KBXBlobTypeHeader  = 1
	KBXBlobTypeOpenPGP = 2
	KBXBlobTypeX509    = 3
)

// ReadKeyBoxKeyRing reads the OpenPGP keys stored in a GnuPG keybox (.kbx)
// file and returns them as an EntityList, ignoring X.509 and empty blobs.
//
// This implementation is deliberately "dumb" as it simply aims to provide
// keyring "read" compatibility and nothing fancy that the keybox format would
// otherwise allow.
func ReadKeyBoxKeyRing(r io.Reader) (el EntityList, err error) {
	br := bufio.NewReader(r)
	var hdr [16]byte // not 20 bytes because we never read the last 4 bytes
	headerBlob := true

	for {
		// Every blob begins with a big-endian u32 length covering the whole
		// blob, then a one-byte type at offset 4.
		//
		// A clean EOF on the length read marks the end of the file; a partial
		// read means the file is truncated, while any other error is a genuine
		// I/O failure and is returned unchanged.
		if _, err := io.ReadFull(br, hdr[:4]); err != nil {
			if err == io.EOF {
				break
			}
			if err == io.ErrUnexpectedEOF {
				return nil, errors.StructuralError("truncated keybox blob length")
			}
			return nil, err
		}

		blobLength := uint64(binary.BigEndian.Uint32(hdr[:4]))
		// 4-byte length + 1 type byte: the minimum to read a blob's framing
		if blobLength < 5 {
			return nil, errors.StructuralError(fmt.Sprintf("invalid keybox blob length %d", blobLength))
		}

		// Read the type byte (offset 4)
		// remaining tracks the number of bytes left in the blob after what we
		// have already consumed so we can discard (skip) them if needed
		if err := readFull(br, hdr[4:5], "truncated keybox blob"); err != nil {
			return nil, err
		}
		remaining := blobLength - 5
		blobType := hdr[4]

		switch {
		case headerBlob:
			// The header blob (first blob in the file) require the "KBXf" magic
			// bytes at offset 8 as a sanity check that this really is a keybox.
			if blobLength < 12 {
				return nil, errors.InvalidArgumentError("not a keybox file (header blob too short)")
			}
			if err := readFull(br, hdr[5:12], "truncated keybox header"); err != nil { // offsets 5..11
				return nil, err
			}
			remaining -= 7
			if blobType != KBXBlobTypeHeader || string(hdr[8:12]) != "KBXf" {
				return nil, errors.InvalidArgumentError("not a keybox file (missing KBXf magic)")
			}
			if err := discard(br, remaining); err != nil {
				return nil, err
			}

			headerBlob = false

		case blobType == KBXBlobTypeOpenPGP:
			// u32 @ 8  -> offset of the embedded keyblock (from blob start)
			// u32 @ 12 -> length of the embedded keyblock
			if blobLength < 16 {
				return nil, errors.StructuralError("keybox OpenPGP blob too short")
			}
			if err := readFull(br, hdr[5:16], "truncated keybox OpenPGP blob"); err != nil {
				return nil, err
			}

			dataOffset := uint64(binary.BigEndian.Uint32(hdr[8:12]))
			dataLength := uint64(binary.BigEndian.Uint32(hdr[12:16]))
			if dataLength == 0 || dataOffset < 16 || dataOffset > blobLength || dataLength > blobLength-dataOffset {
				return nil, errors.StructuralError("keybox keyblock out of bounds")
			}

			// Skip forward to the keyblock, then stream exactly dataLen bytes
			// into the parser. The embedded keyblock is byte-identical to a
			// legacy/classic keyring entry, so ReadKeyRing handles it unchanged.
			if err := discard(br, dataOffset-16); err != nil { // we're already @ 16 so we need to subtract that
				return nil, err
			}
			lr := &io.LimitedReader{R: br, N: int64(dataLength)}
			blobEl, err := ReadKeyRing(lr)
			if err != nil {
				return nil, err
			}
			el = append(el, blobEl...)

			// Drain any keyblock bytes the parser left, then the blob's
			// trailing bytes (reserved space, padding, checksum).
			if err := discard(br, uint64(lr.N)); err != nil {
				return nil, err
			}
			if err := discard(br, blobLength-dataOffset-dataLength); err != nil {
				return nil, err
			}

		default:
			// Empty, X.509 and any unknown blob type: skip the remainder.
			if err := discard(br, remaining); err != nil {
				return nil, err
			}
		}
	}

	return el, nil
}

// readFull fills buf from r. A truncated read (EOF before buf is full) is
// reported as a StructuralError using truncMsg; any other read error is a
// genuine I/O failure and is returned unchanged.
func readFull(r io.Reader, buf []byte, truncMsg string) error {
	if _, err := io.ReadFull(r, buf); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return errors.StructuralError(truncMsg)
		}
		return err
	}
	return nil
}

// discard skips exactly n bytes from r, treating a short read as a truncated
// (and therefore corrupted) keybox. Other read errors are returned unchanged.
func discard(r io.Reader, n uint64) error {
	if n == 0 {
		return nil
	}
	skipped, err := io.CopyN(io.Discard, r, int64(n))
	if err == io.EOF || (err == nil && uint64(skipped) != n) {
		return errors.StructuralError("truncated keybox blob")
	}
	return err
}

// IsKeyBox reports whether rs begins like a GnuPG keybox file: a header blob
// carrying the "KBXf" magic at offset 8. Use it to choose between
// ReadKeyBoxKeyRing and ReadKeyRing when the input format is unknown.
//
// It reads the framing bytes then seeks back, leaving rs at its original
// position so the same reader can be passed straight to ReadKeyBoxKeyRing or
// ReadKeyRing.
func IsKeyBox(rs io.ReadSeeker) (bool, error) {
	var hdr [12]byte

	n, err := io.ReadFull(rs, hdr[:])
	// Restore the position regardless of the read outcome, rewinding exactly
	// what we consumed (works whether rs started at offset 0 or not).
	if _, serr := rs.Seek(-int64(n), io.SeekCurrent); serr != nil {
		return false, serr
	}

	// A short stream (EOF / unexpected EOF) simply isn't a keybox; any other
	// error is a genuine I/O failure.
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return false, err
	}

	return n >= 12 && hdr[4] == KBXBlobTypeHeader && string(hdr[8:12]) == "KBXf", nil
}
