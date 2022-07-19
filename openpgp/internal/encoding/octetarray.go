// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package encoding

import (
	"io"
)

// OctetArray is used to store a fixed-length field
type OctetArray struct {
	length int
	bytes []byte
}

// NewOctetArray returns a OID initialized with bytes.
func NewOctetArray(bytes []byte) *OctetArray {
	return &OctetArray{
		length: len(bytes),
		bytes: bytes,
	}
}

func NewEmptyOctetArray(length int) *OctetArray {
	return &OctetArray{
		length: length,
		bytes: nil,
	}
}

// Bytes returns the decoded data.
func (o *OctetArray) Bytes() []byte {
	return o.bytes
}

// BitLength is the size in bits of the decoded data.
func (o *OctetArray) BitLength() uint16 {
	return uint16(o.length * 8)
}

// EncodedBytes returns the encoded data.
func (o *OctetArray) EncodedBytes() []byte {
	if len(o.bytes) != o.length {
		panic("invalid length")
	}
	return o.bytes
}

// EncodedLength is the size in bytes of the encoded data.
func (o *OctetArray) EncodedLength() uint16 {
	return uint16(o.length)
}

// ReadFrom reads into b the next OID from r.
func (o *OctetArray) ReadFrom(r io.Reader) (int64, error) {
	o.bytes = make([]byte, o.length)

	nn, err := io.ReadFull(r, o.bytes)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}

	return int64(nn), err
}
