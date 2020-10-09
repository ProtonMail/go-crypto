// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package encoding

import (
	"bytes"
	"testing"
)

type bufferCloser struct {
	buf *bytes.Buffer
}

func (c bufferCloser) Write(b []byte) (n int, err error) {
	return c.buf.Write(b)
}

func (c bufferCloser) Close() error {
	return nil
}

func testCanonicalTextWriteCloser(t *testing.T, input, expected string) {
	w := bufferCloser{bytes.NewBuffer(nil)}
	c := NewCanonicalTextWriteCloser(&w)
	_, err := c.Write([]byte(input))
	if err != nil {
		t.Errorf("unexpected error on input: %x", input)
	}
	err = c.Close()
	if err != nil {
		t.Errorf("unexpected error on input: %x", input)
	}

	if expected != string(w.buf.Bytes()) {
		t.Errorf("input: %x got: %x want: %x", input, string(w.buf.Bytes()), expected)
	}
}

func testCanonicalTextReader(t *testing.T, input, expected string) {
	r := bytes.NewBuffer([]byte(input))
	out := make([]byte, len(input) + 1)
	c := NewCanonicalTextReader(r)
	l, err := c.Read(out)
	if err != nil {
		t.Errorf("unexpected error on input: %x", input)
	}

	if expected != string(out[:l]) {
		t.Errorf("input: %x got: %x want: %x", input, string(out[:l]), expected)
	}
}

func TestCanonicalText(t *testing.T) {
	testCanonicalTextWriteCloser(t, "foo\n", "foo\r\n")
	testCanonicalTextWriteCloser(t, "foo", "foo")
	testCanonicalTextWriteCloser(t, "foo\r\n", "foo\r\n")
	testCanonicalTextWriteCloser(t, "foo\r\nbar", "foo\r\nbar")
	testCanonicalTextWriteCloser(t, "foo\r\nbar\n\n", "foo\r\nbar\r\n\r\n")

	testCanonicalTextReader(t, "foo\r\n", "foo\n")
	testCanonicalTextReader(t, "foo", "foo")
	testCanonicalTextReader(t, "foo\r", "foo\r")
	testCanonicalTextReader(t, "foo\rbar", "foo\rbar")
	testCanonicalTextReader(t, "foo\n", "foo\n")
	testCanonicalTextReader(t, "foo\nbar", "foo\nbar")
	testCanonicalTextReader(t, "foo\r\nbar\n\r\n", "foo\nbar\n\n")
}
