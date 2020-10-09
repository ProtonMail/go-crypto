// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package encoding

import (
	"io"
)

func NewCanonicalTextWriteCloser(w io.WriteCloser) io.WriteCloser {
	return &canonicalTextWriteCloser{w, 0}
}

func NewCanonicalTextReader(r io.Reader) io.Reader {
	return &canonicalTextReader{r, 0}
}


type canonicalTextWriteCloser struct {
	w io.WriteCloser
	s int
}

type canonicalTextReader struct {
	r io.Reader
	s int
}

var newline = []byte{'\r', '\n'}

func WriteCanonical(cw io.Writer, buf []byte, s *int) (int, error) {
	start := 0
	for i, c := range buf {
		switch *s {
			case 0:
				if c == '\r' {
					*s = 1
				} else if c == '\n' {
					cw.Write(buf[start:i])
					cw.Write(newline)
					start = i + 1
				}
			case 1:
				*s = 0
		}
	}
	cw.Write(buf[start:])
	return len(buf), nil
}

func ReadCanonical(r io.Reader, buf []byte, s *int) (int, error) {
	j := 0
	i := 0
	var err error

	if *s == 1 {
		_, err = r.Read(buf[:1])
		if buf[0] != '\n' {
			buf[j] = '\r'
			j += 1
		}
		buf[j] = buf[0]
		j += 1
		*s = 0
	}

	l, err := r.Read(buf[j:])
	for i < l {
		c := buf[i]
		switch *s {
			case 0:
				if c == '\r' {
					*s = 1
				} else {
					buf[j] = c
					j += 1
				}
			case 1:
				if c != '\n' {
					buf[j] = '\r'
					j += 1
				}
				buf[j] = c
				j += 1
				*s = 0
		}
		i += 1
	}

	if *s == 1 && l < len(buf) {
		buf[j] = '\r'
		j += 1
		*s = 0
	}

	return j, err
}

func (ctc *canonicalTextWriteCloser) Write(buf []byte) (int, error) {
	return WriteCanonical(ctc.w, buf, &ctc.s)
}

func (ctc *canonicalTextWriteCloser) Close() error {
	return ctc.w.Close()
}

func (ctr *canonicalTextReader) Read(buf []byte) (int, error) {
	return ReadCanonical(ctr.r, buf, &ctr.s)
}