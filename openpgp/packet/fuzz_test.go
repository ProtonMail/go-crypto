//go:build go1.18
// +build go1.18

package packet

import (
	"bytes"
	"testing"
)

func FuzzPackets(f *testing.F) {
	f.Add([]byte("\x980\x040000\x16\t+\x06\x01\x04\x01\xdaG\x0f\x01\x00\x00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Read(bytes.NewReader(data))
	})
}
