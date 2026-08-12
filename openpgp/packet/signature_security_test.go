package packet

import (
	"bytes"
	"runtime"
	"testing"
)

func TestV6SignatureHugeSubpacketLength(t *testing.T) {
	body := []byte{
		0x06,                   // version 6
		0x00,                   // signature type
		0x01,                   // pubkey algo
		0x08,                   // hash algo
		0x7f, 0xff, 0xff, 0xff, // hashed subpacket length (~2 GiB)
	}
	pkt := append([]byte{0xc0 | 2, byte(len(body))}, body...)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err := Read(bytes.NewReader(pkt))
	runtime.ReadMemStats(&after)

	if err == nil {
		t.Fatal("expected an error for oversized hashed subpacket length, got nil")
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 10<<20 {
		t.Fatalf("Read allocated %d bytes for a tiny packet declaring a huge subpacket length", allocated)
	}
}
