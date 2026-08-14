package packet

import (
	"bytes"
	"testing"
)

const embeddedSignatureSubpacketByte = 32

func sigBodyWithEmbedded(sigType byte, embedded []byte) []byte {
	var hashed []byte
	hashed = append(hashed, 0x05, 0x02, 0x00, 0x00, 0x00, 0x01) // creation time subpacket
	if embedded != nil {
		sub := append([]byte{embeddedSignatureSubpacketByte}, embedded...)
		hashed = append(hashed, byte(len(sub)))
		hashed = append(hashed, sub...)
	}

	var body []byte
	body = append(body, 0x04, sigType, 0x01, 0x08)
	body = append(body, byte(len(hashed)>>8), byte(len(hashed)))
	body = append(body, hashed...)
	body = append(body, 0x00, 0x00) // unhashed subpackets length
	body = append(body, 0x00, 0x00) // hash tag
	body = append(body, 0x00, 0x00) // RSA signature MPI, 0 bits
	return body
}

// A primary key binding signature must not contain an embedded signature, so a
// nested embedding is rejected while parsing the inner signature.
func TestNestedEmbeddedSignatureRejected(t *testing.T) {
	deepest := sigBodyWithEmbedded(byte(SigTypePrimaryKeyBinding), nil)
	inner := sigBodyWithEmbedded(byte(SigTypePrimaryKeyBinding), deepest)
	outer := sigBodyWithEmbedded(byte(SigTypeSubkeyBinding), inner)
	pkt := append([]byte{0xc0 | 2, byte(len(outer))}, outer...)

	if _, err := Read(bytes.NewReader(pkt)); err == nil {
		t.Fatal("expected an error for nested embedded signatures, got nil")
	}
}
