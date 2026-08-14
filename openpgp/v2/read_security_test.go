package v2

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func packetLength(n int) []byte {
	switch {
	case n < 192:
		return []byte{byte(n)}
	case n < 8384:
		n -= 192
		return []byte{byte(n>>8) + 192, byte(n)}
	default:
		return []byte{0xff, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
}

func wrapPacket(tag byte, body []byte) []byte {
	out := []byte{0xc0 | tag}
	out = append(out, packetLength(len(body))...)
	return append(out, body...)
}

func sigNoIssuer() []byte {
	creation := []byte{0x05, 0x02, 0x00, 0x00, 0x00, 0x01}
	var body bytes.Buffer
	body.WriteByte(0x04)
	body.WriteByte(0x00)
	body.WriteByte(0x01)
	body.WriteByte(0x08)
	binary.Write(&body, binary.BigEndian, uint16(len(creation)))
	body.Write(creation)
	binary.Write(&body, binary.BigEndian, uint16(0))
	body.Write([]byte{0x00, 0x00})
	body.Write([]byte{0x00, 0x00})
	return wrapPacket(2, body.Bytes())
}

func literalPacket(data []byte) []byte {
	var body bytes.Buffer
	body.WriteByte('b')
	body.WriteByte(0x00)
	body.Write([]byte{0x00, 0x00, 0x00, 0x00})
	body.Write(data)
	return wrapPacket(11, body.Bytes())
}

func TestReadMessageNilIssuerNoPanic(t *testing.T) {
	msg := append(sigNoIssuer(), literalPacket([]byte("hello"))...)
	md, err := ReadMessage(bytes.NewReader(msg), nil, nil, nil)
	if err == nil {
		if md != nil && md.UnverifiedBody != nil {
			io.Copy(io.Discard, md.UnverifiedBody)
		}
		t.Fatal("expected an error for signature without issuer, got nil")
	}
}
