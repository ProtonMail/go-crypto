package openpgp

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
	"time"
)

func secPacketLength(n int) []byte {
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

func secWrapPacket(tag byte, body []byte) []byte {
	out := []byte{0xc0 | tag}
	out = append(out, secPacketLength(len(body))...)
	return append(out, body...)
}

func secOnePassSig(keyId uint64) []byte {
	var body bytes.Buffer
	body.WriteByte(0x03)
	body.WriteByte(0x00)
	body.WriteByte(0x08)
	body.WriteByte(0x01)
	var id [8]byte
	binary.BigEndian.PutUint64(id[:], keyId)
	body.Write(id[:])
	body.WriteByte(0x01)
	return secWrapPacket(4, body.Bytes())
}

func secLiteral(data []byte) []byte {
	var body bytes.Buffer
	body.WriteByte('b')
	body.WriteByte(0x00)
	body.Write([]byte{0x00, 0x00, 0x00, 0x00})
	body.Write(data)
	return secWrapPacket(11, body.Bytes())
}

func secSigNoIssuer() []byte {
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
	return secWrapPacket(2, body.Bytes())
}

func TestReadV1NilIssuerNoPanic(t *testing.T) {
	entity, err := NewEntity("test", "", "test@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	signingKey, ok := entity.SigningKey(time.Now())
	if !ok {
		t.Fatal("no signing key")
	}

	var msg []byte
	msg = append(msg, secOnePassSig(signingKey.PublicKey.KeyId)...)
	msg = append(msg, secLiteral([]byte("hello"))...)
	msg = append(msg, secSigNoIssuer()...)

	md, err := ReadMessage(bytes.NewReader(msg), EntityList{entity}, nil, nil)
	if err != nil {
		return
	}
	io.Copy(io.Discard, md.UnverifiedBody)
}
