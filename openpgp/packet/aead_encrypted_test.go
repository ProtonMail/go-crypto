// Copyright (C) 2019 ProtonTech AG

package packet

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	mathrand "math/rand"
	"testing"
)

var (
	maxChunkSizeByte = byte(0x09) // 1<<(7+9) = 65536 bytes
)

const (
	keyLength  = 16
	iterations = 100
	// Approx. plaintext length, in amount of chunks
	maxChunks = 200
)

func TestAeadNewAEADInstanceWithDefaultConfig(t *testing.T) {
	key := make([]byte, keyLength)
	if _, err := rand.Read(key); err != nil {
		t.Error(err)
	}
	var modesToPrefix = map[AEADMode][]byte{
		// Packet tags in new format
		EaxID: []byte{0xd4, 0x01, 0x07, 0x01, 0x01},
		OcbID: []byte{0xd4, 0x01, 0x07, 0x02, 0x01},
	}
	for mode, prefix := range modesToPrefix {
		conf := &AEADConfig{mode: AEADMode(mode)}
		_, header, err := initAlgorithm(key, conf)
		if err != nil {
			t.Errorf("Error creating valid AEAD from default: %s", err)
		}
		if !bytes.Equal(header, prefix) {
			t.Errorf("Packet Tag error in AEAD-EAX instance: got\n%X\nwant\n%X",
				header, prefix)
		}
	}
}

func TestAeadRFCParse(t *testing.T) {
	for _, sample := range samplesAeadEncryptedDataPacket {
		key, _ := hex.DecodeString(sample.cek)
		packetBytes, _ := hex.DecodeString(sample.full)
		packetReader := bytes.NewBuffer(packetBytes)
		packet := new(AEADEncrypted)
		err := packet.parse(packetReader)
		if err != nil {
			t.Error(err)
		}
		// decrypted plaintext can be read from 'rc'
		rc, err := packet.GetStreamReader(key)
		if err != nil {
			t.Error(err)
		}
		// Start opening
		var got []byte
		for {
			// Read 10 bytes at a time
			decryptedChunk := make([]byte, 5)
			n, errRead := rc.Read(decryptedChunk)
			got = append(got, decryptedChunk[:n]...)
			if n == 0 || err != nil {
				err = errRead
				break
			}
		}
		if err != io.EOF && err != io.ErrUnexpectedEOF && err != nil {
			t.Error(err)
		}

		want, _ := hex.DecodeString(sample.plaintext)
		if !bytes.Equal(got, want) {
			t.Errorf("Error opening:\ngot\n%s\nwant\n%s", got, want)
		}
	}
}

// Verifies that the ciphertext stream is at least the same length than the
// plaintext plus tags
func TestAeadLength(t *testing.T) {
	for i := 0; i < iterations; i++ {
		key := make([]byte, 16)
		rand.Read(key)

		chunkSizeByte := byte(mathrand.Intn(int(maxChunkSizeByte)))
		config := &AEADConfig{chunkSizeByte: chunkSizeByte}

		// Plaintext
		randomLength := mathrand.Intn(maxChunks * int(config.ChunkSize()))
		plaintext := make([]byte, randomLength)
		rand.Read(plaintext)

		// 'writeCloser' encrypts and writes the plaintext bytes.
		raw := bytes.NewBuffer(nil)
		writeCloser, err := GetStreamWriter(raw, key, config)
		if err != nil {
			t.Error(err)
		}
		// Write the partial lengths packet into 'raw'
		if _, err = writeCloser.Write(plaintext); err != nil {
			t.Error(err)
		}
		// Close MUST be called - it appends the final auth. tag
		if err = writeCloser.Close(); err != nil {
			t.Error(err)
		}
		// Packet is ready.
		encryptedBytes := len(raw.Bytes()) - len(config.InitialNonce())
		encryptedBytes -= (1 + len(plaintext)/int(config.ChunkSize()))*config.TagLength()
		if encryptedBytes < len(plaintext) {
			t.Error("Ciphertext stream shorter than plaintext")
		}
	}

}

func TestAeadRandomStream(t *testing.T) {
	for i := 0; i < iterations; i++ {
		key := make([]byte, 16)
		rand.Read(key)

		chunkSizeByte := byte(mathrand.Intn(int(maxChunkSizeByte)))
		config := &AEADConfig{chunkSizeByte: chunkSizeByte}

		// Plaintext
		randomLength := mathrand.Intn(maxChunks*int(config.ChunkSize()))
		plaintext := make([]byte, randomLength)
		rand.Read(plaintext)

		// 'writeCloser' encrypts and writes the plaintext bytes.
		raw := bytes.NewBuffer(nil)
		writeCloser, err := GetStreamWriter(raw, key, config)
		if err != nil {
			t.Error(err)
		}
		// Write the partial lengths packet into 'raw'
		if _, err = writeCloser.Write(plaintext); err != nil {
			t.Error(err)
		}
		// Close MUST be called - it appends the final auth. tag
		if err = writeCloser.Close(); err != nil {
			t.Error(err)
		}
		// Packet is ready.

		// Start decrypting stream
		packet := new(AEADEncrypted)
		if err = packet.parse(raw); err != nil {
			t.Error(err)
		}
		// decrypted plaintext can be read from 'rc'
		rc, err := packet.GetStreamReader(key)

		maxRead := 3 * int(config.ChunkSize())
		var got []byte
		for {
			// Read a random number of bytes, until the end of the packet.
			decrypted := make([]byte, 1 + mathrand.Intn(maxRead))
			n, errRead := rc.Read(decrypted)
			err = errRead
			decrypted = decrypted[:n]
			got = append(got, decrypted...)
			if n == 0 || err != nil {
				// Finished reading
				break
			}
		}
		if err != nil && err != io.EOF {
			t.Error("decrypting random stream failed:", err)
		}
		want := plaintext
		if !bytes.Equal(got, want) {
			t.Errorf("Error encrypting/decrypting random stream")
			// t.Errorf("Error encrypting/decrypting random stream: got\n%X\nwant\n%X",
			// 	got, want)
		}
	}
}

func TestAeadRandomCorruptStream(t *testing.T) {
	for i := 0; i < iterations; i++ {
		print(i)
		print("\n")
		key := make([]byte, 16)
		rand.Read(key)

		chunkSizeByte := byte(mathrand.Intn(int(maxChunkSizeByte)))
		config := &AEADConfig{chunkSizeByte: chunkSizeByte}

		// Plaintext
		randomLength := 1 + mathrand.Intn(maxChunks * int(config.ChunkSize()))
		plaintext := make([]byte, randomLength)
		rand.Read(plaintext)

		// 'writeCloser' encrypts and writes the plaintext bytes.
		raw := bytes.NewBuffer(nil)
		writeCloser, err := GetStreamWriter(raw, key, config)
		if err != nil {
			t.Error(err)
		}
		// Write the partial lengths packet into 'raw'
		if _, err = writeCloser.Write(plaintext); err != nil {
			t.Error(err)
		}
		// Close MUST be called - it appends the final auth. tag
		if err = writeCloser.Close(); err != nil {
			t.Error(err)
		}
		// Packet is ready.

		// Corrupt some bytes of the stream
		for j := 0; j < 10; j++ {
			index := mathrand.Intn(len(raw.Bytes()))
			if index < 8 || len(plaintext) == 0 {
				// avoid corrupting header or nonce, that's useless
				continue
			}
			raw.Bytes()[index] = 255 - raw.Bytes()[index]
		}
		packet := new(AEADEncrypted)
		if err = packet.parse(raw); err != nil {
			// Header was corrupted
			continue
		}
		rc, err := packet.GetStreamReader(key)

		maxRead := 3 * int(config.ChunkSize())
		var got []byte
		for {
			// Read a random number of bytes, until the end of the packet.
			decrypted := make([]byte, 1 + mathrand.Intn(maxRead))
			n, errRead := rc.Read(decrypted)
			err = errRead

			decrypted = decrypted[:n]
			// got = append(got, decrypted...)
			if n == 0 || err != nil {
				if err != nil {
					// Finished reading
					break
				}
			}
		}
		if bytes.Equal(got, plaintext) {
			t.Errorf("Error: Succesfully decrypted corrupt stream")
		}
		if err == nil || err == io.EOF {
			t.Fatal("No error raised when decrypting corrupt stream")
		}
	}
}

func DontTestAeadEmptyStream(t *testing.T) {
	t.Error("Write me")
}

