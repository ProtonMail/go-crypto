// Copyright (C) 2018 ProtonTech AG

package packet

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/base64"
	"io"
	"io/ioutil"
	mathrand "math/rand"
	"testing"
)

var (
	maxChunkSizeExp = 10  // Test chunk sizes are at most 1 << maxChunkSizeExp
)

const (
	keyLength  = 16
	iterations = 200
	// Approx. plaintext length, in amount of chunks
	maxChunks = 15
)

func TestAeadNewAEADInstanceWithDefaultConfig(t *testing.T) {
	key := make([]byte, keyLength)
	if _, err := rand.Read(key); err != nil {
		t.Error(err)
	}
	var modesToPrefix = map[AEADMode][]byte{
		// Packet tags in new format
		AEADModeEAX: []byte{0xd4, 0x01, 0x07, 0x01, 0x01},
		AEADModeOCB: []byte{0xd4, 0x01, 0x07, 0x02, 0x01},
	}
	for mode := range modesToPrefix {
		conf := &Config{
			AEADConfig: AEADConfig{DefaultMode: mode},
		}
		_, err := initAlgorithm(key, conf.Mode(), conf.Cipher())
		if err != nil {
			t.Errorf("Error creating valid AEAD from default: %s", err)
		}
	}
}

func TestAeadRFCParse(t *testing.T) {
	for _, sample := range samplesAeadEncryptedDataPacket {
		key, _ := hex.DecodeString(sample.cek)
		packetBytes, _ := hex.DecodeString(sample.full)
		packetReader := bytes.NewBuffer(packetBytes)
		packet := new(AEADEncrypted)
		ptype, _, contentsReader, err := readHeader(packetReader)
		if ptype != packetTypeAEADEncrypted || err != nil {
			t.Error("Error reading packet header")
		}
		if err = packet.parse(contentsReader); err != nil {
			t.Error(err)
		}
		// decrypted plaintext can be read from 'rc'
		rc, err := packet.Decrypt(key)
		if err != nil {
			t.Error(err)
		}
		// Start opening
		var got []byte
		for {
			// Read some bytes at a time
			decryptedChunk := make([]byte, mathrand.Intn(6)+1)
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

func WIPTestAeadOpenPGPJSParse(t *testing.T) {
	data, err := ioutil.ReadFile("openpgpjs_samples/aead-packet.b64")
	rawPlaintext, err := ioutil.ReadFile("openpgpjs_samples/plaintext.txt")
	buf := bytes.NewBuffer(nil)
	w := noOpCloser{buf}
	wc, err := SerializeLiteral(w, false, "msg.txt", 100)
	wc.Write(rawPlaintext)
	wc.Close()
	want := buf.Bytes()

    // Decode
    raw, err := base64.StdEncoding.DecodeString(string(data))
    if err != nil {
        panic(err)
    }
	key := []byte{79, 41, 206, 112, 224, 133, 140, 223, 27, 61, 227, 57, 114, 118, 64, 60, 177, 26, 42, 174, 151, 5, 186, 74, 226, 97, 214, 63, 114, 77, 215, 121}

	packetReader := bytes.NewBuffer(raw)
	packet := new(AEADEncrypted)
	ptype, _, contentsReader, err := readHeader(packetReader)
	if ptype != packetTypeAEADEncrypted || err != nil {
		t.Error("Error reading packet header")
	}
	if err = packet.parse(contentsReader); err != nil {
		t.Error(err)
	}
	// decrypted plaintext can be read from 'rc'
	rc, err := packet.Decrypt(key)
	if err != nil {
		t.Error(err)
	}
	// Start opening
	var got []byte
	for {
		// Read some bytes at a time
		decryptedChunk := make([]byte, mathrand.Intn(6)+1)
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
	literalPacket := new(LiteralData)
	literalPacket.parse(bytes.NewBuffer(got))
	io.ReadFull(literalPacket.Body, got)
	if !bytes.Equal(got, want) {
		t.Errorf("Could not decrypt properly")
	}
}

func TestAeadRandomStream(t *testing.T) {
	for i := 0; i < iterations; i++ {
		key := make([]byte, 16)
		rand.Read(key)

		chunkSizeExp := mathrand.Intn(maxChunkSizeExp)
		chunkSize := uint64(1 << (6 + uint(chunkSizeExp)))
		config := &Config{
			AEADConfig: AEADConfig{DefaultChunkSize: chunkSize},
		}

		// Plaintext
		randomLength := mathrand.Intn(maxChunks*int(config.ChunkSize()))
		plaintext := make([]byte, randomLength)
		rand.Read(plaintext)

		// 'writeCloser' encrypts and writes the plaintext bytes.
		raw := bytes.NewBuffer(nil)
		writeCloser, err := SerializeAEADEncrypted(raw, key, config)
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

		ptype, _, contentsReader, err := readHeader(raw)
		if ptype != packetTypeAEADEncrypted || err != nil {
			t.Error("Error reading packet header")
		}

		if err = packet.parse(contentsReader); err != nil {
			t.Error(err)
		}
		// decrypted plaintext can be read from 'rc'
		rc, err := packet.Decrypt(key)

		maxRead := 3 * int(config.ChunkSize())
		var got []byte
		for {
			// Read a random number of bytes, until the end of the packet.
			decrypted := make([]byte, 1 + mathrand.Intn(maxRead))
			n, errRead := rc.Read(decrypted)
			err = errRead
			decrypted = decrypted[:n]
			got = append(got, decrypted...)
			if err != nil {
				if err == io.EOF {
					// Finished reading
					break
				} else if err != io.ErrUnexpectedEOF {
					// Something happened
					t.Error("decrypting random stream failed:", err)
					break
				}
			}
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
		key := make([]byte, 16)
		rand.Read(key)

		var chunkSizeExp int
		for chunkSizeExp == 0 {
			chunkSizeExp = mathrand.Intn(maxChunkSizeExp)
		}
		chunkSize := uint64(1 << (6 + uint(chunkSizeExp)))
		config := &Config{
			AEADConfig: AEADConfig{DefaultChunkSize: chunkSize},
		}

		// Plaintext
		randomLength := 1 + mathrand.Intn(maxChunks * int(config.ChunkSize()))
		plaintext := make([]byte, randomLength)
		rand.Read(plaintext)

		// 'writeCloser' encrypts and writes the plaintext bytes.
		raw := bytes.NewBuffer(nil)
		writeCloser, err := SerializeAEADEncrypted(raw, key, config)
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
		ptype, _, contentsReader, err := readHeader(raw)
		if ptype != packetTypeAEADEncrypted || err != nil {
			t.Error("Error reading packet header")
		}

		if err = packet.parse(contentsReader); err != nil {
			// Header was corrupted
			continue
		}
		rc, err := packet.Decrypt(key)
		maxRead := 3 * int(config.ChunkSize())
		var got []byte
		for {
			// Read a random number of bytes, until the end of the packet.
			decrypted := make([]byte, 1 + mathrand.Intn(maxRead))
			n, errRead := rc.Read(decrypted)
			err = errRead
			decrypted = decrypted[:n]
			got = append(got, decrypted...)
			if err != nil {
				if err == io.EOF {
					// Finished reading
					break
				} else if err != io.ErrUnexpectedEOF {
					// Something happened
					break
				}
			}
		}

		// maxRead := 3 * int(config.ChunkSize())
		// var got []byte
		// for {
		// 	// Read a random number of bytes, until the end of the packet.
		// 	decrypted := make([]byte, 1 + mathrand.Intn(maxRead))
		// 	n, errRead := rc.Read(decrypted)
		// 	err = errRead
        //
		// 	decrypted = decrypted[:n]
		// 	// got = append(got, decrypted...)
		// 	if n == 0 || err != nil {
		// 		if err != nil {
		// 			// Finished reading
		// 			break
		// 		}
		// 	}
		// }
		if bytes.Equal(got, plaintext) {
			t.Errorf("Error: Succesfully decrypted corrupt stream")
		}
		if err == nil || err == io.EOF {
			t.Errorf("No error raised when decrypting corrupt stream")
		}
	}
}

func DontTestAeadEmptyStream(t *testing.T) {
	t.Error("Write me")
}
