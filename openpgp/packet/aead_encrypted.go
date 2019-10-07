// Copyright (C) 2019 ProtonTech AG

package packet

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/eax"
	"golang.org/x/crypto/ocb"
	"golang.org/x/crypto/openpgp/errors"
	"golang.org/x/crypto/openpgp/internal/algorithm"
)

// AEADEncrypted represents an AEAD Encrypted Packet (tag 20, RFC4880bis-5.16).
type AEADEncrypted struct {
	prefix       []byte    // Packet tag, version, cipher, mode, chunk size byte
	initialNonce []byte    // Referred to as IV in RFC4880-bis
	Contents     io.Reader // Encrypted chunks and tags
}

// An AEAD opener/sealer, its configuration, and data for en/decryption.
type worker struct {
	aead         cipher.AEAD
	config       *AEADConfig
	header       []byte // Chunk-independent associated data
	index        []byte // Chunk counter
	initialNonce []byte
	cache        []byte
}

// streamWriter encrypts and writes bytes. It encrypts when necessary according
// to the AEAD block size, and caches the extra encrypted bytes for next write.
type streamWriter struct {
	worker                               // Embedded plaintext sealer
	writer                io.WriteCloser // 'writer' is a partialLengthWriter
	writtenEncryptedBytes int
}

// streamReader reads and decrypts bytes. It caches extra decrypted bytes when
// necessary, similar to streamWriter.
type streamReader struct {
	worker                       // Embedded ciphertext opener
	reader             io.Reader // 'reader' is a partialLengthReader
	carry              []byte    // Used to detect last chunk
	readPlaintextBytes int
}

func (ae *AEADEncrypted) parse(buf io.Reader) error {
	ptype, _, contentsReader, err := readHeader(buf)
	if ptype != packetTypeAEADEncrypted || err != nil {
		return errors.AEADError("Error reading packet header")
	}
	// Information needed for opening chunks
	header := make([]byte, 5)
	header[0] = 0x80 | 0x40 | byte(ptype) // Should equal 212
	if n, err := contentsReader.Read(header[1:5]); err != nil || n < 4 {
		return errors.AEADError("could not read aead header")
	}
	// Read initial nonce
	nonceLength := (&AEADConfig{mode: AEADMode(header[3])}).NonceLength()
	initialNonce := make([]byte, nonceLength)
	if _, err := contentsReader.Read(initialNonce); err != nil {
		return err
	}
	ae.Contents = contentsReader
	ae.prefix = header
	ae.initialNonce = initialNonce
	return nil
}

// GetStreamReader prepares a worker and returns a ReadCloser from which
// decrypted bytes can be read (see streamReader.Read()).
func (ae *AEADEncrypted) GetStreamReader(key []byte) (io.ReadCloser, error) {
	config := &AEADConfig{
		cipher:        CipherFunction(ae.prefix[2]),
		mode:          AEADMode(ae.prefix[3]),
		chunkSizeByte: byte(ae.prefix[4]),
	}
	aead, err := initAlgorithm(key, config)
	if err != nil {
		return nil, err
	}
	// Carry the first tagLen bytes
	carry := make([]byte, config.TagLength())
	n, err := ae.Contents.Read(carry)
	if err != nil || n < config.TagLength() {
		return nil, errors.AEADError("Not enough data to decrypt")
	}
	return &streamReader{
		worker: worker{
			aead:         aead,
			config:       config,
			initialNonce: ae.initialNonce,
			header:       ae.prefix,
			index:        make([]byte, 8),
		},
		reader: ae.Contents,
		carry:  carry}, nil
}

// Read decrypts bytes and reads them into dst. It decrypts when necessary and
// caches extra decrypted bytes. It returns the number of bytes copied into dst
// and an error.
func (ar *streamReader) Read(dst []byte) (n int, err error) {
	if len(dst) == 0 {
		return 0, errors.AEADError("argument of Read must have positive length")
	}
	chunkLen := int(ar.config.ChunkSize())
	tagLen := ar.config.TagLength()
	if len(dst) <= len(ar.cache) {
		n = copy(dst, ar.cache[:len(dst)])
		ar.cache = ar.cache[n:]
		return
	}
	// Retrieve cached plaintext bytes from previous calls
	decrypted := ar.cache

	// Decrypt the necessary amount of chunks
	for i := 0; i <= (len(dst)-len(ar.cache))/chunkLen; i++ {
		cipherChunk := make([]byte, chunkLen+tagLen)
		readBytes, err := io.ReadFull(ar.reader, cipherChunk)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return 0, err
		}
		err = err
		if readBytes == 0 {
			break
		}
		cipherChunk = cipherChunk[:readBytes]
		plainChunk, errChunk := ar.processChunk(cipherChunk)
		if errChunk != nil {
			return 0, errChunk
		}
		decrypted = append(decrypted, plainChunk...)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
	}
	// Append necessary bytes, and cache the rest
	if len(dst) < len(decrypted) {
		n = copy(dst, decrypted[:len(dst)])
		ar.cache = decrypted[len(dst):]
	} else {
		n = copy(dst, decrypted)
		ar.cache = nil
	}
	return

}

// Close wipes the worker, along with the reader, cached, and carried bytes.
func (ar *streamReader) Close() (err error) {
	ar.worker = worker{}
	ar.carry = nil
	return nil
}

// GetStreamWriter initializes the worker and returns a writer. This writer
// encrypts and writes bytes (see streamWriter.Write()).
func GetStreamWriter(w io.Writer, key []byte, config *AEADConfig) (io.WriteCloser, error) {
	writeCloser := noOpCloser{w}
	writer, err := serializeStreamHeader(writeCloser, packetTypeAEADEncrypted)
	if err != nil {
		return nil, err
	}
	// Set packet tag
	buf := bytes.NewBuffer(nil)
	if err := serializeType(buf, packetTypeAEADEncrypted); err != nil {
		return nil, err
	}
	// Data for en/decryption: tag, version, cipher, aead mode, chunk size
	header := []byte{
		config.Version(),
		byte(config.Cipher()),
		byte(config.Mode()),
		config.ChunkSizeByte()}
	n, err := writer.Write(header)
	if err != nil || n < 4 {
		return nil, errors.AEADError("could not write AEAD headers")
	}
	// Sample nonce
	nonce := make([]byte, config.NonceLength())
	n, err = rand.Read(nonce)
	if n < config.NonceLength() || err != nil {
		panic("Could not sample random nonce")
	}
	_, err = writer.Write(nonce)
	if err != nil {
		return nil, err
	}
	alg, err := initAlgorithm(key, config)
	if err != nil {
		return nil, err
	}

	return &streamWriter{
		worker: worker{
			aead:         alg,
			config:       config,
			header:       append(buf.Bytes(), header...),
			index:        make([]byte, 8),
			initialNonce: nonce,
		},
		writer: writer}, nil
}

// Write encrypts and writes bytes. It encrypts when necessary and caches extra
// plaintext bytes for next call. When the stream is finished, Close() MUST be
// called to append the final tag.
func (aw *streamWriter) Write(plaintextBytes []byte) (n int, err error) {
	chunkLen := int(aw.config.ChunkSize())
	tagLen := aw.config.TagLength()
	buf := append(aw.cache, plaintextBytes...)
	n = 0
	i := 0
	for i = 0; i < len(buf)/chunkLen; i++ {
		plaintext := buf[chunkLen*i : chunkLen*(i+1)]
		encryptedChunk, errSeal := aw.sealChunk(plaintext)
		if errSeal != nil {
			return n, errSeal
		}
		n, err = aw.writer.Write(encryptedChunk)
		if err != nil || n < tagLen {
			return n, errors.AEADError("error writing encrypted chunk")
		}
		aw.writtenEncryptedBytes += n - tagLen
	}
	// Cache remaining plaintext for next chunk
	aw.cache = plaintextBytes[chunkLen*i:]
	return
}

// Close encrypts and writes the remaining cached plaintext if any, appends the
// final authentication tag, and closes the embedded writer. This function MUST
// be called at the end of a stream.
func (aw *streamWriter) Close() (err error) {
	tagLen := aw.config.TagLength()
	// Encrypt and write whatever is left on the cache (it may be empty)
	if len(aw.cache) > 0 {
		lastEncryptedChunk, err := aw.sealChunk(aw.cache)
		if err != nil {
			return err
		}
		n, err := aw.writer.Write(lastEncryptedChunk)
		if err != nil {
			return err
		}
		if n < tagLen {
			return errors.AEADError("close chunk without tag")
		}
		aw.writtenEncryptedBytes += n - tagLen
	}
	// Compute final tag (associated data: packet tag, version, cipher, aead,
	// chunk size, index, total number of encrypted octets).
	amountBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(amountBytes, uint64(aw.writtenEncryptedBytes))
	adata := append(aw.header[:], aw.index[:]...)
	adata = append(adata, amountBytes...)
	nonce := aw.computeNextNonce()
	finalTag := aw.aead.Seal(nil, nonce, nil, adata)
	n, err := aw.writer.Write(finalTag)
	if err != nil {
		return err
	}
	aw.writtenEncryptedBytes += n
	if err = aw.writer.Close(); err != nil {
		return err
	}
	return nil
}

// initAlgorithm sets up the AEAD algorithm with the given key according
// to the given AEADConfig. It returns the AEAD instance and an error.
func initAlgorithm(key []byte, conf *AEADConfig) (cipher.AEAD, error) {
	// Check configuration
	if err := conf.Check(); err != nil {
		return nil, err
	}
	// Set up cipher
	ciph := algorithm.CipherFunction(conf.Cipher()).New(key)
	// Set up cipher.AEAD
	var newFunc func(cipher.Block) (cipher.AEAD, error)
	switch conf.Mode() {
	case AEADModeEAX:
		newFunc = eax.NewEAX
	case AEADModeOCB:
		newFunc = ocb.NewOCB
	default:
		return nil, errors.UnsupportedError("unsupported AEAD mode")
	}
	alg, err := newFunc(ciph)
	if err != nil {
		return nil, err
	}
	return alg, nil
}

// sealChunk Encrypts and authenticates the given chunk.
func (aw *streamWriter) sealChunk(data []byte) ([]byte, error) {
	if len(data) > int(aw.config.ChunkSize()) {
		return nil, errors.AEADError("chunk exceeds maximum length")
	}
	if aw.header == nil {
		return nil, errors.AEADError("can't seal without headers")
	}
	adata := append(aw.header, aw.index...)
	nonce := aw.computeNextNonce()
	encrypted := aw.aead.Seal(nil, nonce, data, adata)
	if err := aw.worker.incrementIndex(); err != nil {
		return nil, err
	}
	return encrypted, nil
}

// processChunk decrypts and checks integrity of an encrypted chunk, returning
// the underlying plaintext and an error. It access peeked bytes from next
// chunk, to identify the last chunk and decrypt/validate accordingly.
func (ar *streamReader) processChunk(data []byte) ([]byte, error) {

	tagLen := ar.config.TagLength()
	chunkLen := int(ar.config.ChunkSize())
	ctLen := tagLen + chunkLen
	// Restore carried bytes from last call
	chunkExtra := append(ar.carry, data...)
	chunk := chunkExtra[:len(chunkExtra)-tagLen]
	// 'chunk' contains encrypted bytes, followed by an authentication tag.
	var finalTag []byte
	if len(chunk) < ctLen || (len(chunk) == ctLen && len(ar.carry) < tagLen) {
		// Case final chunk
		finalTag = chunkExtra[len(chunkExtra)-tagLen:]
	} else {
		// Case Regular chunk
		ar.carry = chunkExtra[len(chunkExtra)-tagLen:]
	}
	// Decrypt and authenticate chunk
	adata := append(ar.header, ar.index...)
	nonce := ar.computeNextNonce()
	plainChunk, err := ar.aead.Open(nil, nonce, chunk, adata)
	if err != nil {
		return nil, err
	}
	ar.readPlaintextBytes += len(plainChunk)
	if err = ar.worker.incrementIndex(); err != nil {
		return nil, err
	}

	if finalTag != nil {
		err = ar.validateFinalTag(finalTag)
		if err != nil {
			// Final tag is corrupt
			ar.Close()
			return nil, errors.AEADError(
				"final tag authentication failed, remaining stream wiped")
		}
	}
	return plainChunk, nil
}

// Checks the summary tag. It takes into account the total decrypted bytes into
// the associated data. It returns an error, or nil if the tag is valid.
func (ar *streamReader) validateFinalTag(tag []byte) error {
	// Associated: tag, version, cipher, aead, chunk size, index, and octets
	amountBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(amountBytes, uint64(ar.readPlaintextBytes))
	adata := append(ar.header, ar.index...)
	adata = append(adata, amountBytes...)
	nonce := ar.computeNextNonce()
	_, err := ar.aead.Open(nil, nonce, tag, adata)
	if err != nil {
		return err
	}
	return nil
}

// computeNonce takes the incremental index and computes an eXclusive OR with
// the least significant 8 bytes of the receivers' initial nonce (see sec.
// 5.16.1 and 5.16.2). It returns the resulting nonce.
func (wo *worker) computeNextNonce() (nonce []byte) {
	nonce = make([]byte, len(wo.initialNonce))
	copy(nonce, wo.initialNonce)
	offset := len(wo.initialNonce) - 8
	for i := 0; i < 8; i++ {
		nonce[i+offset] ^= wo.index[i]
	}
	return
}

// incrementIndex perfoms an integer increment by 1 of the integer represented by the
// slice, modifying it accordingly.
func (wo *worker) incrementIndex() error {
	index := wo.index
	if len(index) == 0 {
		return errors.AEADError("Index has length 0")
	}
	for i := len(index) - 1; i >= 0; i-- {
		if index[i] < 255 {
			index[i]++
			return nil
		}
		index[i] = 0
	}
	return errors.AEADError("cannot further increment index")
}
