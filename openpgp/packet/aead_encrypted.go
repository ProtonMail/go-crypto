// Copyright (C) 2019 ProtonTech AG

package packet

import (
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
	cipher        CipherFunction
	mode          AEADMode
	chunkSizeByte byte
	Contents      io.Reader // Encrypted chunks and tags
	initialNonce  []byte    // Referred to as IV in RFC4880-bis
}

// An AEAD opener/sealer, its configuration, and data for en/decryption.
type aeadCrypter struct {
	aead           cipher.AEAD
	config         *AEADConfig
	initialNonce   []byte
	associatedData []byte // Chunk-independent associated data
	chunkIndex     []byte // Chunk counter
	bytesProcessed int    // Amount of (plain/cipher)-text bytes read/written
	cache          []byte
}

// aeadEncrypter encrypts and writes bytes. It encrypts when necessary according
// to the AEAD block size, and caches the extra encrypted bytes for next write.
type aeadEncrypter struct {
	aeadCrypter                // Embedded plaintext sealer
	writer      io.WriteCloser // 'writer' is a partialLengthWriter
}

// aeadDecrypter reads and decrypts bytes. It caches extra decrypted bytes when
// necessary, similar to aeadEncrypter.
type aeadDecrypter struct {
	aeadCrypter           // Embedded ciphertext opener
	reader      io.Reader // 'reader' is a partialLengthReader
	peekedBytes []byte    // Used to detect last chunk
}

func (ae *AEADEncrypted) parse(buf io.Reader) error {
	headerData := make([]byte, 4)
	if n, err := buf.Read(headerData); err != nil || n < 4 {
		return errors.AEADError("could not read aead header")
	}
	// Read initial nonce
	mode := AEADMode(headerData[2])
	nonceLen := mode.nonceLength()
	initialNonce := make([]byte, nonceLen)
	if n, err := buf.Read(initialNonce); err != nil || n < nonceLen {
		return err
	}
	ae.Contents = buf
	ae.initialNonce = initialNonce
	ae.cipher = CipherFunction(headerData[1])
	ae.mode = mode
	ae.chunkSizeByte = byte(headerData[3])
	return nil
}

// Decrypt prepares an aeadCrypter and returns a ReadCloser from which
// decrypted bytes can be read (see aeadDecrypter.Read()).
func (ae *AEADEncrypted) Decrypt(key []byte) (io.ReadCloser, error) {
	aead, err := initAlgorithm(key, ae.mode, ae.cipher)
	if err != nil {
		return nil, err
	}
	// Carry the first tagLen bytes
	tagLen := ae.mode.tagLength()
	peekedBytes := make([]byte, tagLen)
	if n, err := ae.Contents.Read(peekedBytes); err != nil || n < tagLen {
		return nil, errors.AEADError("Not enough data to decrypt")
	}
	return &aeadDecrypter{
		aeadCrypter: aeadCrypter{
			config: &AEADConfig{
				chunkSizeByte: ae.chunkSizeByte,
				mode:          ae.mode,
			},
			aead: aead,
			initialNonce:   ae.initialNonce,
			associatedData: ae.associatedData(),
			chunkIndex:     make([]byte, 8),
		},
		reader:      ae.Contents,
		peekedBytes: peekedBytes}, nil
}

// Read decrypts bytes and reads them into dst. It decrypts when necessary and
// caches extra decrypted bytes. It returns the number of bytes copied into dst
// and an error.
func (ar *aeadDecrypter) Read(dst []byte) (n int, err error) {
	if len(dst) == 0 {
		return 0, errors.AEADError("argument of Read must have positive length")
	}
	chunkLen := int(ar.config.ChunkSize())
	tagLen := ar.config.Mode().tagLength()
	if len(dst) <= len(ar.cache) {
		n = copy(dst, ar.cache[:len(dst)])
		ar.cache = ar.cache[n:]
		return
	}
	// Retrieve cached plaintext bytes from previous calls
	decrypted := ar.cache

	// Read a chunk
	cipherChunk := make([]byte, chunkLen+tagLen)
	bytesRead, errRead := io.ReadFull(ar.reader, cipherChunk)
	if errRead != nil && errRead != io.EOF && errRead != io.ErrUnexpectedEOF {
		return 0, errRead
	}
	if bytesRead > 0 {
		cipherChunk = cipherChunk[:bytesRead]
		plainChunk, errChunk := ar.processChunk(cipherChunk)
		if errChunk != nil {
			return 0, errChunk
		}
		decrypted = append(decrypted, plainChunk...)
	}

	// Append necessary bytes, and cache the rest
	if len(dst) < len(decrypted) {
		n = copy(dst, decrypted[:len(dst)])
		ar.cache = decrypted[len(dst):]
	} else {
		n = copy(dst, decrypted)
		ar.cache = nil
	}
	err = errRead
	return
}

// Close wipes the aeadCrypter, along with the reader, cached, and carried bytes.
func (ar *aeadDecrypter) Close() (err error) {
	ar.aeadCrypter = aeadCrypter{}
	ar.peekedBytes = nil
	return nil
}

// GetStreamWriter initializes the aeadCrypter and returns a writer. This writer
// encrypts and writes bytes (see aeadEncrypter.Write()).
func SerializeAEADEncrypted(w io.Writer, key []byte, config *Config) (io.WriteCloser, error) {
	writeCloser := noOpCloser{w}
	writer, err := serializeStreamHeader(writeCloser, packetTypeAEADEncrypted)
	if err != nil {
		return nil, err
	}
	// Data for en/decryption: tag, version, cipher, aead mode, chunk size
	prefix := []byte{
		0xD4,
		config.AEADConfig.Version(),
		byte(config.Cipher()),
		byte(config.Mode()),
		config.ChunkSizeByte(),
	}
	n, err := writer.Write(prefix[1:])
	if err != nil || n < 4 {
		return nil, errors.AEADError("could not write AEAD headers")
	}
	// Sample nonce
	nonceLen := config.Mode().nonceLength()
	nonce := make([]byte, nonceLen)
	n, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		panic("Could not sample random nonce")
	}
	_, err = writer.Write(nonce)
	if err != nil {
		return nil, err
	}
	alg, err := initAlgorithm(key, config.AEADConfig.Mode(), config.Cipher())
	if err != nil {
		return nil, err
	}

	return &aeadEncrypter{
		aeadCrypter: aeadCrypter{
			aead:           alg,
			config:         &config.AEADConfig,
			associatedData: prefix,
			chunkIndex:     make([]byte, 8),
			initialNonce:   nonce,
		},
		writer: writer}, nil
}

// Write encrypts and writes bytes. It encrypts when necessary and caches extra
// plaintext bytes for next call. When the stream is finished, Close() MUST be
// called to append the final tag.
func (aw *aeadEncrypter) Write(plaintextBytes []byte) (n int, err error) {
	chunkLen := int(aw.config.ChunkSize())
	tagLen := aw.config.Mode().tagLength()
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
		aw.bytesProcessed += n - tagLen
	}
	// Cache remaining plaintext for next chunk
	aw.cache = plaintextBytes[chunkLen*i:]
	return
}

// Close encrypts and writes the remaining cached plaintext if any, appends the
// final authentication tag, and closes the embedded writer. This function MUST
// be called at the end of a stream.
func (aw *aeadEncrypter) Close() (err error) {
	tagLen := aw.config.Mode().tagLength()
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
		aw.bytesProcessed += n - tagLen
	}
	// Compute final tag (associated data: packet tag, version, cipher, aead,
	// chunk size, index, total number of encrypted octets).
	amountBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(amountBytes, uint64(aw.bytesProcessed))
	adata := append(aw.associatedData[:], aw.chunkIndex[:]...)
	adata = append(adata, amountBytes...)
	nonce := aw.computeNextNonce()
	finalTag := aw.aead.Seal(nil, nonce, nil, adata)
	n, err := aw.writer.Write(finalTag)
	if err != nil {
		return err
	}
	aw.bytesProcessed += n
	if err = aw.writer.Close(); err != nil {
		return err
	}
	return nil
}

// initAlgorithm sets up the AEAD algorithm with the given key according
// to the given AEADConfig. It returns the AEAD instance and an error.
func initAlgorithm(key []byte, mode AEADMode, ciph CipherFunction) (cipher.AEAD, error) {
	// Set up cipher
	blockCipher := algorithm.CipherFunction(ciph).New(key)
	// Set up cipher.AEAD
	var newFunc func(cipher.Block) (cipher.AEAD, error)
	switch mode {
	case AEADModeEAX:
		newFunc = eax.NewEAX
	case AEADModeOCB:
		newFunc = ocb.NewOCB
	default:
		return nil, errors.UnsupportedError("unsupported AEAD mode")
	}
	alg, err := newFunc(blockCipher)
	if err != nil {
		return nil, err
	}
	return alg, nil
}

// sealChunk Encrypts and authenticates the given chunk.
func (aw *aeadEncrypter) sealChunk(data []byte) ([]byte, error) {
	if len(data) > int(aw.config.ChunkSize()) {
		return nil, errors.AEADError("chunk exceeds maximum length")
	}
	if aw.associatedData == nil {
		return nil, errors.AEADError("can't seal without headers")
	}
	adata := append(aw.associatedData, aw.chunkIndex...)
	nonce := aw.computeNextNonce()
	encrypted := aw.aead.Seal(nil, nonce, data, adata)
	if err := aw.aeadCrypter.incrementIndex(); err != nil {
		return nil, err
	}
	return encrypted, nil
}

// processChunk decrypts and checks integrity of an encrypted chunk, returning
// the underlying plaintext and an error. It access peeked bytes from next
// chunk, to identify the last chunk and decrypt/validate accordingly.
func (ar *aeadDecrypter) processChunk(data []byte) ([]byte, error) {

	tagLen := ar.config.Mode().tagLength()
	chunkLen := int(ar.config.ChunkSize())
	ctLen := tagLen + chunkLen
	// Restore carried bytes from last call
	chunkExtra := append(ar.peekedBytes, data...)
	chunk := chunkExtra[:len(chunkExtra)-tagLen]
	// 'chunk' contains encrypted bytes, followed by an authentication tag.
	var finalTag []byte
	if len(chunk) < ctLen ||
		(len(chunk) == ctLen && len(ar.peekedBytes) < tagLen) {
		// Case final chunk
		finalTag = chunkExtra[len(chunkExtra)-tagLen:]
	} else {
		// Case Regular chunk
		ar.peekedBytes = chunkExtra[len(chunkExtra)-tagLen:]
	}
	// Decrypt and authenticate chunk
	adata := append(ar.associatedData, ar.chunkIndex...)
	nonce := ar.computeNextNonce()
	plainChunk, err := ar.aead.Open(nil, nonce, chunk, adata)
	if err != nil {
		return nil, err
	}
	ar.bytesProcessed += len(plainChunk)
	if err = ar.aeadCrypter.incrementIndex(); err != nil {
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
func (ar *aeadDecrypter) validateFinalTag(tag []byte) error {
	// Associated: tag, version, cipher, aead, chunk size, index, and octets
	amountBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(amountBytes, uint64(ar.bytesProcessed))
	adata := append(ar.associatedData, ar.chunkIndex...)
	adata = append(adata, amountBytes...)
	nonce := ar.computeNextNonce()
	_, err := ar.aead.Open(nil, nonce, tag, adata)
	if err != nil {
		return err
	}
	return nil
}

// Associated data for chunks: tag, version, cipher, mode, chunk size byte
func (ae *AEADEncrypted) associatedData() []byte {
	return []byte{
		0xD4,
		aeadEncryptedVersion,
		byte(ae.cipher),
		byte(ae.mode),
		ae.chunkSizeByte}
}

// computeNonce takes the incremental index and computes an eXclusive OR with
// the least significant 8 bytes of the receivers' initial nonce (see sec.
// 5.16.1 and 5.16.2). It returns the resulting nonce.
func (wo *aeadCrypter) computeNextNonce() (nonce []byte) {
	nonce = make([]byte, len(wo.initialNonce))
	copy(nonce, wo.initialNonce)
	offset := len(wo.initialNonce) - 8
	for i := 0; i < 8; i++ {
		nonce[i+offset] ^= wo.chunkIndex[i]
	}
	return
}

// incrementIndex perfoms an integer increment by 1 of the integer represented by the
// slice, modifying it accordingly.
func (wo *aeadCrypter) incrementIndex() error {
	index := wo.chunkIndex
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
