// Copyright (C) 2019 ProtonTech AG

package packet

import (
	"io"
	"crypto/rand"
	"golang.org/x/crypto/openpgp/errors"
)

type AEADMode uint8

// Supported modes of operation (see RFC4880bis [EAX] and RFC7253)
const (
	EaxID = AEADMode(1)
	OcbID = AEADMode(2)
	defaultChunkSize = 1 << 12 // 4 Kb
)

// AEADConfig collects a number of AEAD parameters along with sensible defaults.
// A nil *Config is valid and results in all default values.
type AEADConfig struct {
	// The used AEAD algorithm.
	Mode AEADMode
	// Rand provides the source of entropy.
	// If nil, the crypto/rand Reader is used.
	Rand io.Reader
	// DefaultCipher is the cipher to be used. Its value needs to be consistent
	// with the intended AEAD instance to configure.
	DefaultCipher CipherFunction
	// The size of data chunks to encrypt and authenticate.
	DefaultChunkSize uint32
	// If set to true, the first nonce is read from Rand and the subsequent
	// nonces are incremental. If set to false, all nonces are read from the
	// random reader. The default value is true.
	IncrementalNonces bool
}

func (c *AEADConfig) Algorithm() (AEADMode, error) {
	if c == nil || c.Mode == 0 {
		return 0, errors.StructuralError("AEAD error: mode of operation is not set for this instance.")
	}
	return c.Mode, nil
}

func (c *AEADConfig) Random() io.Reader {
	if c == nil || c.Rand == nil {
		return rand.Reader
	}
	return c.Rand
}

func (c *AEADConfig) Cipher() CipherFunction {
	if c == nil || uint8(c.DefaultCipher) == 0 {
		return CipherAES128
	}
	return c.DefaultCipher
}

func (c *AEADConfig) ChunkSize() uint32 {
	if c == nil || c.DefaultChunkSize == 0 {
		return defaultChunkSize
	}
	return c.DefaultChunkSize
}

func (c *AEADConfig) AreNoncesIncremental() bool {
	if c == nil {
		return true
	}
	return c.IncrementalNonces
}
