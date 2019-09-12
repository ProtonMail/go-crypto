// Copyright (C) 2019 ProtonTech AG

package packet

import (
	"crypto/rand"
	"golang.org/x/crypto/openpgp/errors"
	"golang.org/x/crypto/openpgp/internal/algorithm"
)

// Only currently defined version
const aeadEncryptedVersion = 0x01

type AEADMode uint8

// Supported modes of operation (see RFC4880bis [EAX] and RFC7253)
const (
	EaxID = AEADMode(1)
	OcbID = AEADMode(2)
)

// AEADConfig collects a number of AEAD parameters along with sensible defaults.
// A nil AEADConfig is valid and results in all default values.
type AEADConfig struct {
	version byte
	// The block cipher algorithm to be used. Its value needs to be consistent
	// with the intended AEAD instance to configure.
	cipher CipherFunction
	// The AEAD mode of operation.
	mode AEADMode
	// Amount of octets in each chunk of data, according to the formula
	// chunkSize = ((uint64_t)1 << (chunkSizeByte + 6))
	chunkSizeByte byte
	initialNonce []byte  // Optional
}

var defaultConfig = &AEADConfig{
	version:       aeadEncryptedVersion,
	cipher:        CipherAES128,
	mode:          EaxID,
	chunkSizeByte: 0x01,  // 1<<(1+6) = 128 bytes
}

// Version returns the AEAD version implemented, and is currently defined as
// 0x01.
func (conf *AEADConfig) Version() byte {
	return defaultConfig.version
}

// Cipher returns the underlying block cipher used by the AEAD algorithm.
func (conf *AEADConfig) Cipher() CipherFunction {
	if conf == nil || conf.cipher == 0 {
		return defaultConfig.cipher
	}
	return conf.cipher
}

// Mode returns the AEAD mode of operation.
func (conf *AEADConfig) Mode() AEADMode {
	if conf == nil || conf.mode == 0 {
		return EaxID
	}
	return conf.mode
}

// ChunkSizeByte returns the byte indicating the chunk size. The effective
// chunk size is computed with the formula uint64(1) << (chunkSizeByte + 6)
func (conf *AEADConfig) ChunkSizeByte() byte {
	if conf == nil || conf.chunkSizeByte == 0 {
		return defaultConfig.chunkSizeByte
	}
	return conf.chunkSizeByte
}

// ChunkSize returns the maximum number of body octets in each chunk of data.
func (conf *AEADConfig) ChunkSize() uint64 {
	return uint64(1) << (conf.ChunkSizeByte() + 6)
}

// InitialNonce returns the nonce for the first chunk. If nonce is nil, it is
// sampled with crypto/rand.
func (conf *AEADConfig) InitialNonce() []byte {
	if conf == nil || conf.initialNonce == nil {
		var nonceLen int
		switch conf.Mode() {
		case EaxID:
			nonceLen = 16
		case OcbID:
			nonceLen = 15
		default:
			panic("unsupported aead mode")  // Should never occur
			return nil
		}
		conf.initialNonce = make([]byte, nonceLen)
		n, err := rand.Read(conf.initialNonce)
		if n < nonceLen || err != nil {
			panic("Could not sample random nonce")
		}
	}
	return conf.initialNonce
}

// TagLength returns the length in bytes of authentication tags.
func (conf *AEADConfig) TagLength() int {
	switch conf.Mode() {
	case EaxID:
		return 16
	case OcbID:
		return 16
	}
	return 0
}

// Check verifies that the receiver configuration is correct and supported.
func (conf *AEADConfig) Check() error {
	if conf.Version() != aeadEncryptedVersion {
		return errors.UnsupportedError("Unsupported AEAD version")
	}
	_, ok := algorithm.CipherById[uint8(conf.Cipher())]
	if !ok {
		return errors.UnsupportedError("aead: Unknown block cipher algorithm")
	}
	if conf.Mode() != AEADMode(1) && conf.Mode() != AEADMode(2) {
		return errors.AEADError("AEAD mode unsupported")
	}
	if conf.ChunkSizeByte() > 0x56 {
		return errors.StructuralError("Too long chunk size")
	}
	return nil
}
