// Copyright (C) 2019 ProtonTech AG

package packet

import (
	// "crypto/rand"
	"golang.org/x/crypto/openpgp/internal/algorithm"
)

// Only currently defined version
const aeadEncryptedVersion = 1

type AEADMode uint8

// Supported modes of operation (see RFC4880bis [EAX] and RFC7253)
const (
	AEADModeEAX = AEADMode(1)
	AEADModeOCB = AEADMode(2)
)

// AEADConfig collects a number of AEAD parameters along with sensible defaults.
// A nil AEADConfig is valid and results in all default values.
type AEADConfig struct {
	cipher CipherFunction
	// The AEAD mode of operation.
	mode AEADMode
	// Amount of octets in each chunk of data, according to the formula
	// chunkSize = ((uint64_t)1 << (chunkSizeByte + 6))
	chunkSizeByte byte
}

var defaultConfig = &AEADConfig{
	cipher:        CipherAES128,
	mode:          AEADModeEAX,
	chunkSizeByte: 0x12,  // 1<<(6 + 12) = 262144 bytes
}

// Version returns the AEAD version implemented, and is currently defined as
// 0x01.
func (conf *AEADConfig) Version() byte {
	return aeadEncryptedVersion
}

// Cipher returns the underlying block cipher used by the AEAD algorithm.
func (conf *AEADConfig) Cipher() CipherFunction {
	if conf == nil || conf.cipher == 0 {
		return defaultConfig.cipher
	}
	_, ok := algorithm.CipherById[uint8(conf.cipher)]
	if !ok {
		panic("aead: Unknown block cipher algorithm")
	}
	return conf.cipher
}

// Mode returns the AEAD mode of operation.
func (conf *AEADConfig) Mode() AEADMode {
	if conf == nil || conf.mode == 0 {
		return AEADModeEAX
	}
	if conf.mode != AEADMode(1) && conf.mode != AEADMode(2) {
		panic("AEAD mode unsupported")
	}
	return conf.mode
}

// ChunkSizeByte returns the byte indicating the chunk size. The effective
// chunk size is computed with the formula uint64(1) << (chunkSizeByte + 6)
func (conf *AEADConfig) ChunkSizeByte() byte {
	if conf == nil || conf.chunkSizeByte == 0 {
		return defaultConfig.chunkSizeByte
	}
	if conf.chunkSizeByte > 0x56 {
		panic("aead: too long chunk size")
	}
	return conf.chunkSizeByte
}

// ChunkSize returns the maximum number of body octets in each chunk of data.
func (conf *AEADConfig) ChunkSize() uint64 {
	return uint64(1) << (conf.ChunkSizeByte() + 6)
}

// TagLength returns the length in bytes of authentication tags.
func tagLength(mode AEADMode) int {
	switch mode {
	case AEADModeEAX:
		return 16
	case AEADModeOCB:
		return 16
	}
	panic("Unsupported AEAD mode")
}

// NonceLength returns the length in bytes of nonces.
func nonceLength(mode AEADMode) int {
	switch mode {
	case AEADModeEAX:
		return 16
	case AEADModeOCB:
		return 15
	}
	panic("unsupported aead mode")
}
