// Copyright (C) 2019 ProtonTech AG

package packet

import "math/bits"

// Only currently defined version
const aeadEncryptedVersion = 1

// AEADConfig collects a number of AEAD parameters along with sensible defaults.
// A nil AEADConfig is valid and results in all default values.
type AEADConfig struct {
	// The AEAD mode of operation.
	DefaultMode AEADMode
	// Amount of octets in each chunk of data
	ChunkSize uint64
}

var defaultAEADConfig = &AEADConfig{
	DefaultMode:      AEADModeEAX,
	ChunkSize: 1 << 18, // 262144 bytes
}

// Version returns the AEAD version implemented, and is currently defined as
// 0x01.
func (conf *AEADConfig) Version() byte {
	return aeadEncryptedVersion
}

// Mode returns the AEAD mode of operation.
func (conf *AEADConfig) Mode() AEADMode {
	if conf == nil || conf.DefaultMode == 0 {
		return defaultAEADConfig.DefaultMode
	}
	mode := conf.DefaultMode
	if mode != AEADModeEAX && mode != AEADModeOCB && mode != AEADModeGCM {
		panic("AEAD mode unsupported")
	}
	return conf.DefaultMode
}

// ChunkLength returns the maximum number of body octets in each chunk of data.
func (conf *AEADConfig) ChunkLength() uint64 {
	if conf == nil || conf.ChunkSize == 0 {
		return defaultAEADConfig.ChunkSize
	}
	size := conf.ChunkSize
	if size&(size-1) != 0 {
		panic("aead: chunk size must be a power of 2")
	}
	if size < 1<<6 {
		panic("aead: chunk size too small, minimum value is 1 << 6")
	}
	if size > 1<<62 {
		panic("aead: chunk size too large, maximum value is 1 << 62")
	}
	return size
}

// ChunkLengthByte returns the byte indicating the chunk size. The effective
// chunk size is computed with the formula uint64(1) << (chunkSizeByte + 6)
func (conf *AEADConfig) ChunkLengthByte() byte {
	chunkSize := conf.ChunkLength()
	exponent := bits.Len64(chunkSize) - 1
	if exponent < 6 {
		// Should never occur, since also checked in ChunkSize()
		panic("aead: chunk size too small, minimum value is 1 << 6")
	}
	return byte(exponent - 6)
}
