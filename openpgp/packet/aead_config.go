// Copyright (C) 2019 ProtonTech AG

package packet

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
	// The AEAD mode of operation.
	DefaultMode AEADMode
	// Amount of octets in each chunk of data, according to the formula
	// chunkSize = ((uint64_t)1 << (chunkSizeByte + 6))
	DefaultChunkSizeByte byte
}

var defaultConfig = &AEADConfig{
	DefaultMode:          AEADModeEAX,
	DefaultChunkSizeByte: 0x12,  // 1<<(6 + 12) = 262144 bytes
}

// Version returns the AEAD version implemented, and is currently defined as
// 0x01.
func (conf *AEADConfig) Version() byte {
	return aeadEncryptedVersion
}

// Mode returns the AEAD mode of operation.
func (conf *AEADConfig) Mode() AEADMode {
	if conf == nil || conf.DefaultMode == 0 {
		return AEADModeEAX
	}
	if conf.DefaultMode != AEADMode(1) && conf.DefaultMode != AEADMode(2) {
		panic("AEAD mode unsupported")
	}
	return conf.DefaultMode
}

// ChunkSizeByte returns the byte indicating the chunk size. The effective
// chunk size is computed with the formula uint64(1) << (chunkSizeByte + 6)
func (conf *AEADConfig) ChunkSizeByte() byte {
	if conf == nil || conf.DefaultChunkSizeByte == 0 {
		return defaultConfig.DefaultChunkSizeByte
	}
	if conf.DefaultChunkSizeByte > 0x56 {
		panic("aead: too long chunk size")
	}
	return conf.DefaultChunkSizeByte
}

// ChunkSize returns the maximum number of body octets in each chunk of data.
func (conf *AEADConfig) ChunkSize() uint64 {
	return uint64(1) << (conf.ChunkSizeByte() + 6)
}

// TagLength returns the length in bytes of authentication tags.
func (mode AEADMode) tagLength() int {
	switch mode {
	case AEADModeEAX:
		return 16
	case AEADModeOCB:
		return 16
	}
	panic("Unsupported AEAD mode")
}

// NonceLength returns the length in bytes of nonces.
func (mode AEADMode) nonceLength() int {
	switch mode {
	case AEADModeEAX:
		return 16
	case AEADModeOCB:
		return 15
	}
	panic("unsupported aead mode")
}
