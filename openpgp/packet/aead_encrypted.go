// Copyright (C) 2019 ProtonTech AG

package packet

import (
	"crypto/cipher"
	"golang.org/x/crypto/openpgp/errors"
)

const aeadEncryptedVersion = 1

type aead struct {
	config        *AEADConfig
	instance      cipher.AEAD
	lastUsedNonce []byte
}

// NewAEADInstance sets the aead from the given cipher.AEAD algorithm
// and the parameters in the given configuration.
func NewAEADInstance(aeadObject cipher.AEAD, config *AEADConfig) (*aead, error) {
	reader := config.Random()
	firstNonce := make([]byte, aeadObject.NonceSize())
	if _, err := reader.Read(firstNonce); err != nil {
		return &aead{}, err
	}
	return &aead{
		config:   config,
		instance: aeadObject,
		lastUsedNonce: firstNonce,
	}, nil
}

// AEADEncrypted is an Authenticated Encryption with Associated Data Encrypted
// Data Packet, as specified in RFC4880bis, sec. 5.16.
type AEADEncrypted struct {
	CipherFunc    CipherFunction
	AEADAlgorithm AEADMode
	ChunkSize     uint32
	// Nonce is referred to as IV in RFC4880bis
	Nonce             []byte
	EncryptedData     []byte
	AuthenticationTag []byte
}

// AEADSeal encrypts and authenticates the given data and associated data,
// using the given AEAD instance. The initial nonce is read from the given
// random reader and the subsequent nonces are incremental by default (see
// AEADConfig).
func (sealer *aead) Seal(data []byte) (*AEADEncrypted, error) {
	// Increment nonce or read it from the reader
	nonce := sealer.lastUsedNonce
	if sealer.config.IncrementalNonces {
		if err := incrementNonce(nonce); err != nil {
			return nil, err
		}
	} else {
		reader := sealer.config.Random()
		if _, err := reader.Read(nonce); err != nil {
			return nil, err
		}
	}
	sep := len(data)
	sealed := make([]byte, sep+sealer.instance.Overhead())
	encryptedData := sealed[:sep]
	tag := sealed[sep:]
	sealer.instance.Seal(sealed, nonce, data, adata)
	mode, err := sealer.config.Algorithm()
	if err != nil {
		return nil, err
	}
	packet := &AEADEncrypted{
		CipherFunc:        sealer.config.Cipher(),
		AEADAlgorithm:     mode,
		ChunkSize:         sealer.config.ChunkSize(),
		Nonce:             nonce,
		EncryptedData:     encryptedData,
		AuthenticationTag: tag,
	}
	return packet, nil
}

func (opener *aead) Open(data *AEADEncrypted, error) {
	jk
}

// TODO: Benchmark this vs. big.Int vs. something better
func incrementNonce(nonce []byte) error {
	for i := range nonce {
		if nonce[i] < 255 {
			nonce[i] ++
			return nil
		} else {
			nonce[i] = 0
		}
	}
	return errors.NonceError("reached nonce limit for incremental nonces")
}
