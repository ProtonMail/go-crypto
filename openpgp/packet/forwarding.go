package packet

import (
	"encoding/binary"
	"strconv"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
)

// ForwardingInstance represents a single forwarding instance (mapping IDs to a Proxy Param)
type ForwardingInstance struct {
	KeyVersion           int
	ForwarderFingerprint []byte
	ForwardeeFingerprint []byte
	ProxyParameter       []byte
}

// GetForwarderKeyId returns the key ID of the forwarder key.
// Returns 0 if the instance is malformed, see Validate.
func (f *ForwardingInstance) GetForwarderKeyId() uint64 {
	keyId, _ := computeForwardingKeyId(f.ForwarderFingerprint, f.KeyVersion)
	return keyId
}

// GetForwardeeKeyId returns the key ID of the forwardee key.
// Returns 0 if the instance is malformed, see Validate.
func (f *ForwardingInstance) GetForwardeeKeyId() uint64 {
	keyId, _ := computeForwardingKeyId(f.ForwardeeFingerprint, f.KeyVersion)
	return keyId
}

// Validate returns an error if the key version or the fingerprints of the
// forwarding instance are malformed.
func (f *ForwardingInstance) Validate() error {
	if _, err := computeForwardingKeyId(f.ForwarderFingerprint, f.KeyVersion); err != nil {
		return err
	}
	_, err := computeForwardingKeyId(f.ForwardeeFingerprint, f.KeyVersion)
	return err
}

func (f *ForwardingInstance) getForwardeeKeyIdOrZero(originalKeyId uint64) uint64 {
	if originalKeyId == 0 {
		return 0
	}

	return f.GetForwardeeKeyId()
}

func computeForwardingKeyId(fingerprint []byte, version int) (uint64, error) {
	switch version {
	case 4:
		if len(fingerprint) != fingerprintSize {
			return 0, errors.InvalidArgumentError("invalid fingerprint length in forwarding instance: " + strconv.Itoa(len(fingerprint)))
		}
		return binary.BigEndian.Uint64(fingerprint[12:20]), nil
	default:
		return 0, errors.InvalidArgumentError("invalid key version in forwarding instance: " + strconv.Itoa(version))
	}
}
