// Package sphincs_plus implements SPHINCS+ suitable for OpenPGP, experimental.
// It follows the specs https://www.ietf.org/archive/id/draft-wussler-openpgp-pqc-00.html#name-sphincs-8
package sphincs_plus

import (
	goerrors "errors"
)

// ParameterSetId represents the security level parameters defined in:
// https://www.ietf.org/archive/id/draft-wussler-openpgp-pqc-00.html#table-13
type ParameterSetId uint8
const (
	Param128s  ParameterSetId = 1
	Param128f  ParameterSetId = 2
	Param192s  ParameterSetId = 3
	Param192f  ParameterSetId = 4
	Param256s ParameterSetId = 5
	Param256f ParameterSetId = 6
)

// ParseParameterSetID parses the ParameterSetId from a byte, returning an error if it's not recognised
func ParseParameterSetID(data [1]byte) (setId ParameterSetId, err error) {
	setId = ParameterSetId(data[0])
	switch setId {
	case Param128s, Param128f, Param192s, Param192f, Param256s, Param256f:
		return setId, nil
	default:
		return 0, goerrors.New("packet: unsupported sphincs+ parameter id")
	}
}

// GetPkLen returns the size of the public key in octets according to
// https://www.ietf.org/archive/id/draft-wussler-openpgp-pqc-00.html#section-6.1
func (setId ParameterSetId) GetPkLen() int {
	switch setId {
	case Param128s, Param128f:
		return 32
	case Param192s, Param192f:
		return 48
	case Param256s, Param256f:
		return 64
	default:
		panic("sphincs_plus: unsupported parameter")
	}
}

// GetSkLen returns the size of the secret key in octets according to
// https://www.ietf.org/archive/id/draft-wussler-openpgp-pqc-00.html#section-6.1
func (setId ParameterSetId) GetSkLen() int {
	switch setId {
	case Param128s, Param128f:
		return 64
	case Param192s, Param192f:
		return 96
	case Param256s, Param256f:
		return 128
	default:
		panic("sphincs_plus: unsupported parameter")
	}
}

// GetSigLen returns the size of the signature in octets according to
// https://www.ietf.org/archive/id/draft-wussler-openpgp-pqc-00.html#section-6.1
func (setId ParameterSetId) GetSigLen() int {
	switch setId {
	case Param128s:
		return 7856
	case Param128f:
		return 17088
	case Param192s:
		return 16224
	case Param192f:
		return 35664
	case Param256s:
		return 29792
	case Param256f:
		return 49856
	default:
		panic("sphincs_plus: unsupported parameter")
	}
}

func (setId ParameterSetId) EncodedBytes() []byte {
	return []byte{byte(setId)}
}
