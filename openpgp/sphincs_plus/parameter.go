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
	Parameter1 ParameterSetId = 1
	Parameter2 ParameterSetId = 2
	Parameter3 ParameterSetId = 3
	Parameter4 ParameterSetId = 4
	Parameter5 ParameterSetId = 5
	Parameter6 ParameterSetId = 6
)

// ParseParameterSetID parses the ParameterSetId from a byte, returning an error if it's not recognised
func ParseParameterSetID(data [1]byte) (setId ParameterSetId, err error) {
	setId = ParameterSetId(data[0])
	switch setId {
	case Parameter1, Parameter2, Parameter3, Parameter4, Parameter5, Parameter6:
		return setId, nil
	default:
		return 0, goerrors.New("packet: unsupported sphincs+ parameter id")
	}
}

// GetPkLen returns the size of the public key in octets according to
// https://www.ietf.org/archive/id/draft-wussler-openpgp-pqc-00.html#section-6.1
func (setId ParameterSetId) GetPkLen() int {
	switch setId {
	case Parameter1, Parameter2:
		return 32
	case Parameter3, Parameter4:
		return 48
	case Parameter5, Parameter6:
		return 64
	default:
		panic("sphincs_plus: unsupported parameter")
	}
}

// GetSkLen returns the size of the secret key in octets according to
// https://www.ietf.org/archive/id/draft-wussler-openpgp-pqc-00.html#section-6.1
func (setId ParameterSetId) GetSkLen() int {
	switch setId {
	case Parameter1, Parameter2:
		return 64
	case Parameter3, Parameter4:
		return 96
	case Parameter5, Parameter6:
		return 128
	default:
		panic("sphincs_plus: unsupported parameter")
	}
}

// GetSigLen returns the size of the signature in octets according to
// https://www.ietf.org/archive/id/draft-wussler-openpgp-pqc-00.html#section-6.1
func (setId ParameterSetId) GetSigLen() int {
	switch setId {
	case Parameter1:
		return 7856
	case Parameter2:
		return 17088
	case Parameter3:
		return 16224
	case Parameter4:
		return 35664
	case Parameter5:
		return 29792
	case Parameter6:
		return 49856
	default:
		panic("sphincs_plus: unsupported parameter")
	}
}

func (setId ParameterSetId) EncodedBytes() []byte {
	return []byte{byte(setId)}
}
