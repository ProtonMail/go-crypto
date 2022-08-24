package kyber

import (
	"errors"
	libkyber "github.com/kudelskisecurity/crystals-go/crystals-kyber"
)

type ParameterSetId uint8

const (
	Parameter1 ParameterSetId = 1
	Parameter2 ParameterSetId = 2
	Parameter3 ParameterSetId = 3
)

// ParseParameterSetID parses the ParameterSetId from a byte, returning an error if it's not recognised
func ParseParameterSetID(data [1]byte) (setId ParameterSetId, err error) {
	setId = ParameterSetId(data[0])
	switch setId {
	case Parameter1, Parameter2, Parameter3:
		return setId, nil
	default:
		return 0, errors.New("packet: unsupported Kyber public key algorithm")
	}
}

// GetKyber returns the Kyber instance from the matching Kyber ParameterSet ID
func (setId ParameterSetId) GetKyber() *libkyber.Kyber {
	switch setId {
	case Parameter1:
		return libkyber.NewKyber512()
	case Parameter2:
		return libkyber.NewKyber768()
	case Parameter3:
		return libkyber.NewKyber1024()
	default:
		panic("packet: unsupported Kyber public key algorithm")
	}
}

func (setId ParameterSetId) GetPkLen() int {
	switch setId {
	case Parameter1:
		return 800
	case Parameter2:
		return 1184
	case Parameter3:
		return 1568
	default:
		panic("packet: unsupported Kyber public key algorithm")
	}
}

func (setId ParameterSetId) GetSkLen() int {
	switch setId {
	case Parameter1:
		return 1632
	case Parameter2:
		return 2400
	case Parameter3:
		return 3168
	default:
		panic("packet: unsupported Kyber public key algorithm")
	}
}

func (setId ParameterSetId) GetEphemeralLen() int {
	switch setId {
	case Parameter1:
		return 768
	case Parameter2:
		return 1088
	case Parameter3:
		return 1568
	default:
		panic("packet: unsupported Kyber public key algorithm")
	}
}

func (setId ParameterSetId) EncodedBytes() []byte {
	return []byte{byte(setId)}
}