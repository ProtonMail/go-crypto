package dilithium

import (
	"errors"
	libdilithium "github.com/kudelskisecurity/crystals-go/crystals-dilithium"
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
		return 0, errors.New("packet: unsupported Dilithium public key algorithm")
	}
}

func (setId ParameterSetId) GetDilithium() *libdilithium.Dilithium {
	switch setId {
	case Parameter1:
		return libdilithium.NewDilithium2()
	case Parameter2:
		return libdilithium.NewDilithium3()
	case Parameter3:
		return libdilithium.NewDilithium5()
	default:
		panic("packet: unsupported Dilithium public key algorithm")
	}
}

func (setId ParameterSetId) GetPkLen() int {
	switch setId {
	case Parameter1:
		return 1312
	case Parameter2:
		return 1952
	case Parameter3:
		return 2592
	default:
		panic("packet: unsupported Dilithium public key algorithm")
	}
}

func (setId ParameterSetId) GetSkLen() int {
	switch setId {
	case Parameter1:
		return 2528
	case Parameter2:
		return 4000
	case Parameter3:
		return 4864
	default:
		panic("packet: unsupported Dilithium public key algorithm")
	}
}

func (setId ParameterSetId) GetSigLen() int {
	switch setId {
	case Parameter1:
		return 2420
	case Parameter2:
		return 3293
	case Parameter3:
		return 4595
	default:
		panic("packet: unsupported Dilithium public key algorithm")
	}
}

func (setId ParameterSetId) EncodedBytes() []byte {
	return []byte{byte(setId)}
}