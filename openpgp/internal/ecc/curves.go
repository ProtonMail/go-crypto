// Package ecc implements a generic interface for ECDH, ECDSA, and EdDSA.
package ecc

import (
	"io"
	"math/big"
)

type Curve interface {
	GetCurveType() CurveType
	GetCurveName() string
}

type ECDSACurve interface {
	Curve
	MarshalPoint(x, y *big.Int) []byte
	UnmarshalPoint([]byte) (x, y *big.Int)
	MarshalIntegerSecret(d *big.Int) []byte
	UnmarshalIntegerSecret(d []byte) *big.Int
	GenerateECDSA(rand io.Reader) (x, y, secret *big.Int, err error)
	Sign(rand io.Reader, x, y, d *big.Int, hash []byte) (r, s *big.Int, err error)
	Verify(x, y *big.Int, hash []byte, r, s *big.Int) bool
	Validate(x, y *big.Int, secret []byte) error
}

type EdDSACurve interface {
	Curve
	MarshalPoint(x []byte) []byte
	UnmarshalPoint([]byte) (x []byte)
	MarshalByteSecret(d []byte) []byte
	UnmarshalByteSecret(d []byte) []byte
	GenerateEdDSA(rand io.Reader) (pub, priv []byte, err error)
	Sign(publicKey, privateKey, message []byte) (r, s []byte, err error)
	Verify(publicKey, message, r, s []byte) bool
	Validate(publicKey, privateKey []byte) (err error)
}
type ECDHCurve interface {
	Curve
	MarshalPoint(x, y *big.Int) []byte
	UnmarshalPoint([]byte) (x, y *big.Int)
	MarshalByteSecret(d []byte) []byte
	UnmarshalByteSecret(d []byte) []byte
	GenerateECDH(rand io.Reader) (x, y *big.Int, secret []byte, err error)
	Encaps(rand io.Reader, x, y *big.Int) (ephemeral, sharedSecret []byte, err error)
	Decaps(ephemeral, secret []byte) (sharedSecret []byte, err error)
	Validate(x, y *big.Int, secret []byte) error
}
