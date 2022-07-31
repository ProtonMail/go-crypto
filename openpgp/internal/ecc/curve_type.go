// Package ecc implements a generic interface for ECDH, ECDSA, and EdDSA.
package ecc

type CurveType uint8

const (
	NISTCurve CurveType = 1
	Curve25519 CurveType = 2
	BitCurve CurveType = 3
	BrainpoolCurve CurveType = 4
	Ed25519 = 5
)