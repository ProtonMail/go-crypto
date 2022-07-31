// Package ecc implements a generic interface for ECDH, ECDSA, and EdDSA.
package ecc

import (
	"bytes"
	"crypto/elliptic"
	"github.com/ProtonMail/go-crypto/bitcurves"
	"github.com/ProtonMail/go-crypto/brainpool"
	"github.com/ProtonMail/go-crypto/openpgp/internal/encoding"
)

type SignatureAlgorithm uint8

type CurveInfo struct {
	Name string
	Oid *encoding.OID
	Curve Curve
	CanEncrypt bool
}

var Curves = []CurveInfo{
	{
		Name: "NIST curve P-256",
		Oid: encoding.NewOID([]byte{0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}),
		Curve: NewGenericCurve(elliptic.P256(), NISTCurve),
	},
	{
		Name: "NIST curve P-384",
		Oid: encoding.NewOID([]byte{0x2B, 0x81, 0x04, 0x00, 0x22}),
		Curve: NewGenericCurve(elliptic.P384(), NISTCurve),
	},
	{
		Name: "NIST curve P-521",
		Oid: encoding.NewOID([]byte{0x2B, 0x81, 0x04, 0x00, 0x23}),
		Curve: NewGenericCurve(elliptic.P521(), NISTCurve),
	},
	{
		Name: "SecP256k1",
		Oid: encoding.NewOID([]byte{0x2B, 0x81, 0x04, 0x00, 0x0A}),
		Curve: NewGenericCurve(bitcurves.S256(), BitCurve),
	},
	{
		Name: "Curve25519",
		Oid: encoding.NewOID([]byte{0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01}),
		Curve: NewCurve25519(),
	},
	{
		Name: "Ed25519",
		Oid: encoding.NewOID([]byte{0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01}),
		Curve: NewEd25519(),
	},
	{
		Name: "Brainpool P256r1",
		Oid: encoding.NewOID([]byte{0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07}),
		Curve: NewGenericCurve(brainpool.P256r1(), BrainpoolCurve),
	},
	{
		Name: "BrainpoolP384r1",
		Oid: encoding.NewOID([]byte{0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B}),
		Curve: NewGenericCurve(brainpool.P384r1(), BrainpoolCurve),
	},
	{
		Name: "BrainpoolP512r1",
		Oid: encoding.NewOID([]byte{0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D}),
		Curve: NewGenericCurve(brainpool.P512r1(), BrainpoolCurve),
	},
}

func FindByCurve(curve Curve) *CurveInfo {
	for _, curveInfo := range Curves {
		if curveInfo.Curve.GetCurveType() == curve.GetCurveType() && curveInfo.Curve.GetCurveName() == curve.GetCurveName() {
			return &curveInfo
		}
	}
	return nil
}

func FindByOid(oid encoding.Field) *CurveInfo {
	var rawBytes = oid.Bytes()
	for _, curveInfo := range Curves {
		if bytes.Equal(curveInfo.Oid.Bytes(), rawBytes) {
			return &curveInfo
		}
	}
	return nil
}