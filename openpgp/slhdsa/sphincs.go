// Package slhdsa implements SLH-DSA suitable for OpenPGP, experimental.
// It follows the specs https://www.ietf.org/archive/id/draft-wussler-openpgp-pqc-03.html#name-slh-dsa-2
package slhdsa

import (
	"crypto/subtle"
	goerrors "errors"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
)

// Mode defines the underlying hash and mode depending on the algorithm ID as specified here:
// https://www.ietf.org/archive/id/draft-wussler-openpgp-pqc-03.html#name-parameter-specification
type Mode uint8
const (
	ModeSimpleSHA2  Mode = 1
	ModeSimpleShake Mode = 2
)

type PublicKey struct {
	ParameterSetId ParameterSetId
	Mode Mode
	Parameters *parameters.Parameters
	PublicData *sphincs.SPHINCS_PK
}

type PrivateKey struct {
	PublicKey
	SecretData *sphincs.SPHINCS_SK
}

func (priv *PrivateKey) SerializePrivate ()([]byte, error) {
	return priv.SecretData.SerializeSK()
}

func (priv *PrivateKey) UnmarshalPrivate (data []byte) (err error) {
	// Copy data to prevent library from using an older reference
	serialized := make([]byte, len(data))
	copy(serialized, data)

	priv.SecretData, err = sphincs.DeserializeSK(priv.Parameters, serialized)
	if  err != nil {
		return err
	}

	return nil
}

func (pub *PublicKey) SerializePublic ()([]byte, error) {
	return pub.PublicData.SerializePK()
}

func (pub *PublicKey) UnmarshalPublic (data []byte) (err error) {
	// Copy data to prevent library from using an older reference
	serialized := make([]byte, len(data))
	copy(serialized, data)

	pub.PublicData, err = sphincs.DeserializePK(pub.Parameters, serialized)
	if  err != nil {
		return err
	}

	return nil
}

// GenerateKey generates a SLH-DSA key as specified in
// https://www.ietf.org/archive/id/draft-wussler-openpgp-pqc-03.html#name-key-generation
func GenerateKey(_ io.Reader, mode Mode, param ParameterSetId) (priv *PrivateKey, err error) {
	priv = new(PrivateKey)

	priv.ParameterSetId = param
	priv.Mode = mode
	if priv.Parameters, err = GetParametersFromModeAndId(mode, param); err != nil {
		return nil, err
	}

	// TODO: add error handling to library
	// TODO: accept external randomness source
	priv.SecretData, priv.PublicData = sphincs.Spx_keygen(priv.Parameters)

	return
}

// Sign generates a SLH-DSA signature as specified in
// https://www.ietf.org/archive/id/draft-wussler-openpgp-pqc-03.html#name-signature-generation-2
func Sign(priv *PrivateKey, message []byte) ([]byte, error) {
	sig := sphincs.Spx_sign(priv.Parameters, message, priv.SecretData)
	return sig.SerializeSignature()
}

// Verify verifies a SLH-DSA signature as specified in
// https://www.ietf.org/archive/id/draft-wussler-openpgp-pqc-03.html#name-signature-verification-2
func Verify(pub *PublicKey, message, sig []byte) bool {
	deserializedSig, err := sphincs.DeserializeSignature(pub.Parameters, sig)
	if err != nil {
		return false
	}

	return sphincs.Spx_verify(pub.Parameters, message, deserializedSig, pub.PublicData)
}

// Validate checks that the public key corresponds to the private key
func Validate(priv *PrivateKey) (err error) {
	if subtle.ConstantTimeCompare(priv.PublicData.PKseed, priv.SecretData.PKseed) == 0 ||
		subtle.ConstantTimeCompare(priv.PublicData.PKroot, priv.SecretData.PKroot) == 0 {
		return errors.KeyInvalidError("slhdsa: invalid public key")
	}

	return
}

// GetParametersFromModeAndId returns the instance Parameters given a Mode and a ParameterSetID
func GetParametersFromModeAndId(mode Mode, param ParameterSetId) (*parameters.Parameters, error) {
	switch mode {
	case ModeSimpleSHA2:
		switch param {
		case Param128s:
			return parameters.MakeSphincsPlusSHA256128sSimple(false), nil
		case Param128f:
			return parameters.MakeSphincsPlusSHA256128fSimple(false), nil
		case Param192s:
			return parameters.MakeSphincsPlusSHA256192sSimple(false), nil
		case Param192f:
			return parameters.MakeSphincsPlusSHA256192fSimple(false), nil
		case Param256s:
			return parameters.MakeSphincsPlusSHA256256sSimple(false), nil
		case Param256f:
			return parameters.MakeSphincsPlusSHA256256fSimple(false), nil
		default:
			return nil, goerrors.New("slhdsa: invalid sha2 parameter")
		}
	case ModeSimpleShake:
		switch param {
		case Param128s:
			return parameters.MakeSphincsPlusSHAKE256128sSimple(false), nil
		case Param128f:
			return parameters.MakeSphincsPlusSHAKE256128fSimple(false), nil
		case Param192s:
			return parameters.MakeSphincsPlusSHAKE256192sSimple(false), nil
		case Param192f:
			return parameters.MakeSphincsPlusSHAKE256192fSimple(false), nil
		case Param256s:
			return parameters.MakeSphincsPlusSHAKE256256sSimple(false), nil
		case Param256f:
			return parameters.MakeSphincsPlusSHAKE256256fSimple(false), nil
		default:
			return nil, goerrors.New("slhdsa: invalid shake parameter")
		}
	default:
		return nil, goerrors.New("slhdsa: invalid hash algorithm")
	}
}
