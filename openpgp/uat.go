// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package openpgp

import (
	"crypto"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func (t *Entity) AddPhoto(jpegBytes []byte, config *packet.Config) error {
	creationTime := config.Now()
	keyLifetimeSecs := config.KeyLifetime()

	uat, err := packet.NewUserAttributePhotoBytes([][]byte{jpegBytes})
	if err != nil {
		return errors.InvalidArgumentError("add photo field contained invalid characters")
	}

	primary := t.PrivateKey

	isPrimaryId := false

	if len(t.Identities) == 0 {
		isPrimaryId = true
	}

	selfSignature := &packet.Signature{
		Version:           primary.PublicKey.Version,
		SigType:           packet.SigTypePositiveCert,
		PubKeyAlgo:        primary.PublicKey.PubKeyAlgo,
		Hash:              config.Hash(),
		CreationTime:      creationTime,
		KeyLifetimeSecs:   &keyLifetimeSecs,
		IssuerKeyId:       &primary.PublicKey.KeyId,
		IssuerFingerprint: primary.PublicKey.Fingerprint,
		IsPrimaryId:       &isPrimaryId,
		FlagsValid:        true,
		FlagSign:          true,
		FlagCertify:       true,
		MDC:               true, // true by default, see 5.8 vs. 5.14
		AEAD:              config.AEAD() != nil,
		V5Keys:            config != nil && config.V5Keys,
	}

	// Set the PreferredHash for the SelfSignature from the packet.Config.
	// If it is not the must-implement algorithm from rfc4880bis, append that.
	selfSignature.PreferredHash = []uint8{hashToHashId(config.Hash())}
	if config.Hash() != crypto.SHA256 {
		selfSignature.PreferredHash = append(selfSignature.PreferredHash, hashToHashId(crypto.SHA256))
	}

	// Likewise for DefaultCipher.
	selfSignature.PreferredSymmetric = []uint8{uint8(config.Cipher())}
	if config.Cipher() != packet.CipherAES128 {
		selfSignature.PreferredSymmetric = append(selfSignature.PreferredSymmetric, uint8(packet.CipherAES128))
	}

	// We set CompressionNone as the preferred compression algorithm because
	// of compression side channel attacks, then append the configured
	// DefaultCompressionAlgo if any is set (to signal support for cases
	// where the application knows that using compression is safe).
	selfSignature.PreferredCompression = []uint8{uint8(packet.CompressionNone)}
	if config.Compression() != packet.CompressionNone {
		selfSignature.PreferredCompression = append(selfSignature.PreferredCompression, uint8(config.Compression()))
	}

	// And for DefaultMode.
	selfSignature.PreferredAEAD = []uint8{uint8(config.AEAD().Mode())}
	if config.AEAD().Mode() != packet.AEADModeEAX {
		selfSignature.PreferredAEAD = append(selfSignature.PreferredAEAD, uint8(packet.AEADModeEAX))
	}

	// User ID binding signature
	err = selfSignature.SignPhoto(uat, &primary.PublicKey, primary, config)
	if err != nil {
		return err
	}
	userAttribute := &UserAttribute{
		UserAttribute: uat,
		SelfSignature: selfSignature,
		Signatures:    []*packet.Signature{selfSignature},
	}
	t.UserAttribute = append(t.UserAttribute, userAttribute)
	return nil
}

func addUserAttribute(e *Entity, packets *packet.Reader, pkt *packet.UserAttribute) error {
	// Make a new Identity object, that we might wind up throwing away.
	// We'll only add it if we get a valid self-signature over this
	// userID.
	uat := new(UserAttribute)
	uat.UserAttribute = pkt
	e.UserAttribute = append(e.UserAttribute, uat)

	for {
		p, err := packets.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		sig, ok := p.(*packet.Signature)
		if !ok {
			packets.Unread(p)
			break
		}

		if sig.SigType != packet.SigTypeGenericCert &&
			sig.SigType != packet.SigTypePersonaCert &&
			sig.SigType != packet.SigTypeCasualCert &&
			sig.SigType != packet.SigTypePositiveCert &&
			sig.SigType != packet.SigTypeCertificationRevocation {
			return errors.StructuralError("user ID signature with wrong type")
		}

		if sig.CheckKeyIdOrFingerprint(e.PrimaryKey) {
			if err = e.PrimaryKey.VerifyUserAttributeSignature(pkt, e.PrimaryKey, sig); err != nil {
				return errors.StructuralError("user attribute self-signature invalid: " + err.Error())
			}
			if sig.SigType == packet.SigTypeCertificationRevocation {
				uat.Revocations = append(uat.Revocations, sig)
			} else if uat.SelfSignature == nil || sig.CreationTime.After(uat.SelfSignature.CreationTime) {
				uat.SelfSignature = sig
			}
			uat.Signatures = append(uat.Signatures, sig)
		} else {
			uat.Signatures = append(uat.Signatures, sig)
		}
	}

	return nil
}
