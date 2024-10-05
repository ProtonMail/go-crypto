package v2

import (
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func (t *Entity) AddPhotos(jpegBytes [][]byte, config *packet.Config) error {
	creationTime := config.Now()

	uat, err := packet.NewUserAttributePhotoBytes(jpegBytes)
	if err != nil {
		return errors.InvalidArgumentError("add photo field contained invalid characters")
	}

	primary := t.PrivateKey

	isPrimaryId := len(t.Attributes) == 0

	selfSignature := &packet.Signature{
		Version:           primary.PublicKey.Version,
		SigType:           packet.SigTypePositiveCert,
		PubKeyAlgo:        primary.PublicKey.PubKeyAlgo,
		Hash:              config.Hash(),
		CreationTime:      creationTime,
		IssuerKeyId:       &primary.PublicKey.KeyId,
		IssuerFingerprint: primary.PublicKey.Fingerprint,
		IsPrimaryId:       &isPrimaryId,
	}

	// User Attribute binding signature
	err = selfSignature.SignUserAttribute(uat, &primary.PublicKey, primary, config)
	if err != nil {
		return err
	}
	userAttribute := &Attribute{
		UserAttribute: uat,
		SelfSignature: selfSignature,
		Signatures:    []*packet.Signature{selfSignature},
	}
	t.Attributes = append(t.Attributes, userAttribute)
	return nil
}

func addUserAttribute(e *Entity, packets *packet.Reader, pkt *packet.UserAttribute) error {
	uat := new(Attribute)
	uat.UserAttribute = pkt
	e.Attributes = append(e.Attributes, uat)

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
			return errors.StructuralError("user attribute signature with wrong type")
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
