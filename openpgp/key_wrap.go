package openpgp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"

	"github.com/ProtonMail/go-crypto/openpgp/eddsa"
	"github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/internal/ecc"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	internalecdsa "github.com/ProtonMail/go-crypto/openpgp/ecdsa"
)

// NewSigningEntityFromKey returns an Entity that contains either a RSA, ECDSA
// or Ed25519 keypair passed by the user with a single identity composed of the
// given full name, comment and email, any of which may be empty but must not
// contain any of "()<>\x00". If config is nil, sensible defaults will be used.
// It is not required to assign any of the key type parameters in the config
// (in fact, they will be ignored); these will be set based on the passed key.
//
// The following key types are currently supported: *rsa.PrivateKey,
// *ecdsa.PrivateKey and ed25519.PrivateKey (not a pointer). Unsupported key
// types result in an error.
func NewSigningEntityFromKey(name, comment, email string, key crypto.PrivateKey, config *packet.Config) (*Entity, error) {
	creationTime := config.Now()
	keyLifetimeSecs := config.KeyLifetime()

	primaryPrivRaw, err := newSignerFromKey(key, config)
	if err != nil {
		return nil, err
	}
	primary := packet.NewSignerPrivateKey(creationTime, primaryPrivRaw)
	if config.V6() {
		primary.UpgradeToV6()
	}

	e := &Entity{
		PrimaryKey: &primary.PublicKey,
		PrivateKey: primary,
		Identities: make(map[string]*Identity),
		Subkeys:    []Subkey{},
		Signatures: []*packet.Signature{},
	}

	if config.V6() {
		// In v6 keys algorithm preferences should be stored in direct key signatures
		selfSignature := createSignaturePacket(&primary.PublicKey, packet.SigTypeDirectSignature, config)
		err = writeKeyProperties(selfSignature, creationTime, keyLifetimeSecs, config)
		if err != nil {
			return nil, err
		}
		err = selfSignature.SignDirectKeyBinding(&primary.PublicKey, primary, config)
		if err != nil {
			return nil, err
		}
		e.Signatures = append(e.Signatures, selfSignature)
		e.SelfSignature = selfSignature
	}

	err = e.addUserId(name, comment, email, config, creationTime, keyLifetimeSecs, !config.V6())
	if err != nil {
		return nil, err
	}

	return e, nil
}

func (e *Entity) AddSigningSubkeyFromKey(key crypto.PrivateKey, config *packet.Config) error {
	creationTime := config.Now()
	keyLifetimeSecs := config.KeyLifetime()

	subPrivRaw, err := newSignerFromKey(key, config)
	if err != nil {
		return err
	}
	sub := packet.NewSignerPrivateKey(creationTime, subPrivRaw)
	sub.IsSubkey = true
	if config.V6() {
		sub.UpgradeToV6()
	}

	subkey := Subkey{
		PublicKey:  &sub.PublicKey,
		PrivateKey: sub,
	}
	subkey.Sig = createSignaturePacket(e.PrimaryKey, packet.SigTypeSubkeyBinding, config)
	subkey.Sig.CreationTime = creationTime
	subkey.Sig.KeyLifetimeSecs = &keyLifetimeSecs
	subkey.Sig.FlagsValid = true
	subkey.Sig.FlagSign = true
	subkey.Sig.EmbeddedSignature = createSignaturePacket(subkey.PublicKey, packet.SigTypePrimaryKeyBinding, config)
	subkey.Sig.EmbeddedSignature.CreationTime = creationTime

	err = subkey.Sig.EmbeddedSignature.CrossSignKey(subkey.PublicKey, e.PrimaryKey, subkey.PrivateKey, config)
	if err != nil {
		return err
	}

	err = subkey.Sig.SignKey(subkey.PublicKey, e.PrivateKey, config)
	if err != nil {
		return err
	}

	e.Subkeys = append(e.Subkeys, subkey)
	return nil
}

func newSignerFromKey(key crypto.PrivateKey, config *packet.Config) (interface{}, error) {
	switch key := key.(type) {
	case *rsa.PrivateKey:
		config.Algorithm = packet.PubKeyAlgoRSA
		return key, nil
	case *ecdsa.PrivateKey:
		var c ecc.ECDSACurve
		switch key.Curve {
		case elliptic.P256():
			c = ecc.NewGenericCurve(elliptic.P256())
			config.Curve = packet.CurveNistP256
			// The default hash SHA256 will serve here
		case elliptic.P384():
			c = ecc.NewGenericCurve(elliptic.P384())
			config.Curve = packet.CurveNistP384
			if config.DefaultHash == 0 {
				config.DefaultHash = crypto.SHA384
			}
		case elliptic.P521():
			c = ecc.NewGenericCurve(elliptic.P521())
			config.Curve = packet.CurveNistP521
			if config.DefaultHash == 0 {
				config.DefaultHash = crypto.SHA512
			}
		default:
			return nil, errors.InvalidArgumentError("unsupported elliptic curve")
		}
		priv := internalecdsa.NewPrivateKey(
			*internalecdsa.NewPublicKey(c),
		)
		priv.PublicKey.X, priv.PublicKey.Y, priv.D = key.X, key.Y, key.D
		config.Algorithm = packet.PubKeyAlgoECDSA
		return priv, nil
	case ed25519.PrivateKey:
		if config.V6() {
			// Implementations MUST NOT accept or generate v6 key material
			// using the deprecated OIDs.
			return nil, errors.InvalidArgumentError("EdDSALegacy cannot be used for v6 keys")
		}
		curve := ecc.FindEdDSAByGenName(string(packet.Curve25519))
		if curve == nil {
			return nil, errors.InvalidArgumentError("unsupported curve")
		}
		priv := eddsa.NewPrivateKey(*eddsa.NewPublicKey(curve))
		priv.PublicKey.X = key.Public().(ed25519.PublicKey)[:]
		priv.D = key.Seed()
		config.Algorithm = packet.PubKeyAlgoEdDSA
		return priv, nil
	default:
		return nil, errors.InvalidArgumentError("unsupported public key algorithm")
	}
}
