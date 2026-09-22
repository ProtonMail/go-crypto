// Copyright 2026 Proton AG. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"crypto"
	"hash"
	"io"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/s2k"
	"golang.org/x/crypto/hkdf"
)

type PersistentSymmetricKeyPublicFields struct {
	SymmetricAlgorithm CipherFunction
	FingerprintSeed    []byte
}

type PersistentSymmetricKeyPrivateFields struct {
	Key []byte
}

// PersistentSymmetricKey represents a persistent symmetric key packet.
// See draft-ietf-openpgp-persistent-symmetric-keys.
type PersistentSymmetricKey struct {
	PrivateKey
}

func NewPersistentSymmetricKey(creationTime time.Time, symmetricAlgorithm CipherFunction, fingerprintSeed, keyMaterial []byte) *PersistentSymmetricKey {
	if len(fingerprintSeed) != 32 {
		panic("openpgp: incorrect fingerprint seed length in NewPersistentSymmetricKey")
	}
	if len(keyMaterial) != symmetricAlgorithm.KeySize() {
		panic("openpgp: incorrect key material length in NewPersistentSymmetricKey")
	}
	psk := &PersistentSymmetricKey{
		PrivateKey: PrivateKey{
			PublicKey: PublicKey{
				Version:      6,
				CreationTime: creationTime,
				PubKeyAlgo:   PubKeyAlgoAEAD,
				PublicKey:    &PersistentSymmetricKeyPublicFields{
					SymmetricAlgorithm: symmetricAlgorithm,
					FingerprintSeed: fingerprintSeed,
				},
			},
			PrivateKey: &PersistentSymmetricKeyPrivateFields{
				Key: keyMaterial,
			},
		},
	}
	psk.setFingerprintAndKeyId()
	return psk
}

func (psk *PersistentSymmetricKey) parse(r io.Reader) (err error) {
	err = (&psk.PrivateKey).parsePrivateKey(r)
	if err != nil {
		return
	}
	if psk.Version < 6 {
		return errors.StructuralError("Persistent Symmetric Key packets can only be used with version 6")
	}
	if psk.PubKeyAlgo != PubKeyAlgoAEAD {
		return errors.StructuralError("Persistent Symmetric Key packets can only be used with algorithm 0")
	}
	if psk.s2kType != S2KNON && psk.s2kType != S2KAEAD {
		return errors.StructuralError("Persistent Symmetric Key packets can only be encrypted with modern AEAD")
	}
	return
}

func (psk *PersistentSymmetricKey) Serialize(w io.Writer) (err error) {
	// Sanity checks
	if psk.Version < 6 {
		return errors.StructuralError("Persistent Symmetric Key packets can only be used with version 6")
	}
	if psk.PubKeyAlgo != PubKeyAlgoAEAD {
		return errors.StructuralError("Persistent Symmetric Key packets can only be used with algorithm 0")
	}
	if psk.s2kType != S2KNON && psk.s2kType != S2KAEAD {
		return errors.StructuralError("Persistent Symmetric Key packets can only be encrypted with modern AEAD")
	}

	contents := bytes.NewBuffer(nil)
	err = (&psk.PrivateKey).serializeWithoutHeaders(contents)
	if err != nil {
		return
	}

	err = serializeHeader(w, packetTypePersistentSymmetricKey, contents.Len())
	if err != nil {
		return
	}
	_, err = io.Copy(w, contents)
	if err != nil {
		return
	}
	return
}

// EncryptWithConfig encrypts an unencrypted persistent symmetric key using the passphrase and the config.
func (psk *PersistentSymmetricKey) EncryptWithConfig(passphrase []byte, config *Config) error {
	params, err := s2k.Generate(config.Random(), config.S2K())
	if err != nil {
		return err
	}
	// Derive an encryption key with the configured s2k function.
	key := make([]byte, config.Cipher().KeySize())
	s2k, err := params.Function()
	if err != nil {
		return err
	}
	s2k(key, passphrase)
	s2kType := S2KAEAD
	psk.aead = config.AEAD().Mode()
	psk.cipher = config.Cipher()
	key = psk.applyHKDF(key)
	// Encrypt the persistent symmetric key with the derived encryption key.
	return psk.encrypt(key, params, s2kType, config.Cipher(), config.Random())
}

// Encrypt encrypts an unencrypted persistent symmetric key using a passphrase.
func (psk *PersistentSymmetricKey) Encrypt(passphrase []byte) error {
	// Default config of persistent symmetric key encryption
	config := &Config{
		S2KConfig: &s2k.Config{
			S2KMode:  s2k.Argon2S2K,
		},
		DefaultCipher: CipherAES256,
	}
	return psk.EncryptWithConfig(passphrase, config)
}

// VerifySignature returns nil iff sig is a valid signature, made by this
// key, of the data hashed into signed. signed is mutated by this call.
func (psk *PersistentSymmetricKey) VerifySignature(signed hash.Hash, sig *Signature) (err error) {
	signed.Write(sig.HashSuffix)
	hashBytes := signed.Sum(nil)
	if hashBytes[0] != sig.HashTag[0] || hashBytes[1] != sig.HashTag[1] {
		return errors.SignatureError("hash tag doesn't match")
	}

	if sig.PubKeyAlgo != PubKeyAlgoAEAD {
		return errors.SignatureError("persistent symmetric keys can only verify AEAD signatures")
	}

	pk := psk.PublicKey.PublicKey.(*PersistentSymmetricKeyPublicFields)
	sk := psk.PrivateKey.PrivateKey.(*PersistentSymmetricKeyPrivateFields)
	packetID := 0xC0 | packetTypeSignature
	version := sig.Version
	aeadMode := *sig.AEADMode
	info := []byte{byte(packetID), byte(version), byte(pk.SymmetricAlgorithm), byte(aeadMode)}
	salt := sig.SigBytes1
	hkdf := hkdf.New(crypto.SHA512.New, sk.Key, salt, info)
	keySize := pk.SymmetricAlgorithm.KeySize()
	ivLength := aeadMode.IvLength()
	encKey := make([]byte, keySize)
	iv := make([]byte, ivLength)
	_, err = hkdf.Read(encKey)
	if err != nil {
		return err
	}
	_, err = hkdf.Read(iv)
	if err != nil {
		return err
	}
	authTag := sig.SigBytes2
	modeInstance := aeadMode.new(pk.SymmetricAlgorithm.new(encKey))
	result, err := modeInstance.Open(nil, iv, authTag, hashBytes)
	if err != nil {
		return err
	}
	if len(result) != 0 {
		return errors.SignatureError("unexpected plaintext in AEAD signature")
	}
	return nil
}
