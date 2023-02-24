// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package openpgp

import (
	goerrors "errors"
	"github.com/ProtonMail/go-crypto/openpgp/ecdh"
	"github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func (e *Entity) NewForwardingEntity(config *packet.Config) (forwardeeKey *Entity, proxyParam []byte, err error) {
	encryptionSubKey, ok := e.EncryptionKey(config.Now())
	if !ok {
		return nil, nil, errors.InvalidArgumentError("no valid encryption key found")
	}

	if encryptionSubKey.PublicKey.Version != 4 {
		return nil, nil, errors.InvalidArgumentError("unsupported encryption subkey version")
	}

	if encryptionSubKey.PrivateKey.PubKeyAlgo != packet.PubKeyAlgoECDH {
		return nil, nil, errors.InvalidArgumentError("encryption subkey is not algorithm 18 (ECDH)")
	}

	ecdhKey, ok := encryptionSubKey.PrivateKey.PrivateKey.(*ecdh.PrivateKey)
	if !ok {
		return nil, nil, errors.InvalidArgumentError("encryption subkey is not type ECDH")
	}

	config.Algorithm = packet.PubKeyAlgoEdDSA
	config.Curve = packet.Curve25519
	id := e.PrimaryIdentity().UserId

	forwardeeKey, err = NewEntity(id.Name, id.Comment, id.Email, config)
	if err != nil {
		return nil, nil, err
	}

	forwardeeEcdhKey, ok := forwardeeKey.Subkeys[0].PrivateKey.PrivateKey.(*ecdh.PrivateKey)
	if !ok {
		return nil, nil, goerrors.New("wrong forwarding sub key generation")
	}

	proxyParam, err = ecdh.DeriveProxyParam(ecdhKey, forwardeeEcdhKey)
	if err != nil {
		return nil, nil, err
	}

	kdf := ecdh.KDF{
		Version: ecdh.KDFVersionForwarding,
		Hash: ecdhKey.KDF.Hash,
		Cipher: ecdhKey.KDF.Cipher,
		ReplacementFingerprint: encryptionSubKey.PublicKey.Fingerprint,
	}

	err = forwardeeKey.Subkeys[0].PublicKey.ReplaceKDF(kdf)
	if err != nil {
		return nil, nil, err
	}

	// 0x04 - This key may be used to encrypt communications.
	forwardeeKey.Subkeys[0].Sig.FlagEncryptCommunications = false

	// 0x08 - This key may be used to encrypt storage.
	forwardeeKey.Subkeys[0].Sig.FlagEncryptStorage = false

	// 0x10 - The private component of this key may have been split by a secret-sharing mechanism.
	forwardeeKey.Subkeys[0].Sig.FlagSplitKey = true

	// 0x40 - This key may be used for forwarded communications.
	forwardeeKey.Subkeys[0].Sig.FlagForward = true

	return forwardeeKey, proxyParam, nil
}
