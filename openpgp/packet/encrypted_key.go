// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"encoding/binary"
	"encoding/hex"
	"io"
	"math/big"
	"strconv"

	"github.com/ProtonMail/go-crypto/openpgp/ecdh"
	"github.com/ProtonMail/go-crypto/openpgp/elgamal"
	"github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/internal/encoding"
)

// EncryptedKey represents a public-key encrypted session key. See RFC 4880,
// section 5.1.
type EncryptedKey struct {
	Version     int
	KeyId       uint64
	KeyVersion	int // v6
	KeyFingerprint []byte // v6
	Algo        PublicKeyAlgorithm
	CipherFunc  CipherFunction // only valid after a successful Decrypt for a v3 packet
	Key         []byte         // only valid after a successful Decrypt

	encryptedMPI1, encryptedMPI2 encoding.Field
}

func (e *EncryptedKey) parse(r io.Reader) (err error) {
	var buf [8]byte
	_, err = readFull(r, buf[:1])
	if err != nil {
		return
	}
	e.Version =  int(buf[0])
	if e.Version != 3 && e.Version != 6 {
		return errors.UnsupportedError("unknown EncryptedKey version " + strconv.Itoa(int(buf[0])))
	}
	if e.Version == 6 {
		_, err = readFull(r, buf[:1])
		if err != nil {
			return
		}
		e.KeyVersion =  int(buf[0])
		if e.KeyVersion != 0 && e.KeyVersion != 4 && e.KeyVersion != 6 {
			return errors.UnsupportedError("unknown public key version " + strconv.Itoa(e.KeyVersion))
		}
		var fingerprint []byte
		if e.KeyVersion == 6 {
			fingerprint = make([]byte, 32)
		} else if e.KeyVersion == 4 {
			fingerprint = make([]byte, 20)
		}
		_, err = readFull(r, fingerprint)
		if err != nil {
			return
		}
		e.KeyFingerprint = fingerprint
		if e.KeyVersion == 6 {
			e.KeyId = binary.BigEndian.Uint64(e.KeyFingerprint[:8])
		} else if e.KeyVersion == 4 {
			e.KeyId = binary.BigEndian.Uint64(e.KeyFingerprint[12:20])
		}
	} else {
		_, err = readFull(r, buf[:8])
		if err != nil {
			return
		}
		e.KeyId = binary.BigEndian.Uint64(buf[:8])
	}

	_, err = readFull(r, buf[:1])
	if err != nil {
		return
	}
	e.Algo = PublicKeyAlgorithm(buf[0])
	switch e.Algo {
	case PubKeyAlgoRSA, PubKeyAlgoRSAEncryptOnly:
		e.encryptedMPI1 = new(encoding.MPI)
		if _, err = e.encryptedMPI1.ReadFrom(r); err != nil {
			return
		}
	case PubKeyAlgoElGamal:
		e.encryptedMPI1 = new(encoding.MPI)
		if _, err = e.encryptedMPI1.ReadFrom(r); err != nil {
			return
		}

		e.encryptedMPI2 = new(encoding.MPI)
		if _, err = e.encryptedMPI2.ReadFrom(r); err != nil {
			return
		}
	case PubKeyAlgoECDH:
		e.encryptedMPI1 = new(encoding.MPI)
		if _, err = e.encryptedMPI1.ReadFrom(r); err != nil {
			return
		}

		e.encryptedMPI2 = new(encoding.OID)
		if _, err = e.encryptedMPI2.ReadFrom(r); err != nil {
			return
		}
	}
	_, err = consumeAll(r)
	return
}

func checksumKeyMaterial(key []byte) uint16 {
	var checksum uint16
	for _, v := range key {
		checksum += uint16(v)
	}
	return checksum
}

// Decrypt decrypts an encrypted session key with the given private key. The
// private key must have been decrypted first.
// If config is nil, sensible defaults will be used.
func (e *EncryptedKey) Decrypt(priv *PrivateKey, config *Config) error {
	if e.Version < 6 && e.KeyId != 0 && e.KeyId != priv.KeyId {
		return errors.InvalidArgumentError("cannot decrypt encrypted session key for key id " + strconv.FormatUint(e.KeyId, 16) + " with private key id " + strconv.FormatUint(priv.KeyId, 16))
	}
	if e.Version == 6 && e.KeyVersion != 0 && !bytes.Equal(e.KeyFingerprint, priv.Fingerprint) {
		return errors.InvalidArgumentError("cannot decrypt encrypted session key for key fingerprint " + hex.EncodeToString(e.KeyFingerprint) + " with private key fingerprint " + hex.EncodeToString(priv.Fingerprint) )
	}
	if e.Algo != priv.PubKeyAlgo {
		return errors.InvalidArgumentError("cannot decrypt encrypted session key of type " + strconv.Itoa(int(e.Algo)) + " with private key of type " + strconv.Itoa(int(priv.PubKeyAlgo)))
	}
	if priv.Dummy() {
		return errors.ErrDummyPrivateKey("dummy key found")
	}

	var err error
	var b []byte

	// TODO(agl): use session key decryption routines here to avoid
	// padding oracle attacks.
	switch priv.PubKeyAlgo {
	case PubKeyAlgoRSA, PubKeyAlgoRSAEncryptOnly:
		// Supports both *rsa.PrivateKey and crypto.Decrypter
		k := priv.PrivateKey.(crypto.Decrypter)
		b, err = k.Decrypt(config.Random(), padToKeySize(k.Public().(*rsa.PublicKey), e.encryptedMPI1.Bytes()), nil)
	case PubKeyAlgoElGamal:
		c1 := new(big.Int).SetBytes(e.encryptedMPI1.Bytes())
		c2 := new(big.Int).SetBytes(e.encryptedMPI2.Bytes())
		b, err = elgamal.Decrypt(priv.PrivateKey.(*elgamal.PrivateKey), c1, c2)
	case PubKeyAlgoECDH:
		vsG := e.encryptedMPI1.Bytes()
		m := e.encryptedMPI2.Bytes()
		oid := priv.PublicKey.oid.EncodedBytes()
		b, err = ecdh.Decrypt(priv.PrivateKey.(*ecdh.PrivateKey), vsG, m, oid, priv.PublicKey.Fingerprint[:])
	default:
		err = errors.InvalidArgumentError("cannot decrypt encrypted session key with private key of type " + strconv.Itoa(int(priv.PubKeyAlgo)))
	}

	if err != nil {
		return err
	}
	
	keyOffset := 0
	if e.Version < 6 {
		keyOffset = 1
		e.CipherFunc = CipherFunction(b[0])
		if !e.CipherFunc.IsSupported() {
			return errors.UnsupportedError("unsupported encryption function")
		}
	}
	
	e.Key = b[keyOffset : len(b)-2]
	expectedChecksum := uint16(b[len(b)-2])<<8 | uint16(b[len(b)-1])
	checksum := checksumKeyMaterial(e.Key)
	if checksum != expectedChecksum {
		return errors.StructuralError("EncryptedKey checksum incorrect")
	}

	return nil
}

// Serialize writes the encrypted key packet, e, to w.
func (e *EncryptedKey) Serialize(w io.Writer) error {
	var mpiLen int
	switch e.Algo {
	case PubKeyAlgoRSA, PubKeyAlgoRSAEncryptOnly:
		mpiLen = int(e.encryptedMPI1.EncodedLength())
	case PubKeyAlgoElGamal:
		mpiLen = int(e.encryptedMPI1.EncodedLength()) + int(e.encryptedMPI2.EncodedLength())
	case PubKeyAlgoECDH:
		mpiLen = int(e.encryptedMPI1.EncodedLength()) + int(e.encryptedMPI2.EncodedLength())
	default:
		return errors.InvalidArgumentError("don't know how to serialize encrypted key type " + strconv.Itoa(int(e.Algo)))
	}

	packetLen := 1 /* version */ +8 /* key id */ +1 /* algo */ + mpiLen
	if e.Version == 6 {
		packetLen = 1 /* version */ +1 /* algo */ + mpiLen + 1 /* key version */ 
		if e.KeyVersion == 6 {
			packetLen += 32
		} else if e.KeyVersion == 4 {
			packetLen += 20
		}
	}

	err := serializeHeader(w, packetTypeEncryptedKey, packetLen)
	if err != nil {
		return err
	}

	_, err = w.Write([]byte{byte(e.Version)})
	if err != nil {
		return err
	}
	if e.Version == 6 {
		_, err = w.Write([]byte{byte(e.KeyVersion)})
		if err != nil {
			return err
		}
		// The key version number may also be zero, 
		// and the fingerprint omitted
		if e.KeyVersion != 0 {
			_, err = w.Write(e.KeyFingerprint)
			if err != nil {
				return err
			}
		}
	} else {
		// Write KeyID
		err = binary.Write(w, binary.BigEndian, e.KeyId)
		if err != nil {
			return err
		}
	}
	_, err = w.Write([]byte{byte(e.Algo)})
	if err != nil {
		return err
	}
	
	switch e.Algo {
	case PubKeyAlgoRSA, PubKeyAlgoRSAEncryptOnly:
		_, err := w.Write(e.encryptedMPI1.EncodedBytes())
		return err
	case PubKeyAlgoElGamal:
		if _, err := w.Write(e.encryptedMPI1.EncodedBytes()); err != nil {
			return err
		}
		_, err := w.Write(e.encryptedMPI2.EncodedBytes())
		return err
	case PubKeyAlgoECDH:
		if _, err := w.Write(e.encryptedMPI1.EncodedBytes()); err != nil {
			return err
		}
		_, err := w.Write(e.encryptedMPI2.EncodedBytes())
		return err
	default:
		panic("internal error")
	}
}

// SerializeEncryptedKey serializes an encrypted key packet to w that contains
// key, encrypted to pub.
// If config is nil, sensible defaults will be used.
func SerializeEncryptedKey(w io.Writer, pub *PublicKey, cipherFunc CipherFunction, aeadSupported bool, key []byte, config *Config) error {
	var buf [35]byte // max possible header size is v6
	lenHeaderWritten := 1
	version := 3

	if aeadSupported {
		version = 6
	}
	// An implementation MUST NOT generate ElGamal v6 PKESKs.
	if version == 6 && pub.PubKeyAlgo == PubKeyAlgoElGamal {
		return errors.InvalidArgumentError("ElGamal v6 PKESK are not allowed")
	}
	buf[0] = byte(version)

	if version == 6 {
		if pub != nil {
			buf[1] = byte(pub.Version)
			copy(buf[2: len(pub.Fingerprint)+2], pub.Fingerprint)
			lenHeaderWritten += len(pub.Fingerprint) + 1
		} else {
			// anonymous case
			buf[1] = 0
			lenHeaderWritten += 1
		}
	} else {
		binary.BigEndian.PutUint64(buf[1:9], pub.KeyId)
		lenHeaderWritten += 8
	}
	buf[lenHeaderWritten] = byte(pub.PubKeyAlgo)
	lenHeaderWritten += 1

	lenKeyBlock := 1 /* cipher type */ +len(key)+2 /* checksum */
	if version == 6 {
		lenKeyBlock = len(key) + 2 // no cipher type 
	}
	keyBlock := make([]byte, lenKeyBlock)
	keyOffset := 0
	if version < 6 {
		keyBlock[0] = byte(cipherFunc)
		keyOffset = 1
	} 
	
	copy(keyBlock[keyOffset:], key)
	checksum := checksumKeyMaterial(key)
	keyBlock[keyOffset+len(key)] = byte(checksum >> 8)
	keyBlock[keyOffset+len(key)+1] = byte(checksum)

	switch pub.PubKeyAlgo {
	case PubKeyAlgoRSA, PubKeyAlgoRSAEncryptOnly:
		return serializeEncryptedKeyRSA(w, config.Random(), buf[:lenHeaderWritten], pub.PublicKey.(*rsa.PublicKey), keyBlock)
	case PubKeyAlgoElGamal:
		return serializeEncryptedKeyElGamal(w, config.Random(), buf[:lenHeaderWritten], pub.PublicKey.(*elgamal.PublicKey), keyBlock)
	case PubKeyAlgoECDH:
		return serializeEncryptedKeyECDH(w, config.Random(), buf[:lenHeaderWritten], pub.PublicKey.(*ecdh.PublicKey), keyBlock, pub.oid, pub.Fingerprint)
	case PubKeyAlgoDSA, PubKeyAlgoRSASignOnly:
		return errors.InvalidArgumentError("cannot encrypt to public key of type " + strconv.Itoa(int(pub.PubKeyAlgo)))
	}

	return errors.UnsupportedError("encrypting a key to public key of type " + strconv.Itoa(int(pub.PubKeyAlgo)))
}

func serializeEncryptedKeyRSA(w io.Writer, rand io.Reader, header []byte, pub *rsa.PublicKey, keyBlock []byte) error {
	cipherText, err := rsa.EncryptPKCS1v15(rand, pub, keyBlock)
	if err != nil {
		return errors.InvalidArgumentError("RSA encryption failed: " + err.Error())
	}

	cipherMPI := encoding.NewMPI(cipherText)
	packetLen := len(header) /* header length */ + int(cipherMPI.EncodedLength())

	err = serializeHeader(w, packetTypeEncryptedKey, packetLen)
	if err != nil {
		return err
	}
	_, err = w.Write(header[:])
	if err != nil {
		return err
	}
	_, err = w.Write(cipherMPI.EncodedBytes())
	return err
}

func serializeEncryptedKeyElGamal(w io.Writer, rand io.Reader, header []byte, pub *elgamal.PublicKey, keyBlock []byte) error {
	c1, c2, err := elgamal.Encrypt(rand, pub, keyBlock)
	if err != nil {
		return errors.InvalidArgumentError("ElGamal encryption failed: " + err.Error())
	}

	packetLen := len(header) /* header length */
	packetLen += 2 /* mpi size */ + (c1.BitLen()+7)/8
	packetLen += 2 /* mpi size */ + (c2.BitLen()+7)/8

	err = serializeHeader(w, packetTypeEncryptedKey, packetLen)
	if err != nil {
		return err
	}
	_, err = w.Write(header[:])
	if err != nil {
		return err
	}
	if _, err = w.Write(new(encoding.MPI).SetBig(c1).EncodedBytes()); err != nil {
		return err
	}
	_, err = w.Write(new(encoding.MPI).SetBig(c2).EncodedBytes())
	return err
}

func serializeEncryptedKeyECDH(w io.Writer, rand io.Reader, header []byte, pub *ecdh.PublicKey, keyBlock []byte, oid encoding.Field, fingerprint []byte) error {
	vsG, c, err := ecdh.Encrypt(rand, pub, keyBlock, oid.EncodedBytes(), fingerprint)
	if err != nil {
		return errors.InvalidArgumentError("ECDH encryption failed: " + err.Error())
	}

	g := encoding.NewMPI(vsG)
	m := encoding.NewOID(c)

	packetLen := len(header) /* header length */
	packetLen += int(g.EncodedLength()) + int(m.EncodedLength())

	err = serializeHeader(w, packetTypeEncryptedKey, packetLen)
	if err != nil {
		return err
	}

	_, err = w.Write(header[:])
	if err != nil {
		return err
	}
	if _, err = w.Write(g.EncodedBytes()); err != nil {
		return err
	}
	_, err = w.Write(m.EncodedBytes())
	return err
}
