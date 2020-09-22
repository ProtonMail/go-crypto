// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"crypto"
	"crypto/cipher"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha1"
	"io"
	"io/ioutil"
	"math/big"
	"strconv"
	"time"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/openpgp/ecdh"
	"golang.org/x/crypto/openpgp/elgamal"
	"golang.org/x/crypto/openpgp/errors"
	"golang.org/x/crypto/openpgp/internal/encoding"
	"golang.org/x/crypto/openpgp/s2k"
	"golang.org/x/crypto/rsa"
)

// PrivateKey represents a possibly encrypted private key. See RFC 4880,
// section 5.5.3.
type PrivateKey struct {
	PublicKey
	Encrypted     bool // if true then the private key is unavailable until Decrypt has been called.
	encryptedData []byte
	cipher        CipherFunction
	s2k           func(out, in []byte)
	// An *{rsa|dsa|elgamal|ecdh|ecdsa|ed25519}.PrivateKey or
	// crypto.Signer/crypto.Decrypter (Decryptor RSA only).
	PrivateKey   interface{}
	sha1Checksum bool
	iv           []byte

	// Type of encryption of the S2K packet
	// Allowed values are 0 (Not encrypted), 254 (SHA1), or
	// 255 (2-byte checksum)
	s2kType S2KType
	// Full parameters of the S2K packet
	s2kParams *s2k.Params
}

//S2KType s2k packet type
type S2KType uint8

const (
	// S2KNON unencrypt
	S2KNON S2KType = 0
	// S2KSHA1 sha1 sum check
	S2KSHA1 S2KType = 254
	// S2KCHECKSUM sum check
	S2KCHECKSUM S2KType = 255
)

func NewRSAPrivateKey(creationTime time.Time, priv *rsa.PrivateKey) *PrivateKey {
	pk := new(PrivateKey)
	pk.PublicKey = *NewRSAPublicKey(creationTime, &priv.PublicKey)
	pk.PrivateKey = priv
	return pk
}

func NewDSAPrivateKey(creationTime time.Time, priv *dsa.PrivateKey) *PrivateKey {
	pk := new(PrivateKey)
	pk.PublicKey = *NewDSAPublicKey(creationTime, &priv.PublicKey)
	pk.PrivateKey = priv
	return pk
}

func NewElGamalPrivateKey(creationTime time.Time, priv *elgamal.PrivateKey) *PrivateKey {
	pk := new(PrivateKey)
	pk.PublicKey = *NewElGamalPublicKey(creationTime, &priv.PublicKey)
	pk.PrivateKey = priv
	return pk
}

func NewECDSAPrivateKey(creationTime time.Time, priv *ecdsa.PrivateKey) *PrivateKey {
	pk := new(PrivateKey)
	pk.PublicKey = *NewECDSAPublicKey(creationTime, &priv.PublicKey)
	pk.PrivateKey = priv
	return pk
}

func NewEdDSAPrivateKey(creationTime time.Time, priv *ed25519.PrivateKey) *PrivateKey {
	pk := new(PrivateKey)
	pub := priv.Public().(ed25519.PublicKey)
	pk.PublicKey = *NewEdDSAPublicKey(creationTime, &pub)
	pk.PrivateKey = priv
	return pk
}

func NewECDHPrivateKey(creationTime time.Time, priv *ecdh.PrivateKey) *PrivateKey {
	pk := new(PrivateKey)
	pk.PublicKey = *NewECDHPublicKey(creationTime, &priv.PublicKey)
	pk.PrivateKey = priv
	return pk
}

// NewSignerPrivateKey creates a PrivateKey from a crypto.Signer that
// implements RSA, ECDSA or EdDSA.
func NewSignerPrivateKey(creationTime time.Time, signer crypto.Signer) *PrivateKey {
	pk := new(PrivateKey)
	// In general, the public Keys should be used as pointers. We still
	// type-switch on the values, for backwards-compatibility.
	switch pubkey := signer.Public().(type) {
	case *rsa.PublicKey:
		pk.PublicKey = *NewRSAPublicKey(creationTime, pubkey)
	case rsa.PublicKey:
		pk.PublicKey = *NewRSAPublicKey(creationTime, &pubkey)
	case *ecdsa.PublicKey:
		pk.PublicKey = *NewECDSAPublicKey(creationTime, pubkey)
	case ecdsa.PublicKey:
		pk.PublicKey = *NewECDSAPublicKey(creationTime, &pubkey)
	case *ed25519.PublicKey:
		pk.PublicKey = *NewEdDSAPublicKey(creationTime, pubkey)
	case ed25519.PublicKey:
		pk.PublicKey = *NewEdDSAPublicKey(creationTime, &pubkey)
	default:
		panic("openpgp: unknown crypto.Signer type in NewSignerPrivateKey")
	}
	pk.PrivateKey = signer
	return pk
}

// NewDecrypterPrivateKey creates a PrivateKey from a *{rsa|elgamal|ecdh}.PrivateKey.
func NewDecrypterPrivateKey(creationTime time.Time, decrypter interface{}) *PrivateKey {
	pk := new(PrivateKey)
	switch priv := decrypter.(type) {
	case *rsa.PrivateKey:
		pk.PublicKey = *NewRSAPublicKey(creationTime, &priv.PublicKey)
	case *elgamal.PrivateKey:
		pk.PublicKey = *NewElGamalPublicKey(creationTime, &priv.PublicKey)
	case *ecdh.PrivateKey:
		pk.PublicKey = *NewECDHPublicKey(creationTime, &priv.PublicKey)
	default:
		panic("openpgp: unknown decrypter type in NewDecrypterPrivateKey")
	}
	pk.PrivateKey = decrypter
	return pk
}

func (pk *PrivateKey) parse(r io.Reader) (err error) {
	err = (&pk.PublicKey).parse(r)
	if err != nil {
		return
	}
	v5 := pk.PublicKey.Version == 5

	var buf [1]byte
	_, err = readFull(r, buf[:])
	if err != nil {
		return
	}
	pk.s2kType = S2KType(buf[0])
	var optCount [1]byte
	if v5 {
		if _, err = readFull(r, optCount[:]); err != nil {
			return
		}
	}

	switch pk.s2kType {
	case S2KNON:
		pk.s2k = nil
		pk.Encrypted = false
	case S2KSHA1, S2KCHECKSUM:
		if v5 && pk.s2kType == S2KCHECKSUM {
			return errors.StructuralError("wrong s2k identifier for version 5")
		}
		_, err = readFull(r, buf[:])
		if err != nil {
			return
		}
		pk.cipher = CipherFunction(buf[0])
		pk.s2kParams, err = s2k.ParseIntoParams(r)
		if err != nil {
			return
		}
		if pk.s2kParams.Dummy() {
			return
		}
		pk.s2k, err = pk.s2kParams.Function()
		if err != nil {
			return
		}
		pk.Encrypted = true
		if pk.s2kType == S2KSHA1 {
			pk.sha1Checksum = true
		}
	default:
		return errors.UnsupportedError("deprecated s2k function in private key")
	}

	if pk.Encrypted {
		blockSize := pk.cipher.blockSize()
		if blockSize == 0 {
			return errors.UnsupportedError("unsupported cipher in private key: " + strconv.Itoa(int(pk.cipher)))
		}
		pk.iv = make([]byte, blockSize)
		_, err = readFull(r, pk.iv)
		if err != nil {
			return
		}
	}

	if v5 {
		var n [4]byte /* secret material four octet count */
		_, err = readFull(r, n[:])
		if err != nil {
			return
		}
		count := int(uint32(n[0])<<24 | uint32(n[1])<<16 | uint32(n[2])<<8 | uint32(n[3]))
		if !pk.Encrypted {
			count = count+2 /* two octet checksum */
		}
		pk.encryptedData = make([]byte, count)
		_, err = readFull(r, pk.encryptedData)
		if err != nil {
			return
		}
	} else {
		pk.encryptedData, err = ioutil.ReadAll(r)
		if err != nil {
			return
		}
	}
	if !pk.Encrypted {
		return pk.parsePrivateKey(pk.encryptedData)
	}

	return
}

// Dummy returns true if the private key is a dummy key. This is a GNU extension.
func (pk *PrivateKey) Dummy() bool {
	return pk.s2kParams.Dummy()
}

func mod64kHash(d []byte) uint16 {
	var h uint16
	for _, b := range d {
		h += uint16(b)
	}
	return h
}

func (pk *PrivateKey) Serialize(w io.Writer) (err error) {
	contents := bytes.NewBuffer(nil)
	err = pk.PublicKey.serializeWithoutHeaders(contents)
	if err != nil {
		return
	}

	priv := bytes.NewBuffer(nil)
	if pk.Dummy() {
		err = pk.serializeDummy(priv)
	} else if pk.Encrypted {
		err = pk.serializeEncrypted(priv)
	} else {
		err = pk.serializeUnencrypted(priv)
	}
	if err != nil {
		return
	}

	ptype := packetTypePrivateKey
	if pk.IsSubkey {
		ptype = packetTypePrivateSubkey
	}
	err = serializeHeader(w, ptype, contents.Len()+priv.Len())
	if err != nil {
		return
	}
	_, err = io.Copy(w, contents)
	if err != nil {
		return
	}
	_, err = io.Copy(w, priv)
	if err != nil {
		return
	}
	return
}

func (pk *PrivateKey) serializeDummy(w io.Writer) (err error) {
	if _, err = w.Write([]byte{uint8(pk.s2kType)}); err != nil {
		return
	}

	optional := bytes.NewBuffer([]byte{uint8(pk.cipher)})
	if err = pk.s2kParams.Serialize(optional); err != nil {
		return
	}
	if pk.Version == 5 {
		if _, err = w.Write([]byte{uint8(optional.Len())}); err != nil {
			return
		}
	}
	io.Copy(w, optional)
	return
}

func (pk *PrivateKey) serializeEncrypted(w io.Writer) error {
	encoded := bytes.NewBuffer([]byte{uint8(pk.s2kType)})
	optional := bytes.NewBuffer([]byte{uint8(pk.cipher)})
	err := pk.s2kParams.Serialize(optional)
	if err != nil {
		return err
	}
	optional.Write(pk.iv)
	if pk.Version == 5 {
		encoded.Write([]byte{uint8(optional.Len())})
	}
	io.Copy(encoded, optional)

	if pk.Version == 5 {
		s := len(pk.encryptedData)
		encoded.Write([]byte{byte(s>>24), byte(s>>16), byte(s>>8), byte(s)})
	}
	io.Copy(w, encoded)
	w.Write(pk.encryptedData)
	return nil
}

func (pk *PrivateKey) serializeUnencrypted(w io.Writer) (err error) {
	encoded := bytes.NewBuffer([]byte{uint8(S2KNON)}) /* no encryption */
	if pk.Version == 5 {
		encoded.Write([]byte{0x00}) /* no optional fields */
	}
	priv := bytes.NewBuffer(nil)
	err = pk.serializePrivateKey(priv)
	if err != nil {
		return err
	}
	l := priv.Len() // Private material count
	if pk.sha1Checksum {
		h := sha1.New()
		io.Copy(h, priv)
		priv.Write(h.Sum(nil))
	} else {
		checksum := mod64kHash(priv.Bytes())
		priv.Write([]byte{byte(checksum>>8), byte(checksum)})
	}
	if pk.Version == 5 {
		encoded.Write([]byte{byte(l>>24), byte(l>>16), byte(l>>8), byte(l)})
	}
	io.Copy(w, encoded)
	io.Copy(w, priv)
	return
}

func serializeRSAPrivateKey(w io.Writer, priv *rsa.PrivateKey) error {
	if _, err := w.Write(new(encoding.MPI).SetBig(priv.D).EncodedBytes()); err != nil {
		return err
	}
	if _, err := w.Write(new(encoding.MPI).SetBig(priv.Primes[1]).EncodedBytes()); err != nil {
		return err
	}
	if _, err := w.Write(new(encoding.MPI).SetBig(priv.Primes[0]).EncodedBytes()); err != nil {
		return err
	}
	_, err := w.Write(new(encoding.MPI).SetBig(priv.Precomputed.Qinv).EncodedBytes())
	return err
}

func serializeDSAPrivateKey(w io.Writer, priv *dsa.PrivateKey) error {
	_, err := w.Write(new(encoding.MPI).SetBig(priv.X).EncodedBytes())
	return err
}

func serializeElGamalPrivateKey(w io.Writer, priv *elgamal.PrivateKey) error {
	_, err := w.Write(new(encoding.MPI).SetBig(priv.X).EncodedBytes())
	return err
}

func serializeECDSAPrivateKey(w io.Writer, priv *ecdsa.PrivateKey) error {
	_, err := w.Write(new(encoding.MPI).SetBig(priv.D).EncodedBytes())
	return err
}

func serializeEdDSAPrivateKey(w io.Writer, priv *ed25519.PrivateKey) error {
	keySize := ed25519.PrivateKeySize - ed25519.PublicKeySize
	_, err := w.Write(encoding.NewMPI((*priv)[:keySize]).EncodedBytes())
	return err
}

func serializeECDHPrivateKey(w io.Writer, priv *ecdh.PrivateKey) error {
	_, err := w.Write(encoding.NewMPI(priv.D).EncodedBytes())
	return err
}

// Decrypt decrypts an encrypted private key using a passphrase.
func (pk *PrivateKey) Decrypt(passphrase []byte) error {
	if pk.Dummy() {
		return errors.ErrDummyPrivateKey("dummy key found")
	}
	if !pk.Encrypted {
		return nil
	}

	key := make([]byte, pk.cipher.KeySize())
	pk.s2k(key, passphrase)
	block := pk.cipher.new(key)
	cfb := cipher.NewCFBDecrypter(block, pk.iv)

	data := make([]byte, len(pk.encryptedData))
	cfb.XORKeyStream(data, pk.encryptedData)

	if pk.sha1Checksum {
		if len(data) < sha1.Size {
			return errors.StructuralError("truncated private key data")
		}
		h := sha1.New()
		h.Write(data[:len(data)-sha1.Size])
		sum := h.Sum(nil)
		if !bytes.Equal(sum, data[len(data)-sha1.Size:]) {
			return errors.StructuralError("private key checksum failure")
		}
		data = data[:len(data)-sha1.Size]
	} else {
		if len(data) < 2 {
			return errors.StructuralError("truncated private key data")
		}
		var sum uint16
		for i := 0; i < len(data)-2; i++ {
			sum += uint16(data[i])
		}
		if data[len(data)-2] != uint8(sum>>8) ||
			data[len(data)-1] != uint8(sum) {
			return errors.StructuralError("private key checksum failure")
		}
		data = data[:len(data)-2]
	}

	return pk.parsePrivateKey(data)
}

// Encrypt encrypts an unencrypted private key using a passphrase.
func (pk *PrivateKey) Encrypt(passphrase []byte) error {
	priv := bytes.NewBuffer(nil)
	err := pk.serializePrivateKey(priv)
	if err != nil {
		return err
	}

	//Default config of private key encryption
	pk.cipher = CipherAES256
	s2kConfig := &s2k.Config{
		S2KMode:  3, //Iterated
		S2KCount: 65536,
		Hash:     crypto.SHA256,
	}

	pk.s2kParams, err = s2k.Generate(rand.Reader, s2kConfig)
	key := make([]byte, pk.cipher.KeySize())

	pk.sha1Checksum = true
	pk.s2k, err = pk.s2kParams.Function()
	if err != nil {
		return err
	}
	pk.s2k(key, passphrase)
	block := pk.cipher.new(key)
	pk.iv = make([]byte, pk.cipher.blockSize())
	_, err = rand.Read(pk.iv)
	if err != nil {
		return err
	}
	cfb := cipher.NewCFBEncrypter(block, pk.iv)

	if pk.sha1Checksum {
		pk.s2kType = S2KSHA1
		h := sha1.New()
		h.Write(priv.Bytes())
		priv.Write(h.Sum(nil))
	} else {
		pk.s2kType = S2KCHECKSUM
		var sum uint16
		buf := priv.Bytes()
		for i := 0; i < priv.Len(); i++ {
			sum += uint16(buf[i])
		}
		priv.Write([]byte{uint8(sum>>8), uint8(sum)})
	}

	pk.encryptedData = make([]byte, priv.Len())
	cfb.XORKeyStream(pk.encryptedData, priv.Bytes())
	pk.Encrypted = true
	pk.PrivateKey = nil
	return err
}

func (pk *PrivateKey) serializePrivateKey(w io.Writer) (err error) {
	switch priv := pk.PrivateKey.(type) {
	case *rsa.PrivateKey:
		err = serializeRSAPrivateKey(w, priv)
	case *dsa.PrivateKey:
		err = serializeDSAPrivateKey(w, priv)
	case *elgamal.PrivateKey:
		err = serializeElGamalPrivateKey(w, priv)
	case *ecdsa.PrivateKey:
		err = serializeECDSAPrivateKey(w, priv)
	case *ed25519.PrivateKey:
		err = serializeEdDSAPrivateKey(w, priv)
	case *ecdh.PrivateKey:
		err = serializeECDHPrivateKey(w, priv)
	default:
		err = errors.InvalidArgumentError("unknown private key type")
	}
	return
}

func (pk *PrivateKey) parsePrivateKey(data []byte) (err error) {
	switch pk.PublicKey.PubKeyAlgo {
	case PubKeyAlgoRSA, PubKeyAlgoRSASignOnly, PubKeyAlgoRSAEncryptOnly:
		return pk.parseRSAPrivateKey(data)
	case PubKeyAlgoDSA:
		return pk.parseDSAPrivateKey(data)
	case PubKeyAlgoElGamal:
		return pk.parseElGamalPrivateKey(data)
	case PubKeyAlgoECDSA:
		return pk.parseECDSAPrivateKey(data)
	case PubKeyAlgoECDH:
		return pk.parseECDHPrivateKey(data)
	case PubKeyAlgoEdDSA:
		return pk.parseEdDSAPrivateKey(data)
	}
	panic("impossible")
}

func (pk *PrivateKey) parseRSAPrivateKey(data []byte) (err error) {
	rsaPub := pk.PublicKey.PublicKey.(*rsa.PublicKey)
	rsaPriv := new(rsa.PrivateKey)
	rsaPriv.PublicKey = *rsaPub

	buf := bytes.NewBuffer(data)
	d := new(encoding.MPI)
	if _, err := d.ReadFrom(buf); err != nil {
		return err
	}

	p := new(encoding.MPI)
	if _, err := p.ReadFrom(buf); err != nil {
		return err
	}

	q := new(encoding.MPI)
	if _, err := q.ReadFrom(buf); err != nil {
		return err
	}

	rsaPriv.D = new(big.Int).SetBytes(d.Bytes())
	rsaPriv.Primes = make([]*big.Int, 2)
	rsaPriv.Primes[0] = new(big.Int).SetBytes(p.Bytes())
	rsaPriv.Primes[1] = new(big.Int).SetBytes(q.Bytes())
	if err := rsaPriv.Validate(); err != nil {
		return err
	}
	rsaPriv.Precompute()
	pk.PrivateKey = rsaPriv
	pk.Encrypted = false
	pk.encryptedData = nil

	return nil
}

func (pk *PrivateKey) parseDSAPrivateKey(data []byte) (err error) {
	dsaPub := pk.PublicKey.PublicKey.(*dsa.PublicKey)
	dsaPriv := new(dsa.PrivateKey)
	dsaPriv.PublicKey = *dsaPub

	buf := bytes.NewBuffer(data)
	x := new(encoding.MPI)
	if _, err := x.ReadFrom(buf); err != nil {
		return err
	}

	dsaPriv.X = new(big.Int).SetBytes(x.Bytes())
	pk.PrivateKey = dsaPriv
	pk.Encrypted = false
	pk.encryptedData = nil

	return nil
}

func (pk *PrivateKey) parseElGamalPrivateKey(data []byte) (err error) {
	pub := pk.PublicKey.PublicKey.(*elgamal.PublicKey)
	priv := new(elgamal.PrivateKey)
	priv.PublicKey = *pub

	buf := bytes.NewBuffer(data)
	x := new(encoding.MPI)
	if _, err := x.ReadFrom(buf); err != nil {
		return err
	}

	priv.X = new(big.Int).SetBytes(x.Bytes())
	pk.PrivateKey = priv
	pk.Encrypted = false
	pk.encryptedData = nil

	return nil
}

func (pk *PrivateKey) parseECDSAPrivateKey(data []byte) (err error) {
	ecdsaPub := pk.PublicKey.PublicKey.(*ecdsa.PublicKey)
	ecdsaPriv := new(ecdsa.PrivateKey)
	ecdsaPriv.PublicKey = *ecdsaPub

	buf := bytes.NewBuffer(data)
	d := new(encoding.MPI)
	if _, err := d.ReadFrom(buf); err != nil {
		return err
	}

	ecdsaPriv.D = new(big.Int).SetBytes(d.Bytes())
	pk.PrivateKey = ecdsaPriv
	pk.Encrypted = false
	pk.encryptedData = nil

	return nil
}

func (pk *PrivateKey) parseECDHPrivateKey(data []byte) (err error) {
	ecdhPub := pk.PublicKey.PublicKey.(*ecdh.PublicKey)
	ecdhPriv := new(ecdh.PrivateKey)
	ecdhPriv.PublicKey = *ecdhPub

	buf := bytes.NewBuffer(data)
	d := new(encoding.MPI)
	if _, err := d.ReadFrom(buf); err != nil {
		return err
	}

	ecdhPriv.D = d.Bytes()
	pk.PrivateKey = ecdhPriv
	pk.Encrypted = false
	pk.encryptedData = nil

	return nil
}

func (pk *PrivateKey) parseEdDSAPrivateKey(data []byte) (err error) {
	eddsaPub := pk.PublicKey.PublicKey.(*ed25519.PublicKey)
	eddsaPriv := make(ed25519.PrivateKey, ed25519.PrivateKeySize)

	buf := bytes.NewBuffer(data)
	d := new(encoding.MPI)
	if _, err := d.ReadFrom(buf); err != nil {
		return err
	}

	priv := d.Bytes()
	copy(eddsaPriv[32-len(priv):32], priv)
	copy(eddsaPriv[32:], (*eddsaPub)[:])

	pk.PrivateKey = &eddsaPriv
	pk.Encrypted = false
	pk.encryptedData = nil

	return nil
}
