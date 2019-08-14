// Copyright (C) 2019 ProtonTech AG
// [1]  https://web.cs.ucdavis.edu/~rogaway/papers/eax.pdf

package eax

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
)

const (
	defaultTagSize   = 16
	defaultNonceSize = 16
)

type eax struct {
	block     cipher.Block // Only AES-{128, 192, 256} supported
	tagSize   int          // At least 12 bytes recommended
	nonceSize int
}

// NewEAX returns an EAX instance with AES-{keyLength} and default parameters.
func NewEAX(key []byte) eax {
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	return eax{
		block:     aesCipher,
		tagSize:   defaultTagSize,
		nonceSize: defaultNonceSize,
	}
}

// NewEAXWithNonceAndTagSize returns an EAX instance with AES-{keyLength} and
// given nonce and tag lengths in bytes. Panics on zero nonceSize and
// exceedingly long tags.
//
// We recommend to use at least 12 bytes as tag length (see, for instance,
// NIST SP 800-38D).
//
// Only to be used for compatibility with existing cryptosystems with
// non-standard parameters. For all other cases, prefer NewEAX.
func NewEAXWithNonceAndTagSize(key []byte, nonceSize, tagSize int) eax {
	if nonceSize == 0 {
		panic(`Error: Can't initialize EAX instance with nonceSize = 0`)
	}
	eaxInstance := NewEAX(key)
	if tagSize > eaxInstance.block.BlockSize() {
		panic(`Error: Custom tag length exceeds blocksize`)
	}
	eaxInstance.nonceSize = nonceSize
	eaxInstance.tagSize = tagSize
	return eaxInstance
}

func (e *eax) NonceSize() int {
	return e.nonceSize
}

func (e *eax) TagSize() int {
	return e.tagSize
}

// Encrypt function (see [1]). Returns Ciphertext || Tag
func (e *eax) Encrypt(plaintext, nonce, adata []byte) []byte {

	omacNonce := e.omacT(0, nonce)
	omacAdata := e.omacT(1, adata)

	// Encrypt message using CTR mode and omacNonce as IV
	ctr := cipher.NewCTR(e.block, omacNonce)
	ciphertext := make([]byte, len(plaintext))
	ctr.XORKeyStream(ciphertext, plaintext)

	omacCiphertext := e.omacT(2, ciphertext)

	tag := make([]byte, e.tagSize)
	for i := 0; i < len(tag); i++ {
		tag[i] = omacCiphertext[i] ^ omacNonce[i] ^ omacAdata[i]
	}

	return append(ciphertext, tag...)
}

// Decrypt function (see [1]). If tag is invalid, returns nil
func (e *eax) Decrypt(ciphertext, nonce, adata []byte) []byte {
	if len(ciphertext) < e.TagSize() {
		return nil
	}

	ct := ciphertext[:len(ciphertext)-e.tagSize]

	// Compute tag
	omacNonce := e.omacT(0, nonce)
	omacAdata := e.omacT(1, adata)
	omacCiphertext := e.omacT(2, ct)

	tag := make([]byte, e.tagSize)
	copy(tag, omacCiphertext)
	for i := 0; i < e.tagSize; i++ {
		tag[i] ^= omacNonce[i] ^ omacAdata[i]
	}

	// Compare tags
	inputTag := ciphertext[len(ciphertext)-e.tagSize:]
	if !bytes.Equal(tag, inputTag) {
		return nil
	}

	// Decrypt ciphertext
	ctr := cipher.NewCTR(e.block, omacNonce)
	plaintext := make([]byte, len(ct))
	ctr.XORKeyStream(plaintext, ct)

	return plaintext
}

// Tweakable OMAC - Calls OMAC_K([t]_n || plaintext)
func (e *eax) omacT(t byte, plaintext []byte) []byte {
	blockSize := e.block.BlockSize()
	byteT := make([]byte, blockSize)
	byteT[blockSize-1] = t
	concat := append(byteT, plaintext...)
	return e.omac(concat)
}

func (e *eax) omac(plaintext []byte) []byte {
	// L ← E_K(0^n); B ← 2L; P ← 4L
	L := make([]byte, e.block.BlockSize())
	e.block.Encrypt(L, L)
	B := gfnDouble(L)
	P := gfnDouble(B)

	// CBC with IV = 0
	blockSize := e.block.BlockSize()
	cbc := cipher.NewCBCEncrypter(e.block, make([]byte, blockSize))
	padded := e.pad(plaintext, B, P)
	cbcCiphertext := make([]byte, len(padded))
	cbc.CryptBlocks(cbcCiphertext, padded)

	return cbcCiphertext[len(cbcCiphertext)-blockSize:]
}

func (e *eax) pad(plaintext, B, P []byte) []byte {
	// if |M| in {n, 2n, 3n, ...}
	blockSize := e.block.BlockSize()
	if len(plaintext) != 0 && len(plaintext)%blockSize == 0  {
		return rightXor(plaintext, B)
	}

	// else return (M || 1 || 0^(n−1−(|M| % n))) xor→ P
	ending := make([]byte, blockSize-len(plaintext)%blockSize)
	ending[0] = 0x80
	padded := append(plaintext, ending...)
	return rightXor(padded, P)
}
