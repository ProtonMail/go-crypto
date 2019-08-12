// Copyright (C) 2019 ProtonTech AG
// [1]  https://web.cs.ucdavis.edu/~rogaway/papers/eax.pdf

package eax

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
)

const (
	blockLength = 16
	tagLength   = 16
)

// Encrypt function (see [1]). Returns Ciphertext || Tag
func Encrypt(key, plaintext, nonce, adata []byte) []byte {

	omacNonce := omacT(0, key, nonce)
	omacAdata := omacT(1, key, adata)

	// Encrypt message using AES-128 in CTR mode and omacNonce as IV
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	ctrAes := cipher.NewCTR(aesCipher, omacNonce)
	ciphertext := make([]byte, len(plaintext))
	ctrAes.XORKeyStream(ciphertext, plaintext)

	two := make([]byte, blockLength)
	two[blockLength-1] = 2
	omacCiphertext := omacT(2, key, ciphertext)

	// Compute tag
	tag := make([]byte, tagLength)
	copy(tag, omacCiphertext)
	for i := 0; i < len(tag); i++ {
		tag[i] ^= omacNonce[i] ^ omacAdata[i]
	}

	return append(ciphertext, tag...)
}

// Decrypt function (see [1]). If tag is invalid, returns nil
func Decrypt(key, ciphertext, nonce, adata []byte) []byte {
	if len(ciphertext) < tagLength {
		return nil
	}
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	ct := ciphertext[:len(ciphertext)-tagLength]

	// Compute tag
	omacNonce := omacT(0, key, nonce)
	omacAdata := omacT(1, key, adata)
	omacCiphertext := omacT(2, key, ct)

	tag := make([]byte, tagLength)
	copy(tag, omacCiphertext)
	for i := 0; i < tagLength; i++ {
		tag[i] ^= omacNonce[i] ^ omacAdata[i]
	}

	// Compare tags
	inputTag := ciphertext[len(ciphertext)-tagLength:]
	if !bytes.Equal(tag, inputTag) {
		return nil
	}

	// Decrypt ciphertext
	ctrAes := cipher.NewCTR(aesCipher, omacNonce)
	plaintext := make([]byte, len(ct))
	ctrAes.XORKeyStream(plaintext, ct)

	return plaintext
}

// Tweaked OMAC - Calls OMAC_K([t]_n || plaintext)
func omacT(t byte, key, plaintext []byte) []byte {
	byteT := make([]byte, blockLength)
	byteT[blockLength-1] = t
	concat := append(byteT, plaintext...)
	return omac(key, concat)
}

func omac(key, plaintext []byte) []byte {
	aesCipher, errAes := aes.NewCipher(key)
	if errAes != nil {
		panic(errAes)
	}

	// L ← E_K(0^n); B ← 2L; P ← 4L
	L := make([]byte, blockLength)
	aesCipher.Encrypt(L, L); B := gfnDouble(L); P := gfnDouble(B)

	// CBC with IV = 0
	cbcEncrypter := cipher.NewCBCEncrypter(aesCipher, make([]byte, blockLength))
	padded := pad(plaintext, B, P)
	cbcCiphertext := make([]byte, len(padded))
	cbcEncrypter.CryptBlocks(cbcCiphertext, padded)

	return cbcCiphertext[len(cbcCiphertext)-blockLength:]
}

func pad(plaintext, B, P []byte) []byte {
	// if |M| in {n, 2n, 3n, ...}
	if len(plaintext)%blockLength == 0 {
		return rightXorMut(plaintext, B)
	}

	// else return (M || 10^(n−1−(|M| mod n))) xor→ P
	ending := make([]byte, blockLength-len(plaintext)%blockLength)
	ending[0] = 0x80
	padded := append(plaintext, ending...)
	return rightXorMut(padded, P)
}
