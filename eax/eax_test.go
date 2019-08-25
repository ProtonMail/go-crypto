// Copyright 2019 ProtonTech AG.
//
// This file only tests EAX mode when instantiated with AES-128.

package eax

import (
	"bytes"
	"crypto/rand"
	"crypto/cipher"
	"encoding/hex"
	mathrand "math/rand"
	"testing"
)

const (
	blockLength = 16
	iterations  = 20
	maxLength   = 262144
)

func TestEAXImplementsAEADInterface(t *testing.T) {
	var eaxInstance eax
	var aux interface{} = &eaxInstance
	_, ok := aux.(cipher.AEAD)
	if !ok {
		t.Errorf("Error: EAX does not implement AEAD interface")
	}
}

// Test vectors from https://web.cs.ucdavis.edu/~rogaway/papers/eax.pdf
func TestEncryptDecryptEAXTestVectors(t *testing.T) {
	for _, test := range testVectors {
		adata, _ := hex.DecodeString(test.header)
		key, _ := hex.DecodeString(test.key)
		nonce, _ := hex.DecodeString(test.nonce)
		targetPt, _ := hex.DecodeString(test.msg)
		targetCt, _ := hex.DecodeString(test.ciphertext)
		eax, errEax := NewEAX(key)
		if errEax != nil {
			panic(errEax)
		}

		ct := eax.Seal(nil, nonce, targetPt, adata)
		if !bytes.Equal(ct, targetCt) {
			t.Errorf(
				`Test vectors Encrypt error (ciphertexts don't match):
				Got:  %X
				Want: %X`, ct, targetCt)
		}
		pt, err := eax.Open(nil, nonce, ct, adata)
		if err != nil {
			t.Errorf(
				`Decrypt refused valid tag:
				ciphertext %X
				key %X
				nonce %X
				header %X`, ct, key, nonce, adata)
		}
		if !bytes.Equal(pt, targetPt) {
			t.Errorf(
				`Test vectors Decrypt error (plaintexts don't match):
				Got:  %X
				Want: %X`, pt, targetPt)
		}
	}
}

// Test vectors from generated file
func TestEncryptDecryptGoTestVectors(t *testing.T) {
	for _, test := range randomVectors {
		adata, _ := hex.DecodeString(test.header)
		key, _ := hex.DecodeString(test.key)
		nonce, _ := hex.DecodeString(test.nonce)
		targetPt, _ := hex.DecodeString(test.plaintext)
		targetCt, _ := hex.DecodeString(test.ciphertext)
		eax, errEax := NewEAX(key)
		if errEax != nil {
			panic(errEax)
		}

		ct := eax.Seal(nil, nonce, targetPt, adata)
		if !bytes.Equal(ct, targetCt) {
			t.Errorf(
				`Test vectors Encrypt error (ciphertexts don't match):
				Got:  %X
				Want: %X`, ct, targetCt)
		}
		pt, err := eax.Open(nil, nonce, ct, adata)
		if err != nil {
			t.Errorf(
				`Decrypt refused valid tag:
				ciphertext %X
				key %X
				nonce %X
				header %X`, ct, key, nonce, adata)
		}
		if !bytes.Equal(pt, targetPt) {
			t.Errorf(
				`Test vectors Decrypt error (plaintexts don't match):
				Got:  %X
				Want: %X`, pt, targetPt)
		}
	}
}

// Generates random examples and tests correctness
func TestEncryptDecryptRandomVectorsWithPreviousData(t *testing.T) {
	// Considering AES
	allowedKeyLengths := []int{16, 24, 32}
	for _, keyLength := range allowedKeyLengths {
		for i := 0; i < iterations; i++ {
			pt := make([]byte, mathrand.Intn(maxLength))
			header := make([]byte, mathrand.Intn(maxLength))
			key := make([]byte, keyLength)
			nonce := make([]byte, 1+mathrand.Intn(blockLength))
			previousData := make([]byte, mathrand.Intn(maxLength)-2*blockLength)
			// Populate items with crypto/rand
			rand.Read(pt)
			rand.Read(header)
			rand.Read(key)
			rand.Read(nonce)
			rand.Read(previousData)

			eax, errEax := NewEAX(key)
			if errEax != nil {
				panic(errEax)
			}
			newData := eax.Seal(previousData, nonce, pt, header)
			ct := newData[len(previousData):]
			decrypted, err := eax.Open(nil, nonce, ct, header)
			if err != nil {
				t.Errorf(
					`Decrypt refused valid tag (not displaying long output)`)
					break
			}
			if !bytes.Equal(pt, decrypted) {
				t.Errorf(
					`Random Encrypt/Decrypt error (plaintexts don't match)`)
					break
			}
		}
	}
}

func TestRejectTamperedCiphertext(t *testing.T) {
	for i := 0; i < iterations; i++ {
		pt := make([]byte, mathrand.Intn(maxLength))
		header := make([]byte, mathrand.Intn(maxLength))
		key := make([]byte, blockLength)
		nonce := make([]byte, blockLength)
		rand.Read(pt)
		rand.Read(header)
		rand.Read(key)
		rand.Read(nonce)
		eax, errEax := NewEAX(key)
		if errEax != nil {
			panic(errEax)
		}
		ct := eax.Seal(nil, nonce, pt, header)
		// Change one byte of ct (could affect either the tag or the ciphertext)
		tampered := make([]byte, len(ct))
		copy(tampered, ct)
		for bytes.Equal(tampered, ct) {
			tampered[mathrand.Intn(len(ct))] = byte(mathrand.Intn(len(ct)))
		}
		_, err := eax.Open(nil, nonce, tampered, header)
		if err == nil {
			t.Errorf(`Tampered ciphertext was not refused decryption`)
			break
		}
	}
}

func TestParameters(t *testing.T) {
	t.Run("Should panic on unsupported keySize/blockSize", func(st *testing.T) {
		keySize := mathrand.Intn(32)
		for keySize == 16 {
			keySize = mathrand.Intn(32)
		}
		key := make([]byte, keySize)
		defer func() {
			if r := recover(); r == nil {
				st.Errorf("EAX didn't panic")
			}
		}()
		NewEAX(key)
	})
	t.Run("Should return error on too long tagSize", func(st *testing.T) {
		tagSize := blockLength + 1 + mathrand.Intn(12)
		nonceSize := 1 + mathrand.Intn(16)
		key := make([]byte, blockLength)
		_, err := NewEAXWithNonceAndTagSize(key, nonceSize, tagSize)
		if err == nil {
			st.Errorf("No error was given")
		}
	})
	t.Run("Should not give error with allowed custom parameters", func(st *testing.T) {
		key := make([]byte, blockLength)
		nonceSize := mathrand.Intn(32) + 1
		tagSize := 12 + mathrand.Intn(blockLength-11)
		_, err := NewEAXWithNonceAndTagSize(key, nonceSize, tagSize)
		if err != nil {
			st.Errorf("An error was returned")
		}
	})
}

func BenchmarkEncrypt(b *testing.B) {
	// OpenPGP.js defaults plaintext chunks at 256 KiB
	plaintextLength := 262144
	headerLength := 16
	pt := make([]byte, plaintextLength)
	header := make([]byte, headerLength)
	key := make([]byte, blockLength)
	nonce := make([]byte, blockLength)
	rand.Read(pt)
	rand.Read(header)
	rand.Read(key)
	rand.Read(nonce)
	eax, errEax:= NewEAX(key)
	if errEax != nil {
		panic(errEax)
	}
	for i := 0; i < b.N; i++ {
		eax.Seal(nil, nonce, pt, header)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	// OpenPGP.js defaults plaintext chunks at 256 KiB
	plaintextLength := 262144
	headerLength := 16
	pt := make([]byte, plaintextLength)
	header := make([]byte, headerLength)
	key := make([]byte, blockLength)
	nonce := make([]byte, blockLength)
	rand.Read(pt)
	rand.Read(header)
	rand.Read(key)
	rand.Read(nonce)
	eax, errEax:= NewEAX(key)
	if errEax != nil {
		panic(errEax)
	}
	ct := eax.Seal(nil, nonce, pt, header)
	for i := 0; i < b.N; i++ {
		eax.Open(nil, nonce, ct, header)
	}
}
