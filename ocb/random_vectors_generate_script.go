package ocb

import (
	"crypto/aes"
	"crypto/rand"
	"fmt"
	"io"
	mathrand "math/rand"
	"os"
	"testing"
	"time"
)

// The following scripts create random test vectors for the ocb package
// and writes them to a file.
// In the test vectors provided by RFC 7253, the "bottom"
// internal variable, which defines "offset" for the first time, does not
// exceed 15. However, it can attain values up to 63.

// These vectors include key length in {128, 192, 256}, tag size 128, and
// random nonce, header, and plaintext lengths.

func generateRandomVectors(t *testing.T) {
	fmt.Println("Generating new test vectors")
	mathrand.Seed(time.Now().UnixNano())
	allowedKeyLengths := []int{16, 24, 32}
	blockLength := 16
	numberOfVectors := 24
	str := "// This file was automatically generated.\n"
	str += "package ocb\nvar randomVectors = []struct {\nkey, nonce, header, plaintext, ciphertext string\n}{\n\n"
	for _, keyLength := range allowedKeyLengths {
		for i := 0; i < numberOfVectors/3; i++ {
			pt := make([]byte, mathrand.Intn(128))
			header := make([]byte, mathrand.Intn(128))
			key := make([]byte, keyLength)
			// Testing for short nonces but take notice they are not recommended
			nonce := make([]byte, 12+mathrand.Intn(blockLength-12))
			// Populate items with crypto/rand
			rand.Read(pt)
			rand.Read(header)
			rand.Read(key)
			rand.Read(nonce)
			// Considering AES
			aesCipher, err := aes.NewCipher(key)
			if err != nil {
				panic(err)
			}
			ocb, errOcb := NewOCBWithNonceAndTagSize(
				aesCipher, len(nonce), aesCipher.BlockSize())
			if errOcb != nil {
				panic(errOcb)
			}
			ct := ocb.Seal(nil, nonce, pt, header)
			// key, N, A, P, C
			str += fmt.Sprintf(
				"{\"%X\",\n\"%X\",\n\"%X\",\n\"%X\",\n\"%X\"},\n",
				key, nonce, header, pt, ct)
		}
	}
	str += "}"
	WriteToFile("random_vectors.go", str)
}

func WriteToFile(filename string, data string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = io.WriteString(file, data)
	if err != nil {
		return err
	}
	return file.Sync()
}
