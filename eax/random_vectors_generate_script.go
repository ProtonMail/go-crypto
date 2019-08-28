package eax

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

// The following scripts create random test vectors for the eax package
// and writes them to a file.
func generateRandomVectors(t *testing.T) {
	fmt.Println("Generating new test vectors")
	mathrand.Seed(time.Now().UnixNano())
	allowedKeyLengths := []int{16, 24, 32}
	blockLength := 16
	numberOfVectors := 24
	str := "// This file was automatically generated.\n"
	str += "package eax\nvar randomVectors = []struct {\nkey, nonce, header, plaintext, ciphertext string\n}{\n\n"
	for _, keyLength := range allowedKeyLengths {
		for i := 0; i < numberOfVectors/3; i++ {
			pt := make([]byte, mathrand.Intn(128))
			header := make([]byte, mathrand.Intn(128))
			key := make([]byte, keyLength)
			// Testing for short nonces but take notice they are not recommended
			nonce := make([]byte, blockLength)
			// Populate items with crypto/rand
			itemsToRandomize := [][]byte{pt, header, key, nonce}
			for _, item := range itemsToRandomize {
				_, err := rand.Read(item)
				if err != nil {
					panic(err)
				}
			}
			aesCipher, err := aes.NewCipher(key)
			if err != nil {
				panic(err)
			}
			eax, errEax := NewEAX(aesCipher)
			if errEax != nil {
				panic(errEax)
			}
			ct := eax.Seal(nil, nonce, pt, header)
			// key, N, A, P, C
			str += fmt.Sprintf(
				"{\"%X\",\n\"%X\",\n\"%X\",\n\"%X\",\n\"%X\"},\n",
				key, nonce, header, pt, ct)
		}
	}
	str += "}"
	err := writeToFile("random_vectors.go", str)
	if err != nil {
		panic(err)
	}
}

func writeToFile(filename string, data string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer func () {
		err := file.Close()
		if err != nil {
			panic(err)
		}
	}()

	_, err = io.WriteString(file, data)
	if err != nil {
		return err
	}
	return file.Sync()
}
