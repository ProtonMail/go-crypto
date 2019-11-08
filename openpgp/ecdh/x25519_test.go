// Copyright 2019 ProtonTech AG.
//

package ecdh

import (
	"testing"
	"crypto/rand"
	"fmt"
)
// Some implementations, such as gpg 2.2.12, do not accept ECDH private keys
// if they're not masked. This is because they're not of the proper form,
// cryptographically, and they don't mask input keys during crypto operations.
// This test checks if the keys that this library stores or outputs are properly
// masked.
func TestGenerateMaskedPrivateKeyX25519(t *testing.T) {
	priv, pub, err := generateKeyPair(rand.Reader)
	if err != nil  {
		t.Fatal(err)
	}
	// Check masking
	// 3 lsb
	fmt.Println(pub)
	fmt.Println(priv)
	fmt.Println(priv[0])

    for _, n := range(priv) {
        fmt.Printf("% 08b", n) // prints 00000000 11111101
    }
	print("\n")
}
