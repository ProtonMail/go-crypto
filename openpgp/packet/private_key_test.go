// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"crypto"
	"crypto/dsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"hash"
	"math/big"
	mathrand "math/rand"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/ecdsa"
	"github.com/ProtonMail/go-crypto/openpgp/eddsa"
	"github.com/ProtonMail/go-crypto/openpgp/elgamal"
	"github.com/ProtonMail/go-crypto/openpgp/internal/ecc"
	"github.com/ProtonMail/go-crypto/openpgp/s2k"
)

const maxMessageLength = 1 << 10

var privateKeyTests = []struct {
	privateKeyHex string
	creationTime  time.Time
}{
	{
		privKeyRSAHex,
		time.Unix(0x4cc349a8, 0),
	},
	{
		privKeyElGamalHex,
		time.Unix(0x4df9ee1a, 0),
	},
}

func TestExternalPrivateKeyRead(t *testing.T) {
	for i, test := range privateKeyTests {
		packet, err := Read(readerFromHex(test.privateKeyHex))
		if err != nil {
			t.Errorf("#%d: failed to parse: %s", i, err)
			continue
		}

		privKey := packet.(*PrivateKey)

		if !privKey.Encrypted {
			t.Errorf("#%d: private key isn't encrypted", i)
			continue
		}

		err = privKey.Decrypt([]byte("wrong password"))
		if err == nil {
			t.Errorf("#%d: decrypted with incorrect key", i)
			continue
		}

		err = privKey.Decrypt([]byte("testing"))
		if err != nil {
			t.Errorf("#%d: failed to decrypt: %s", i, err)
			continue
		}

		if !privKey.CreationTime.Equal(test.creationTime) || privKey.Encrypted {
			t.Errorf("#%d: bad result, got: %#v", i, privKey)
		}
	}
}

// En/decryption of private keys provided externally, with random passwords
func TestExternalPrivateKeyEncryptDecryptRandomizeSlow(t *testing.T) {
	for i, test := range privateKeyTests {
		packet, err := Read(readerFromHex(test.privateKeyHex))
		if err != nil {
			t.Errorf("#%d: failed to parse: %s", i, err)
			continue
		}

		privKey := packet.(*PrivateKey)

		if !privKey.Encrypted {
			t.Errorf("#%d: private key isn't encrypted", i)
			continue
		}

		// Decrypt with the correct password
		err = privKey.Decrypt([]byte("testing"))
		if err != nil {
			t.Errorf("#%d: failed to decrypt: %s", i, err)
			continue
		}

		// Encrypt with another (possibly empty) password
		randomPassword := make([]byte, mathrand.Intn(30))
		rand.Read(randomPassword)
		err = privKey.Encrypt(randomPassword)
		if err != nil {
			t.Errorf("#%d: failed to encrypt: %s", i, err)
			continue
		}

		// Try to decrypt with incorrect password
		incorrect := make([]byte, 1+mathrand.Intn(30))
		for rand.Read(incorrect); bytes.Equal(incorrect, randomPassword); {
			rand.Read(incorrect)
		}
		err = privKey.Decrypt(incorrect)
		if err == nil {
			t.Errorf("#%d: decrypted with incorrect password\nPassword is:%vDecrypted with:%v", i, randomPassword, incorrect)
			continue
		}

		// Try to decrypt with old password
		err = privKey.Decrypt([]byte("testing"))
		if err == nil {
			t.Errorf("#%d: decrypted with old password", i)
			continue
		}

		// Decrypt with correct password
		err = privKey.Decrypt(randomPassword)
		if err != nil {
			t.Errorf("#%d: failed to decrypt: %s", i, err)
			continue
		}

		if !privKey.CreationTime.Equal(test.creationTime) || privKey.Encrypted {
			t.Errorf("#%d: bad result, got: %#v", i, privKey)
		}
	}
}

func TestExternalPrivateKeyEncryptDecryptArgon2(t *testing.T) {
	config := &Config{
		S2KConfig: &s2k.Config{S2KMode: s2k.Argon2S2K},
	}
	for i, test := range privateKeyTests {
		packet, err := Read(readerFromHex(test.privateKeyHex))
		if err != nil {
			t.Errorf("#%d: failed to parse: %s", i, err)
			continue
		}

		privKey := packet.(*PrivateKey)

		if !privKey.Encrypted {
			t.Errorf("#%d: private key isn't encrypted", i)
			continue
		}

		// Decrypt with the correct password
		err = privKey.Decrypt([]byte("testing"))
		if err != nil {
			t.Errorf("#%d: failed to decrypt: %s", i, err)
			continue
		}

		// Encrypt with another (possibly empty) password
		randomPassword := make([]byte, mathrand.Intn(30))
		rand.Read(randomPassword)
		err = privKey.EncryptWithConfig(randomPassword, config)
		if err != nil {
			t.Errorf("#%d: failed to encrypt: %s", i, err)
			continue
		}

		// Try to decrypt with incorrect password
		incorrect := make([]byte, 1+mathrand.Intn(30))
		for rand.Read(incorrect); bytes.Equal(incorrect, randomPassword); {
			rand.Read(incorrect)
		}
		err = privKey.Decrypt(incorrect)
		if err == nil {
			t.Errorf("#%d: decrypted with incorrect password\nPassword is:%vDecrypted with:%v", i, randomPassword, incorrect)
			continue
		}

		// Try to decrypt with old password
		err = privKey.Decrypt([]byte("testing"))
		if err == nil {
			t.Errorf("#%d: decrypted with old password", i)
			continue
		}

		// Decrypt with correct password
		err = privKey.Decrypt(randomPassword)
		if err != nil {
			t.Errorf("#%d: failed to decrypt: %s", i, err)
			continue
		}

		if !privKey.CreationTime.Equal(test.creationTime) || privKey.Encrypted {
			t.Errorf("#%d: bad result, got: %#v", i, privKey)
		}
	}
}

func populateHash(hashFunc crypto.Hash, msg []byte) (hash.Hash, error) {
	h := hashFunc.New()
	if _, err := h.Write(msg); err != nil {
		return nil, err
	}
	return h, nil
}

func TestExternalRSAPrivateKey(t *testing.T) {
	privKeyDER, _ := hex.DecodeString(pkcs1PrivKeyHex)
	rsaPriv, err := x509.ParsePKCS1PrivateKey(privKeyDER)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	xrsaPriv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			E: rsaPriv.PublicKey.E,
			N: rsaPriv.PublicKey.N,
		},
		D:      rsaPriv.D,
		Primes: rsaPriv.Primes,
	}
	xrsaPriv.Precompute()
	if err := NewRSAPrivateKey(time.Now(), xrsaPriv).Serialize(&buf); err != nil {
		t.Fatal(err)
	}

	p, err := Read(&buf)
	if err != nil {
		t.Fatal(err)
	}

	priv, ok := p.(*PrivateKey)
	if !ok {
		t.Fatal("didn't parse private key")
	}

	sig := &Signature{
		Version:    4,
		PubKeyAlgo: PubKeyAlgoRSA,
		Hash:       crypto.SHA256,
	}
	for j := 0; j < 256; j++ {
		msg := make([]byte, maxMessageLength)
		rand.Read(msg)

		h, err := populateHash(sig.Hash, msg)
		if err != nil {
			t.Fatal(err)
		}
		if err := sig.Sign(h, priv, nil); err != nil {
			t.Fatal(err)
		}

		if h, err = populateHash(sig.Hash, msg); err != nil {
			t.Fatal(err)
		}
		if err := priv.VerifySignature(h, sig); err != nil {
			t.Fatal(err)
		}
	}
}

func TestECDSAPrivateKeysRandomizeFast(t *testing.T) {
	ecdsaPriv, err := ecdsa.GenerateKey(rand.Reader, ecc.NewGenericCurve(elliptic.P256()))
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := NewECDSAPrivateKey(time.Now(), ecdsaPriv).Serialize(&buf); err != nil {
		t.Fatal(err)
	}

	p, err := Read(&buf)
	if err != nil {
		t.Fatal(err)
	}

	priv, ok := p.(*PrivateKey)
	if !ok {
		t.Fatal("didn't parse private key")
	}

	sig := &Signature{
		Version:    4,
		PubKeyAlgo: PubKeyAlgoECDSA,
		Hash:       crypto.SHA256,
	}
	msg := make([]byte, mathrand.Intn(maxMessageLength))
	rand.Read(msg)

	h, err := populateHash(sig.Hash, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := sig.Sign(h, priv, nil); err != nil {
		t.Fatal(err)
	}

	if h, err = populateHash(sig.Hash, msg); err != nil {
		t.Fatal(err)
	}
	if err := priv.VerifySignature(h, sig); err != nil {
		t.Fatal(err)
	}
}

func TestRSASignerPrivateKeysRandomizeSlow(t *testing.T) {
	// Generate random key
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}

	priv := NewSignerPrivateKey(time.Now(), rsaPriv)

	sig := &Signature{
		Version:    4,
		PubKeyAlgo: PubKeyAlgoRSA,
		Hash:       crypto.SHA256,
	}

	// Sign random message
	msg := make([]byte, maxMessageLength)
	h, err := populateHash(sig.Hash, msg)

	if err != nil {
		t.Fatal(err)
	}
	if err := sig.Sign(h, priv, nil); err != nil {
		t.Fatal(err)
	}

	if h, err = populateHash(sig.Hash, msg); err != nil {
		t.Fatal(err)
	}

	// Verify signature
	if err := priv.VerifySignature(h, sig); err != nil {
		t.Fatal(err)
	}

	// Try to verify signature with wrong key
	incorrectRsaPriv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	incorrectPriv := NewSignerPrivateKey(time.Now(), incorrectRsaPriv)
	if err = incorrectPriv.VerifySignature(h, sig); err == nil {
		t.Fatalf(
			"Verified signature with incorrect key.\nCorrect key:  \n%v\nIncorrect key:\n%v\nSignature:%v",
			priv, incorrectPriv, sig)
	}
}

func TestECDSASignerPrivateKeysRandomizeFast(t *testing.T) {
	ecdsaPriv, err := ecdsa.GenerateKey(rand.Reader, ecc.NewGenericCurve(elliptic.P256()))
	if err != nil {
		t.Fatal(err)
	}

	priv := NewSignerPrivateKey(time.Now(), ecdsaPriv)

	if priv.PubKeyAlgo != PubKeyAlgoECDSA {
		t.Fatal("NewSignerPrivateKey should have made an ECSDA private key")
	}

	sig := &Signature{
		Version:    4,
		PubKeyAlgo: PubKeyAlgoECDSA,
		Hash:       crypto.SHA256,
	}
	msg := make([]byte, mathrand.Intn(maxMessageLength))
	rand.Read(msg)

	h, err := populateHash(sig.Hash, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := sig.Sign(h, priv, nil); err != nil {
		t.Fatal(err)
	}

	if h, err = populateHash(sig.Hash, msg); err != nil {
		t.Fatal(err)
	}
	if err := priv.VerifySignature(h, sig); err != nil {
		t.Fatal(err)
	}
}

func TestEdDSASignerPrivateKeyRandomizeFast(t *testing.T) {
	eddsaPriv, err := eddsa.GenerateKey(rand.Reader, ecc.NewEd25519())
	if err != nil {
		t.Fatal(err)
	}

	priv := NewSignerPrivateKey(time.Now(), eddsaPriv)

	if priv.PubKeyAlgo != PubKeyAlgoEdDSA {
		t.Fatal("NewSignerPrivateKey should have made a EdDSA private key")
	}

	sig := &Signature{
		Version:    4,
		PubKeyAlgo: PubKeyAlgoEdDSA,
		Hash:       crypto.SHA256,
	}
	msg := make([]byte, maxMessageLength)
	rand.Read(msg)

	h, err := populateHash(sig.Hash, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := sig.Sign(h, priv, nil); err != nil {
		t.Fatal(err)
	}
	if h, err = populateHash(sig.Hash, msg); err != nil {
		t.Fatal(err)
	}
	if err := priv.VerifySignature(h, sig); err != nil {
		t.Fatal(err)
	}
}

// Tests correctness when encrypting an EdDSA private key with a password.
func TestEncryptDecryptEdDSAPrivateKeyRandomizeFast(t *testing.T) {
	password := make([]byte, 20)
	_, err := rand.Read(password)
	if err != nil {
		panic(err)
	}
	primaryKey, err := eddsa.GenerateKey(rand.Reader, ecc.NewEd25519())
	if err != nil {
		panic(err)
	}
	privKey := *NewEdDSAPrivateKey(time.Now(), primaryKey)

	copiedSecret := make([]byte, len(primaryKey.D))
	copy(copiedSecret, privKey.PrivateKey.(*eddsa.PrivateKey).D)

	// Encrypt private key with random passphrase
	privKey.Encrypt(password)
	// Decrypt and check correctness
	privKey.Decrypt(password)

	decryptedSecret := privKey.PrivateKey.(*eddsa.PrivateKey).D
	if !bytes.Equal(decryptedSecret, copiedSecret) {
		t.Fatalf("Private key was not correctly decrypted:\ngot:\n%v\nwant:\n%v", decryptedSecret, copiedSecret)
	}
}

func TestIssue11505(t *testing.T) {
	// parsing a rsa private key with p or q == 1 used to panic due to a divide by zero
	_, _ = Read(readerFromHex("9c3004303030300100000011303030000000000000010130303030303030303030303030303030303030303030303030303030303030303030303030303030303030"))
}

func TestDSAValidation(t *testing.T) {
	var priv dsa.PrivateKey
	params := &priv.Parameters
	err := dsa.GenerateParameters(params, rand.Reader, dsa.L1024N160)
	if err != nil {
		t.Fatalf("could not generate test params: %s", err)
	}
	err = dsa.GenerateKey(&priv, rand.Reader)
	if err != nil {
		t.Fatalf("could not generate test key: %s", err)
	}
	if err = validateDSAParameters(&priv); err != nil {
		t.Fatalf("valid key marked as invalid: %s", err)
	}
	// g = 1
	g := *priv.G
	priv.G = big.NewInt(1)
	if err = validateDSAParameters(&priv); err == nil {
		t.Fatalf("failed to detect invalid key (g)")
	}
	priv.G = &g
	// corrupt q
	q := *priv.Q
	priv.Q.Sub(priv.Q, big.NewInt(1))
	if err = validateDSAParameters(&priv); err == nil {
		t.Fatalf("failed to detect invalid key (q)")
	}
	priv.Q = &q
	// corrupt y
	y := *priv.Y
	priv.Y.Sub(priv.Y, big.NewInt(1))
	if err = validateDSAParameters(&priv); err == nil {
		t.Fatalf("failed to detect invalid key (y)")
	}
	priv.Y = &y
}

func TestElGamalValidation(t *testing.T) {
	// we generate dsa key and then reuse values for elgamal
	var dsaPriv dsa.PrivateKey
	params := &dsaPriv.Parameters
	err := dsa.GenerateParameters(params, rand.Reader, dsa.L1024N160)
	if err != nil {
		t.Fatalf("could not generate test params: %s", err)
	}
	err = dsa.GenerateKey(&dsaPriv, rand.Reader)
	if err != nil {
		t.Fatalf("could not generate test key: %s", err)
	}
	// this elgamal key is technically not valid since g has order q < p-1
	// but q is large enough and tests should pass
	var priv elgamal.PrivateKey
	priv.G = dsaPriv.G
	priv.P = dsaPriv.P
	priv.X = dsaPriv.X
	priv.Y = dsaPriv.Y
	if err = validateElGamalParameters(&priv); err != nil {
		t.Fatalf("valid key marked as invalid: %s", err)
	}
	// g = 1
	g := *priv.G
	priv.G = big.NewInt(1)
	if err = validateElGamalParameters(&priv); err == nil {
		t.Fatalf("failed to detect invalid key (g)")
	}
	// g of order 2: g**(p-1)/2
	pSub1 := new(big.Int).Sub(priv.P, big.NewInt(1))
	pSub1Div2 := new(big.Int).Rsh(pSub1, 1)
	priv.G = new(big.Int).Exp(&g, pSub1Div2, priv.P)
	if err = validateElGamalParameters(&priv); err == nil {
		t.Fatalf("failed to detect invalid key (g small order)")
	}
	priv.G = &g
	// corrupt y
	y := *priv.Y
	priv.Y.Sub(priv.Y, big.NewInt(1))
	if err = validateElGamalParameters(&priv); err == nil {
		t.Fatalf("failed to detect invalid key (y)")
	}
	priv.Y = &y
}
