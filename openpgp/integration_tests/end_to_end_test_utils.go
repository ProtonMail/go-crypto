package integrationTests

import (
	"bytes"
	"strings"
	"crypto/rand"
	mathrand "math/rand"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)
var maxPasswordLength = 64
var maxMessageLength = 1 << 12

// TODO: Describe what this function does.
func generateFreshTestSets() (testSets []algorithmSet, err error) {
	email := "tester@tester.tester"
	comments := ""

	for _, keySet := range keySets {
		// Sample random password and message
		rawPwd := make([]byte, mathrand.Intn(maxPasswordLength))
		if _, err = rand.Read(rawPwd); err != nil {
			return
		}
		message := make([]byte, mathrand.Intn(maxMessageLength))
		if _, err = rand.Read(message); err != nil {
			return
		}

		newTestSet := algorithmSet{
			name: keySet.name + "_keygen",
			password: string(rawPwd),
			message: string(message),
		}

		// Generate keys
		newEntity, _ := openpgp.NewEntity(email, comments, email, keySet.cfg)
		if err = newEntity.SelfSign(nil); err != nil {
			panic(err)
		}

		// Encrypt private key of entity
		if newEntity.PrivateKey != nil && !newEntity.PrivateKey.Encrypted {
			if err = newEntity.PrivateKey.Encrypt(rawPwd); err != nil {
				panic(err)
			}
		}

		// Encrypt subkeys of entity
		for _, sub := range newEntity.Subkeys {
			if sub.PrivateKey != nil && !sub.PrivateKey.Encrypted {
				if err = sub.PrivateKey.Encrypt(rawPwd); err != nil {
					panic(err)
				}
			}
		}

		w := bytes.NewBuffer(nil)
		if err = newEntity.SerializePrivateNoSign(w, nil); err != nil {
			return
		}

		serialized := w.Bytes()

		privateKey, _ := armorWithType(serialized, "PGP PRIVATE KEY BLOCK")
		newTestSet.privateKey = privateKey
		newTestSet.publicKey, _ = publicKey(privateKey)

		testSets = append(testSets, newTestSet)
	}
	return
}

// armorWithType make bytes input to armor format
func armorWithType(input []byte, armorType string) (string, error) {
	var b bytes.Buffer
	w, err := armor.Encode(&b, armorType, nil)
	if err != nil {
		return "", err
	}
	_, err = w.Write(input)
	if err != nil {
		return "", err
	}
	w.Close()
	return b.String(), nil
}

func publicKey(privateKey string) (string, error) {
	privKeyReader := strings.NewReader(privateKey)
	entries, err := openpgp.ReadArmoredKeyRing(privKeyReader)
	if err != nil {
		return "", err
	}

	var outBuf bytes.Buffer
	for _, e := range entries {
		e.Serialize(&outBuf)
	}

	outString, err := armorWithType(outBuf.Bytes(), "PGP PUBLIC KEY BLOCK")
	if err != nil {
		return "", nil
	}

	return outString, nil
}
