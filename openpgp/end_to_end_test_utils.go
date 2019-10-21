package openpgp

import (
	"bytes"
	"strings"
	"golang.org/x/crypto/openpgp/armor"
)

// TODO: Describe what this function does.
func makeKeyGenTestSets() (testSets []algorithmSet, err error) {
	// TODO: Randomize this.
	email := "sunny@sunny.sunny"
	comments := ""
	password := "123"

	for _, keySet := range keySets {

		newTestSet := algorithmSet{}
		newTestSet.name = keySet.name + "_keygen"
		newTestSet.password = password
		newTestSet.message = test_message

		newEntity, _ := NewEntity(email, comments, email, keySet.cfg)
		if err = newEntity.SelfSign(nil); err != nil {
			return
		}

		rawPwd := []byte(password)
		if newEntity.PrivateKey != nil && !newEntity.PrivateKey.Encrypted {
			if err = newEntity.PrivateKey.Encrypt(rawPwd); err != nil {
				return
			}
		}

		for _, sub := range newEntity.Subkeys {
			if sub.PrivateKey != nil && !sub.PrivateKey.Encrypted {
				if err = sub.PrivateKey.Encrypt(rawPwd); err != nil {
					return
				}
			}
		}

		w := bytes.NewBuffer(nil)
		if err = newEntity.SerializePrivateNoSign(w, nil); err != nil {
			return
		}

		serialized := w.Bytes()

		privateKey, _ := ArmorWithType(serialized, "PGP PRIVATE KEY BLOCK")
		newTestSet.privateKey = privateKey
		newTestSet.publicKey, _ = PublicKey(privateKey)

		testSets = append(testSets, newTestSet)
	}
	return
}

// ArmorWithType make bytes input to armor format
func ArmorWithType(input []byte, armorType string) (string, error) {
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

func PublicKey(privateKey string) (string, error) {
	privKeyReader := strings.NewReader(privateKey)
	entries, err := ReadArmoredKeyRing(privKeyReader)
	if err != nil {
		return "", err
	}

	var outBuf bytes.Buffer
	for _, e := range entries {
		e.Serialize(&outBuf)
	}

	outString, err := ArmorWithType(outBuf.Bytes(), "PGP PUBLIC KEY BLOCK")
	if err != nil {
		return "", nil
	}

	return outString, nil
}
