package integrationtests

import (
	"bytes"
	"strings"
	"crypto/rand"
	mathrand "math/rand"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"time"
)
var maxPasswordLength = 64
var maxMessageLength = 1 << 12

// This function produces random test vectors: generates keys according to the
// given settings, associates a random message for each key. It returns the
// test vectors.
func generateFreshTestVectors(settings []keySetting) (vectors []testVector, err error) {
	mathrand.Seed(time.Now().UTC().UnixNano())

	for _, setting := range settings {
		// Sample random email, comment, password and message
		name := randomName()
		email := randomEmail()
		comment := randomComment()
		password := randomPassword()
		message := randomMessage()

		newVector := testVector{
			name: setting.name + "_fresh",
			password: password,
			message: message,
		}

		// Generate keys
		newEntity, errKG := openpgp.NewEntity(name, comment, email, setting.cfg)
		if errKG != nil {
			panic(errKG)
		}
		if err = newEntity.SelfSign(nil); err != nil {
			panic(err)
		}

		// Encrypt private key of entity
		rawPwd := []byte(password)
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
		newVector.privateKey = privateKey
		newVector.publicKey, _ = publicKey(privateKey)

		vectors = append(vectors, newVector)
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
	if _, err = w.Write(input); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
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
		err := e.Serialize(&outBuf)
		if err != nil {
			return "", err
		}
	}

	outString, err := armorWithType(outBuf.Bytes(), "PGP PUBLIC KEY BLOCK")
	if err != nil {
		return "", err
	}

	return outString, nil
}

var runes = []rune("abcdefghijklmnopqrstuvwxyz0123456789._ABCDEFGHIJKMNOPQRSTUVWXYZ:;?/!@#$%^&*{}[]_'\"-+~()<>")

func randomName() string {
	firstName := make([]rune, 8)
	lastName := make([]rune, 8)
    for i := range firstName {
        firstName[i] = runes[mathrand.Intn(len(runes)) % 26]
    }
    for i := range lastName {
        lastName[i] = runes[mathrand.Intn(len(runes)) % 26]
    }
    return string(firstName) + " " + string(lastName)
}
func randomEmail() string {
    address := make([]rune, 20)
	domain := make([]rune, 5)
	ext := make([]rune, 3)
    for i := range address {
        address[i] = runes[mathrand.Intn(len(runes)) % 38]
    }
    for i := range domain {
        domain[i] = runes[mathrand.Intn(len(runes)) % 36]
    }
    for i := range ext {
        ext[i] = runes[mathrand.Intn(len(runes)) % 36]
    }
	email := string(address) + "@" + string(domain) + "." + string(ext)
    return email
}

// Comment does not allow the following characters: ()<>\x00
func randomComment() string {
    comment := make([]rune, 140)
    for i := range comment {
        comment[i] = runes[mathrand.Intn(len(runes)) % 85]
    }
    return string(comment)
	// return ""
}

func randomPassword() string {
    password := make([]rune, mathrand.Intn(maxPasswordLength-1)+1)
    for i := range password {
        password[i] = runes[mathrand.Intn(len(runes))]
    }
    return string(password)
	// return "password"
}

func randomMessage() string {
	message := make([]byte, mathrand.Intn(maxMessageLength))
	if _, err := rand.Read(message); err != nil {
		panic(err)
	}
	return string(message)
	// return "hello world"
}

// Change one char of the input
func corrupt(input string) string {
	if input == "" {
		return string(runes[mathrand.Intn(len(runes))])
	}
	output := []rune(input)
	for string(output) == input {
		output[mathrand.Intn(len(output))] = runes[mathrand.Intn(len(runes))]
	}
	return string(output)
}
