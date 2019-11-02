package integrationtests

import (
	"bytes"
	"crypto/rand"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	mathrand "math/rand"
	"strings"
)


// This function produces random test vectors: generates keys according to the
// given settings, associates a random message for each key. It returns the
// test vectors.
func generateFreshTestVectors() (vectors []testVector, err error) {
	// Settings for generating random, fresh key pairs
	var keySettings = []struct {
		name string
		cfg  *packet.Config
	}{
		{
			"rsa2048",
			&packet.Config{
				RSABits:   2048,
				Algorithm: packet.PubKeyAlgoRSA,
			},
		},
		{
			"rsa4096",
			&packet.Config{
				RSABits:   4096,
				Algorithm: packet.PubKeyAlgoRSA,
			},
		},
		{
			"ed25519",
			&packet.Config{
				Algorithm: packet.PubKeyAlgoEdDSA,
			},
		},
	}

	for _, setting := range keySettings {
		// Sample random email, comment, password and message
		name, email, comment, password, message := randEntityData()

		newVector := testVector{
			Name:     setting.name + "_fresh",
			Password: password,
			Message:  message,
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
		newVector.PrivateKey = privateKey
		newVector.PublicKey, _ = publicKey(privateKey)

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

var runes = []rune("abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKMNOPQRSTUVWXYZ.:;?/!@#$%^&*{}[]_'\"-+~()<>")

func randName() string {
	firstName := make([]rune, 8)
	lastName := make([]rune, 8)
	nameRunes := runes[:26]

	for i := range firstName {
		firstName[i] = nameRunes[mathrand.Intn(len(nameRunes))]
	}

	for i := range lastName {
		lastName[i] = nameRunes[mathrand.Intn(len(nameRunes))]
	}

	return string(firstName) + " " + string(lastName)
}

func randEmail() string {
	address := make([]rune, 20)
	addressRunes := runes[:38]
	domain := make([]rune, 5)
	domainRunes := runes[:36]
	ext := make([]rune, 3)
	for i := range address {
		address[i] = addressRunes[mathrand.Intn(len(addressRunes))]
	}
	for i := range domain {
		domain[i] = domainRunes[mathrand.Intn(len(domainRunes))]
	}
	for i := range ext {
		ext[i] = domainRunes[mathrand.Intn(len(domainRunes))]
	}
	email := string(address) + "@" + string(domain) + "." + string(ext)
	return email
}

// Comment does not allow the following characters: ()<>\x00
func randComment() string {
	comment := make([]rune, 140)
	commentRunes := runes[:84]
	for i := range comment {
		comment[i] = commentRunes[mathrand.Intn(len(commentRunes))]
	}
	return string(comment)
}

func randPassword() string {
	maxPasswordLength := 64
	password := make([]rune, mathrand.Intn(maxPasswordLength-1)+1)
	for i := range password {
		password[i] = runes[mathrand.Intn(len(runes))]
	}
	return string(password)
}

func randMessage() string {
	maxMessageLength := 1 << 12
	message := make([]byte, 1+mathrand.Intn(maxMessageLength-1))
	if _, err := rand.Read(message); err != nil {
		panic(err)
	}
	return string(message)
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

func randEntityData() (string, string, string, string, string) {
	return randName(), randEmail(), randComment(), randPassword(), randMessage()
}
