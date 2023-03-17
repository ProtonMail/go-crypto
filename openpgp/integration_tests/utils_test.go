package integrationtests

import (
	"bytes"
	"crypto"
	"crypto/rand"
	mathrand "math/rand"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/go-crypto/openpgp/s2k"
)

// This function produces random test vectors: generates keys according to the
// given settings, associates a random message for each key. It returns the
// test vectors.
func generateFreshTestVectors() (vectors []testVector, err error) {
	mathrand.Seed(time.Now().UTC().UnixNano())
	for i := 0; i < 3; i++ {
		config := randConfig()
		// Sample random email, comment, password and message
		name, email, comment, password, message := randEntityData()

		// Only for verbose display
		v := "v4"
		if config.V5Keys {
			v = "v5"
		}
		pkAlgoNames := map[packet.PublicKeyAlgorithm]string{
			packet.PubKeyAlgoRSA:   "rsa_" + v,
			packet.PubKeyAlgoEdDSA: "ed25519_" + v,
		}

		newVector := testVector{
			config:   config,
			Name:     pkAlgoNames[config.Algorithm],
			Password: password,
			Message:  message,
		}

		// Generate keys
		newEntity, errKG := openpgp.NewEntity(name, comment, email, config)
		if errKG != nil {
			panic(errKG)
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
		if err = newEntity.SerializePrivateWithoutSigning(w, nil); err != nil {
			return nil, err
		}

		serialized := w.Bytes()

		privateKey, _ := armorWithType(serialized, "PGP PRIVATE KEY BLOCK")
		newVector.PrivateKey = privateKey
		newVector.PublicKey, _ = publicKey(privateKey)
		vectors = append(vectors, newVector)
	}
	return vectors, err
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

var runes = []rune("abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKMNOPQRSTUVWXYZ.@-_:;?/!#$%^&*{}[]'\"+~()<>")

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

func randFileHints() *openpgp.FileHints {
	fileNameRunes := runes[:66]
	fileName := make([]rune, 1+mathrand.Intn(255))
	for i := range fileName {
		fileName[i] = fileNameRunes[mathrand.Intn(len(fileNameRunes))]
	}

	return &openpgp.FileHints{
		IsBinary: mathrand.Intn(2) == 0,
		FileName: string(fileName),
		ModTime:  time.Now(),
	}
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
	maxMessageLength := 1 << 20
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

func randConfig() *packet.Config {
	hashes := []crypto.Hash{
		crypto.SHA256,
	}
	hash := hashes[mathrand.Intn(len(hashes))]

	ciphers := []packet.CipherFunction{
		packet.CipherAES256,
	}
	ciph := ciphers[mathrand.Intn(len(ciphers))]

	compAlgos := []packet.CompressionAlgo{
		packet.CompressionNone,
		packet.CompressionZIP,
		packet.CompressionZLIB,
	}
	compAlgo := compAlgos[mathrand.Intn(len(compAlgos))]

	pkAlgos := []packet.PublicKeyAlgorithm{
		packet.PubKeyAlgoRSA,
		packet.PubKeyAlgoEdDSA,
	}
	pkAlgo := pkAlgos[mathrand.Intn(len(pkAlgos))]

	aeadModes := []packet.AEADMode{
		packet.AEADModeOCB,
		packet.AEADModeEAX,
		packet.AEADModeGCM,
	}
	var aeadConf = packet.AEADConfig{
		DefaultMode: aeadModes[mathrand.Intn(len(aeadModes))],
	}

	var rsaBits int
	if pkAlgo == packet.PubKeyAlgoRSA {
		switch mathrand.Int() % 4 {
		case 0:
			rsaBits = 2048
		case 1:
			rsaBits = 3072
		case 2:
			rsaBits = 4096
		default:
			rsaBits = 0
		}
	}

	level := mathrand.Intn(11) - 1
	compConf := &packet.CompressionConfig{level}

	var v5 bool
	if mathrand.Int()%2 == 0 {
		v5 = true
	}

	var s2kConf *s2k.Config
	if mathrand.Int()%2 == 0 {
		s2kConf = &s2k.Config{
			S2KMode:  s2k.IteratedSaltedS2K,
			Hash:     hash,
			S2KCount: 1024 + mathrand.Intn(65010689),
		}
	} else {
		s2kConf = &s2k.Config{
			S2KMode: s2k.Argon2S2K,
		}
	}

	return &packet.Config{
		V5Keys:                 v5,
		Rand:                   rand.Reader,
		DefaultHash:            hash,
		DefaultCipher:          ciph,
		DefaultCompressionAlgo: compAlgo,
		CompressionConfig:      compConf,
		S2KConfig:              s2kConf,
		RSABits:                rsaBits,
		Algorithm:              pkAlgo,
		AEADConfig:             &aeadConf,
	}
}
