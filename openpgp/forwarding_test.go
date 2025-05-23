package openpgp

import (
	"bytes"
	"crypto/rand"
	goerrors "errors"
	"io"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"golang.org/x/crypto/openpgp/armor"
)

const forwardeeKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

xVgEZAdtGBYJKwYBBAHaRw8BAQdAcNgHyRGEaqGmzEqEwCobfUkyrJnY8faBvsf9
R2c5ZzYAAP9bFL4nPBdo04ei0C2IAh5RXOpmuejGC3GAIn/UmL5cYQ+XzRtjaGFy
bGVzIDxjaGFybGVzQHByb3Rvbi5tZT7CigQTFggAPAUCZAdtGAmQFXJtmBzDhdcW
IQRl2gNflypl1XjRUV8Vcm2YHMOF1wIbAwIeAQIZAQILBwIVCAIWAAIiAQAAJKYA
/2qY16Ozyo5erNz51UrKViEoWbEpwY3XaFVNzrw+b54YAQC7zXkf/t5ieylvjmA/
LJz3/qgH5GxZRYAH9NTpWyW1AsdxBGQHbRgSCisGAQQBl1UBBQEBB0CxmxoJsHTW
TiETWh47ot+kwNA1hCk1IYB9WwKxkXYyIBf/CgmKXzV1ODP/mRmtiBYVV+VQk5MF
EAAA/1NW8D8nMc2ky140sPhQrwkeR7rVLKP2fe5n4BEtAnVQEB3CeAQYFggAKgUC
ZAdtGAmQFXJtmBzDhdcWIQRl2gNflypl1XjRUV8Vcm2YHMOF1wIbUAAAl/8A/iIS
zWBsBR8VnoOVfEE+VQk6YAi7cTSjcMjfsIez9FYtAQDKo9aCMhUohYyqvhZjn8aS
3t9mIZPc+zRJtCHzQYmhDg==
=lESj
-----END PGP PRIVATE KEY BLOCK-----`

const forwardedMessage = `-----BEGIN PGP MESSAGE-----

wV4DB27Wn97eACkSAQdA62TlMU2QoGmf5iBLnIm4dlFRkLIg+6MbaatghwxK+Ccw
yGZuVVMAK/ypFfebDf4D/rlEw3cysv213m8aoK8nAUO8xQX3XQq3Sg+EGm0BNV8E
0kABEPyCWARoo5klT1rHPEhelnz8+RQXiOIX3G685XCWdCmaV+tzW082D0xGXSlC
7lM8r1DumNnO8srssko2qIja
=pVRa
-----END PGP MESSAGE-----`

const forwardedPlaintext = "Message for Bob"

func TestForwardingStatic(t *testing.T) {
	charlesKey, err := ReadArmoredKeyRing(bytes.NewBufferString(forwardeeKey))
	if err != nil {
		t.Error(err)
		return
	}

	ciphertext, err := armor.Decode(strings.NewReader(forwardedMessage))
	if err != nil {
		t.Error(err)
		return
	}

	m, err := ReadMessage(ciphertext.Body, charlesKey, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	dec, err := ioutil.ReadAll(m.decrypted)

	if !bytes.Equal(dec, []byte(forwardedPlaintext)) {
		t.Fatal("forwarded decrypted does not match original")
	}
}

func TestForwardingFull(t *testing.T) {
	keyConfig := &packet.Config{
		Algorithm: packet.PubKeyAlgoEdDSA,
		Curve:     packet.Curve25519,
	}

	plaintext := make([]byte, 1024)
	rand.Read(plaintext)

	bobEntity, err := NewEntity("bob", "", "bob@proton.me", keyConfig)
	if err != nil {
		t.Fatal(err)
	}

	charlesEntity, instances, err := bobEntity.NewForwardingEntity("charles", "", "charles@proton.me", keyConfig, true)
	if err != nil {
		t.Fatal(err)
	}

	charlesEntity = serializeAndParseForwardeeKey(t, charlesEntity)

	if len(instances) != 1 {
		t.Fatalf("invalid number of instances, expected 1 got %d", len(instances))
	}

	if !bytes.Equal(instances[0].ForwarderFingerprint, bobEntity.Subkeys[0].PublicKey.Fingerprint) {
		t.Fatalf("invalid forwarder key ID, expected: %x, got: %x", bobEntity.Subkeys[0].PublicKey.Fingerprint, instances[0].ForwarderFingerprint)
	}

	if !bytes.Equal(instances[0].ForwardeeFingerprint, charlesEntity.Subkeys[0].PublicKey.Fingerprint) {
		t.Fatalf("invalid forwardee key ID, expected: %x, got: %x", charlesEntity.Subkeys[0].PublicKey.Fingerprint, instances[0].ForwardeeFingerprint)
	}

	// Encrypt message
	buf := bytes.NewBuffer(nil)
	w, err := Encrypt(buf, []*Entity{bobEntity}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = w.Write(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	err = w.Close()
	if err != nil {
		t.Fatal(err)
	}

	encrypted := buf.Bytes()

	// Decrypt message for Bob
	m, err := ReadMessage(bytes.NewBuffer(encrypted), EntityList([]*Entity{bobEntity}), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := ioutil.ReadAll(m.decrypted)

	if !bytes.Equal(dec, plaintext) {
		t.Fatal("decrypted does not match original")
	}

	// Forward message

	transformed := transformTestMessage(t, encrypted, instances[0])

	// Decrypt forwarded message for Charles
	m, err = ReadMessage(bytes.NewBuffer(transformed), EntityList([]*Entity{charlesEntity}), nil /* no prompt */, nil)
	if err != nil {
		t.Fatal(err)
	}

	dec, err = ioutil.ReadAll(m.decrypted)

	if !bytes.Equal(dec, plaintext) {
		t.Fatal("forwarded decrypted does not match original")
	}

	// Setup further forwarding
	danielEntity, secondForwardInstances, err := charlesEntity.NewForwardingEntity("Daniel", "", "daniel@proton.me", keyConfig, true)
	if err != nil {
		t.Fatal(err)
	}

	danielEntity = serializeAndParseForwardeeKey(t, danielEntity)

	secondTransformed := transformTestMessage(t, transformed, secondForwardInstances[0])

	// Decrypt forwarded message for Charles
	m, err = ReadMessage(bytes.NewBuffer(secondTransformed), EntityList([]*Entity{danielEntity}), nil /* no prompt */, nil)
	if err != nil {
		t.Fatal(err)
	}

	dec, err = ioutil.ReadAll(m.decrypted)

	if !bytes.Equal(dec, plaintext) {
		t.Fatal("forwarded decrypted does not match original")
	}
}

func transformTestMessage(t *testing.T, encrypted []byte, instance packet.ForwardingInstance) []byte {
	bytesReader := bytes.NewReader(encrypted)
	packets := packet.NewReader(bytesReader)
	splitPoint := int64(0)
	transformedEncryptedKey := bytes.NewBuffer(nil)

Loop:
	for {
		p, err := packets.Next()
		if goerrors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("error in parsing message: %s", err)
		}
		switch p := p.(type) {
		case *packet.EncryptedKey:
			tp, err := p.ProxyTransform(instance)
			if err != nil {
				t.Fatalf("error transforming PKESK: %s", err)
			}

			splitPoint = bytesReader.Size() - int64(bytesReader.Len())

			err = tp.Serialize(transformedEncryptedKey)
			if err != nil {
				t.Fatalf("error serializing transformed PKESK: %s", err)
			}
			break Loop
		}
	}

	transformed := transformedEncryptedKey.Bytes()
	transformed = append(transformed, encrypted[splitPoint:]...)

	return transformed
}

func serializeAndParseForwardeeKey(t *testing.T, key *Entity) *Entity {
	serializedEntity := bytes.NewBuffer(nil)
	err := key.SerializePrivateWithoutSigning(serializedEntity, nil)
	if err != nil {
		t.Fatalf("Error in serializing forwardee key: %s", err)
	}
	el, err := ReadKeyRing(serializedEntity)
	if err != nil {
		t.Fatalf("Error in reading forwardee key: %s", err)
	}

	if len(el) != 1 {
		t.Fatalf("Wrong number of entities in parsing, expected 1, got %d", len(el))
	}

	return el[0]
}
