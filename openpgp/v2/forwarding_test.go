package v2

import (
	"bytes"
	"crypto/rand"
	goerrors "errors"
	"io"
	"io/ioutil"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

const forwardeeKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

xVgEZQRXoxYJKwYBBAHaRw8BAQdAhxdzZ8ZP1M4UcauXSGbts38KhhAZxHNRcChs
9H7danMAAQC4tHykQmFpnlvhLYJDDc4MJm68mUB9qUls34GgKkqKNw6FzRtjaGFy
bGVzIDxjaGFybGVzQHByb3Rvbi5tZT7CiwQTFggAPQUCZQRXowkQizX+kwlYIwMW
IQTYm4qmQoyzTnG0eZKLNf6TCVgjAwIbAwIeAQIZAQILBwIVCAIWAAMnBwIAAMsQ
AQD9UHMIU418Z10UQrymhbjkGq/PHCytaaneaq5oycpN/QD/UiK3aA4+HxWhX/F2
VrvEKL5a2xyd1AKKQ2DInF3xUg3HcQRlBFejEgorBgEEAZdVAQUBAQdAep7x8ncL
ShzEgKL6h9MAJbgX2z3BBgSLeAdg/rczKngX/woJjSg9O4DzqQOtAvdhYkDoOCNf
QgUAAP9OMqK0IwNmshCtktDy1/RTeyPKT8ItHDFAZ1ReKMA5CA63wngEGBYIACoF
AmUEV6MJEIs1/pMJWCMDFiEE2JuKpkKMs05xtHmSizX+kwlYIwMCG1wAAC5EAP9s
AbYBf9NGv1NxJvU0n0K++k3UIGkw9xgGJa3VFHFKvwEAx0DZpTVpCkJmiOFAOcfu
cSvjlMyQwsC/hAAzQpcqvwE=
=8LJg
-----END PGP PRIVATE KEY BLOCK-----`

const forwardedMessage = `-----BEGIN PGP MESSAGE-----

wV4DKsXbtIU9/JMSAQdA/6+foCjeUhS7Xto3fimUi6pfMQ/Ft3caHkK/1i767isw
NvG8xRbjQ0sAE1IZVGE1MBcVhCIbHhqp0h2J479Zmfn/iP7hfomYxrkJ/6UMnlEo
0kABKyyfO3QVAzBBNeq6hH27uqzwLgjWVrpgY7dmWPv0goSSaqHUda0lm+8JNUuF
wssOJTwrSwQrX3ezy5D/h/E6
=okS+
-----END PGP MESSAGE-----`

const forwardedPlaintext = "Message for Bob"

const forwardingKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

xYUEZJ7obRYJKwYBBAHaRw8BAQdA0rsiAXbk646zNSFtehSG8tXV+933gX9qdlcv
y3dsETr+CQEIRDbKlCJxPw4WjfCI1f90n4Kr4ymuStB7MLm/mh+IyheqJgLtD4ak
EhgPd3R4o9TjQnwNbHnIfPo+FBbuo9T8yfnGzz0RvpL/ReZOViVdzRtjaGFybGll
IDxjaGFybGllQHByb3Rvbi5tZT7CjwQTFggAQQUCZJ7obQmQr3ZWGFoRxXwWIQTQ
TSCJvfPq/1Z83TKvdlYYWhHFfAIbAwIeAQIZAQMLCQcCFQgDFgACBScJAgcCAACM
OgD/cEsqqZdYl/RvYG3Kew658THsRFSGKeoEOZMvC0Ubza8BAIk6/dJNIYVvEBne
gCHO0yCfIITw5pH4SoF3okqOdaIKx54EZJ7obRIKKwYBBAGXVQEFAQEHQPNm6WCv
WZOZVKx0pYZJPWDxA1BfUrHStlBiaPqWHPkmF/8KCQ2qVg8YlFj8Z6f13kH8i+iY
FuX1/gkBCEQ2ypQicT8Oyr4aomc4TdKzvSb+xZA6xYugIUFzV4ojuS9UAuOB6yd2
Ye66Exx6qz3kpxcDgbcf3ZRO/ljZT8XWItM7j/wiUrjxuxHw4cJ4BBgWCAAqBQJk
nuhtCZCvdlYYWhHFfBYhBNBNIIm98+r/VnzdMq92VhhaEcV8AhtQAADBagD+IrnW
ecLlUsQEhs4brBFXTpF5jy0p/aAjJ9AkNoYvS9YA/27VaHCJzZwJsc7HQWOxQB+V
gZt8hzaHXTuA3JwjuKEB
=DPb7
-----END PGP PRIVATE KEY BLOCK-----`

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
	w, err := Encrypt(buf, []*Entity{bobEntity}, nil, nil, nil, nil)
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

func TestForwardingKeyNotEncrypt(t *testing.T) {
	charlesKey, err := ReadArmoredKeyRing(bytes.NewBufferString(forwardingKey))
	if err != nil {
		t.Error(err)
		return
	}
	if _, ok := charlesKey[0].EncryptionKey(time.Time{}, nil); ok {
		t.Fatal("Marked forwarding keys should not be usable for encryption")
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
