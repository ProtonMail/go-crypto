package openpgp

import (
	"bytes"
	"crypto/rand"
	goerrors "errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"golang.org/x/crypto/openpgp/armor"
	"io"
	"io/ioutil"
	"strings"
	"testing"
)

const forwardeeKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

xVgEY/ikABYJKwYBBAHaRw8BAQdAzz/nPfhJnoAYwg43AFYzxX1v6UwGmfN9jPiI
/MOFxFgAAQDTqvO94jZPb9brhpwayNI9QlqqTlvDP6AH8CpXUfoVmxDczRNib2Ig
PGJvYkBwcm90b24ubWU+wooEExYIADwFAmP4pAAJkIdp9lyYAlNMFiEEzW5s1IvY
GXCwcJkZh2n2XJgCU0wCGwMCHgECGQECCwcCFQgCFgACIgEAAPmGAQDxysrSwxQO
27X/eg7xSE5JVXT7bt8cEZOE+iC2IDS02QEA2CvXnZJK4AOmPsFWKzn3HkFxCybc
CefzoJe0Pp4QNwPHcQRj+KQAEgorBgEEAZdVAQUBAQdArC6ijiQbE4ddGzqYHuq3
0rV05YYDP+5GtCecalGVizUX/woJzG7AoQ/hzzDi4rf+is90WDIIeHwAAP9JzVrf
QzMRicxCz1PbXNRW/OwKHg0X0bH3MA5A/j3mcBCrwngEGBYIACoFAmP4pAAJkIdp
9lyYAlNMFiEEzW5s1IvYGXCwcJkZh2n2XJgCU0wCG1AAAN0hAP9kJ/CQDBAwrVj5
92/mkV/4bEWAql/jEEfbBTAGHEb+5wD/ca5jm4FThIaGNO/mLtbkodfR0RTQ5usZ
Xvoo9PdnBQg=
=7A/f
-----END PGP PRIVATE KEY BLOCK-----`

const forwardedMessage = `-----BEGIN PGP MESSAGE-----

wV4Dwkk3ytpHrqASAQdAzPWbm24Uj6OYSDaauOuFMRPPLr5zWKXgvC1eHPD78ykw
YkvxNCwD6hfzjLoASVv9jhHJoXY+Pag6QHvoFuMn+hdG90yFh5HMFyileY/CTrT7
0kcBAPalcAq/OH/pBtIhGT/TKS88IIkz2aSukjbQRf+JNyh7bF+uXVDGmD8zOGa8
mM9TmGOf8Vi3sjgVAQ5rZQzh36HrBDloBA==
=PotS
-----END PGP MESSAGE-----`

const forwardedPlaintext = "Hello Bob, hello world"

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

	if bytes.Compare(dec, []byte(forwardedPlaintext)) != 0 {
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

	charlesEntity, proxyParam, err := bobEntity.NewForwardingEntity(keyConfig)
	if err != nil {
		t.Fatal(err)
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

	if bytes.Compare(dec, plaintext) != 0 {
		t.Fatal("decrypted does not match original")
	}

	// Forward message
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
			err = p.ProxyTransform(
				proxyParam,
				charlesEntity.Subkeys[0].PublicKey.KeyId,
				bobEntity.Subkeys[0].PublicKey.KeyId,
			)
			if err != nil {
				t.Fatalf("error transforming PKESK: %s", err)
			}

			splitPoint = bytesReader.Size() - int64(bytesReader.Len())

			err = p.Serialize(transformedEncryptedKey)
			if err != nil {
				t.Fatalf("error serializing transformed PKESK: %s", err)
			}
			break Loop
		}
	}

	transformed := transformedEncryptedKey.Bytes()
	transformed = append(transformed, encrypted[splitPoint:]...)

	// Decrypt forwarded message for Charles
	m, err = ReadMessage(bytes.NewBuffer(transformed), EntityList([]*Entity{charlesEntity}), nil /* no prompt */, nil)
	if err != nil {
		t.Fatal(err)
	}

	dec, err = ioutil.ReadAll(m.decrypted)

	if bytes.Compare(dec, plaintext) != 0 {
		t.Fatal("forwarded decrypted does not match original")
	}
}
