package v2

import (
	"bytes"
	"crypto"
	"crypto/dsa"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/ecdh"
	"github.com/ProtonMail/go-crypto/openpgp/ecdsa"
	"github.com/ProtonMail/go-crypto/openpgp/eddsa"
	"github.com/ProtonMail/go-crypto/openpgp/elgamal"
	"github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/internal/algorithm"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/go-crypto/openpgp/s2k"
	"github.com/ProtonMail/go-crypto/openpgp/symmetric"
)

var hashes = []crypto.Hash{
	crypto.SHA1,
	crypto.SHA224,
	crypto.SHA256,
	crypto.SHA384,
	crypto.SHA512,
	crypto.SHA3_256,
	crypto.SHA3_512,
}

var ciphers = []packet.CipherFunction{
	packet.Cipher3DES,
	packet.CipherCAST5,
	packet.CipherAES128,
	packet.CipherAES192,
	packet.CipherAES256,
}

var aeadModes = []packet.AEADMode{
	packet.AEADModeOCB,
	packet.AEADModeEAX,
	packet.AEADModeGCM,
}

var allowAllAlgorithmsConfig = packet.Config{
	RejectPublicKeyAlgorithms:   map[packet.PublicKeyAlgorithm]bool{},
	RejectCurves:                map[packet.Curve]bool{},
	RejectMessageHashAlgorithms: map[crypto.Hash]bool{},
	MinRSABits:                  512,
}

func TestKeyExpiry(t *testing.T) {
	kring, err := ReadKeyRing(readerFromHex(expiringKeyHex))
	if err != nil {
		t.Fatal(err)
	}
	entity := kring[0]

	const timeFormat = "2006-01-02"
	time1, _ := time.Parse(timeFormat, "2013-07-02")

	// The expiringKeyHex key is structured as:
	//
	// pub  1024R/5E237D8C  created: 2013-07-01                      expires: 2013-07-31  usage: SC
	// sub  1024R/1ABB25A0  created: 2013-07-01 23:11:07 +0200 CEST  expires: 2013-07-08  usage: E
	// sub  1024R/96A672F5  created: 2013-07-01 23:11:23 +0200 CEST  expires: 2013-07-31  usage: E
	//
	// So this should select the newest, non-expired encryption key.
	key, ok := entity.EncryptionKey(time1, nil)
	if !ok {
		t.Fatal("No encryption key found")
	}
	if id, expected := key.PublicKey.KeyIdShortString(), "CD3D39FF"; id != expected {
		t.Errorf("Expected key %s at time %s, but got key %s", expected, time1.Format(timeFormat), id)
	}

	// Once the first encryption subkey has expired, the second should be
	// selected.
	time2, _ := time.Parse(timeFormat, "2013-07-09")
	key, _ = entity.EncryptionKey(time2, nil)
	if id, expected := key.PublicKey.KeyIdShortString(), "CD3D39FF"; id != expected {
		t.Errorf("Expected key %s at time %s, but got key %s", expected, time2.Format(timeFormat), id)
	}

	// Once all the keys have expired, nothing should be returned.
	time3, _ := time.Parse(timeFormat, "2013-08-01")
	if key, ok := entity.EncryptionKey(time3, nil); ok {
		t.Errorf("Expected no key at time %s, but got key %s", time3.Format(timeFormat), key.PublicKey.KeyIdShortString())
	}
}

// https://tests.sequoia-pgp.org/#Certificate_expiration
// P _ U f
func TestExpiringPrimaryUIDKey(t *testing.T) {
	// P _ U f
	kring, err := ReadArmoredKeyRing(bytes.NewBufferString((expiringPrimaryUIDKey)))
	if err != nil {
		t.Fatal(err)
	}
	entity := kring[0]

	const timeFormat string = "2006-01-02"
	const expectedKeyID string = "015E7330"

	// Before the primary UID has expired, the primary key should be returned.
	time1, err := time.Parse(timeFormat, "2022-02-05")
	if err != nil {
		t.Fatal(err)
	}
	key, found := entity.SigningKey(time1, nil)
	if !found {
		t.Errorf("Signing subkey %s not found at time %s", expectedKeyID, time1.Format(timeFormat))
	} else if observedKeyID := key.PublicKey.KeyIdShortString(); observedKeyID != expectedKeyID {
		t.Errorf("Expected key %s at time %s, but got key %s", expectedKeyID, time1.Format(timeFormat), observedKeyID)
	}

	// After the primary UID has expired, nothing should be returned.
	time2, err := time.Parse(timeFormat, "2022-02-06")
	if err != nil {
		t.Fatal(err)
	}
	if key, ok := entity.SigningKey(time2, nil); ok {
		t.Errorf("Expected no key at time %s, but got key %s", time2.Format(timeFormat), key.PublicKey.KeyIdShortString())
	}
}

func TestReturnFirstUnexpiredSigningSubkey(t *testing.T) {
	// Make a master key.
	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	// First signing subkey does not expire.
	err = entity.AddSigningSubkey(nil)
	if err != nil {
		t.Fatal(err)
	}
	// Get the first signing subkey (added after the default encryption subkey).
	subkey1 := entity.Subkeys[1]

	// Second signing subkey expires in a day.
	err = entity.AddSigningSubkey(&packet.Config{
		KeyLifetimeSecs: 24 * 60 * 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Get the second signing subkey.
	subkey2 := entity.Subkeys[2]

	// Before second signing subkey has expired, it should be returned.
	time1 := time.Now()
	expected := subkey2.PublicKey.KeyIdShortString()
	subkey, found := entity.SigningKey(time1, nil)
	if !found {
		t.Errorf("Signing subkey %s not found at time %s", expected, time1.Format(time.UnixDate))
	}
	observed := subkey.PublicKey.KeyIdShortString()
	if observed != expected {
		t.Errorf("Expected key %s at time %s, but got key %s", expected, time1.Format(time.UnixDate), observed)
	}

	// After the second signing subkey has expired, the first one should be returned.
	time2 := time1.AddDate(0, 0, 2)
	expected = subkey1.PublicKey.KeyIdShortString()
	subkey, found = entity.SigningKey(time2, nil)
	if !found {
		t.Errorf("Signing subkey %s not found at time %s", expected, time2.Format(time.UnixDate))
	}
	observed = subkey.PublicKey.KeyIdShortString()
	if observed != expected {
		t.Errorf("Expected key %s at time %s, but got key %s", expected, time2.Format(time.UnixDate), observed)
	}
}

func TestSignatureExpiry(t *testing.T) {
	// Make a master key, and attach it to a keyring.
	var keyring EntityList
	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	keyring = append(keyring, entity)

	// Make a signature that never expires.
	var signatureWriter1 bytes.Buffer
	const input string = "Hello, world!"
	message := strings.NewReader(input)
	err = ArmoredDetachSign(&signatureWriter1, []*Entity{entity}, message, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Make a signature that expires in a day.
	var signatureWriter2 bytes.Buffer
	message = strings.NewReader(input)
	err = ArmoredDetachSign(&signatureWriter2, []*Entity{entity}, message, &SignParams{
		Config: &packet.Config{
			SigLifetimeSecs: 24 * 60 * 60,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Make a time that is day after tomorrow.
	futureTime := func() time.Time {
		return time.Now().AddDate(0, 0, 2)
	}

	// Make a signature that was created in the future.
	var signatureWriter3 bytes.Buffer
	message = strings.NewReader(input)
	err = ArmoredDetachSign(&signatureWriter3, []*Entity{entity}, message, &SignParams{
		Config: &packet.Config{
			Time: futureTime,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Check that the first signature has not expired day after tomorrow.
	message = strings.NewReader(input)
	signatureReader1 := strings.NewReader(signatureWriter1.String())
	_, _, err = VerifyArmoredDetachedSignature(keyring, message, signatureReader1, &packet.Config{
		Time: futureTime,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Check that the second signature has expired day after tomorrow.
	message = strings.NewReader(input)
	signatureReader2 := strings.NewReader(signatureWriter2.String())
	const expectedErr string = "openpgp: signature expired"
	_, _, observedErr := VerifyArmoredDetachedSignature(keyring, message, signatureReader2, &packet.Config{
		Time: futureTime,
	})
	if observedErr.Error() != expectedErr {
		t.Errorf("Expected error '%s', but got error '%s'", expectedErr, observedErr)
	}

	// Check that the third signature is also considered expired even now.
	message = strings.NewReader(input)
	signatureReader3 := strings.NewReader(signatureWriter3.String())
	_, _, observedErr = VerifyArmoredDetachedSignature(keyring, message, signatureReader3, nil)
	if observedErr.Error() != expectedErr {
		t.Errorf("Expected error '%s', but got error '%s'", expectedErr, observedErr)
	}
}

func TestMissingCrossSignature(t *testing.T) {
	// This public key has a signing subkey, but the subkey does not
	// contain a cross-signature.
	keys, _ := ReadArmoredKeyRing(bytes.NewBufferString(missingCrossSignatureKey))
	var config *packet.Config
	_, err := keys[0].Subkeys[0].Verify(config.Now())
	if err == nil {
		t.Fatal("Failed to detect error in keyring with missing cross signature")
	}
	structural, ok := err.(errors.StructuralError)
	if !ok {
		t.Fatalf("Unexpected class of error: %T. Wanted StructuralError", err)
	}
	const expectedMsg = "no valid binding signature found for subkey"
	if !strings.Contains(string(structural), expectedMsg) {
		t.Fatalf("Unexpected error: %q. Expected it to contain %q", err, expectedMsg)
	}
}

func TestInvalidCrossSignature(t *testing.T) {
	// This public key has a signing subkey, and the subkey has an
	// embedded cross-signature. However, the cross-signature does
	// not correctly validate over the primary and subkey.
	keys, _ := ReadArmoredKeyRing(bytes.NewBufferString(invalidCrossSignatureKey))
	var config *packet.Config
	_, err := keys[0].Subkeys[0].Verify(config.Now())
	if err == nil {
		t.Fatal("Failed to detect error in keyring with an invalid cross signature")
	}
	structural, ok := err.(errors.StructuralError)
	if !ok {
		t.Fatalf("Unexpected class of error: %T. Wanted StructuralError", err)
	}
	const expectedMsg = "no valid binding signature found for subkey"
	if !strings.Contains(string(structural), expectedMsg) {
		t.Fatalf("Unexpected error: %q. Expected it to contain %q", err, expectedMsg)
	}
}

func TestGoodCrossSignature(t *testing.T) {
	// This public key has a signing subkey, and the subkey has an
	// embedded cross-signature which correctly validates over the
	// primary and subkey.
	keys, err := ReadArmoredKeyRing(bytes.NewBufferString(goodCrossSignatureKey))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Errorf("Failed to accept key with good cross signature, %d", len(keys))
	}
	if len(keys[0].Subkeys) != 1 {
		t.Errorf("Failed to accept good subkey, %d", len(keys[0].Subkeys))
	}
}

func TestRevokedUserID(t *testing.T) {
	// This key contains 2 UIDs, one of which is revoked and has no valid self-signature:
	// [ultimate] (1)  Golang Gopher <no-reply@golang.com>
	// [ revoked] (2)  Golang Gopher <revoked@golang.com>
	keys, err := ReadArmoredKeyRing(bytes.NewBufferString(revokedUserIDKey))
	if err != nil {
		t.Fatal(err)
	}

	if len(keys) != 1 {
		t.Fatal("Failed to read key with a revoked user id")
	}

	identities := keys[0].Identities

	if numIdentities, numExpected := len(identities), 2; numIdentities != numExpected {
		t.Errorf("obtained %d identities, expected %d", numIdentities, numExpected)
	}

	firstIdentity, found := identities["Golang Gopher <no-reply@golang.com>"]
	if !found {
		t.Errorf("missing first identity")
	}

	secondIdentity, found := identities["Golang Gopher <revoked@golang.com>"]
	if !found {
		t.Errorf("missing second identity")
	}

	if firstIdentity.Revoked(nil, time.Now()) {
		t.Errorf("expected first identity not to be revoked")
	}

	if !secondIdentity.Revoked(nil, time.Now()) {
		t.Errorf("expected second identity to be revoked")
	}

	const timeFormat = "2006-01-02"
	time1, _ := time.Parse(timeFormat, "2020-01-01")

	if _, found := keys[0].SigningKey(time1, nil); !found {
		t.Errorf("Expected SigningKey to return a signing key when one User IDs is revoked")
	}

	if _, found := keys[0].EncryptionKey(time1, nil); !found {
		t.Errorf("Expected EncryptionKey to return an encryption key when one User IDs is revoked")
	}
}

func TestFirstUserIDRevoked(t *testing.T) {
	// Same test as above, but with the User IDs reversed:
	// [ revoked] (1)  Golang Gopher <revoked@golang.com>
	// [ultimate] (2)  Golang Gopher <no-reply@golang.com>
	keys, err := ReadArmoredKeyRing(bytes.NewBufferString(keyWithFirstUserIDRevoked))
	if err != nil {
		t.Fatal(err)
	}

	if len(keys) != 1 {
		t.Fatal("Failed to read key with a revoked user id")
	}

	identities := keys[0].Identities

	if numIdentities, numExpected := len(identities), 2; numIdentities != numExpected {
		t.Errorf("obtained %d identities, expected %d", numIdentities, numExpected)
	}

	firstIdentity, found := identities["Golang Gopher <revoked@golang.com>"]
	if !found {
		t.Errorf("missing first identity")
	}

	secondIdentity, found := identities["Golang Gopher <no-reply@golang.com>"]
	if !found {
		t.Errorf("missing second identity")
	}

	if !firstIdentity.Revoked(nil, time.Now()) {
		t.Errorf("expected first identity to be revoked")
	}

	if secondIdentity.Revoked(nil, time.Now()) {
		t.Errorf("expected second identity not to be revoked")
	}

	const timeFormat = "2006-01-02"
	time1, _ := time.Parse(timeFormat, "2020-01-01")

	if _, found := keys[0].SigningKey(time1, nil); !found {
		t.Errorf("Expected SigningKey to return a signing key when first User IDs is revoked")
	}

	if _, found := keys[0].EncryptionKey(time1, nil); !found {
		t.Errorf("Expected EncryptionKey to return an encryption key when first User IDs is revoked")
	}
}

func TestOnlyUserIDRevoked(t *testing.T) {
	// This key contains 1 UID which is revoked (but also has a self-signature)
	keys, err := ReadArmoredKeyRing(bytes.NewBufferString(keyWithOnlyUserIDRevoked))
	if err != nil {
		t.Fatal(err)
	}

	if len(keys) != 1 {
		t.Fatal("Failed to read key with a revoked user id")
	}

	identities := keys[0].Identities

	if numIdentities, numExpected := len(identities), 1; numIdentities != numExpected {
		t.Errorf("obtained %d identities, expected %d", numIdentities, numExpected)
	}

	identity, found := identities["Revoked Primary User ID <revoked@key.com>"]
	if !found {
		t.Errorf("missing identity")
	}

	if !identity.Revoked(nil, time.Now()) {
		t.Errorf("expected identity to be revoked")
	}

	if _, found := keys[0].SigningKey(time.Now(), nil); found {
		t.Errorf("Expected SigningKey not to return a signing key when the only User IDs is revoked")
	}

	if _, found := keys[0].EncryptionKey(time.Now(), nil); found {
		t.Errorf("Expected EncryptionKey not to return an encryption key when the only User IDs is revoked")
	}
}

func TestDummyPrivateKey(t *testing.T) {
	// This public key has a signing subkey, but has a dummy placeholder
	// instead of the real private key. It's used in scenarios where the
	// main private key is withheld and only signing is allowed (e.g. build
	// servers).
	keys, err := ReadArmoredKeyRing(bytes.NewBufferString(onlySubkeyNoPrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Errorf("Failed to accept key with dummy private key, %d", len(keys))
	}
	if !keys[0].PrivateKey.Dummy() {
		t.Errorf("Primary private key should be marked as a dummy key")
	}
	if len(keys[0].Subkeys) != 1 {
		t.Errorf("Failed to accept good subkey, %d", len(keys[0].Subkeys))
	}

	// Test serialization of stub private key via entity.SerializePrivate().
	var buf bytes.Buffer
	w, err := armor.EncodeWithChecksumOption(&buf, PrivateKeyType, nil, false)
	if err != nil {
		t.Errorf("Failed top initialise armored key writer")
	}
	err = keys[0].SerializePrivateWithoutSigning(w, nil)
	if err != nil {
		t.Errorf("Failed to serialize entity")
	}
	if w.Close() != nil {
		t.Errorf("Failed to close writer for armored key")
	}

	keys, err = ReadArmoredKeyRing(bytes.NewBufferString(buf.String()))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Errorf("Failed to accept key with dummy private key, %d", len(keys))
	}
	if !keys[0].PrivateKey.Dummy() {
		t.Errorf("Primary private key should be marked as a dummy key after serialisation")
	}
	if len(keys[0].Subkeys) != 1 {
		t.Errorf("Failed to accept good subkey, %d", len(keys[0].Subkeys))
	}
}

// TestExternallyRevokableKey attempts to load and parse a key with a third party revocation permission.
func TestExternallyRevocableKey(t *testing.T) {
	kring, err := ReadKeyRing(readerFromHex(subkeyUsageHex))
	if err != nil {
		t.Fatal(err)
	}

	// The 0xA42704B92866382A key can be revoked by 0xBE3893CB843D0FE70C
	// according to this signature that appears within the key:
	// :signature packet: algo 1, keyid A42704B92866382A
	//    version 4, created 1396409682, md5len 0, sigclass 0x1f
	//    digest algo 2, begin of digest a9 84
	//    hashed subpkt 2 len 4 (sig created 2014-04-02)
	//    hashed subpkt 12 len 22 (revocation key: c=80 a=1 f=CE094AA433F7040BB2DDF0BE3893CB843D0FE70C)
	//    hashed subpkt 7 len 1 (not revocable)
	//    subpkt 16 len 8 (issuer key ID A42704B92866382A)
	//    data: [1024 bits]

	id := uint64(0xA42704B92866382A)
	keys := kring.KeysById(id)
	if len(keys) != 1 {
		t.Errorf("Expected to find key id %X, but got %d matches", id, len(keys))
	}
}

func TestKeyRevocation(t *testing.T) {
	kring, err := ReadKeyRing(readerFromHex(revokedKeyHex))
	if err != nil {
		t.Fatal(err)
	}

	if len(kring) != 1 {
		t.Fatal("Failed to read key with a sub key")
	}

	// revokedKeyHex contains these keys:
	// pub   1024R/9A34F7C0 2014-03-25 [revoked: 2014-03-25]
	// sub   1024R/1BA3CD60 2014-03-25 [revoked: 2014-03-25]
	ids := []uint64{0xA401D9F09A34F7C0, 0x5CD3BE0A1BA3CD60}

	for _, id := range ids {
		keys := kring.KeysById(id)
		if len(keys) != 1 {
			t.Errorf("Expected KeysById to find revoked key %X, but got %d matches", id, len(keys))
		}
	}

	signingkey, found := kring[0].SigningKey(time.Now(), nil)
	if found {
		t.Errorf("Expected SigningKey not to return a signing key for a revoked key, got %X", signingkey.PublicKey.KeyId)
	}

	encryptionkey, found := kring[0].EncryptionKey(time.Now(), nil)
	if found {
		t.Errorf("Expected EncryptionKey not to return an encryption key for a revoked key, got %X", encryptionkey.PublicKey.KeyId)
	}
}

func TestKeyWithRevokedSubKey(t *testing.T) {
	// This key contains a revoked sub key:
	//  pub   rsa1024/0x4CBD826C39074E38 2018-06-14 [SC]
	//        Key fingerprint = 3F95 169F 3FFA 7D3F 2B47  6F0C 4CBD 826C 3907 4E38
	//  uid   Golang Gopher <no-reply@golang.com>
	//  sub   rsa1024/0x945DB1AF61D85727 2018-06-14 [S] [revoked: 2018-06-14]

	keys, err := ReadArmoredKeyRing(bytes.NewBufferString(keyWithSubKey))
	if err != nil {
		t.Fatal(err)
	}

	if len(keys) != 1 {
		t.Fatal("Failed to read key with a sub key")
	}

	identity := keys[0].Identities["Golang Gopher <no-reply@golang.com>"]
	// Test for an issue where Subkey Binding Signatures (RFC 4880 5.2.1) were added to the identity
	// preceding the Subkey Packet if the Subkey Packet was followed by more than one signature.
	// For example, the current key has the following layout:
	//    PUBKEY UID SELFSIG SUBKEY REV SELFSIG
	// The last SELFSIG would be added to the UID's signatures. This is wrong.
	if numSigs, numExpected := len(identity.SelfCertifications), 1; numSigs != numExpected {
		t.Fatalf("got %d signatures, expected %d", numSigs, numExpected)
	}

	if numSubKeys, numExpected := len(keys[0].Subkeys), 1; numSubKeys != numExpected {
		t.Fatalf("got %d subkeys, expected %d", numSubKeys, numExpected)
	}

	subKey := keys[0].Subkeys[0]
	if len(subKey.Bindings) == 0 {
		t.Fatalf("no binding subkey signature")
	}

}

func TestSubkeyRevocation(t *testing.T) {
	kring, err := ReadKeyRing(readerFromHex(revokedSubkeyHex))
	if err != nil {
		t.Fatal(err)
	}

	if len(kring) != 1 {
		t.Fatal("Failed to read key with a sub key")
	}

	// revokedSubkeyHex contains these keys:
	// pub   1024R/4EF7E4BECCDE97F0 2014-03-25
	// sub   1024R/D63636E2B96AE423 2014-03-25
	// sub   1024D/DBCE4EE19529437F 2014-03-25
	// sub   1024R/677815E371C2FD23 2014-03-25 [revoked: 2014-03-25]
	validKeys := []uint64{0x4EF7E4BECCDE97F0, 0xD63636E2B96AE423, 0xDBCE4EE19529437F}
	encryptionKey := uint64(0xD63636E2B96AE423)
	revokedKey := uint64(0x677815E371C2FD23)

	for _, id := range validKeys {
		keys := kring.KeysById(id)
		if len(keys) != 1 {
			t.Errorf("Expected KeysById to find key %X, but got %d matches", id, len(keys))
		}
		if id == encryptionKey {
			key, found := kring[0].EncryptionKey(time.Now(), &allowAllAlgorithmsConfig)
			if !found || key.PublicKey.KeyId != id {
				t.Errorf("Expected EncryptionKey to find key %X", id)
			}
		} else {
			_, found := kring[0].SigningKeyById(time.Now(), id, &allowAllAlgorithmsConfig)
			if !found {
				t.Errorf("Expected SigningKeyById to find key %X", id)
			}
		}
	}

	keys := kring.KeysById(revokedKey)
	if len(keys) != 1 {
		t.Errorf("Expected KeysById to find key %X, but got %d matches", revokedKey, len(keys))
	}

	signingkey, found := kring[0].SigningKeyById(time.Now(), revokedKey, nil)
	if found {
		t.Errorf("Expected SigningKeyById not to return an encryption key for a revoked key, got %X", signingkey.PublicKey.KeyId)
	}
}

func TestKeyWithSubKeyAndBadSelfSigOrder(t *testing.T) {
	// This key was altered so that the self signatures following the
	// subkey are in a sub-optimal order.
	//
	// Note: Should someone have to create a similar key again, look into
	//       gpgsplit, gpg --dearmor, and gpg --enarmor.
	//
	// The packet ordering is the following:
	//    PUBKEY UID UIDSELFSIG SUBKEY SELFSIG1 SELFSIG2
	//
	// Where:
	//    SELFSIG1 expires on 2018-06-14 and was created first
	//    SELFSIG2 does not expire and was created after SELFSIG1
	//
	// Test for RFC 4880 5.2.3.3:
	// > An implementation that encounters multiple self-signatures on the
	// > same object may resolve the ambiguity in any way it sees fit, but it
	// > is RECOMMENDED that priority be given to the most recent self-
	// > signature.
	//
	// This means that we should keep SELFSIG2.

	keys, err := ReadArmoredKeyRing(bytes.NewBufferString(keyWithSubKeyAndBadSelfSigOrder))
	if err != nil {
		t.Fatal(err)
	}

	if len(keys) != 1 {
		t.Fatal("Failed to read key with a sub key and a bad selfsig packet order")
	}

	key := keys[0]

	if numKeys, expected := len(key.Subkeys), 1; numKeys != expected {
		t.Fatalf("Read %d subkeys, expected %d", numKeys, expected)
	}

	subKey := key.Subkeys[0]
	var zeroTime time.Time
	selfSig, err := subKey.LatestValidBindingSignature(zeroTime)
	if err != nil {
		t.Fatal("expected a self signature to be found")
	}
	if lifetime := selfSig.KeyLifetimeSecs; lifetime != nil {
		t.Errorf("The signature has a key lifetime (%d), but it should be nil", *lifetime)
	}

}

func TestIdVerification(t *testing.T) {
	kring, err := ReadKeyRing(readerFromHex(testKeys1And2PrivateHex))
	if err != nil {
		t.Fatal(err)
	}
	if err := kring[1].PrivateKey.Decrypt([]byte("passphrase")); err != nil {
		t.Fatal(err)
	}

	const signedIdentity = "Test Key 1 (RSA)"
	const signerIdentity = "Test Key 2 (RSA, encrypted private key)"
	config := allowAllAlgorithmsConfig
	config.SigLifetimeSecs = 128
	config.SigningIdentity = signerIdentity
	if err := kring[0].SignIdentity(signedIdentity, kring[1], &config); err != nil {
		t.Fatal(err)
	}

	ident, ok := kring[0].Identities[signedIdentity]
	if !ok {
		t.Fatal("signed identity missing from key after signing")
	}

	checked := false
	for _, sig := range ident.OtherCertifications {
		if sig.Packet.IssuerKeyId == nil || *sig.Packet.IssuerKeyId != kring[1].PrimaryKey.KeyId {
			continue
		}

		if err := kring[1].PrimaryKey.VerifyUserIdSignature(signedIdentity, kring[0].PrimaryKey, sig.Packet); err != nil {
			t.Fatalf("error verifying new identity signature: %s", err)
		}

		if sig.Packet.SignerUserId == nil || *sig.Packet.SignerUserId != signerIdentity {
			t.Fatalf("wrong or nil signer identity")
		}

		if sig.Packet.SigExpired(time.Now()) {
			t.Fatalf("signature is expired")
		}

		if !sig.Packet.SigExpired(time.Now().Add(129 * time.Second)) {
			t.Fatalf("signature has invalid expiration")
		}

		checked = true
		break
	}

	if !checked {
		t.Fatal("didn't find identity signature in Entity")
	}
}

func TestNewEntityWithDefaultHash(t *testing.T) {
	for _, hash := range hashes {
		c := &packet.Config{
			DefaultHash: hash,
			Algorithm:   packet.PubKeyAlgoEdDSA,
		}
		entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", c)
		if hash == crypto.SHA1 {
			if err == nil {
				t.Fatal("should fail on SHA1 key creation")
			}
			continue
		}

		if err != nil {
			t.Fatal(err)
		}

		for _, identity := range entity.Identities {
			var zeroTime time.Time
			selfSig, err := identity.LatestValidSelfCertification(zeroTime)
			if err != nil {
				t.Fatal("expected a self signature to be found ")
			}
			prefs := selfSig.PreferredHash
			if len(prefs) == 0 {
				t.Fatal("didn't find a preferred hash list in self signature")
			}
			ph := hashToHashId(c.DefaultHash)
			if c.DefaultHash != crypto.SHA224 && prefs[0] != ph {
				t.Fatalf("Expected preferred hash to be %d, got %d", ph, prefs[0])
			}
		}
	}
}

func TestNewEntityNilConfigPreferredHash(t *testing.T) {
	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, identity := range entity.Identities {
		var zeroTime time.Time
		selfSig, err := identity.LatestValidSelfCertification(zeroTime)
		if err != nil {
			t.Fatal("expected a self signature to be found ")
		}
		prefs := selfSig.PreferredHash
		if len(prefs) != 1 {
			t.Fatal("expected preferred hashes list to be [SHA256]")
		}
	}
}

func TestNewEntityCorrectName(t *testing.T) {
	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(entity.Identities) != 1 {
		t.Fatalf("len(entity.Identities) = %d, want 1", len(entity.Identities))
	}
	var got string
	for _, i := range entity.Identities {
		got = i.Name
	}
	want := "Golang Gopher (Test Key) <no-reply@golang.com>"
	if got != want {
		t.Fatalf("Identity.Name = %q, want %q", got, want)
	}
}

func TestNewEntityWithDefaultCipher(t *testing.T) {
	for _, cipher := range ciphers {
		c := &packet.Config{
			DefaultCipher: cipher,
		}
		entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", c)
		if err != nil {
			t.Fatal(err)
		}

		for _, identity := range entity.Identities {
			var zeroTime time.Time
			selfSig, err := identity.LatestValidSelfCertification(zeroTime)
			if err != nil {
				t.Fatal("expected a self signature to be found ")
			}
			prefs := selfSig.PreferredSymmetric
			if len(prefs) == 0 {
				t.Fatal("didn't find a preferred cipher list")
			}
			if prefs[0] != uint8(c.DefaultCipher) {
				t.Fatalf("Expected preferred cipher to be %d, got %d", uint8(c.DefaultCipher), prefs[0])
			}
		}
	}
}

func TestNewEntityNilConfigPreferredSymmetric(t *testing.T) {
	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, identity := range entity.Identities {
		var zeroTime time.Time
		selfSig, err := identity.LatestValidSelfCertification(zeroTime)
		if err != nil {
			t.Fatal("expected a self signature to be found ")
		}
		prefs := selfSig.PreferredSymmetric
		if len(prefs) != 1 || prefs[0] != algorithm.AES128.Id() {
			t.Fatal("expected preferred ciphers list to be [AES128]")
		}
	}
}

func TestNewEntityWithDefaultAead(t *testing.T) {
	for _, aeadMode := range aeadModes {
		cfg := &packet.Config{
			AEADConfig: &packet.AEADConfig{
				DefaultMode: aeadMode,
			},
		}
		entity, err := NewEntity("Botvinnik", "1.e4", "tal@chess.com", cfg)
		if err != nil {
			t.Fatal(err)
		}

		for _, identity := range entity.Identities {
			var zeroTime time.Time
			selfSig, err := identity.LatestValidSelfCertification(zeroTime)
			if err != nil {
				t.Fatal("expected a self signature to be found ")
			}
			if len(selfSig.PreferredCipherSuites) == 0 {
				t.Fatal("didn't find a preferred mode in self signature")
			}
			cipher := selfSig.PreferredCipherSuites[0][0]
			if cipher != uint8(cfg.Cipher()) {
				t.Fatalf("Expected preferred cipher to be %d, got %d",
					uint8(cfg.Cipher()),
					selfSig.PreferredCipherSuites[0][0])
			}
			mode := selfSig.PreferredCipherSuites[0][1]
			if mode != uint8(cfg.AEAD().DefaultMode) {
				t.Fatalf("Expected preferred mode to be %d, got %d",
					uint8(cfg.AEAD().DefaultMode),
					selfSig.PreferredCipherSuites[0][1])
			}
		}
	}
}

func TestNewEntityPublicSerialization(t *testing.T) {
	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	serializedEntity := bytes.NewBuffer(nil)
	err = entity.Serialize(serializedEntity)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ReadEntity(packet.NewReader(bytes.NewBuffer(serializedEntity.Bytes())))
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewEntityPrivateSerialization(t *testing.T) {
	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	serializedEntity := bytes.NewBuffer(nil)
	err = entity.SerializePrivateWithoutSigning(serializedEntity, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ReadEntity(packet.NewReader(bytes.NewBuffer(serializedEntity.Bytes())))
	if err != nil {
		t.Fatal(err)
	}
}

func TestNotationPacket(t *testing.T) {
	keys, err := ReadArmoredKeyRing(bytes.NewBufferString(keyWithNotation))
	if err != nil {
		t.Fatal(err)
	}

	assertNotationPackets(t, keys)

	serializedEntity := bytes.NewBuffer(nil)
	err = keys[0].SerializePrivate(serializedEntity, nil)
	if err != nil {
		t.Fatal(err)
	}

	keys, err = ReadKeyRing(serializedEntity)
	if err != nil {
		t.Fatal(err)
	}

	assertNotationPackets(t, keys)
}

func assertNotationPackets(t *testing.T, keys EntityList) {
	if len(keys) != 1 {
		t.Errorf("Failed to accept key, %d", len(keys))
	}

	identity := keys[0].Identities["Test <test@example.com>"]

	if numSigs, numExpected := len(identity.SelfCertifications), 1; numSigs != numExpected {
		t.Fatalf("got %d signatures, expected %d", numSigs, numExpected)
	}

	notations := identity.SelfCertifications[0].Packet.Notations
	if numNotations, numExpected := len(notations), 2; numNotations != numExpected {
		t.Fatalf("got %d Notation Data subpackets, expected %d", numNotations, numExpected)
	}

	if notations[0].IsHumanReadable != true {
		t.Fatalf("got false, expected true")
	}

	if notations[0].Name != "text@example.com" {
		t.Fatalf("got %s, expected text@example.com", notations[0].Name)
	}

	if string(notations[0].Value) != "test" {
		t.Fatalf("got %s, expected \"test\"", string(notations[0].Value))
	}

	if notations[1].IsHumanReadable != false {
		t.Fatalf("got true, expected false")
	}

	if notations[1].Name != "binary@example.com" {
		t.Fatalf("got %s, expected binary@example.com", notations[1].Name)
	}

	if !bytes.Equal(notations[1].Value, []byte{0, 1, 2, 3}) {
		t.Fatalf("got %s, expected {0, 1, 2, 3}", string(notations[1].Value))
	}
}

func TestEntityPrivateSerialization(t *testing.T) {
	keys, err := ReadArmoredKeyRing(bytes.NewBufferString(armoredPrivateKeyBlock))
	if err != nil {
		t.Fatal(err)
	}

	for _, entity := range keys {
		serializedEntity := bytes.NewBuffer(nil)
		err = entity.SerializePrivateWithoutSigning(serializedEntity, nil)
		if err != nil {
			t.Fatal(err)
		}

		_, err := ReadEntity(packet.NewReader(bytes.NewBuffer(serializedEntity.Bytes())))
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestAddUserId(t *testing.T) {
	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	err = entity.AddUserId("Golang Gopher", "Test Key", "add1---@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	err = entity.AddUserId("Golang Gopher", "Test Key", "add2---@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	ignore_err := entity.AddUserId("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if ignore_err == nil {
		t.Fatal(err)
	}

	if len(entity.Identities) != 3 {
		t.Fatalf("Expected 3 id, got %d", len(entity.Identities))
	}

	for _, sk := range entity.Identities {
		var zeroTime time.Time
		selfSig, err := sk.LatestValidSelfCertification(zeroTime)
		if err != nil {
			t.Fatal("expected a self signature to be found")
		}
		err = entity.PrimaryKey.VerifyUserIdSignature(sk.UserId.Id, entity.PrimaryKey, selfSig)
		if err != nil {
			t.Errorf("Invalid subkey signature: %v", err)
		}
	}

	serializedEntity := bytes.NewBuffer(nil)
	if err := entity.SerializePrivate(serializedEntity, nil); err != nil {
		t.Fatal(err)
	}

	_, err = ReadEntity(packet.NewReader(bytes.NewBuffer(serializedEntity.Bytes())))
	if err != nil {
		t.Fatal(err)
	}
}
func TestAddSubkey(t *testing.T) {
	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	err = entity.AddSigningSubkey(nil)
	if err != nil {
		t.Fatal(err)
	}

	err = entity.AddEncryptionSubkey(nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(entity.Subkeys) != 3 {
		t.Fatalf("Expected 3 subkeys, got %d", len(entity.Subkeys))
	}

	for _, sk := range entity.Subkeys {
		var zeroTime time.Time
		selfSig, err := sk.LatestValidBindingSignature(zeroTime)
		if err != nil {
			t.Fatal("expected a self signature to be found")
		}
		err = entity.PrimaryKey.VerifyKeySignature(sk.PublicKey, selfSig)
		if err != nil {
			t.Errorf("Invalid subkey signature: %v", err)
		}
	}

	serializedEntity := bytes.NewBuffer(nil)
	if err := entity.SerializePrivate(serializedEntity, nil); err != nil {
		t.Fatal(err)
	}

	_, err = ReadEntity(packet.NewReader(bytes.NewBuffer(serializedEntity.Bytes())))
	if err != nil {
		t.Fatal(err)
	}
}

func TestAddSubkeySerialized(t *testing.T) {
	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	err = entity.AddSigningSubkey(nil)
	if err != nil {
		t.Fatal(err)
	}

	err = entity.AddEncryptionSubkey(nil)
	if err != nil {
		t.Fatal(err)
	}

	serializedEntity := bytes.NewBuffer(nil)
	if err := entity.SerializePrivateWithoutSigning(serializedEntity, nil); err != nil {
		t.Fatal(err)
	}

	entity, err = ReadEntity(packet.NewReader(bytes.NewBuffer(serializedEntity.Bytes())))
	if err != nil {
		t.Fatal(err)
	}

	if len(entity.Subkeys) != 3 {
		t.Fatalf("Expected 3 subkeys, got %d", len(entity.Subkeys))
	}

	for _, sk := range entity.Subkeys {
		var zeroTime time.Time
		selfSig, err := sk.LatestValidBindingSignature(zeroTime)
		if err != nil {
			t.Fatal("expected a self signature to be found")
		}
		err = entity.PrimaryKey.VerifyKeySignature(sk.PublicKey, selfSig)
		if err != nil {
			t.Errorf("Invalid subkey signature: %v", err)
		}
	}
}

func TestAddSubkeyWithConfig(t *testing.T) {
	c := &packet.Config{
		DefaultHash: crypto.SHA512,
		Algorithm:   packet.PubKeyAlgoEdDSA,
	}
	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	err = entity.AddSigningSubkey(c)
	if err != nil {
		t.Fatal(err)
	}

	err = entity.AddEncryptionSubkey(c)
	if err != nil {
		t.Fatal(err)
	}

	if len(entity.Subkeys) != 3 {
		t.Fatalf("Expected 3 subkeys, got %d", len(entity.Subkeys))
	}

	if entity.Subkeys[1].PublicKey.PubKeyAlgo != packet.PubKeyAlgoEdDSA {
		t.Fatalf("Expected subkey algorithm: %v, got: %v", packet.PubKeyAlgoEdDSA,
			entity.Subkeys[1].PublicKey.PubKeyAlgo)
	}

	if entity.Subkeys[2].PublicKey.PubKeyAlgo != packet.PubKeyAlgoECDH {
		t.Fatalf("Expected subkey algorithm: %v, got: %v", packet.PubKeyAlgoECDH,
			entity.Subkeys[2].PublicKey.PubKeyAlgo)
	}

	var zeroTime time.Time
	selfSig1, err := entity.Subkeys[1].LatestValidBindingSignature(zeroTime)
	if err != nil {
		t.Fatal("expected a self signature to be found")
	}
	if selfSig1.Hash != c.DefaultHash {
		t.Fatalf("Expected subkey hash method: %v, got: %v", c.DefaultHash,
			selfSig1.Hash)
	}
	if selfSig1.EmbeddedSignature.Hash != c.DefaultHash {
		t.Fatalf("Expected subkey hash method: %v, got: %v", c.DefaultHash,
			selfSig1.EmbeddedSignature.Hash)
	}
	err = entity.PrimaryKey.VerifyKeySignature(entity.Subkeys[1].PublicKey, selfSig1)
	if err != nil {
		t.Errorf("Invalid subkey signature: %v", err)
	}

	selfSig2, err := entity.Subkeys[2].LatestValidBindingSignature(zeroTime)
	if err != nil {
		t.Fatal("expected a self signature to be found")
	}
	if selfSig2.Hash != c.DefaultHash {
		t.Fatalf("Expected subkey hash method: %v, got: %v", c.DefaultHash,
			selfSig2.Hash)
	}
	err = entity.PrimaryKey.VerifyKeySignature(entity.Subkeys[2].PublicKey, selfSig2)
	if err != nil {
		t.Errorf("Invalid subkey signature: %v", err)
	}

	serializedEntity := bytes.NewBuffer(nil)
	if err := entity.SerializePrivate(serializedEntity, nil); err != nil {
		t.Fatal(err)
	}

	_, err = ReadEntity(packet.NewReader(bytes.NewBuffer(serializedEntity.Bytes())))
	if err != nil {
		t.Fatal(err)
	}
}

func TestAddSubkeyWithConfigSerialized(t *testing.T) {
	c := &packet.Config{
		DefaultHash: crypto.SHA512,
		Algorithm:   packet.PubKeyAlgoEdDSA,
	}
	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	err = entity.AddSigningSubkey(c)
	if err != nil {
		t.Fatal(err)
	}

	err = entity.AddEncryptionSubkey(c)
	if err != nil {
		t.Fatal(err)
	}

	serializedEntity := bytes.NewBuffer(nil)
	if err := entity.SerializePrivateWithoutSigning(serializedEntity, nil); err != nil {
		t.Fatal(err)
	}

	entity, err = ReadEntity(packet.NewReader(bytes.NewBuffer(serializedEntity.Bytes())))
	if err != nil {
		t.Fatal(err)
	}

	if len(entity.Subkeys) != 3 {
		t.Fatalf("Expected 3 subkeys, got %d", len(entity.Subkeys))
	}

	var zeroTime time.Time
	selfSig1, err := entity.Subkeys[1].LatestValidBindingSignature(zeroTime)
	if err != nil {
		t.Fatal("expected a self signature to be found")
	}
	if entity.Subkeys[1].PublicKey.PubKeyAlgo != packet.PubKeyAlgoEdDSA {
		t.Fatalf("Expected subkey algorithm: %v, got: %v", packet.PubKeyAlgoEdDSA,
			entity.Subkeys[1].PublicKey.PubKeyAlgo)
	}

	if entity.Subkeys[2].PublicKey.PubKeyAlgo != packet.PubKeyAlgoECDH {
		t.Fatalf("Expected subkey algorithm: %v, got: %v", packet.PubKeyAlgoECDH,
			entity.Subkeys[2].PublicKey.PubKeyAlgo)
	}

	if selfSig1.Hash != c.DefaultHash {
		t.Fatalf("Expected subkey hash method: %v, got: %v", c.DefaultHash,
			selfSig1.Hash)
	}

	if selfSig1.EmbeddedSignature.Hash != c.DefaultHash {
		t.Fatalf("Expected subkey hash method: %v, got: %v", c.DefaultHash,
			selfSig1.EmbeddedSignature.Hash)
	}

	selfSig2, err := entity.Subkeys[2].LatestValidBindingSignature(zeroTime)
	if err != nil {
		t.Fatal("expected a self signature to be found")
	}
	if selfSig2.Hash != c.DefaultHash {
		t.Fatalf("Expected subkey hash method: %v, got: %v", c.DefaultHash,
			selfSig2.Hash)
	}
	err = entity.PrimaryKey.VerifyKeySignature(entity.Subkeys[1].PublicKey, selfSig1)
	if err != nil {
		t.Errorf("Invalid subkey signature: %v", err)
	}
	err = entity.PrimaryKey.VerifyKeySignature(entity.Subkeys[2].PublicKey, selfSig2)
	if err != nil {
		t.Errorf("Invalid subkey signature: %v", err)
	}
}

func TestRevokeKey(t *testing.T) {
	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	err = entity.Revoke(packet.NoReason, "Key revocation", nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(entity.Revocations) == 0 {
		t.Fatal("Revocation signature missing from entity")
	}

	for _, r := range entity.Revocations {
		err = entity.PrimaryKey.VerifyRevocationSignature(r.Packet)
		if err != nil {
			t.Errorf("Invalid revocation: %v", err)
		}
	}
}

func TestRevokeKeyWithConfig(t *testing.T) {
	c := &packet.Config{
		DefaultHash: crypto.SHA512,
	}

	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", &packet.Config{
		Algorithm: packet.PubKeyAlgoEdDSA,
	})
	if err != nil {
		t.Fatal(err)
	}

	err = entity.Revoke(packet.NoReason, "Key revocation", c)
	if err != nil {
		t.Fatal(err)
	}

	if len(entity.Revocations) == 0 {
		t.Fatal("Revocation signature missing from entity")
	}

	if entity.Revocations[0].Packet.Hash != c.DefaultHash {
		t.Fatalf("Expected signature hash method: %v, got: %v", c.DefaultHash,
			entity.Revocations[0].Packet.Hash)
	}

	for _, r := range entity.Revocations {
		err = entity.PrimaryKey.VerifyRevocationSignature(r.Packet)
		if err != nil {
			t.Errorf("Invalid revocation: %v", err)
		}
	}
}

func TestRevokeSubkey(t *testing.T) {
	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	err = entity.Subkeys[0].Revoke(packet.NoReason, "Key revocation", nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(entity.Subkeys[0].Revocations) != 1 {
		t.Fatalf("Expected 1 subkey revocation signature, got %v", len(entity.Subkeys[0].Revocations))
	}

	revSig := entity.Subkeys[0].Revocations[0]

	err = entity.PrimaryKey.VerifySubkeyRevocationSignature(revSig.Packet, entity.Subkeys[0].PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	if revSig.Packet.RevocationReason == nil {
		t.Fatal("Revocation reason was not set")
	}
	if revSig.Packet.RevocationReasonText == "" {
		t.Fatal("Revocation reason text was not set")
	}

	serializedEntity := bytes.NewBuffer(nil)
	if err := entity.SerializePrivate(serializedEntity, nil); err != nil {
		t.Fatal(err)
	}

	// Make sure revocation reason subpackets are not lost during serialization.
	newEntity, err := ReadEntity(packet.NewReader(bytes.NewBuffer(serializedEntity.Bytes())))
	if err != nil {
		t.Fatal(err)
	}

	if newEntity.Subkeys[0].Revocations[0].Packet.RevocationReason == nil {
		t.Fatal("Revocation reason lost after serialization of entity")
	}
	if newEntity.Subkeys[0].Revocations[0].Packet.RevocationReasonText == "" {
		t.Fatal("Revocation reason text lost after serialization of entity")
	}
}

func TestRevokeSubkeyWithInvalidSignature(t *testing.T) {
	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	sk := entity.Subkeys[0]
	sk.Bindings[0].Packet = &packet.Signature{Version: 4}

	err = sk.Revoke(packet.NoReason, "Key revocation", nil)
	if err == nil {
		t.Fatal("Entity was able to revoke a subkey with invalid signature")
	}
}

func TestRevokeSubkeyWithConfig(t *testing.T) {
	c := &packet.Config{
		DefaultHash: crypto.SHA512,
	}

	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	sk := entity.Subkeys[0]
	err = sk.Revoke(packet.NoReason, "Key revocation", c)
	if err != nil {
		t.Fatal(err)
	}

	if len(sk.Revocations) != 1 {
		t.Fatalf("Expected 1 subkey revocation signature, got %v", len(sk.Revocations))
	}

	revSig := sk.Revocations[0].Packet

	if revSig.Hash != c.DefaultHash {
		t.Fatalf("Expected signature hash method: %v, got: %v", c.DefaultHash, revSig.Hash)
	}

	err = entity.PrimaryKey.VerifySubkeyRevocationSignature(revSig, sk.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
}

func TestEncryptAndDecryptPrivateKeys(t *testing.T) {
	s2kModesToTest := []s2k.Mode{s2k.IteratedSaltedS2K, s2k.Argon2S2K}

	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	err = entity.AddSigningSubkey(nil)
	if err != nil {
		t.Fatal(err)
	}

	err = entity.AddEncryptionSubkey(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range s2kModesToTest {
		t.Run(fmt.Sprintf("S2KMode %d", mode), func(t *testing.T) {
			passphrase := []byte("password")
			config := &packet.Config{
				S2KConfig: &s2k.Config{
					S2KMode: mode,
				},
			}
			err = entity.EncryptPrivateKeys(passphrase, config)
			if err != nil {
				t.Fatal(err)
			}

			if !entity.PrivateKey.Encrypted {
				t.Fatal("Expected encrypted private key")
			}
			for _, subkey := range entity.Subkeys {
				if !subkey.PrivateKey.Encrypted {
					t.Fatal("Expected encrypted private key")
				}
			}

			err = entity.DecryptPrivateKeys(passphrase)
			if err != nil {
				t.Fatal(err)
			}

			if entity.PrivateKey.Encrypted {
				t.Fatal("Expected plaintext private key")
			}
			for _, subkey := range entity.Subkeys {
				if subkey.PrivateKey.Encrypted {
					t.Fatal("Expected plaintext private key")
				}
			}
		})
	}
}

func TestKeyValidateOnDecrypt(t *testing.T) {
	randomPassword := make([]byte, 128)
	_, err := rand.Read(randomPassword)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("RSA", func(t *testing.T) {
		t.Run("Hardcoded:2048 bits", func(t *testing.T) {
			keys, err := ReadArmoredKeyRing(bytes.NewBufferString(rsa2048PrivateKey))
			if err != nil {
				t.Fatal("Unable to parse hardcoded key: ", err)
			}

			if err := keys[0].PrivateKey.Decrypt([]byte("password")); err != nil {
				t.Fatal("Unable to decrypt hardcoded key: ", err)
			}

			testKeyValidateRsaOnDecrypt(t, keys[0], randomPassword)
		})

		for _, bits := range []int{2048, 3072, 4096} {
			t.Run("Generated:"+strconv.Itoa(bits)+" bits", func(t *testing.T) {
				key := testGenerateRSA(t, bits)
				testKeyValidateRsaOnDecrypt(t, key, randomPassword)
			})
		}
	})

	t.Run("ECDSA", func(t *testing.T) {
		t.Run("Hardcoded:NIST P-256", func(t *testing.T) {
			keys, err := ReadArmoredKeyRing(bytes.NewBufferString(ecdsaPrivateKey))
			if err != nil {
				t.Fatal("Unable to parse hardcoded key: ", err)
			}

			if err := keys[0].PrivateKey.Decrypt([]byte("password")); err != nil {
				t.Fatal("Unable to decrypt hardcoded key: ", err)
			}

			if err := keys[0].Subkeys[0].PrivateKey.Decrypt([]byte("password")); err != nil {
				t.Fatal("Unable to decrypt hardcoded subkey: ", err)
			}

			testKeyValidateEcdsaOnDecrypt(t, keys[0], randomPassword)
		})

		ecdsaCurves := map[string]packet.Curve{
			"NIST P-256":      packet.CurveNistP256,
			"NIST P-384":      packet.CurveNistP384,
			"NIST P-521":      packet.CurveNistP521,
			"Brainpool P-256": packet.CurveBrainpoolP256,
			"Brainpool P-384": packet.CurveBrainpoolP384,
			"Brainpool P-512": packet.CurveBrainpoolP512,
			"SecP256k1":       packet.CurveSecP256k1,
		}

		for name, curveType := range ecdsaCurves {
			t.Run("Generated:"+name, func(t *testing.T) {
				key := testGenerateEC(t, packet.PubKeyAlgoECDSA, curveType)
				testKeyValidateEcdsaOnDecrypt(t, key, randomPassword)
			})
		}
	})

	t.Run("EdDSA", func(t *testing.T) {
		eddsaHardcoded := map[string]string{
			"Curve25519": curve25519PrivateKey,
			"Curve448":   curve448PrivateKey,
		}

		for name, skData := range eddsaHardcoded {
			t.Run("Hardcoded:"+name, func(t *testing.T) {
				keys, err := ReadArmoredKeyRing(bytes.NewBufferString(skData))
				if err != nil {
					t.Fatal("Unable to parse hardcoded key: ", err)
				}

				testKeyValidateEddsaOnDecrypt(t, keys[0], randomPassword)
			})
		}

		eddsaCurves := map[string]packet.Curve{
			"Curve25519": packet.Curve25519,
			"Curve448":   packet.Curve448,
		}

		for name, curveType := range eddsaCurves {
			t.Run("Generated:"+name, func(t *testing.T) {
				key := testGenerateEC(t, packet.PubKeyAlgoEdDSA, curveType)
				testKeyValidateEddsaOnDecrypt(t, key, randomPassword)
			})
		}
	})

	t.Run("DSA With El Gamal Subkey", func(t *testing.T) {
		testKeyValidateDsaElGamalOnDecrypt(t, randomPassword)
	})
}

func testGenerateRSA(t *testing.T, bits int) *Entity {
	config := &packet.Config{Algorithm: packet.PubKeyAlgoRSA, RSABits: bits}
	rsaEntity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", config)
	if err != nil {
		t.Fatal(err)
	}

	return rsaEntity
}

func testKeyValidateRsaOnDecrypt(t *testing.T, rsaEntity *Entity, password []byte) {
	var err error
	rsaPrimaryKey := rsaEntity.PrivateKey
	if err = rsaPrimaryKey.Encrypt(password); err != nil {
		t.Fatal(err)
	}
	if err = rsaPrimaryKey.Decrypt(password); err != nil {
		t.Fatal("Valid RSA key was marked as invalid: ", err)
	}

	if err = rsaPrimaryKey.Encrypt(password); err != nil {
		t.Fatal(err)
	}

	// Corrupt public modulo n in primary key
	n := rsaPrimaryKey.PublicKey.PublicKey.(*rsa.PublicKey).N
	rsaPrimaryKey.PublicKey.PublicKey.(*rsa.PublicKey).N = new(big.Int).Add(n, big.NewInt(2))
	err = rsaPrimaryKey.Decrypt(password)
	if _, ok := err.(errors.KeyInvalidError); !ok {
		t.Fatal("Failed to detect invalid RSA key")
	}
}

func testGenerateEC(t *testing.T, algorithm packet.PublicKeyAlgorithm, curve packet.Curve) *Entity {
	config := &packet.Config{Algorithm: algorithm, Curve: curve}
	rsaEntity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", config)
	if err != nil {
		t.Fatal(err)
	}

	return rsaEntity
}

func testKeyValidateEcdsaOnDecrypt(t *testing.T, ecdsaKey *Entity, password []byte) {
	var err error
	ecdsaPrimaryKey := ecdsaKey.PrivateKey

	if err = ecdsaPrimaryKey.Encrypt(password); err != nil {
		t.Fatal(err)
	}

	if err := ecdsaPrimaryKey.Decrypt(password); err != nil {
		t.Fatal("Valid ECDSA key was marked as invalid: ", err)
	}

	if err = ecdsaPrimaryKey.Encrypt(password); err != nil {
		t.Fatal(err)
	}

	// Corrupt public X in primary key
	X := ecdsaPrimaryKey.PublicKey.PublicKey.(*ecdsa.PublicKey).X
	ecdsaPrimaryKey.PublicKey.PublicKey.(*ecdsa.PublicKey).X = new(big.Int).Add(X, big.NewInt(1))
	err = ecdsaPrimaryKey.Decrypt(password)
	if _, ok := err.(errors.KeyInvalidError); !ok {
		t.Fatal("Failed to detect invalid ECDSA key")
	}

	// ECDH
	ecdsaSubkey := ecdsaKey.Subkeys[0].PrivateKey
	if err = ecdsaSubkey.Encrypt(password); err != nil {
		t.Fatal(err)
	}

	if err := ecdsaSubkey.Decrypt(password); err != nil {
		t.Fatal("Valid ECDH key was marked as invalid: ", err)
	}

	if err = ecdsaSubkey.Encrypt(password); err != nil {
		t.Fatal(err)
	}

	// Corrupt public X in subkey
	ecdsaSubkey.PublicKey.PublicKey.(*ecdh.PublicKey).Point[5] ^= 1

	err = ecdsaSubkey.Decrypt(password)
	if _, ok := err.(errors.KeyInvalidError); !ok {
		t.Fatal("Failed to detect invalid ECDH key")
	}
}

func testKeyValidateEddsaOnDecrypt(t *testing.T, eddsaEntity *Entity, password []byte) {
	var err error

	eddsaPrimaryKey := eddsaEntity.PrivateKey // already encrypted
	if err = eddsaPrimaryKey.Encrypt(password); err != nil {
		t.Fatal(err)
	}

	if err := eddsaPrimaryKey.Decrypt(password); err != nil {
		t.Fatal("Valid EdDSA key was marked as invalid: ", err)
	}

	if err = eddsaPrimaryKey.Encrypt(password); err != nil {
		t.Fatal(err)
	}

	pubKey := *eddsaPrimaryKey.PublicKey.PublicKey.(*eddsa.PublicKey)
	pubKey.X[10] ^= 1
	err = eddsaPrimaryKey.Decrypt(password)
	if _, ok := err.(errors.KeyInvalidError); !ok {
		t.Fatal("Failed to detect invalid EdDSA key")
	}

	// ECDH
	ecdhSubkey := eddsaEntity.Subkeys[len(eddsaEntity.Subkeys)-1].PrivateKey
	if err = ecdhSubkey.Encrypt(password); err != nil {
		t.Fatal(err)
	}

	if err := ecdhSubkey.Decrypt(password); err != nil {
		t.Fatal("Valid ECDH key was marked as invalid: ", err)
	}

	if err = ecdhSubkey.Encrypt(password); err != nil {
		t.Fatal(err)
	}

	// Corrupt public X in subkey
	ecdhSubkey.PublicKey.PublicKey.(*ecdh.PublicKey).Point[5] ^= 1
	err = ecdhSubkey.Decrypt(password)
	if _, ok := err.(errors.KeyInvalidError); !ok {
		t.Fatal("Failed to detect invalid ECDH key")
	}
}

// ...the legacy bits
func testKeyValidateDsaElGamalOnDecrypt(t *testing.T, randomPassword []byte) {
	var err error

	dsaKeys, err := ReadArmoredKeyRing(bytes.NewBufferString(dsaPrivateKeyWithElGamalSubkey))
	if err != nil {
		t.Fatal(err)
	}
	dsaPrimaryKey := dsaKeys[0].PrivateKey // already encrypted
	if err := dsaPrimaryKey.Decrypt([]byte("password")); err != nil {
		t.Fatal("Valid DSA key was marked as invalid: ", err)
	}

	if err = dsaPrimaryKey.Encrypt(randomPassword); err != nil {
		t.Fatal(err)
	}
	// corrupt DSA generator
	G := dsaPrimaryKey.PublicKey.PublicKey.(*dsa.PublicKey).G
	dsaPrimaryKey.PublicKey.PublicKey.(*dsa.PublicKey).G = new(big.Int).Add(G, big.NewInt(1))
	err = dsaPrimaryKey.Decrypt(randomPassword)
	if _, ok := err.(errors.KeyInvalidError); !ok {
		t.Fatal("Failed to detect invalid DSA key")
	}

	// ElGamal
	elGamalSubkey := dsaKeys[0].Subkeys[0].PrivateKey // already encrypted
	if err := elGamalSubkey.Decrypt([]byte("password")); err != nil {
		t.Fatal("Valid ElGamal key was marked as invalid: ", err)
	}

	if err = elGamalSubkey.Encrypt(randomPassword); err != nil {
		t.Fatal(err)
	}

	// corrupt ElGamal generator
	G = elGamalSubkey.PublicKey.PublicKey.(*elgamal.PublicKey).G
	elGamalSubkey.PublicKey.PublicKey.(*elgamal.PublicKey).G = new(big.Int).Add(G, big.NewInt(1))
	err = elGamalSubkey.Decrypt(randomPassword)
	if _, ok := err.(errors.KeyInvalidError); !ok {
		t.Fatal("Failed to detect invalid ElGamal key")
	}
}

var foreignKeysv4 = []string{
	v4Key25519,
}

func TestReadPrivateForeignV4Key(t *testing.T) {
	for _, str := range foreignKeysv4 {
		kring, err := ReadArmoredKeyRing(strings.NewReader(str))
		if err != nil {
			t.Fatal(err)
		}
		checkV4Key(t, kring[0])
	}
}

func checkV4Key(t *testing.T, ent *Entity) {
	key := ent.PrimaryKey
	if key.Version != 4 {
		t.Errorf("wrong key version %d", key.Version)
	}
	if len(key.Fingerprint) != 20 {
		t.Errorf("Wrong fingerprint length: %d", len(key.Fingerprint))
	}
	signatures := ent.Revocations
	for _, id := range ent.Identities {
		signatures = append(signatures, id.SelfCertifications...)
	}
	for _, sig := range signatures {
		if sig == nil {
			continue
		}
		if sig.Packet.Version != 4 {
			t.Errorf("wrong signature version %d", sig.Packet.Version)
		}
		fgptLen := len(sig.Packet.IssuerFingerprint)
		if fgptLen != 20 {
			t.Errorf("Wrong fingerprint length in signature: %d", fgptLen)
		}
	}
}

// Should not panic (generated with go-fuzz)
func TestCorruptKeys(t *testing.T) {
	data := `-----BEGIN PGP PUBLIC KEY BLOCK00000

mQ00BF00000BCAD0000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000ABE000G0Dn000000000000000000iQ00BB0BAgAGBCG00000`
	ReadArmoredKeyRing(strings.NewReader(data))
}

func TestMultiIdentity(t *testing.T) {
	data := `-----BEGIN PGP PUBLIC KEY BLOCK-----

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
zaXZE2aAMQ==
=Ty4h
-----END PGP PUBLIC KEY BLOCK-----`
	key, err := ReadArmoredKeyRing(strings.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	var config *packet.Config
	sig, _ := key[0].PrimaryIdentity(config.Now())
	if err != nil {
		t.Fatal(err)
	}
	if sig.IsPrimaryId == nil || !*sig.IsPrimaryId {
		t.Fatal("expected primary identity to be selected")
	}
}

func TestParseKeyWithUnsupportedSubkey(t *testing.T) {
	data := `-----BEGIN PGP PUBLIC KEY BLOCK-----

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
ruxTPhR2zcmefHKGU7cCC/uo
=KLLX
-----END PGP PUBLIC KEY BLOCK-----`
	_, err := ReadArmoredKeyRing(strings.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
}

func TestParseUnsupportedSubkey(t *testing.T) {
	data := `-----BEGIN PGP PUBLIC KEY BLOCK-----

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
NciH07RTRuMS/aRhRg4OB8PQROmTnZ+iZS0=
=7DF0
-----END PGP PUBLIC KEY BLOCK-----
`
	_, err := ReadArmoredKeyRing(strings.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
}

func TestAddHMACSubkey(t *testing.T) {
	c := &packet.Config{
		RSABits:   512,
		Algorithm: packet.ExperimentalPubKeyAlgoHMAC,
	}

	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", &packet.Config{RSABits: 1024})
	if err != nil {
		t.Fatal(err)
	}

	err = entity.AddSigningSubkey(c)
	if err != nil {
		t.Fatal(err)
	}

	buf := bytes.NewBuffer(nil)
	w, _ := armor.Encode(buf, "PGP PRIVATE KEY BLOCK", nil)
	if err := entity.SerializePrivate(w, nil); err != nil {
		t.Errorf("failed to serialize entity: %s", err)
	}
	w.Close()

	key, err := ReadArmoredKeyRing(buf)
	if err != nil {
		t.Error("could not read keyring", err)
	}

	generatedPrivateKey := entity.Subkeys[1].PrivateKey.PrivateKey.(*symmetric.HMACPrivateKey)
	parsedPrivateKey := key[0].Subkeys[1].PrivateKey.PrivateKey.(*symmetric.HMACPrivateKey)

	generatedPublicKey := entity.Subkeys[1].PublicKey.PublicKey.(*symmetric.HMACPublicKey)
	parsedPublicKey := key[0].Subkeys[1].PublicKey.PublicKey.(*symmetric.HMACPublicKey)

	if !bytes.Equal(parsedPrivateKey.Key, generatedPrivateKey.Key) {
		t.Error("parsed wrong key")
	}
	if !bytes.Equal(parsedPublicKey.Key, generatedPrivateKey.Key) {
		t.Error("parsed wrong key in public part")
	}
	if !bytes.Equal(generatedPublicKey.Key, generatedPrivateKey.Key) {
		t.Error("generated Public and Private Key differ")
	}

	if !bytes.Equal(parsedPrivateKey.HashSeed[:], generatedPrivateKey.HashSeed[:]) {
		t.Error("parsed wrong hash seed")
	}

	if parsedPrivateKey.PublicKey.Hash != generatedPrivateKey.PublicKey.Hash {
		t.Error("parsed wrong cipher id")
	}
	if !bytes.Equal(parsedPrivateKey.PublicKey.BindingHash[:], generatedPrivateKey.PublicKey.BindingHash[:]) {
		t.Error("parsed wrong binding hash")
	}
}

func TestSerializeSymmetricSubkeyError(t *testing.T) {
	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", &packet.Config{RSABits: 1024})
	if err != nil {
		t.Fatal(err)
	}

	buf := bytes.NewBuffer(nil)
	w, _ := armor.Encode(buf, "PGP PRIVATE KEY BLOCK", nil)

	entity.PrimaryKey.PubKeyAlgo = 100
	err = entity.Serialize(w)
	if err == nil {
		t.Fatal(err)
	}

	entity.PrimaryKey.PubKeyAlgo = 101
	err = entity.Serialize(w)
	if err == nil {
		t.Fatal(err)
	}
}

func TestAddAEADSubkey(t *testing.T) {
	c := &packet.Config{
		RSABits:   512,
		Algorithm: packet.ExperimentalPubKeyAlgoAEAD,
	}
	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", &packet.Config{RSABits: 1024})
	if err != nil {
		t.Fatal(err)
	}

	err = entity.AddEncryptionSubkey(c)
	if err != nil {
		t.Fatal(err)
	}

	generatedPrivateKey := entity.Subkeys[1].PrivateKey.PrivateKey.(*symmetric.AEADPrivateKey)

	buf := bytes.NewBuffer(nil)
	w, _ := armor.Encode(buf, "PGP PRIVATE KEY BLOCK", nil)
	if err := entity.SerializePrivate(w, nil); err != nil {
		t.Errorf("failed to serialize entity: %s", err)
	}
	w.Close()

	key, err := ReadArmoredKeyRing(buf)
	if err != nil {
		t.Error("could not read keyring", err)
	}

	parsedPrivateKey := key[0].Subkeys[1].PrivateKey.PrivateKey.(*symmetric.AEADPrivateKey)

	generatedPublicKey := entity.Subkeys[1].PublicKey.PublicKey.(*symmetric.AEADPublicKey)
	parsedPublicKey := key[0].Subkeys[1].PublicKey.PublicKey.(*symmetric.AEADPublicKey)

	if !bytes.Equal(parsedPrivateKey.Key, generatedPrivateKey.Key) {
		t.Error("parsed wrong key")
	}
	if !bytes.Equal(parsedPublicKey.Key, generatedPrivateKey.Key) {
		t.Error("parsed wrong key in public part")
	}
	if !bytes.Equal(generatedPublicKey.Key, generatedPrivateKey.Key) {
		t.Error("generated Public and Private Key differ")
	}

	if !bytes.Equal(parsedPrivateKey.HashSeed[:], generatedPrivateKey.HashSeed[:]) {
		t.Error("parsed wrong hash seed")
	}

	if parsedPrivateKey.PublicKey.Cipher.Id() != generatedPrivateKey.PublicKey.Cipher.Id() {
		t.Error("parsed wrong cipher id")
	}
	if !bytes.Equal(parsedPrivateKey.PublicKey.BindingHash[:], generatedPrivateKey.PublicKey.BindingHash[:]) {
		t.Error("parsed wrong binding hash")
	}
}

func TestNoSymmetricKeySerialized(t *testing.T) {
	aeadConfig := &packet.Config{
		RSABits:       512,
		DefaultHash:   crypto.SHA512,
		Algorithm:     packet.ExperimentalPubKeyAlgoAEAD,
		DefaultCipher: packet.CipherAES256,
	}
	hmacConfig := &packet.Config{
		RSABits:       512,
		DefaultHash:   crypto.SHA512,
		Algorithm:     packet.ExperimentalPubKeyAlgoHMAC,
		DefaultCipher: packet.CipherAES256,
	}
	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", &packet.Config{RSABits: 1024})
	if err != nil {
		t.Fatal(err)
	}

	err = entity.AddEncryptionSubkey(aeadConfig)
	if err != nil {
		t.Fatal(err)
	}
	err = entity.AddSigningSubkey(hmacConfig)
	if err != nil {
		t.Fatal(err)
	}

	w := bytes.NewBuffer(nil)
	entity.Serialize(w)

	firstSymKey := entity.Subkeys[1].PrivateKey.PrivateKey.(*symmetric.AEADPrivateKey).Key
	i := bytes.Index(w.Bytes(), firstSymKey)

	secondSymKey := entity.Subkeys[2].PrivateKey.PrivateKey.(*symmetric.HMACPrivateKey).Key
	k := bytes.Index(w.Bytes(), secondSymKey)

	if (i > 0) || (k > 0) {
		t.Error("Private key was serialized with public")
	}

	firstBindingHash := entity.Subkeys[1].PublicKey.PublicKey.(*symmetric.AEADPublicKey).BindingHash
	i = bytes.Index(w.Bytes(), firstBindingHash[:])

	secondBindingHash := entity.Subkeys[2].PublicKey.PublicKey.(*symmetric.HMACPublicKey).BindingHash
	k = bytes.Index(w.Bytes(), secondBindingHash[:])
	if (i > 0) || (k > 0) {
		t.Errorf("Symmetric public key metadata exported %d %d", i, k)
	}

}

func TestSymmetricKeys(t *testing.T) {
	data := `-----BEGIN PGP PRIVATE KEY BLOCK-----
	
xWoEYs7w5mUIcFvlmkuricX26x138uvHGlwIaxWIbRnx1+ggPcveTcwA4zSZ
n6XcD0Q5aLe6dTEBwCyfUecZ/nA0W8Pl9xBHfjIjQuxcUBnIqxZ061RZPjef
D/XIQga1ftLDelhylQwL7R3TzQ1TeW1tZXRyaWMgS2V5wmkEEGUIAB0FAmLO
8OYECwkHCAMVCAoEFgACAQIZAQIbAwIeAQAhCRCRTKq2ObiQKxYhBMHTTXXF
ULQ2M2bYNJFMqrY5uJArIawgJ+5RSsN8VNuZTKJbG88TIedU05wwKjW3wqvT
X6Z7yfbHagRizvDmZAluL/kJo6hZ1kFENpQkWD/Kfv1vAG3nbxhsVEzBQ6a1
OAD24BaKJz6gWgj4lASUNK5OuXnLc3J79Bt1iRGkSbiPzRs/bplB4TwbILeC
ZLeDy9kngZDosgsIk5sBgGEqS9y5HiHCVQQYZQgACQUCYs7w5gIbDAAhCRCR
TKq2ObiQKxYhBMHTTXXFULQ2M2bYNJFMqrY5uJArENkgL0Bc+OI/1na0XWqB
TxGVotQ4A/0u0VbOMEUfnrI8Fms=
=RdCW
-----END PGP PRIVATE KEY BLOCK-----
`
	keys, err := ReadArmoredKeyRing(strings.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Errorf("Expected 1 symmetric key, got %d", len(keys))
	}
	if keys[0].PrivateKey.PubKeyAlgo != packet.ExperimentalPubKeyAlgoHMAC {
		t.Errorf("Expected HMAC primary key")
	}
	if len(keys[0].Subkeys) != 1 {
		t.Errorf("Expected 1 symmetric subkey, got %d", len(keys[0].Subkeys))
	}
	if keys[0].Subkeys[0].PrivateKey.PubKeyAlgo != packet.ExperimentalPubKeyAlgoAEAD {
		t.Errorf("Expected AEAD subkey")
	}
}
