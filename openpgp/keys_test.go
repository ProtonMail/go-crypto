package openpgp

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
	key, ok := entity.EncryptionKey(time1)
	if !ok {
		t.Fatal("No encryption key found")
	}
	if id, expected := key.PublicKey.KeyIdShortString(), "CD3D39FF"; id != expected {
		t.Errorf("Expected key %s at time %s, but got key %s", expected, time1.Format(timeFormat), id)
	}

	// Once the first encryption subkey has expired, the second should be
	// selected.
	time2, _ := time.Parse(timeFormat, "2013-07-09")
	key, _ = entity.EncryptionKey(time2)
	if id, expected := key.PublicKey.KeyIdShortString(), "CD3D39FF"; id != expected {
		t.Errorf("Expected key %s at time %s, but got key %s", expected, time2.Format(timeFormat), id)
	}

	// Once all the keys have expired, nothing should be returned.
	time3, _ := time.Parse(timeFormat, "2013-08-01")
	if key, ok := entity.EncryptionKey(time3); ok {
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
	key, found := entity.SigningKey(time1)
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
	if key, ok := entity.SigningKey(time2); ok {
		t.Errorf("Expected no key at time %s, but got key %s", time2.Format(timeFormat), key.PublicKey.KeyIdShortString())
	}
}

func TestReturnNewestUnexpiredSigningSubkey(t *testing.T) {
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
		Time: func() time.Time {
			return time.Now().Add(1 * time.Second)
		},
		KeyLifetimeSecs: 24 * 60 * 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Get the second signing subkey.
	subkey2 := entity.Subkeys[2]

	// Before second signing subkey has expired, it should be returned.
	time1 := time.Now().Add(2 * time.Second)
	expected := subkey2.PublicKey.KeyIdShortString()
	subkey, found := entity.SigningKey(time1)
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
	subkey, found = entity.SigningKey(time2)
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
	err = ArmoredDetachSign(&signatureWriter1, entity, message, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Make a signature that expires in a day.
	var signatureWriter2 bytes.Buffer
	message = strings.NewReader(input)
	err = ArmoredDetachSign(&signatureWriter2, entity, message, &packet.Config{
		SigLifetimeSecs: 24 * 60 * 60,
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
	err = ArmoredDetachSign(&signatureWriter3, entity, message, &packet.Config{
		Time: futureTime,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Check that the first signature has not expired day after tomorrow.
	message = strings.NewReader(input)
	signatureReader1 := strings.NewReader(signatureWriter1.String())
	_, err = CheckArmoredDetachedSignature(keyring, message, signatureReader1, &packet.Config{
		Time: futureTime,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Check that the second signature has expired day after tomorrow.
	message = strings.NewReader(input)
	signatureReader2 := strings.NewReader(signatureWriter2.String())
	const expectedErr string = "openpgp: signature expired"
	_, observedErr := CheckArmoredDetachedSignature(keyring, message, signatureReader2, &packet.Config{
		Time: futureTime,
	})
	if observedErr.Error() != expectedErr {
		t.Errorf("Expected error '%s', but got error '%s'", expectedErr, observedErr)
	}

	// Check that the third signature is also considered expired even now.
	message = strings.NewReader(input)
	signatureReader3 := strings.NewReader(signatureWriter3.String())
	_, observedErr = CheckArmoredDetachedSignature(keyring, message, signatureReader3, nil)
	if observedErr.Error() != expectedErr {
		t.Errorf("Expected error '%s', but got error '%s'", expectedErr, observedErr)
	}
}

func TestMissingCrossSignature(t *testing.T) {
	// This public key has a signing subkey, but the subkey does not
	// contain a cross-signature.
	keys, err := ReadArmoredKeyRing(bytes.NewBufferString(missingCrossSignatureKey))
	if len(keys) != 0 {
		t.Errorf("Accepted key with missing cross signature")
	}
	if err == nil {
		t.Fatal("Failed to detect error in keyring with missing cross signature")
	}
	structural, ok := err.(errors.StructuralError)
	if !ok {
		t.Fatalf("Unexpected class of error: %T. Wanted StructuralError", err)
	}
	const expectedMsg = "signing subkey is missing cross-signature"
	if !strings.Contains(string(structural), expectedMsg) {
		t.Fatalf("Unexpected error: %q. Expected it to contain %q", err, expectedMsg)
	}
}

func TestInvalidCrossSignature(t *testing.T) {
	// This public key has a signing subkey, and the subkey has an
	// embedded cross-signature. However, the cross-signature does
	// not correctly validate over the primary and subkey.
	keys, err := ReadArmoredKeyRing(bytes.NewBufferString(invalidCrossSignatureKey))
	if len(keys) != 0 {
		t.Errorf("Accepted key with invalid cross signature")
	}
	if err == nil {
		t.Fatal("Failed to detect error in keyring with an invalid cross signature")
	}
	structural, ok := err.(errors.StructuralError)
	if !ok {
		t.Fatalf("Unexpected class of error: %T. Wanted StructuralError", err)
	}
	const expectedMsg = "subkey signature invalid"
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

	if firstIdentity.Revoked(time.Now()) {
		t.Errorf("expected first identity not to be revoked")
	}

	if !secondIdentity.Revoked(time.Now()) {
		t.Errorf("expected second identity to be revoked")
	}

	const timeFormat = "2006-01-02"
	time1, _ := time.Parse(timeFormat, "2020-01-01")

	if _, found := keys[0].SigningKey(time1); !found {
		t.Errorf("Expected SigningKey to return a signing key when one User IDs is revoked")
	}

	if _, found := keys[0].EncryptionKey(time1); !found {
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

	if !firstIdentity.Revoked(time.Now()) {
		t.Errorf("expected first identity to be revoked")
	}

	if secondIdentity.Revoked(time.Now()) {
		t.Errorf("expected second identity not to be revoked")
	}

	const timeFormat = "2006-01-02"
	time1, _ := time.Parse(timeFormat, "2020-01-01")

	if _, found := keys[0].SigningKey(time1); !found {
		t.Errorf("Expected SigningKey to return a signing key when first User IDs is revoked")
	}

	if _, found := keys[0].EncryptionKey(time1); !found {
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

	if !identity.Revoked(time.Now()) {
		t.Errorf("expected identity to be revoked")
	}

	if _, found := keys[0].SigningKey(time.Now()); found {
		t.Errorf("Expected SigningKey not to return a signing key when the only User IDs is revoked")
	}

	if _, found := keys[0].EncryptionKey(time.Now()); found {
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
	w, err := armor.Encode(&buf, PrivateKeyType, nil)
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
		keys = kring.KeysByIdUsage(id, 0)
		if len(keys) != 1 {
			t.Errorf("Expected KeysByIdUsage to find revoked key %X, but got %d matches", id, len(keys))
		}
	}

	signingkey, found := kring[0].SigningKey(time.Now())
	if found {
		t.Errorf("Expected SigningKey not to return a signing key for a revoked key, got %X", signingkey.PublicKey.KeyId)
	}

	encryptionkey, found := kring[0].EncryptionKey(time.Now())
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
	if numSigs, numExpected := len(identity.Signatures), 1; numSigs != numExpected {
		t.Fatalf("got %d signatures, expected %d", numSigs, numExpected)
	}

	if numSubKeys, numExpected := len(keys[0].Subkeys), 1; numSubKeys != numExpected {
		t.Fatalf("got %d subkeys, expected %d", numSubKeys, numExpected)
	}

	subKey := keys[0].Subkeys[0]
	if subKey.Sig == nil {
		t.Fatalf("subkey signature is nil")
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
		keys = kring.KeysByIdUsage(id, 0)
		if len(keys) != 1 {
			t.Errorf("Expected KeysByIdUsage to find key %X, but got %d matches", id, len(keys))
		}
		if id == encryptionKey {
			key, found := kring[0].EncryptionKey(time.Now())
			if !found || key.PublicKey.KeyId != id {
				t.Errorf("Expected EncryptionKey to find key %X", id)
			}
		} else {
			_, found := kring[0].SigningKeyById(time.Now(), id)
			if !found {
				t.Errorf("Expected SigningKeyById to find key %X", id)
			}
		}
	}

	keys := kring.KeysById(revokedKey)
	if len(keys) != 1 {
		t.Errorf("Expected KeysById to find key %X, but got %d matches", revokedKey, len(keys))
	}

	keys = kring.KeysByIdUsage(revokedKey, 0)
	if len(keys) != 1 {
		t.Errorf("Expected KeysByIdUsage to find key %X, but got %d matches", revokedKey, len(keys))
	}

	signingkey, found := kring[0].SigningKeyById(time.Now(), revokedKey)
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

	if lifetime := subKey.Sig.KeyLifetimeSecs; lifetime != nil {
		t.Errorf("The signature has a key lifetime (%d), but it should be nil", *lifetime)
	}

}

func TestKeyUsage(t *testing.T) {
	kring, err := ReadKeyRing(readerFromHex(subkeyUsageHex))
	if err != nil {
		t.Fatal(err)
	}

	// subkeyUsageHex contains these keys:
	// pub  1024R/2866382A  created: 2014-04-01  expires: never       usage: SC
	// sub  1024R/936C9153  created: 2014-04-01  expires: never       usage: E
	// sub  1024R/64D5F5BB  created: 2014-04-02  expires: never       usage: E
	// sub  1024D/BC0BA992  created: 2014-04-02  expires: never       usage: S
	certifiers := []uint64{0xA42704B92866382A}
	signers := []uint64{0xA42704B92866382A, 0x42CE2C64BC0BA992}
	encrypters := []uint64{0x09C0C7D9936C9153, 0xC104E98664D5F5BB}

	for _, id := range certifiers {
		keys := kring.KeysByIdUsage(id, packet.KeyFlagCertify)
		if len(keys) == 1 {
			if keys[0].PublicKey.KeyId != id {
				t.Errorf("Expected to find certifier key id %X, but got %X", id, keys[0].PublicKey.KeyId)
			}
		} else {
			t.Errorf("Expected one match for certifier key id %X, but got %d matches", id, len(keys))
		}
	}

	for _, id := range signers {
		keys := kring.KeysByIdUsage(id, packet.KeyFlagSign)
		if len(keys) == 1 {
			if keys[0].PublicKey.KeyId != id {
				t.Errorf("Expected to find signing key id %X, but got %X", id, keys[0].PublicKey.KeyId)
			}
		} else {
			t.Errorf("Expected one match for signing key id %X, but got %d matches", id, len(keys))
		}

		// This keyring contains no encryption keys that are also good for signing.
		keys = kring.KeysByIdUsage(id, packet.KeyFlagEncryptStorage|packet.KeyFlagEncryptCommunications)
		if len(keys) != 0 {
			t.Errorf("Unexpected match for encryption key id %X", id)
		}
	}

	for _, id := range encrypters {
		keys := kring.KeysByIdUsage(id, packet.KeyFlagEncryptStorage|packet.KeyFlagEncryptCommunications)
		if len(keys) == 1 {
			if keys[0].PublicKey.KeyId != id {
				t.Errorf("Expected to find encryption key id %X, but got %X", id, keys[0].PublicKey.KeyId)
			}
		} else {
			t.Errorf("Expected one match for encryption key id %X, but got %d matches", id, len(keys))
		}

		// This keyring contains no encryption keys that are also good for signing.
		keys = kring.KeysByIdUsage(id, packet.KeyFlagSign)
		if len(keys) != 0 {
			t.Errorf("Unexpected match for signing key id %X", id)
		}
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
	config := &packet.Config{SigLifetimeSecs: 128, SigningIdentity: signerIdentity}
	if err := kring[0].SignIdentity(signedIdentity, kring[1], config); err != nil {
		t.Fatal(err)
	}

	ident, ok := kring[0].Identities[signedIdentity]
	if !ok {
		t.Fatal("signed identity missing from key after signing")
	}

	checked := false
	for _, sig := range ident.Signatures {
		if sig.IssuerKeyId == nil || *sig.IssuerKeyId != kring[1].PrimaryKey.KeyId {
			continue
		}

		if err := kring[1].PrimaryKey.VerifyUserIdSignature(signedIdentity, kring[0].PrimaryKey, sig); err != nil {
			t.Fatalf("error verifying new identity signature: %s", err)
		}

		if sig.SignerUserId == nil || *sig.SignerUserId != signerIdentity {
			t.Fatalf("wrong or nil signer identity")
		}

		if sig.SigExpired(time.Now()) {
			t.Fatalf("signature is expired")
		}

		if !sig.SigExpired(time.Now().Add(129 * time.Second)) {
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
			prefs := identity.SelfSignature.PreferredHash
			if len(prefs) == 0 {
				t.Fatal("didn't find a preferred hash list in self signature")
			}
			ph := hashToHashId(c.DefaultHash)
			if prefs[0] != ph {
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
		prefs := identity.SelfSignature.PreferredHash
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
			prefs := identity.SelfSignature.PreferredSymmetric
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
		prefs := identity.SelfSignature.PreferredSymmetric
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
			if len(identity.SelfSignature.PreferredCipherSuites) == 0 {
				t.Fatal("didn't find a preferred mode in self signature")
			}
			cipher := identity.SelfSignature.PreferredCipherSuites[0][0]
			if cipher != uint8(cfg.Cipher()) {
				t.Fatalf("Expected preferred cipher to be %d, got %d",
					uint8(cfg.Cipher()),
					identity.SelfSignature.PreferredCipherSuites[0][0])
			}
			mode := identity.SelfSignature.PreferredCipherSuites[0][1]
			if mode != uint8(cfg.AEAD().DefaultMode) {
				t.Fatalf("Expected preferred mode to be %d, got %d",
					uint8(cfg.AEAD().DefaultMode),
					identity.SelfSignature.PreferredCipherSuites[0][1])
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

	if numSigs, numExpected := len(identity.Signatures), 1; numSigs != numExpected {
		t.Fatalf("got %d signatures, expected %d", numSigs, numExpected)
	}

	notations := identity.Signatures[0].Notations
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
		err = entity.PrimaryKey.VerifyUserIdSignature(sk.UserId.Id, entity.PrimaryKey, sk.SelfSignature)
		if err != nil {
			t.Errorf("Invalid subkey signature: %v", err)
		}
	}

	serializedEntity := bytes.NewBuffer(nil)
	entity.SerializePrivate(serializedEntity, nil)

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
		err = entity.PrimaryKey.VerifyKeySignature(sk.PublicKey, sk.Sig)
		if err != nil {
			t.Errorf("Invalid subkey signature: %v", err)
		}
	}

	serializedEntity := bytes.NewBuffer(nil)
	entity.SerializePrivate(serializedEntity, nil)

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
	entity.SerializePrivateWithoutSigning(serializedEntity, nil)

	entity, err = ReadEntity(packet.NewReader(bytes.NewBuffer(serializedEntity.Bytes())))
	if err != nil {
		t.Fatal(err)
	}

	if len(entity.Subkeys) != 3 {
		t.Fatalf("Expected 3 subkeys, got %d", len(entity.Subkeys))
	}

	for _, sk := range entity.Subkeys {
		err = entity.PrimaryKey.VerifyKeySignature(sk.PublicKey, sk.Sig)
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

	if entity.Subkeys[1].Sig.Hash != c.DefaultHash {
		t.Fatalf("Expected subkey hash method: %v, got: %v", c.DefaultHash,
			entity.Subkeys[1].Sig.Hash)
	}

	if entity.Subkeys[1].Sig.EmbeddedSignature.Hash != c.DefaultHash {
		t.Fatalf("Expected subkey hash method: %v, got: %v", c.DefaultHash,
			entity.Subkeys[1].Sig.EmbeddedSignature.Hash)
	}

	if entity.Subkeys[2].Sig.Hash != c.DefaultHash {
		t.Fatalf("Expected subkey hash method: %v, got: %v", c.DefaultHash,
			entity.Subkeys[2].Sig.Hash)
	}

	for _, sk := range entity.Subkeys {
		err = entity.PrimaryKey.VerifyKeySignature(sk.PublicKey, sk.Sig)
		if err != nil {
			t.Errorf("Invalid subkey signature: %v", err)
		}
	}

	serializedEntity := bytes.NewBuffer(nil)
	entity.SerializePrivate(serializedEntity, nil)

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
	entity.SerializePrivateWithoutSigning(serializedEntity, nil)

	entity, err = ReadEntity(packet.NewReader(bytes.NewBuffer(serializedEntity.Bytes())))
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

	if entity.Subkeys[1].Sig.Hash != c.DefaultHash {
		t.Fatalf("Expected subkey hash method: %v, got: %v", c.DefaultHash,
			entity.Subkeys[1].Sig.Hash)
	}

	if entity.Subkeys[1].Sig.EmbeddedSignature.Hash != c.DefaultHash {
		t.Fatalf("Expected subkey hash method: %v, got: %v", c.DefaultHash,
			entity.Subkeys[1].Sig.EmbeddedSignature.Hash)
	}

	if entity.Subkeys[2].Sig.Hash != c.DefaultHash {
		t.Fatalf("Expected subkey hash method: %v, got: %v", c.DefaultHash,
			entity.Subkeys[2].Sig.Hash)
	}

	for _, sk := range entity.Subkeys {
		err = entity.PrimaryKey.VerifyKeySignature(sk.PublicKey, sk.Sig)
		if err != nil {
			t.Errorf("Invalid subkey signature: %v", err)
		}
	}
}

func TestRevokeKey(t *testing.T) {
	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	err = entity.RevokeKey(packet.NoReason, "Key revocation", nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(entity.Revocations) == 0 {
		t.Fatal("Revocation signature missing from entity")
	}

	for _, r := range entity.Revocations {
		err = entity.PrimaryKey.VerifyRevocationSignature(r)
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

	err = entity.RevokeKey(packet.NoReason, "Key revocation", c)
	if err != nil {
		t.Fatal(err)
	}

	if len(entity.Revocations) == 0 {
		t.Fatal("Revocation signature missing from entity")
	}

	if entity.Revocations[0].Hash != c.DefaultHash {
		t.Fatalf("Expected signature hash method: %v, got: %v", c.DefaultHash,
			entity.Revocations[0].Hash)
	}

	for _, r := range entity.Revocations {
		err = entity.PrimaryKey.VerifyRevocationSignature(r)
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

	sk := &entity.Subkeys[0]
	err = entity.RevokeSubkey(sk, packet.NoReason, "Key revocation", nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(entity.Subkeys[0].Revocations) != 1 {
		t.Fatalf("Expected 1 subkey revocation signature, got %v", len(sk.Revocations))
	}

	revSig := entity.Subkeys[0].Revocations[0]

	err = entity.PrimaryKey.VerifySubkeyRevocationSignature(revSig, sk.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	if revSig.RevocationReason == nil {
		t.Fatal("Revocation reason was not set")
	}
	if revSig.RevocationReasonText == "" {
		t.Fatal("Revocation reason text was not set")
	}

	serializedEntity := bytes.NewBuffer(nil)
	entity.SerializePrivate(serializedEntity, nil)

	// Make sure revocation reason subpackets are not lost during serialization.
	newEntity, err := ReadEntity(packet.NewReader(bytes.NewBuffer(serializedEntity.Bytes())))
	if err != nil {
		t.Fatal(err)
	}

	if newEntity.Subkeys[0].Revocations[0].RevocationReason == nil {
		t.Fatal("Revocation reason lost after serialization of entity")
	}
	if newEntity.Subkeys[0].Revocations[0].RevocationReasonText == "" {
		t.Fatal("Revocation reason text lost after serialization of entity")
	}
}

func TestRevokeSubkeyWithAnotherEntity(t *testing.T) {
	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	sk := entity.Subkeys[0]

	newEntity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	err = newEntity.RevokeSubkey(&sk, packet.NoReason, "Key revocation", nil)
	if err == nil {
		t.Fatal("Entity was able to revoke a subkey owned by a different entity")
	}
}

func TestRevokeSubkeyWithInvalidSignature(t *testing.T) {
	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	sk := entity.Subkeys[0]
	sk.Sig = &packet.Signature{Version: 4}

	err = entity.RevokeSubkey(&sk, packet.NoReason, "Key revocation", nil)
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
	err = entity.RevokeSubkey(&sk, packet.NoReason, "Key revocation", c)
	if err != nil {
		t.Fatal(err)
	}

	if len(sk.Revocations) != 1 {
		t.Fatalf("Expected 1 subkey revocation signature, got %v", len(sk.Revocations))
	}

	revSig := sk.Revocations[0]

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
