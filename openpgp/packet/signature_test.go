// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

func TestSignatureReadAndReserialize(t *testing.T) {
	packet, err := Read(readerFromHex(signatureDataHex))
	if err != nil {
		t.Error(err)
		return
	}
	sig, ok := packet.(*Signature)
	if !ok || sig.SigType != SigTypeBinary || sig.PubKeyAlgo != PubKeyAlgoRSA || sig.Hash != crypto.SHA1 {
		t.Errorf("failed to parse, got: %#v", packet)
	}

	serializedSig := new(bytes.Buffer)
	err = sig.Serialize(serializedSig)
	if err != nil {
		t.Fatalf("Unable to reserialize signature, got %s", err)
	}

	hexSig := hex.EncodeToString(serializedSig.Bytes())
	if hexSig != signatureDataHex {
		t.Fatalf("Wrong signature serialized: expected %s, got %s", signatureDataHex, hexSig)
	}
}

func TestOnePassSignatureReadAndReserialize(t *testing.T) {
	packet, err := Read(readerFromHex(onePassSignatureDataHex))
	if err != nil {
		t.Error(err)
		return
	}
	sig, ok := packet.(*OnePassSignature)
	if !ok || sig.SigType != SigTypeBinary || sig.PubKeyAlgo != PubKeyAlgoRSA || sig.Hash != crypto.SHA1 {
		t.Errorf("failed to parse, got: %#v", packet)
	}

	serializedSig := new(bytes.Buffer)
	err = sig.Serialize(serializedSig)
	if err != nil {
		t.Fatalf("Unable to reserialize one-pass signature, got %s", err)
	}

	hexSig := hex.EncodeToString(serializedSig.Bytes())
	if hexSig != onePassSignatureDataHex {
		t.Fatalf("Wrong one-pass signature serialized: expected %s, got %s", onePassSignatureDataHex, hexSig)
	}
}

func TestSignatureEmptyFingerprint(t *testing.T) {
	armoredSig := `-----BEGIN PGP SIGNATURE-----

wpQEEAEIAAgFAohuCQABIQAATHUEAIiL44Hde8vbjvtHwx71Pr+gdxP1WoCifxaD
JKBccKkn82LY1qkfj50BvG0znrloMeQpfLZX1ybHiJwXG0P+cTQJ8m4GkwxlhBkT
BhLGOpf6bhM+HhXONIyoG9qp2ZVpgdOoC3zrsUuHvWKelBT8a3t6mCaTDmpvEMf1
ltm2aQaG
=ZWr8
-----END PGP SIGNATURE-----
	`
	unarmored, err := armor.Decode(strings.NewReader(armoredSig))
	if err != nil {
		t.Error(err)
		return
	}
	_, err = Read(unarmored.Body)
	if err == nil {
		t.Errorf("Expected a parsing error")
		return
	}
}

func TestSignatureReserialize(t *testing.T) {
	packet, _ := Read(readerFromHex(signatureDataHex))
	sig := packet.(*Signature)
	out := new(bytes.Buffer)
	err := sig.Serialize(out)
	if err != nil {
		t.Errorf("error reserializing: %s", err)
		return
	}

	expected, _ := hex.DecodeString(signatureDataHex)
	if !bytes.Equal(expected, out.Bytes()) {
		t.Errorf("output doesn't match input (got vs expected):\n%s\n%s", hex.Dump(out.Bytes()), hex.Dump(expected))
	}
}

func TestPositiveCertSignatureRead(t *testing.T) {
	packet, err := Read(readerFromHex(positiveCertSignatureDataHex))
	if err != nil {
		t.Error(err)
		return
	}
	sig, ok := packet.(*Signature)
	if !ok || sig.SigType != SigTypePositiveCert || sig.PubKeyAlgo != PubKeyAlgoRSA || sig.Hash != crypto.SHA256 {
		t.Errorf("failed to parse, got: %#v", packet)
	}
}

func TestPositiveCertSignatureReserialize(t *testing.T) {
	packet, _ := Read(readerFromHex(positiveCertSignatureDataHex))
	sig := packet.(*Signature)
	out := new(bytes.Buffer)
	err := sig.Serialize(out)
	if err != nil {
		t.Errorf("error reserializing: %s", err)
		return
	}

	expected, _ := hex.DecodeString(positiveCertSignatureDataHex)
	if !bytes.Equal(expected, out.Bytes()) {
		t.Errorf("output doesn't match input (got vs expected):\n%s\n%s", hex.Dump(out.Bytes()), hex.Dump(expected))
	}
}

func TestSignUserId(t *testing.T) {
	sig := &Signature{
		Version:    4,
		SigType:    SigTypeGenericCert,
		PubKeyAlgo: PubKeyAlgoRSA,
		Hash:       0, // invalid hash function
	}

	packet, err := Read(readerFromHex(rsaPkDataHex))
	if err != nil {
		t.Fatalf("failed to deserialize public key: %v", err)
	}
	pubKey := packet.(*PublicKey)

	packet, err = Read(readerFromHex(privKeyRSAHex))
	if err != nil {
		t.Fatalf("failed to deserialize private key: %v", err)
	}
	privKey := packet.(*PrivateKey)

	err = sig.SignUserId("", pubKey, privKey, nil)
	if err == nil {
		t.Errorf("did not receive an error when expected")
	}

	sig.Hash = crypto.SHA256
	err = privKey.Decrypt([]byte("testing"))
	if err != nil {
		t.Fatalf("failed to decrypt private key: %v", err)
	}

	err = sig.SignUserId("", pubKey, privKey, nil)
	if err != nil {
		t.Errorf("failed to sign user id: %v", err)
	}
}

func TestSignatureWithLifetime(t *testing.T) {
	lifeTime := uint32(3600 * 24 * 30) // 30 days
	sig := &Signature{
		SigType:         SigTypeGenericCert,
		PubKeyAlgo:      PubKeyAlgoRSA,
		Hash:            crypto.SHA256,
		SigLifetimeSecs: &lifeTime,
	}

	packet, err := Read(readerFromHex(rsaPkDataHex))
	if err != nil {
		t.Fatalf("failed to deserialize public key: %v", err)
	}
	pubKey := packet.(*PublicKey)

	packet, err = Read(readerFromHex(privKeyRSAHex))
	if err != nil {
		t.Fatalf("failed to deserialize private key: %v", err)
	}
	privKey := packet.(*PrivateKey)

	err = privKey.Decrypt([]byte("testing"))
	if err != nil {
		t.Fatalf("failed to decrypt private key: %v", err)
	}

	err = sig.SignUserId("", pubKey, privKey, nil)
	if err != nil {
		t.Errorf("failed to sign user id: %v", err)
	}

	buf := bytes.NewBuffer([]byte{})
	err = sig.Serialize(buf)
	if err != nil {
		t.Errorf("failed to serialize signature: %v", err)
	}

	packet, _ = Read(bytes.NewReader(buf.Bytes()))
	sig = packet.(*Signature)
	if sig.SigLifetimeSecs == nil || *sig.SigLifetimeSecs != lifeTime {
		t.Errorf("signature lifetime is wrong: %d instead of %d", *sig.SigLifetimeSecs, lifeTime)
	}

	for _, subPacket := range sig.rawSubpackets {
		if subPacket.subpacketType == signatureExpirationSubpacket {
			if !subPacket.isCritical {
				t.Errorf("signature expiration subpacket is not marked as critical")
			}
		}
	}
}

func TestSignatureWithPolicyURI(t *testing.T) {
	testPolicy := "This is a test policy"
	sig := &Signature{
		SigType:    SigTypeGenericCert,
		PubKeyAlgo: PubKeyAlgoRSA,
		Hash:       crypto.SHA256,
		PolicyURI:  testPolicy,
	}

	packet, err := Read(readerFromHex(rsaPkDataHex))
	if err != nil {
		t.Fatalf("failed to deserialize public key: %v", err)
	}
	pubKey := packet.(*PublicKey)

	packet, err = Read(readerFromHex(privKeyRSAHex))
	if err != nil {
		t.Fatalf("failed to deserialize private key: %v", err)
	}
	privKey := packet.(*PrivateKey)

	err = privKey.Decrypt([]byte("testing"))
	if err != nil {
		t.Fatalf("failed to decrypt private key: %v", err)
	}

	err = sig.SignUserId("", pubKey, privKey, nil)
	if err != nil {
		t.Errorf("failed to sign user id: %v", err)
	}

	buf := bytes.NewBuffer([]byte{})
	err = sig.Serialize(buf)
	if err != nil {
		t.Errorf("failed to serialize signature: %v", err)
	}

	packet, _ = Read(bytes.NewReader(buf.Bytes()))
	sig = packet.(*Signature)
	if sig.PolicyURI != testPolicy {
		t.Errorf("signature policy is wrong: %s instead of %s", sig.PolicyURI, testPolicy)
	}

	for _, subPacket := range sig.rawSubpackets {
		if subPacket.subpacketType == policyUriSubpacket {
			if subPacket.isCritical {
				t.Errorf("policy URI subpacket is marked as critical")
			}
		}
	}
}

func TestSignatureWithTrust(t *testing.T) {
	packet, err := Read(readerFromHex(signatureWithTrustDataHex))
	if err != nil {
		t.Error(err)
		return
	}
	sig, ok := packet.(*Signature)
	if !ok || sig.SigType != SigTypeGenericCert || sig.PubKeyAlgo != PubKeyAlgoRSA || sig.Hash != crypto.SHA256 || sig.TrustLevel != 0x01 || sig.TrustAmount != 0x03C {
		t.Errorf("failed to parse, got: %#v", packet)
	}

	out := new(bytes.Buffer)
	err = sig.Serialize(out)
	if err != nil {
		t.Errorf("error reserializing: %s", err)
		return
	}

	expected, _ := hex.DecodeString(signatureWithTrustDataHex)
	if !bytes.Equal(expected, out.Bytes()) {
		t.Errorf("output doesn't match input (got vs expected):\n%s\n%s", hex.Dump(out.Bytes()), hex.Dump(expected))
	}
}

func TestSignatureWithTrustAndRegex(t *testing.T) {
	packet, err := Read(readerFromHex(signatureWithTrustRegexHex))
	if err != nil {
		t.Error(err)
		return
	}
	sig, ok := packet.(*Signature)
	if !ok || sig.SigType != SigTypeGenericCert || sig.PubKeyAlgo != PubKeyAlgoRSA || sig.Hash != crypto.SHA256 || sig.TrustLevel != 0x01 || sig.TrustAmount != 0x3C || *sig.TrustRegularExpression != "*.example.com" {
		t.Errorf("failed to parse, got: %#v", packet)
	}

	out := new(bytes.Buffer)
	err = sig.Serialize(out)
	if err != nil {
		t.Errorf("error reserializing: %s", err)
		return
	}

	expected, _ := hex.DecodeString(signatureWithTrustRegexHex)
	if !bytes.Equal(expected, out.Bytes()) {
		t.Errorf("output doesn't match input (got vs expected):\n%s\n%s", hex.Dump(out.Bytes()), hex.Dump(expected))
	}

	// ensure we fail if the regular expression is not null-terminated
	packet, err = Read(readerFromHex(signatureWithBadTrustRegexHex))
	if err == nil {
		t.Errorf("did not receive an error when expected")
	}
	if err.Error() != "openpgp: invalid data: expected regular expression to be null-terminated" {
		t.Errorf("unexpected error while parsing: %v", err)
	}
}

const onePassSignatureDataHex = `c40d03000201ab105c91af38fb1501`

const signatureDataHex = "c2c05c04000102000605024cb45112000a0910ab105c91af38fb158f8d07ff5596ea368c5efe015bed6e78348c0f033c931d5f2ce5db54ce7f2a7e4b4ad64db758d65a7a71773edeab7ba2a9e0908e6a94a1175edd86c1d843279f045b021a6971a72702fcbd650efc393c5474d5b59a15f96d2eaad4c4c426797e0dcca2803ef41c6ff234d403eec38f31d610c344c06f2401c262f0993b2e66cad8a81ebc4322c723e0d4ba09fe917e8777658307ad8329adacba821420741009dfe87f007759f0982275d028a392c6ed983a0d846f890b36148c7358bdb8a516007fac760261ecd06076813831a36d0459075d1befa245ae7f7fb103d92ca759e9498fe60ef8078a39a3beda510deea251ea9f0a7f0df6ef42060f20780360686f3e400e"

const signatureWithTrustDataHex = "c2ad0410010800210502886e09001621040f0bfb42b3b08bece556fffcc181c053de849bf20385013c000035d803ff405c3c10211d680d3f5192e44d5acf7a25068a9938b5e5b1337735658ef8916e6878735ddfe15679c4868fcf46f02890104a5fb7caffa8e628a202deeda8376d58e586d60c1759e667fa49d87c7564c83b88f59db2631dc7e68535fd4a13b6096f91b05f7bb9989ddb36fc7e6e35dcc2f493468320cbe66e27895744eab2ae4b"

const signatureWithTrustRegexHex = "c2bd0410010800310502886e09001621040f0bfb42b3b08bece556fffcc181c053de849bf20385013c0f862a2e6578616d706c652e636f6d000000620603ff7e405020cdbf82ac30f6ad11f82690d3c2fa2107130f80a66fc48a4b6cc426b90585670d8cb8e258f9c1fa35c62381074fd9b740aaebd96a3265c96d145620d7c24265c8e258a2f9a2229e4edb8076e27d5e229cf676135dde4dad54271e061adea05302e81ff412c55742b15c8b20fe3bee4c6b96cd9dfff44da9cc5df328ab"

const signatureWithBadTrustRegexHex = "c2bc0410010800300502886e09001621040f0bfb42b3b08bece556fffcc181c053de849bf20385013c0e862a2e6578616d706c652e636f6d00007e7103fe3fa66963f7a91ceb297286f57bab38446ba591215a9d6589ab6ec0d930438a4d79f80a52440e017dc6dd03f7425ccc1e059edda2b32f4975501eacc5676f216e56c568b75442c3efc750425f0d5276c7611ef838ce3f015f4de0969b4710aac8a76fcf2d48dd0749e937099b55ab77d93132e9777ba3b8cf89f908c2dbfff838"

const positiveCertSignatureDataHex = "c2c0b304130108005d050b0908070206150a09080b020416020301021e010217802418686b70733a2f2f686b70732e706f6f6c2e736b732d6b6579736572766572732e6e65741621045ef9b8a44d89b32f94f3e9333679666422d0f62605025b2cc122021b2f000a09103679666422d0f62668e1080098b71f59ce893769ccb603344290e89df8f12d6ea906cc1c2b166c61a02679070744565f8280712b4e6bdfd482b758ef935655f1674c8f3633ab173d27cbe31e46368a8255134ecc5249ad66324cc4f6a79f160459b326711cfdc35032aac0903657a934f80f79768786ddd6554aa8d385c03adbee17c4e3e2831752d4910077da3b1f5562d267a57540a1c2b0dd2d96ed055c06098599b2390d61cfa37c6d19d9d63749fb3c3cfe0036fd959ba616eb23486216563fed8fdd19f96f5da9943db1698705fb688c1354c379ef01de307c4a0ac016e6385324cb0a7b49cfeee8961a289c8fa4c81d0e24e00969039db223a9835e8b86a8d85df645175f8aa0f8f2"
