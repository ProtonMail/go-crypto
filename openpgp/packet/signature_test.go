// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"testing"
)

func TestSignatureRead(t *testing.T) {
	packet, err := Read(readerFromHex(signatureDataHex))
	if err != nil {
		t.Error(err)
		return
	}
	sig, ok := packet.(*Signature)
	if !ok || sig.SigType != SigTypeBinary || sig.PubKeyAlgo != PubKeyAlgoRSA || sig.Hash != crypto.SHA1 {
		t.Errorf("failed to parse, got: %#v", packet)
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

const signatureDataHex = "c2c05c04000102000605024cb45112000a0910ab105c91af38fb158f8d07ff5596ea368c5efe015bed6e78348c0f033c931d5f2ce5db54ce7f2a7e4b4ad64db758d65a7a71773edeab7ba2a9e0908e6a94a1175edd86c1d843279f045b021a6971a72702fcbd650efc393c5474d5b59a15f96d2eaad4c4c426797e0dcca2803ef41c6ff234d403eec38f31d610c344c06f2401c262f0993b2e66cad8a81ebc4322c723e0d4ba09fe917e8777658307ad8329adacba821420741009dfe87f007759f0982275d028a392c6ed983a0d846f890b36148c7358bdb8a516007fac760261ecd06076813831a36d0459075d1befa245ae7f7fb103d92ca759e9498fe60ef8078a39a3beda510deea251ea9f0a7f0df6ef42060f20780360686f3e400e"

const positiveCertSignatureDataHex = "c2c0b304130108005d050b0908070206150a09080b020416020301021e010217802418686b70733a2f2f686b70732e706f6f6c2e736b732d6b6579736572766572732e6e65741621045ef9b8a44d89b32f94f3e9333679666422d0f62605025b2cc122021b2f000a09103679666422d0f62668e1080098b71f59ce893769ccb603344290e89df8f12d6ea906cc1c2b166c61a02679070744565f8280712b4e6bdfd482b758ef935655f1674c8f3633ab173d27cbe31e46368a8255134ecc5249ad66324cc4f6a79f160459b326711cfdc35032aac0903657a934f80f79768786ddd6554aa8d385c03adbee17c4e3e2831752d4910077da3b1f5562d267a57540a1c2b0dd2d96ed055c06098599b2390d61cfa37c6d19d9d63749fb3c3cfe0036fd959ba616eb23486216563fed8fdd19f96f5da9943db1698705fb688c1354c379ef01de307c4a0ac016e6385324cb0a7b49cfeee8961a289c8fa4c81d0e24e00969039db223a9835e8b86a8d85df645175f8aa0f8f2"
