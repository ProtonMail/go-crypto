/// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package kmac_test implements a vector-based test suite for the cSHAKE KMAC implementation
package kmac_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/ProtonMail/go-crypto/internal/kmac"
	"hash"
	"testing"
)
// Test vectors from
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/cSHAKE_samples.pdf
var kmacTests = []struct {
	security                      int
	key, data, customization, tag string
}{
	{
		128,
		"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
		"00010203",
		"",
		"E5780B0D3EA6F7D3A429C5706AA43A00FADBD7D49628839E3187243F456EE14E",
	},
	{
		128,
		"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
		"00010203",
		"My Tagged Application",
		"3B1FBA963CD8B0B59E8C1A6D71888B7143651AF8BA0A7070C0979E2811324AA5",
	},
	{
		128,
		"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
		"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7",
		"My Tagged Application",
		"1F5B4E6CCA02209E0DCB5CA635B89A15E271ECC760071DFD805FAA38F9729230",
	},
	{
		256,
		"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
		"00010203",
		"My Tagged Application",
		"20C570C31346F703C9AC36C61C03CB64C3970D0CFC787E9B79599D273A68D2F7F69D4CC3DE9D104A351689F27CF6F5951F0103F33F4F24871024D9C27773A8DD",
	},
	{
		256,
		"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
		"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7",
		"",
		"75358CF39E41494E949707927CEE0AF20A3FF553904C86B08F21CC414BCFD691589D27CF5E15369CBBFF8B9A4C2EB17800855D0235FF635DA82533EC6B759B69",
	},
	{
		256,
		"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
		"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7",
		"My Tagged Application",
		"B58618F71F92E1D56C1B8C55DDD7CD188B97B4CA4D99831EB2699A837DA2E4D970FBACFDE50033AEA585F1A2708510C32D07880801BD182898FE476876FC8965",
	},
}
func TestKMAC(t *testing.T) {
	for i, test := range kmacTests {
		key, err := hex.DecodeString(test.key)
		if err != nil {
			t.Errorf("error decoding KAT: %s", err)
		}
		tag, err := hex.DecodeString(test.tag)
		if err != nil {
			t.Errorf("error decoding KAT: %s", err)
		}
		var mac hash.Hash
		if test.security == 128 {
			mac = kmac.NewKMAC128(key, len(tag), []byte(test.customization))
		} else {
			mac = kmac.NewKMAC256(key, len(tag), []byte(test.customization))
		}
		data, err := hex.DecodeString(test.data)
		if err != nil {
			t.Errorf("error decoding KAT: %s", err)
		}
		mac.Write(data)
		computedTag := mac.Sum(nil)
		if !bytes.Equal(tag, computedTag) {
			t.Errorf("#%d: got %x, want %x", i, tag, computedTag)
		}
		if mac.Size() != len(tag) {
			t.Errorf("#%d: Size() = %x, want %x", i, mac.Size(), len(tag))
		}
		// Test if it works after Reset.
		mac.Reset()
		mac.Write(data)
		computedTag = mac.Sum(nil)
		if !bytes.Equal(tag, computedTag) {
			t.Errorf("#%d: got %x, want %x", i, tag, computedTag)
		}
		// Test if Sum does not change state.
		if len(data) > 1 {
			mac.Reset()
			mac.Write(data[0:1])
			mac.Sum(nil)
			mac.Write(data[1:])
			computedTag = mac.Sum(nil)
			if !bytes.Equal(tag, computedTag) {
				t.Errorf("#%d: got %x, want %x", i, tag, computedTag)
			}
		}
	}
}
func ExampleNewKMAC256() {
	key := []byte("this is a secret key; you should generate a strong random key that's at least 32 bytes long")
	tag := make([]byte, 16)
	msg := []byte("The quick brown fox jumps over the lazy dog")
	// Example 1: Simple KMAC
	k := kmac.NewKMAC256(key, len(tag), []byte("Partition1"))
	k.Write(msg)
	k.Sum(tag[:0])
	fmt.Println(hex.EncodeToString(tag))
	// Example 2: Different customization string produces different digest
	k = kmac.NewKMAC256(key, 16, []byte("Partition2"))
	k.Write(msg)
	k.Sum(tag[:0])
	fmt.Println(hex.EncodeToString(tag))
	// Output:
	//3814d78758add078334b8ab9e5c4f942
	//3762371e99e1e01ab17742b95c0360da
}