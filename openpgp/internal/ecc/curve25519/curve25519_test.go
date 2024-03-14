// Package curve25519 implements custom field operations without clamping for forwarding.
package curve25519

import (
	"bytes"
	"encoding/hex"
	"testing"
)

const (
	hexBobSecret = "5989216365053dcf9e35a04b2a1fc19b83328426be6bb7d0a2ae78105e2e3188"
	hexCharlesSecret = "684da6225bcd44d880168fc5bec7d2f746217f014c8019005f144cc148f16a00"
	hexExpectedProxyParam = "e89786987c3a3ec761a679bc372cd11a425eda72bd5265d78ad0f5f32ee64f02"

	hexMessagePoint = "aaea7b3bb92f5f545d023ccb15b50f84ba1bdd53be7f5cfadcfb0106859bf77e"
	hexInputProxyParam = "83c57cbe645a132477af55d5020281305860201608e81a1de43ff83f245fb302"
	hexExpectedTransformedPoint = "ec31bb937d7ef08c451d516be1d7976179aa7171eea598370661d1152b85005a"

	hexSmallSubgroupPoint = "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
)

func TestDeriveProxyParam(t *testing.T) {
	bobSecret, err := hex.DecodeString(hexBobSecret)
	if err != nil {
		t.Fatalf("Unexpected error in decoding recipient secret: %s", err)
	}

	charlesSecret, err := hex.DecodeString(hexCharlesSecret)
	if err != nil {
		t.Fatalf("Unexpected error in decoding forwardee secret: %s", err)
	}

	expectedProxyParam, err := hex.DecodeString(hexExpectedProxyParam)
	if err != nil {
		t.Fatalf("Unexpected error in parameter decoding expected proxy parameter: %s", err)
	}

	proxyParam, err := DeriveProxyParam(bobSecret, charlesSecret)
	if err != nil {
		t.Fatalf("Unexpected error in parameter derivation: %s", err)
	}

	if bytes.Compare(proxyParam, expectedProxyParam) != 0 {
		t.Errorf("Computed wrong proxy parameter, expected %x got %x", expectedProxyParam, proxyParam)
	}
}

func TestTransformMessage(t *testing.T) {
	proxyParam, err := hex.DecodeString(hexInputProxyParam)
	if err != nil {
		t.Fatalf("Unexpected error in decoding proxy parameter: %s", err)
	}

	messagePoint, err := hex.DecodeString(hexMessagePoint)
	if err != nil {
		t.Fatalf("Unexpected error in decoding message point: %s", err)
	}

	expectedTransformed, err := hex.DecodeString(hexExpectedTransformedPoint)
	if err != nil {
		t.Fatalf("Unexpected error in parameter decoding expected transformed point: %s", err)
	}

	transformed, err := ProxyTransform(messagePoint, proxyParam)
	if err != nil {
		t.Fatalf("Unexpected error in parameter derivation: %s", err)
	}

	if bytes.Compare(transformed, expectedTransformed) != 0 {
		t.Errorf("Computed wrong proxy parameter, expected %x got %x", expectedTransformed, transformed)
	}
}

func TestTransformSmallSubgroup(t *testing.T) {
	proxyParam, err := hex.DecodeString(hexInputProxyParam)
	if err != nil {
		t.Fatalf("Unexpected error in decoding proxy parameter: %s", err)
	}

	messagePoint, err := hex.DecodeString(hexSmallSubgroupPoint)
	if err != nil {
		t.Fatalf("Unexpected error in decoding small sugroup point: %s", err)
	}

	_, err = ProxyTransform(messagePoint, proxyParam)
	if err == nil {
		t.Error("Expected small subgroup error")
	}
}
