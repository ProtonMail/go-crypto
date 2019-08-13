// Copyright (C) 2019 ProtonTech AG
// This file contains necessary tools for the eax package.
//
// These functions are not meant to be exported, since they
// are optimized for specific input nature.

package eax

// The irreducible polynomial in the finite field for n=128 is
// x^128 + x^7 + x^2 + x + 1 (equals 0x87)
// Constant-time execution in order to avoid side-channel attacks
func gfnDouble(input []byte) []byte {
	if len(input) != 16 {
		panic("Doubling in GFn only implemented for n = 128")
	}
	// If the first bit is zero, return 2L = L << 1
	// Else return (L << 1) xor 0^120 10000111
	shifted := shiftBytesLeft(input)
	shifted[15] ^= ((input[0] >> 7) * 0x87)
	return shifted
}

// For any bytes array L, outputs the byte array corresponding to L << 1 in
// binary.
func shiftBytesLeft(x []byte) (dst []byte) {
	l := len(x)
	dst = make([]byte, l)
	for i := 0; i < l-1; i++ {
		dst[i] = x[i] << 1
		dst[i] = (dst[i] & 0xfe) | (x[i+1] >> 7)
	}
	dst[l-1] = x[l-1] << 1
	return dst
}

// Assume same length of inputs (else see rightXorMut)
func xorBytes(dst, X, Y []byte) {
	if len(X) != len(Y) {
		panic("Different argument length in xorBytes")
	}
	for i := 0; i < len(Y); i++ {
		dst[i] = X[i] ^ Y[i]
	}
}

// XORs the smaller input at the right of the larger input
func rightXorMut(X, Y []byte) []byte {
	offset := len(Y) - len(X)
	if offset < 0 {
		return rightXorMut(Y, X)
	}

	xored := make([]byte, len(Y));
	copy(xored, Y)
	for i := 0; i < len(X); i++ {
		xored[offset + i] ^= X[i]
	}

	return xored
}
