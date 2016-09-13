// Copyright (c) 2016 Pedro Martelletto. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.
//
// The pss module implements the generation and verification
// of probabilistic RSA signatures as specified in PKCS#1v2.2.
// The mask generator function used is the one defined in
// section B.2.1 of the same document. SHA-256 is used as the
// digest mechanism, and the salt length is assumed to be the
// same size as a SHA-256 digest.

package pss

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"godot/rand"
	"godot/sha256"
	"io"
	"math"
	"math/big"
	"os"
)

const (
	saltLen = sha256.Len
)

// byte2big() transforms a []byte into a *big.Int.
func byte2big(p []byte) *big.Int {
	return new(big.Int).SetBytes(p)
}

// intCeil() rounds the division of two integers up to the nearest integer.
func intCeil(a, b uint32) uint32 {
	return uint32(math.Ceil(float64(a)/float64(b)))
}

// checkLen() implements the first step of 9.1.1 and 9.1.2.
func checkLen(emBits uint32) uint32 {
	emLen := intCeil(emBits, 8)
	if emLen < sha256.Len + saltLen + 2 {
		fmt.Fprintf(os.Stderr, "invalid msg len\n")
		os.Exit(1)
	}
	return emLen
}

// mgf1() implements the mask generator function defined in B.2.1.
func mgf1(mSeed []byte, mLen uint32) []byte {
	var t bytes.Buffer

	n := intCeil(mLen, sha256.Len)
	t.Grow(int(n * sha256.Len))

	for i := uint32(0); i < n; i++ {
		var seed = bytes.NewBuffer(mSeed)
		err := binary.Write(seed, binary.BigEndian, i)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		t.Write(sha256.DigestBytes(seed.Bytes()))
	}

	return t.Bytes()[:mLen]
}

// makeM() implements steps 5 of 9.1.1 and 12 of 9.1.2.
func makeM(mHash, salt []byte) []byte {
	return append(append(make([]byte, 8), mHash...), salt...)
}

// db() implements step 8 of 9.1.1.
func db(salt []byte) *big.Int {
	return byte2big(append(append(make([]byte, 0), 0x01), salt...))
}

// dbMask() implements step 9 of 9.1.1.
func dbMask(h []byte, mLen uint32) *big.Int {
	return byte2big(mgf1(h, mLen))
}

// Encode() implements the PSS encoding operation (section 9.1.1)
func Encode(in io.Reader, emBits uint32) *big.Int {
	emLen := checkLen(emBits)
	salt := rand.Bytes(saltLen)
	h := sha256.DigestBytes(makeM(sha256.DigestAll(in), salt))
	mLen := emLen - sha256.Len - 1
	masked := new(big.Int).Xor(db(salt), dbMask(h, mLen)).Bytes()
	masked[0] &= byte(0xff >> (8 * emLen - emBits)) // step 11

	return byte2big(append(append(masked, h...), 0xbc)) // step 12
}

// splitEncoded() splits an encoded blob into a masked data block and hash
// components.
func splitEncoded(em []byte, i int) ([]byte, []byte) {
	if em[len(em) - 1] != 0xbc {
		fmt.Fprintf(os.Stderr, "invalid signature\n")
		os.Exit(1)
	}

	return em[:i - sha256.Len], em[i - sha256.Len:i] // skip 0xbc
}

// Verify() implements the PSS verification operation (section 9.1.2)
func Verify(in io.Reader, em []byte, emBits uint32) bool {
	emLen := checkLen(emBits)
	masked, h := splitEncoded(em, len(em) - 1)
	if masked[0] >> byte(8 - (8 * emLen - emBits)) != 0 {
		fmt.Fprintf(os.Stderr, "invalid signature\n")
		os.Exit(1)
	}

	mask := mgf1(h, emLen - sha256.Len - 1)
	mask[0] &= byte(0xff >> (8 * emLen - emBits)) // step 9
	db := new(big.Int).Xor(byte2big(masked), byte2big(mask)).Bytes()
	if db[0] != 0x01 || len(db) != sha256.Len + 1 {
		fmt.Fprintf(os.Stderr, "invalid signature\n")
		os.Exit(1)
	}
	t := sha256.DigestBytes(makeM(sha256.DigestAll(in), db[1:]))

	return sha256.Equal(h, t)
}
