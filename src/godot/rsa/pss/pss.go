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
	"errors"
	"godot/rand"
	"godot/sha256"
	"io"
	"math"
	"math/big"
)

const (
	saltLen = sha256.Len
)

// byte2big() transforms a []byte into a *big.Int.
func byte2big(p []byte) *big.Int {
	return new(big.Int).SetBytes(p)
}

// intCeil() rounds the division of two integers up to the nearest
// integer.
func intCeil(a, b uint32) uint32 {
	return uint32(math.Ceil(float64(a)/float64(b)))
}

// mgf1() implements the mask generator function defined in B.2.1.
func mgf1(mSeed []byte, mLen uint32) ([]byte, error) {
	n := intCeil(mLen, sha256.Len)
	t := bytes.NewBuffer(make([]byte, 0, int(n * sha256.Len)))

	for i := uint32(0); i < n; i++ {
		seed := bytes.NewBuffer(mSeed)
		err := binary.Write(seed, binary.BigEndian, i)
		if err != nil {
			return nil, err
		}
		h, err := sha256.DigestBytes(seed.Bytes())
		if err != nil {
			return nil, err
		}
		t.Write(h)
	}

	return t.Bytes()[:mLen], nil
}

// Encode() implements the PSS encoding operation (section 9.1.1).
func Encode(in io.Reader, emBits uint32) (*big.Int, error) {
	// check the length of the desired encoded blob and acquire
	// a random salt of appropriate length.
	emLen := intCeil(emBits, 8)
	if emLen < sha256.Len + saltLen + 2 {
		return nil, errors.New("invalid msg len")
	}
	salt, err := rand.Bytes(saltLen)
	if err != nil {
		return nil, err
	}

	// hash the contents being signed, append the salt, and rehash.
	mHash, err := sha256.DigestAll(in)
	if err != nil {
		return nil, err
	}
	m := append(append(make([]byte, 8), mHash...), salt...)
	h, err := sha256.DigestBytes(m)
	if err != nil {
		return nil, err
	}

	// generate a mask and xor it with the salt to obtain a masked
	// data block.
	mLen := emLen - sha256.Len - 1
	mask, err := mgf1(h, mLen)
	if err != nil {
		return nil, err
	}
	db := byte2big(append(append(make([]byte, 0), 0x01), salt...))
	masked := new(big.Int).Xor(db, byte2big(mask)).Bytes()
	masked[0] &= byte(0xff >> (8 * emLen - emBits))

	return byte2big(append(append(masked, h...), 0xbc)), nil
}

// splitEncoded() splits an encoded blob into a masked data block and
// hash components.
func splitEncoded(em []byte, i int) ([]byte, []byte, error) {
	if em[len(em) - 1] != 0xbc {
		return nil, nil, errors.New("invalid signature")
	}
	// skip 0xbc
	return em[:i - sha256.Len], em[i - sha256.Len:i], nil
}

// Verify() implements the PSS verification operation (section 9.1.2).
func Verify(in io.Reader, em []byte, emBits uint32) (bool, error) {
	// verify the length of the encoded blob and split it in a
	// masked data block and hash components.
	emLen := intCeil(emBits, 8)
	if emLen < sha256.Len + saltLen + 2 {
		return false, errors.New("invalid msg len")
	}
	masked, h, err := splitEncoded(em, len(em) - 1)
	if err != nil {
		return false, err
	}

	// ensure that the (8 - emLen -emBits) most significant bits
	// of the masked data block are zero.
	if masked[0] >> byte(8 - (8 * emLen - emBits)) != 0 {
		return false, errors.New("invalid signature")
	}

	// recalculate the mask, and xor it to recover the original
	// data block, whose first byte should be 0x01.
	mask, err := mgf1(h, emLen - sha256.Len - 1)
	if err != nil {
		return false, err
	}
	mask[0] &= byte(0xff >> (8 * emLen - emBits))
	db := new(big.Int).Xor(byte2big(masked), byte2big(mask)).Bytes()
	if db[0] != 0x01 || len(db) != sha256.Len + 1 {
		return false, errors.New("invalid signature")
	}

	// hash the payload being verified, salt it with the recovered
	// data block, and rehash.
	mHash, err := sha256.DigestAll(in)
	if err != nil {
		return false, err
	}
	m := append(append(make([]byte, 8), mHash...), db[1:]...)
	t, err := sha256.DigestBytes(m)
	if err != nil {
		return false, err
	}

	return sha256.Equal(h, t), nil
}
