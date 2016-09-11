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

// Unless specified otherwise, all references in this file are relative to
// PKCS#1v2.2 section 9.1.1.

// byte2big() transforms a []byte into a *big.Int.
func byte2big(p []byte) *big.Int {
	return new(big.Int).SetBytes(p)
}

// big2byte() transforms a *big.Int into a []byte.
func big2byte(x *big.Int) []byte {
	return x.Bytes()
}

// intCeil() rounds the division of two integers up to the nearest integer.
func intCeil(a, b uint32) uint32 {
	return uint32(math.Ceil(float64(a)/float64(b)))
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

// makeM() implements step 5.
func makeM(mHash, salt []byte) []byte {
	return append(append(make([]byte, 8), mHash...), salt...)
}

// db() implements step 8.
func db(salt []byte) *big.Int {
	return byte2big(append(append(make([]byte, 0), 0x01), salt...))
}

// dbMask() implements step 9.
func dbMask(h []byte, mLen uint32) *big.Int {
	return byte2big(mgf1(h, mLen))
}

// makeEM() implements step 12.
func makeEM(maskedDB *big.Int, h []byte) *big.Int {
	return byte2big(append(append(big2byte(maskedDB), h...), 0xbc))
}

// Encode() implements the EMSA-PSS encoding operation.
func Encode(in io.Reader, emBits uint32) *big.Int {
	emLen := intCeil(emBits, 8)
	if emLen < sha256.Len + saltLen + 2 {
		fmt.Fprintf(os.Stderr, "encoding error\n")
		os.Exit(1)
	}

	salt := rand.Bytes(saltLen)
	h := sha256.DigestBytes(makeM(sha256.DigestAll(in), salt))
	mLen := emLen - sha256.Len - 1

	maskedDB := new(big.Int).Xor(db(salt), dbMask(h, mLen))
	for i := uint32(0); i < 8 * emLen - emBits; i++ {
		// step 11: clear the leftmost 8 * emLen - emBits bits of
		// maskedDB.
		maskedDB.SetBit(maskedDB, int(mLen * 8 - 1 - i), 0)
	}

	return makeEM(maskedDB, h)
}
