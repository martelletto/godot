package sha256

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
)

const (
	chunkLen = 1 << 13  // how much we try to read from stdin in one loop
	maxRounds = 1 << 48 // maximum number of times we will loop
	padLen = 72         // space reserved for padding of the last message
	hLen = 32           // length of a SHA-256 digest in bytes
)

var shaK = [64]uint32 {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

var shaH = [8]uint32 {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

func ch(x, y, z uint32) uint32 {
	return (x & y) ^ (^x & z)
}

func maj(x, y, z uint32) uint32 {
	return (x & y) ^ (x & z) ^ (y & z)
}

func rotr(x, n uint32) uint32 {
	return (x >> n) | (x << (32 - n))
}

func upperSigma0(x uint32) uint32 {
	return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

func upperSigma1(x uint32) uint32 {
	return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}

func lowerSigma0(x uint32) uint32 {
	return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
}

func lowerSigma1(x uint32) uint32 {
	return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
}

func sha256(h [8]uint32, m []uint32) [8]uint32 {
	var l = make([]uint32, 8)
	var w = make([]uint32, 64)

	copy(w, m)

	for t := 16; t < 64; t++ {
		w[t] = lowerSigma1(w[t - 2]) + w[t - 7] +
		    lowerSigma0(w[t - 15]) + w[t - 16]
	}

	for i := 0; i < 8; i++ {
		l[i] = h[i]
	}

	for t := 0; t < 64; t++ {
		t1 := l[7] + upperSigma1(l[4]) + ch(l[4], l[5], l[6]) +
		    shaK[t] + w[t]
		t2 := upperSigma0(l[0]) + maj(l[0], l[1], l[2])
		l[7] = l[6]
		l[6] = l[5]
		l[5] = l[4]
		l[4] = l[3] + t1
		l[3] = l[2]
		l[2] = l[1]
		l[1] = l[0]
		l[0] = t1 + t2
	}

	for i := 0; i < 8; i++ {
		h[i] += l[i]
	}

	return h
}

func hash(h [8]uint32, chunk []byte) [8]uint32 {
	var m = make([]uint32, len(chunk) / 4)

	err := binary.Read(bytes.NewBuffer(chunk), binary.BigEndian, m)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	for i := 0; i < len(m); i += 16 {
		h = sha256(h, m[i:(i+16)])
	}

	return h
}

func wrap(chunk []byte, totalRounds int) []byte {
	var padding = make([]byte, padLen)

	padding[0] = 0x80 // one bit set followed by seven bits unset
	z := uint64((56 - len(chunk))) % 64 // followed by z zero bytes
	t := uint64((len(chunk) + (totalRounds * chunkLen)) * 8)

	for i := uint64(0); i < 8; i++ {
		// total msg len in bits, in big-endian notation
		padding[z + i] = byte((t >> (8 * (7 - i))) & 0xff)
	}

	return append(chunk, padding[:(z + 8)]...)
}

func toByteSlice(h [8]uint32) []byte {
	var r bytes.Buffer

	r.Grow(hLen)
	err := binary.Write(&r, binary.BigEndian, h)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	return r.Bytes()
}

func Digest(r io.Reader) []byte {
	var chunk = make([]byte, chunkLen)
	var h = shaH
	var i int

	in := bufio.NewReader(r)
	for i = 0; i < maxRounds; i++ {
		n, err := in.Read(chunk)
		if err != nil && err != io.EOF {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		} else if n != chunkLen {
			h = hash(h, wrap(chunk[:n], i))
			break
		} else {
			h = hash(h, chunk)
		}
	}

	if i == maxRounds {
		fmt.Fprintf(os.Stderr, "sha256.Digest: input too long\n")
		os.Exit(1)
	}

	return toByteSlice(h)
}

func DigestBytes(p []byte) []byte {
	return toByteSlice(hash(shaH, wrap(p, 0)))
}

// As per PKCS#1v2.2, B.2.1
func MGF1(mgfSeed []byte, maskLen uint32) []byte {
	if maskLen > 2^31*hLen {
		fmt.Fprintf(os.Stderr, "MGF1: mask too long\n")
		os.Exit(1)
	}

	n := int(math.Ceil(float64(maskLen)/float64(hLen)))
	var t bytes.Buffer
	t.Grow(int(n * hLen))

	for i := 0; i < n; i++ {
		var seed = bytes.NewBuffer(mgfSeed)
		seed.Grow(4)
		err := binary.Write(seed, binary.BigEndian, n)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		t.Write(DigestBytes(seed.Bytes()))
	}

	return t.Bytes()
}
