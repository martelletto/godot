// Copyright (c) 2016 Pedro Martelletto. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

package rand

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
)

func openReader() *os.File {
	r, err := os.Open("/dev/urandom")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	return r
}

func closeReader(r *os.File) {
	err := r.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

// Prime() obtains a random n-bit prime from /dev/urandom.
func Prime(n int) *big.Int {
	r := openReader()
	x, err := rand.Prime(r, n)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	closeReader(r)

	return x
}

// Bytes() reads n bytes from /dev/urandom.
func Bytes(n int) []byte {
	r := openReader()
	p := make([]byte, n)
	n, err := r.Read(p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	} else if n != len(p) {
		fmt.Fprintf(os.Stderr, "short read\n")
		os.Exit(1)
	}
	closeReader(r)

	return p
}

// Int() reads a uniform random integer in the range [0, max).
func Int(max *big.Int) *big.Int {
	r := openReader()
	n, err := rand.Int(r, max)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	closeReader(r)

	return n
}
