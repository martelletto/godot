// Copyright (c) 2016 Pedro Martelletto. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

package rand

import (
	"crypto/rand"
	"errors"
	"math/big"
	"os"
)

// Prime() obtains a random n-bit prime from /dev/urandom.
func Prime(n int) (*big.Int, error) {
	r, err := os.Open("/dev/urandom")
	if err != nil {
		return nil, err
	}
	x, err := rand.Prime(r, n)
	if err != nil {
		return nil, err
	}
	err = r.Close()
	if err != nil {
		return nil, err
	}

	return x, nil
}

// Bytes() reads n bytes from /dev/urandom.
func Bytes(n int) ([]byte, error) {
	r, err := os.Open("/dev/urandom")
	if err != nil {
		return nil, err
	}
	p := make([]byte, n)
	n, err = r.Read(p)
	if err != nil {
		return nil, err
	} else if n != len(p) {
		return nil, errors.New("short read")
	}
	err = r.Close()
	if err != nil {
		return nil, err
	}

	return p, nil
}

// Int() reads a uniform random integer in the range [0, max).
func Int(max *big.Int) (*big.Int, error) {
	r, err := os.Open("/dev/urandom")
	if err != nil {
		return nil, err
	}
	n, err := rand.Int(r, max)
	if err != nil {
		return nil, err
	}
	err = r.Close()
	if err != nil {
		return nil, err
	}

	return n, nil
}
