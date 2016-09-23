// Copyright (c) 2016 Pedro Martelletto. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

package secp256k1

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"godot/ecdsa/prime"
	"godot/rand"
	"godot/sha256"
	"math/big"
)

var OID asn1.ObjectIdentifier = []int{1, 3, 132, 0, 10}

// This is the order of the prime field over which secp256k1 is defined:
// 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1.
var fieldOrder = new(big.Int).SetBytes([]byte {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
})

// The order of the base point G.
var baseOrder = new(big.Int).SetBytes([]byte {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
	0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
	0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
})

// The X coordinate of the base point G.
var baseX = new(big.Int).SetBytes([]byte {
	0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
	0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
	0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
	0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
})

// The Y coordinate of the base point G.
var baseY = new(big.Int).SetBytes([]byte {
	0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65,
	0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8,
	0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19,
	0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8,
})

// instantiate a secp256k1 curve
func getCurve() (*prime.Field, *prime.Curve, *prime.Point) {
	f := new(prime.Field).SetOrder(fieldOrder)
	c := new(prime.Curve).Define(f, 0, 7)
	g := c.NewPoint().Set(f.Element(baseX), f.Element(baseY))
	return f, c, g
}

// NewPair() returns a new secp256k1 key pair (q,d).
func NewPair() (*prime.Point, *big.Int, error) {
	var d *big.Int
	var err error

	for {
		// rand.Int() returns an integer in [0,baseOrder).
		// we want d in [1,baseOrder).
		d, err = rand.Int(baseOrder)
		if err != nil {
			return nil, nil, err
		} else if d.Cmp(big.NewInt(0)) == 1 {
			break
		}
	}

	_, c, g := getCurve()
	q := c.NewPoint().Mul(g, d)

	return q, d, nil
}

// Given a field order n, a point generator d, and a message m, nonce()
// returns an integer k in the range [0,n) with a high probability of
// being unique for a given combination (d, m), and which is difficult
// to guess without knowledge of d.
func nonce(n, d *big.Int, m []byte) (*big.Int, error) {
	kLen := len(n.Bytes()) + 8
	kBuf := new(bytes.Buffer)

	for i := 0; i < kLen; i += sha256.Len {
		r, err := rand.Bytes(sha256.Len)
		if err != nil {
			return nil, err
		}
		// p is the concatenation of i, d, m, and r.
		p := bytes.NewBuffer(make([]byte, 0, 128))
		err = binary.Write(p, binary.BigEndian, uint32(i))
		if err != nil {
			return nil, err
		}
		p.Write(d.Bytes())
		p.Write(m)
		p.Write(r)
		h, err := sha256.DigestBytes(p.Bytes())
		if err != nil {
			return nil, err
		}
		kBuf.Write(h)
	}

	k := new(big.Int).SetBytes(kBuf.Bytes()[:kLen])

	return k.Mod(k, n), nil
}

// randPoint() calculates a random point on the curve, returning the
// point's x coordinate r and generator k, where k is a nonce.
func randPoint(h []byte, d *big.Int) (*big.Int, *big.Int, error) {
	var k *big.Int
	var n *big.Int = baseOrder
	var err error

	for {
		k, err = nonce(n, d, h)
		if err != nil {
			return nil, nil, err
		}
		if k.Cmp(big.NewInt(0)) != 0 {
			break
		}
	}

	_, c, g := getCurve()
	Gk := c.NewPoint().Mul(g, k)
	r := new(big.Int).Mod(Gk.GetX(), n)

	return k, r, nil
}

func doSign(h []byte, d *big.Int) (*big.Int, *big.Int, error) {
	var k *big.Int
	var r *big.Int
	var err error

	for {
		k, r, err = randPoint(h, d)
		if err != nil {
			return nil, nil, err
		}
		if r.Cmp(big.NewInt(0)) != 0 {
			break
		}
	}

	n := baseOrder
	f := new(prime.Field).SetOrder(n)
	e := new(big.Int).SetBytes(h)
	e.Mod(e, n)
	dF := f.Element(d)
	eF := f.Element(e)
	kF := f.Element(k)
	rF := f.Element(r)

	s := f.NewElement().Mul(dF, rF)
	s.Add(s, eF)
	s.Div(s, kF)

	return r, s.GetValue(), nil
}

func Sign(h []byte, d *big.Int) (*big.Int, *big.Int, error) {
	var r *big.Int
	var s *big.Int
	var err error

	if len(h) != 32 {
		return nil, nil, errors.New("invalid hash length")
	}

	for {
		r, s, err = doSign(h, d)
		if err != nil {
			return nil, nil, err
		}
		if s.Cmp(big.NewInt(0)) != 0 {
			break
		}
	}

	return r, s, nil
}
