// Copyright (c) 2016 Pedro Martelletto. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

package secp256k1

import (
	"encoding/asn1"
	"godot/ecdsa/prime"
	"godot/rand"
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

func Keypair() (*prime.Point, *big.Int, error) {
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
	q := c.NewPoint().Mul(g, d) // the public point

	return q, d, nil
}
