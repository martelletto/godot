// Copyright (c) 2016 Pedro Martelletto. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

package sec1

import (
	"encoding/asn1"
	"encoding/pem"
	"godot/ecdsa/prime"
	"math/big"
	"io"
)


// As per https://tools.ietf.org/rfc/rfc5915.txt, section 3
type PrivateKey struct {
	Version    *big.Int
	PrivateKey  []byte
	Parameters  asn1.RawValue
	PublicKey   asn1.RawValue
}

// encodePub() encodes a public point as a ASN.1 BIT STRING blob in
// uncompressed format.
func encodePub(q *prime.Point) ([]byte, error) {
	var blob asn1.BitString
	var x = q.GetX().Bytes()
	var y = q.GetY().Bytes()

	blob.Bytes = append(make([]byte, 0, 1 + len(x) + len(y)), 0x04)
	blob.Bytes = append(append(blob.Bytes, x...), y...)

	return asn1.Marshal(blob)
}

func Write(oid asn1.ObjectIdentifier, q *prime.Point, d *big.Int,
    w io.Writer) error {
	var blob = new(pem.Block)
	var ec = new(PrivateKey)
	var err error

	ec.Version = big.NewInt(1)
	ec.PrivateKey = d.Bytes()
	ec.Parameters.Class = asn1.ClassContextSpecific
	ec.Parameters.IsCompound = true // constructed
	ec.Parameters.Tag = 0x00
	ec.Parameters.Bytes, err = asn1.Marshal(oid)
	if err != nil {
		return err
	}
	ec.PublicKey.Class = asn1.ClassContextSpecific
	ec.PublicKey.IsCompound = true // constructed
	ec.PublicKey.Tag = 0x01
	ec.PublicKey.Bytes, err = encodePub(q)
	if err != nil {
		return err
	}

	blob.Type = "EC PRIVATE KEY"
	blob.Bytes, err = asn1.Marshal(*ec)
	if err != nil {
		return err
	}

	return pem.Encode(w, blob)
}
