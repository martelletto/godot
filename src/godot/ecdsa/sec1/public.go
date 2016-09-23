// Copyright (c) 2016 Pedro Martelletto. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

package sec1

import (
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"io"
	"io/ioutil"
)

var ecPublicKey asn1.ObjectIdentifier = []int{1,2,840,10045,2,1}

type Preamble struct {
	ObjectID asn1.ObjectIdentifier
	CurveID  asn1.ObjectIdentifier
}

type PublicKey struct {
	Preamble
	Point    asn1.BitString // public point q
}

// SetBytes() sets the body of the point q of a public key.
func (ec *PublicKey) SetBytes(p []byte) *PublicKey {
	ec.Point.Bytes = p
	return ec
}

// SetPoint() sets the coordinates of the point q of a public key.
func (ec *PublicKey) SetPoint(x, y *big.Int) (*PublicKey, error) {
	qX, qY := x.Bytes(), y.Bytes()
	if len(qX) != len(qY) {
		return nil, ErrBadPoint
	}
	p := make([]byte, 0, 1 + len(qX) + len(qY))
	v := &ec.Point
	v.Bytes = append(append(append(p, 0x04), qX...), qY...)

	return ec, nil
}

// GetPoint() retrieves the coordinates of the point q of a public key.
func (ec *PublicKey) GetPoint() (*big.Int, *big.Int, error) {
	p := ec.Point.Bytes
	if p == nil {
		return nil, nil, ErrEmptyKey
	}
	if len(p) < 2 || (len(p) - 1) % 2 != 0 || p[0] != 0x04 {
		return nil, nil, ErrBadKey
	}
	i := (len(p) - 1) / 2 + 1 // split p in half
	x := new(big.Int).SetBytes(p[1:i])
	y := new(big.Int).SetBytes(p[i:])

	return x, y, nil
}

// SetCurve() sets the curve ID of a public key.
func (ec *PublicKey) SetCurve(oid *asn1.ObjectIdentifier) *PublicKey {
	ec.CurveID = *oid
	return ec
}

// GetCurveID() retrieves the curve ID of a public key.
func (ec *PublicKey) GetCurveID() *asn1.ObjectIdentifier {
	return &ec.CurveID
}

// Write() marshals a PEM-encoded public key.
func (ec *PublicKey) Write(w io.Writer) error {
	var err error

	ec.ObjectID = ecPublicKey
	blob := new(pem.Block)
	blob.Type = "PUBLIC KEY"
	blob.Bytes, err = asn1.Marshal(*ec)
	if err != nil {
		return err
	}

	return pem.Encode(w, blob)
}

// Read() unmarshals a PEM-encoded public key.
func (ec *PublicKey) Read(r io.Reader) (*PublicKey, error) {
	body, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	blob, _ := pem.Decode(body)
	if blob == nil {
		return nil, ErrPemDecode
	}
	if blob.Type != "PUBLIC KEY" || blob.Bytes == nil {
		return nil, ErrBadPem
	}

	_, err = asn1.Unmarshal(blob.Bytes, ec)
	if err != nil {
		return nil, err
	}
	if ecPublicKey.Equal(ec.ObjectID) == false {
		return nil, ErrBadKey
	}

	return ec, nil
}
