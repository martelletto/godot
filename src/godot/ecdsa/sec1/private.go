// Copyright (c) 2016 Pedro Martelletto. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

package sec1

import (
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"io"
	"io/ioutil"
)

var (
	ErrEmptyKey  = errors.New("sec1: empty key")
	ErrBadKey    = errors.New("sec1: invalid key")
	ErrPemDecode = errors.New("sec1: pem decode error")
	ErrBadPem    = errors.New("sec1: invalid pem")
	ErrBadPoint  = errors.New("sec1: invalid point")
)

type PrivateKey struct {
	Version    *big.Int
	PrivateKey  []byte
	Parameters  asn1.RawValue
	PublicKey   asn1.RawValue
}

type Signature struct {
	R *big.Int
	S *big.Int
}

// SetGenerator() sets the generator d of a private key.
func (ec *PrivateKey) SetGenerator(d *big.Int) *PrivateKey {
	ec.PrivateKey = d.Bytes()
	return ec
}

// GetGenerator() retrieves the generator d of a private key.
func (ec *PrivateKey) GetGenerator() (*big.Int, error) {
	if ec.PrivateKey == nil {
		return nil, ErrEmptyKey
	}
	return new(big.Int).SetBytes(ec.PrivateKey), nil
}

// SetCurve() sets the curve ID of a private key.
func (ec *PrivateKey) SetCurve(oid *asn1.ObjectIdentifier) error {
	var err error

	v := &ec.Parameters
	v.Class = asn1.ClassContextSpecific
	v.IsCompound = true // constructed
	v.Tag = 0x00
	v.Bytes, err = asn1.Marshal(*oid)

	return err
}

// GetCurveID() retrieves the curve ID of a private key.
func (ec *PrivateKey) GetCurveID() (*asn1.ObjectIdentifier, error) {
	v := &ec.Parameters
	if v.Class != asn1.ClassContextSpecific ||
	   v.IsCompound != true ||
	   v.Tag != 0x00 ||
	   v.Bytes == nil {
		return nil, ErrBadKey
	}

	oid := new(asn1.ObjectIdentifier)
	_, err := asn1.Unmarshal(v.Bytes, oid)
	if err != nil {
		return nil, err
	}

	return oid, nil
}

// SetPoint() sets the public point q of a private key.
func (ec *PrivateKey) SetPoint(x, y *big.Int) error {
	pub, err := new(PublicKey).SetPoint(x, y)
	if err != nil {
		return err
	}

	v := &ec.PublicKey
	v.Class = asn1.ClassContextSpecific
	v.IsCompound = true // constructed
	v.Tag = 0x01
	b := new(asn1.BitString)
	b.Bytes = pub.Point.Bytes
	v.Bytes, err = asn1.Marshal(*b)

	return err
}

// GetPoint() retrieves the public point q of a private key.
func (ec *PrivateKey) GetPoint() (*big.Int, *big.Int, error) {
	v := &ec.PublicKey
	if v.Class != asn1.ClassContextSpecific ||
	   v.IsCompound != true ||
	   v.Tag != 0x01 ||
	   v.Bytes == nil {
		return nil, nil, ErrBadKey
	}

	b := new(asn1.BitString)
	_, err := asn1.Unmarshal(v.Bytes, b)
	if err != nil {
		return nil, nil, err
	}

	return new(PublicKey).SetBytes(b.Bytes).GetPoint()
}

// Write() marshals a PEM-encoded private key.
func (ec *PrivateKey) Write(w io.Writer) error {
	var err error

	ec.Version = big.NewInt(1)
	blob := new(pem.Block)
	blob.Type = "EC PRIVATE KEY"
	blob.Bytes, err = asn1.Marshal(*ec)
	if err != nil {
		return err
	}

	return pem.Encode(w, blob)
}

// Read() unmarshals a PEM-encoded private key.
func (ec *PrivateKey) Read(r io.Reader) (*PrivateKey, error) {
	body, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	blob, _ := pem.Decode(body)
	if blob == nil {
		return nil, ErrPemDecode
	}
	if blob.Type != "EC PRIVATE KEY" || blob.Bytes == nil {
		return nil, ErrBadPem
	}

	_, err = asn1.Unmarshal(blob.Bytes, ec)
	if err != nil {
		return nil, err
	}
	if ec.Version == nil || ec.Version.Cmp(big.NewInt(1)) != 0 {
		return nil, ErrBadKey
	}

	return ec, nil
}

func (sig *Signature) Set(r, s *big.Int) *Signature {
	sig.R = r
	sig.S = s
	return sig
}

func (sig *Signature) Write(w io.Writer) error {
	body, err := asn1.Marshal(*sig)
	if err != nil {
		return err
	}
	w.Write(body)

	return nil
}

func (sig *Signature) Read(r io.Reader) (*Signature, error) {
	body, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	_, err = asn1.Unmarshal(body, sig)
	if err != nil {
		return nil, err
	}

	return sig, nil
}
