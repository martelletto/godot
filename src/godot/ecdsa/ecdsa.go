// Copyright (c) 2016 Pedro Martelletto. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

package ecdsa

import (
	"errors"
	"godot/ecdsa/sec1"
	"godot/ecdsa/secp256k1"
	"io"
)

type ecdsa struct {
	Private sec1.PrivateKey
}

func New() *ecdsa {
	return new(ecdsa)
}

// NewKey() creates a new secp256k1 key pair and writes it tow in PEM
// format. The parameter l is ignored.
func (k *ecdsa) NewKey(l int, w io.Writer) error {
	q, d, err := secp256k1.NewKeyPair()
	if err != nil {
		return err
	}

	ec := &k.Private
	ec.Set(d)
	err = ec.SetCurve(&secp256k1.OID)
	if err != nil {
		return err
	}
	err = ec.SetPoint(q.GetX(), q.GetY())
	if err != nil {
		return err
	}

	return ec.Write(w)
}

// LoadPriv() loads a private key from r.
func (k *ecdsa) LoadPriv(r io.Reader) error {
	ec := &k.Private
	_, err := ec.Read(r)
	if err != nil {
		return err
	}

	oid, err := ec.GetCurve()
	if err != nil {
		return err
	}
	if secp256k1.OID.Equal(*oid) == false {
		return errors.New("unsupported curve")
	}

	return nil
}

// LoadPub() loads a public key from r.
func (k *ecdsa) LoadPub(r io.Reader) error {
	panic("not yet")
}

// WritePub() writes a public key to w.
func (k *ecdsa) WritePub(w io.Writer) error {
	x, y, _ := k.Private.GetPoint()
	pub, _ := new(sec1.PublicKey).SetPoint(x, y)
	pub.SetCurve(&secp256k1.OID)
	return pub.Write(w)
}

// Sign() generates a signature of m and writes it to w.
func (k *ecdsa) Sign(m io.Reader, w io.Writer) error {
	panic("not yet")
}

// Verify() checks if t is a valid signature of m.
func (k *ecdsa) Verify(t, m io.Reader) (bool, error) {
	panic("not yet")
}
