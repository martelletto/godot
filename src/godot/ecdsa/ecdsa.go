// Copyright (c) 2016 Pedro Martelletto. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

package ecdsa

import (
	"godot/ecdsa/asn1"
	"godot/ecdsa/secp256k1"
	"io"
)

type ecdsa struct {
}

func New() *ecdsa {
	return new(ecdsa)
}

// NewKey() creates a new secp256k1 key pair and writes it tow in PEM
// format. The parameter l is ignored.
func (k *ecdsa) NewKey(l int, w io.Writer) error {
	q, d, err := secp256k1.Keypair()
	if err != nil {
		return nil
	}
	return asn1.Write(secp256k1.OID, q, d, w)
}

// LoadPriv() loads a private key from r.
func (k *ecdsa) LoadPriv(r io.Reader) error {
	panic("not yet")
}

// LoadPub() loads a public key from r.
func (k *ecdsa) LoadPub(r io.Reader) error {
	panic("not yet")
}

// WritePub() writes a public key to w.
func (k *ecdsa) WritePub(w io.Writer) error {
	panic("not yet")
}

// Sign() generates a signature of m and writes it to w.
func (k *ecdsa) Sign(m io.Reader, w io.Writer) error {
	panic("not yet")
}

// Verify() checks if t is a valid signature of m.
func (k *ecdsa) Verify(t, m io.Reader) (bool, error) {
	panic("not yet")
}
