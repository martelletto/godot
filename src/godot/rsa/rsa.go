// Copyright (c) 2016 Pedro Martelletto. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.
//
// This file implements the core of the RSA algorithm.

package rsa

import (
	"godot/rand"
	"godot/rsa/pkcs1"
	"godot/rsa/pss"
	"godot/util"
	"godot/x509"
	"io"
	"math/big"
)

type rsa struct {
	pkcs1 *pkcs1.PrivateKey
	x509  *pkcs1.PublicKey
}

func New() *rsa {
	return new(rsa)
}

// NewKey() creates a new l-bit long private key and writes it to w in
// PEM format.
func (k *rsa) NewKey(l int, w io.Writer) error {
	p, err := rand.Prime(l/2)
	if err != nil {
		return err
	}
	q, err := rand.Prime(l/2)
	if err != nil {
		return err
	}
	n := new(big.Int).Mul(p, q)
	e := big.NewInt(65537)
	pMinus := new(big.Int).Sub(p, big.NewInt(1))
	qMinus := new(big.Int).Sub(q, big.NewInt(1))
	phi := new(big.Int).Mul(pMinus, qMinus)
	d := new(big.Int).ModInverse(e, phi)

	k.pkcs1 = new(pkcs1.PrivateKey)
	k.pkcs1.Version = big.NewInt(0)
	k.pkcs1.Prime1 = p
	k.pkcs1.Prime2 = q
	k.pkcs1.Modulus = n
	k.pkcs1.PublicExponent = e
	k.pkcs1.PrivateExponent = d
	k.pkcs1.Exponent1 = new(big.Int).Mod(d, pMinus)
	k.pkcs1.Exponent2 = new(big.Int).Mod(d, qMinus)
	k.pkcs1.Coefficient = new(big.Int).ModInverse(q, p)

	return pkcs1.Write(k.pkcs1, w)
}

// LoadPriv() loads a private key from r.
func (k *rsa) LoadPriv(r io.Reader) error {
	var err error
	k.pkcs1, err = pkcs1.Read(r)
	return err
}

// LoadPub() loads a public key from r.
func (k *rsa) LoadPub(r io.Reader) error {
	var err error
	k.x509, err = x509.ReadRSA(r)
	return err
}

// WritePub() writes a public key to w.
func (k *rsa) WritePub(w io.Writer) error {
	return x509.WriteRSA(k.pkcs1, w)
}

// Sign() generates a signature of m and writes it to w.
func (k *rsa) Sign(m io.Reader, w io.Writer) error {
	h, err := pss.Encode(m, 4095)
	if err != nil {
		return err
	}
	d := k.pkcs1.PrivateExponent
	n := k.pkcs1.Modulus
	s := new(big.Int).Exp(h, d, n)
	w.Write(s.Bytes())
	return nil
}

// Verify() checks if t is a valid signature of m.
func (k *rsa) Verify(t, m io.Reader) (bool, error) {
	body := util.ReadAll(t)
	e := k.x509.PublicExponent
	n := k.x509.Modulus
	s := new(big.Int).SetBytes(body)
	h := new(big.Int).Exp(s, e, n)
	return pss.Verify(m, h.Bytes(), 4095)
}
