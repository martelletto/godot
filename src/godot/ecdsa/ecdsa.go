// Copyright (c) 2016 Pedro Martelletto. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

package ecdsa

import (
	"errors"
	"godot/ecdsa/sec1"
	"godot/ecdsa/secp256k1"
	"godot/sha256"
	"io"
)

type ecdsa struct {
	Private *sec1.PrivateKey
	Public  *sec1.PublicKey
}

func New() *ecdsa {
	return new(ecdsa)
}

// NewKey() creates a new secp256k1 key pair and writes it to w in PEM
// format. The parameter l is ignored.
func (ec *ecdsa) NewKey(l int, w io.Writer) error {
	q, d, err := secp256k1.NewPair()
	if err != nil {
		return err
	}
	k := new(sec1.PrivateKey)
	err = k.SetCurve(&secp256k1.OID)
	if err != nil {
		return err
	}
	err = k.SetPoint(q.GetX(), q.GetY())
	if err != nil {
		return err
	}
	k.SetGenerator(d)

	ec.Private = k

	return k.Write(w)
}

// LoadPriv() loads a private key from r.
func (ec *ecdsa) LoadPriv(r io.Reader) error {
	k, err := new(sec1.PrivateKey).Read(r)
	if err != nil {
		return err
	}
	id, err := k.GetCurveID()
	if err != nil {
		return nil
	}
	if secp256k1.OID.Equal(*id) == false {
		return errors.New("unsupported curve")
	}

	ec.Private = k

	return nil
}

// LoadPub() loads a public key from r.
func (k *ecdsa) LoadPub(r io.Reader) error {
//	fmt.Println("here 1?")
//	ec := &k.Public
//	_, err := ec.Read(r)
//	if err != nil {
//		return err
//	}
//	oid := ec.GetCurve()
//	if secp256k1.OID.Equal(*oid) == false {
//		return errors.New("unsupported curve")
//	}
	return nil
}

// WritePub() writes a public key to w.
func (ec *ecdsa) WritePub(w io.Writer) error {
	k := ec.Private
	x, y, err := k.GetPoint()
	if err != nil {
		return err
	}
	pk, err := new(sec1.PublicKey).SetPoint(x, y)
	if err != nil {
		return err
	}
	pk.SetCurve(&secp256k1.OID)

	return pk.Write(w)
}

// Sign() generates a signature of m and writes it to w.
func (ec *ecdsa) Sign(m io.Reader, w io.Writer) error {
	k := ec.Private
	d, err := k.GetGenerator()
	if err != nil {
		return err
	}
	h, err := sha256.DigestAll(m)
	if err != nil {
		return err
	}
	r, s, err := secp256k1.Sign(h, d)
	if err != nil {
		return err
	}

	return new(sec1.Signature).Set(r, s).Write(w)
}

// Verify() checks if t is a valid signature of m.
func (k *ecdsa) Verify(t, m io.Reader) (bool, error) {
//	fmt.Println("here?") var foo signature
//	tb, err := ioutil.ReadAll(t)
//	if err != nil {
//		return false, err
//	}
//        _, err = asn1.Unmarshal(tb, &foo)
//	if err != nil {
//		return false, err
//	}
//
//	f, c, g := secp256k1.GetCurve()
//
//	e, _ := sha256.DigestAll(m)
//	eF := f.Element(new(big.Int).SetBytes(e))
//	s := f.Element(foo.S)
//
//	fmt.Fprintf(os.Stderr, "r=%d\n", foo.R)
//	fmt.Fprintf(os.Stderr, "s=%d\n", foo.S)
//
//	w := f.NewElement().Inv(s)
//	u1 := f.NewElement().Mul(eF, w)
//	rF := f.Element(foo.R)
//	u2 := f.NewElement().Mul(rF, w)
//
//	fmt.Fprintf(os.Stderr, "w=%s\n", w)
//	fmt.Fprintf(os.Stderr, "u1=%s\n", u1)
//	fmt.Fprintf(os.Stderr, "u2=%s\n", u2)
//
//	A := c.NewPoint().Mul(g, u1.GetValue())
//	qX, qY, err := k.Public.GetPoint()
//	if err != nil {
//		return false, err
//	}
//	q := c.NewPoint().Set(f.Element(qX), f.Element(qY))
//	B := c.NewPoint().Mul(q, u2.GetValue())
//	fmt.Fprintf(os.Stderr, "A=%s\n", A)
//	fmt.Fprintf(os.Stderr, "B=%s\n", B)
//	C := c.NewPoint().Add(A, B)
//	fmt.Fprintf(os.Stderr, "C=%s\n", C)
//
	return false, nil
}
