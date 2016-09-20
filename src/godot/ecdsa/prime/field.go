// Copyright (c) 2016 Pedro Martelletto. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.
//
// field.go implements finite field arithmetic primitives.

package prime

import (
	"math/big"
)

type Field struct {
	n *big.Int // must be a prime
}

type Element struct {
	f *Field
	v *big.Int
}

func (f *Field) SetOrder(n *big.Int) *Field {
	f.n = n
	return f
}

func (f *Field) Int64(v int64) *Element {
	return new(Element).SetField(f).SetValue(big.NewInt(v))
}

func (f *Field) Element(v *big.Int) *Element {
	return new(Element).SetField(f).SetValue(v)
}

func (f *Field) NewElement() *Element {
	return f.Int64(0)
}

func (e *Element) String() string {
	return e.v.String()
}

func (e *Element) SetField(f *Field) *Element {
	e.f = f
	return e
}

func (e *Element) SetValue(v *big.Int) *Element {
	if v.Cmp(big.NewInt(0)) == -1 || v.Cmp(e.f.n) != -1 {
		panic("integer out of field range")
	}
	e.v = v
	return e
}

func (e *Element) Mod(v *big.Int) *Element {
	e.v.Mod(v, e.f.n)
	return e
}

func (e *Element) Add(x, y *Element) *Element {
	return e.Mod(e.v.Add(x.v, y.v))
}

func (e *Element) Sub(x, y *Element) *Element {
	return e.Mod(e.v.Sub(x.v, y.v))
}

func (e *Element) Mul(x, y *Element) *Element {
	return e.Mod(e.v.Mul(x.v, y.v))
}

func (e *Element) Div(x, y *Element) *Element {
	return e.Mul(x, new(Element).Inv(y))
}

func (e *Element) Exp(x, y *Element) *Element {
	e.v.Exp(x.v, y.v, e.f.n)
	return e
}

func (e *Element) Neg(x *Element) *Element {
	f := e.f
	return f.NewElement().Sub(f.Int64(0), x)
}

func (e *Element) Cmp(x *Element) int {
	return e.v.Cmp(x.v)
}

// Inv() uses Go's GCD() to compute the inverse 'x' of an element 'a' on
// a prime field of order 'n', i.e x such that (a*x)modn = 1.
func (e *Element) Inv(a *Element) *Element {
	var d = new(big.Int)
	var x = new(big.Int)
	var f = a.f
	// d must be 1, since a.v < f.n and f.n is prime.
	if d.GCD(x, nil, a.v, f.n).Cmp(big.NewInt(1)) != 0 {
		panic("bogus parameters in element inversion")
	}
	e.f = f
	e.v = x
	return e
}
