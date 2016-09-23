// Copyright (c) 2016 Pedro Martelletto. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.
//
// curve.go elliptic curve arithmetic over prime curves.

package prime

import (
	"fmt"
	"math/big"
)

// An elliptic curve of the form y^2 = x^3 + a*x + b.
type Curve struct {
	f   *Field   // over which the curve is defined
	a,b *Element // coefficients
}

// A point with nil x,y coordinates is considered a point at infinity.
type Point struct {
	c   *Curve   // associated curve
	x,y *Element // point coordinates
}

func (c *Curve) IsInf(p *Point) bool {
	return p.x == nil && p.y == nil
}

func (c *Curve) Define(f *Field, a, b int) *Curve {
	c.f = f
	c.a = f.Int64(int64(a))
	c.b = f.Int64(int64(b))
	return c
}

func (c *Curve) NewPoint() *Point {
	return new(Point).SetCurve(c)
}

func (p *Point) SetCurve(c *Curve) *Point {
	p.c = c
	return p
}

func (p *Point) Set(x, y *Element) *Point {
	c := p.c
	f := c.f
	// calculate both sides of the curve equation
	l := f.NewElement().Exp(y, f.Int64(2)) // y^2
	r := f.NewElement().Exp(x, f.Int64(3)) // x^3
	r.Add(r, f.NewElement().Mul(c.a, x))   // x^3 + a*x
	r.Add(r, c.b)                          // x^3 + a*x + b
	if l.Cmp(r) != 0 {
		panic("point not on curve")
	}
	p.x = x
	p.y = y

	return p
}

func (p *Point) GetX() *big.Int {
	return p.x.v
}

func (p *Point) GetY() *big.Int {
	return p.y.v
}

func (p *Point) SetInf() *Point {
	p.x = nil
	p.y = nil
	return p
}

func (p *Point) Neg(t *Point) *Point {
	c := t.c
	f := c.f
	if c.IsInf(t) {
		return p.SetInf() // -inf = inf
	} else {
		return p.Set(t.x, f.NewElement().Neg(t.y))
	}
}

func (p *Point) Equal(t *Point) bool {
	if p == t {
		return true
	} else if p.x != nil && t.x != nil {
		return p.x.Cmp(t.x) == 0 && p.y.Cmp(t.y) == 0
	} else {
		return false
	}
}

func (p *Point) String() string {
	c := p.c
	if c.IsInf(p) {
		return "(inf,inf)"
	} else {
		return fmt.Sprintf("(%s,%s)", p.x, p.y)
	}
}

// The three algorithms below (point doubling, addition and
// multiplication) follow the definitions given in Guide to Elliptic
// Curve Cryptogaphy by Hankerson, Menezes & Vanstone, first edition.

// Section 3.1.2
func (p *Point) Double(t *Point) *Point {
	c := t.c
	if t.Equal(c.NewPoint().Neg(t)) {
		return p.SetInf()
	}

	f := c.f
	x := f.NewElement()
	y := f.NewElement()

	y.Exp(t.x, f.Int64(2))
	y.Mul(y, f.Int64(3))
	y.Add(y, c.a)
	y.Div(y, f.NewElement().Mul(f.Int64(2), t.y))
	x.Exp(y, f.Int64(2))
	x.Sub(x, f.NewElement().Mul(f.Int64(2), t.x))
	y.Mul(y, f.NewElement().Sub(t.x, x))
	y.Sub(y, t.y)

	return p.Set(x, y)
}

// Section 3.1.2
func (p *Point) Add(t, u *Point) *Point {
	c := t.c
	if t.Equal(u) || t.Equal(c.NewPoint().Neg(u)) {
		return p.SetInf()
	} else if c.IsInf(u) {
		return p.Set(t.x, t.y)
	} else if c.IsInf(t) {
		return p.Set(u.x, u.y)
	}

	f := c.f
	x := f.NewElement()
	y := f.NewElement()
	y.Sub(u.y, t.y)
	y.Div(y, f.NewElement().Sub(u.x, t.x))
	x.Exp(y, f.Int64(2))
	x.Sub(x, t.x)
	x.Sub(x, u.x)
	y.Mul(y, f.NewElement().Sub(t.x, x))
	y.Sub(y, t.y)

	return p.Set(x, y)
}

// Algorithm 3.26
func (p *Point) Mul(t *Point, k *big.Int) *Point {
	c := t.c
	u := c.NewPoint().Set(t.x, t.y)
	p.SetInf()

	for i := 0; i < k.BitLen(); i++ {
		if k.Bit(i) == 1 {
			p.Add(p, u)
		}
		u.Double(u)
	}

	return p
}
