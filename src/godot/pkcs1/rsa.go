// Copyright (c) 2016 Pedro Martelletto
// All rights reserved.
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//
// The pkcs1 module exports functions that allow RSA PKCS1 private keys to be
// written and read.

package pkcs1

import (
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"godot/util"
	"io"
	"io/ioutil"
	"math/big"
	"os"
)

// As per https://www.ietf.org/rfc/rfc3447.txt, A.1.2
type RSAPrivateKey struct {
	Version		*big.Int
	Modulus		*big.Int
	PublicExponent	*big.Int
	PrivateExponent	*big.Int
	Prime1		*big.Int
	Prime2		*big.Int
	Exponent1	*big.Int
	Exponent2	*big.Int
	Coefficient	*big.Int
}

// As per https://www.ietf.org/rfc/rfc3447.txt, A.1.1
type RSAPublicKey struct {
	Modulus		*big.Int
	PublicExponent	*big.Int
}

// WriteRSA() writes a PKCS1 RSA private key in PEM format.
func WriteRSA(rsa *RSAPrivateKey, w io.Writer) {
	var blob = new(pem.Block)
	var err error

	blob.Type = "RSA PRIVATE KEY"
	blob.Bytes, err = asn1.Marshal(*rsa)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	util.WritePEM(blob, w)
}

// ReadRSA() reads a PKCS1 RSA private key in PEM format.
func ReadRSA(r io.Reader) *RSAPrivateKey {
	var rsa = new (RSAPrivateKey)

	body, err := ioutil.ReadAll(r)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	blob, _ := pem.Decode(body)
	if blob == nil {
		fmt.Fprintf(os.Stderr, "pem decode error\n")
		os.Exit(1)
	}
	if blob.Type != "RSA PRIVATE KEY" || blob.Bytes == nil {
		fmt.Fprintf(os.Stderr, "invalid pem\n")
		os.Exit(1)
	}
	_, err = asn1.Unmarshal(blob.Bytes, rsa)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	return rsa
}
