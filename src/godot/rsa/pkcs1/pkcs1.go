// Copyright (c) 2016 Pedro Martelletto. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.
//
// The pkcs1 module exports functions that allow RSA PKCS1
// private keys to be read and written.

package pkcs1

import (
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"math/big"
)

// As per https://www.ietf.org/rfc/rfc3447.txt, A.1.2
type PrivateKey struct {
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
type PublicKey struct {
	Modulus		*big.Int
	PublicExponent	*big.Int
}

// Write() writes a PKCS1 RSA private key in PEM format.
func Write(rsa *PrivateKey, w io.Writer) error {
	var blob = new(pem.Block)
	var err error

	blob.Type = "RSA PRIVATE KEY"
	blob.Bytes, err = asn1.Marshal(*rsa)
	if err != nil {
		return err
	}

	return pem.Encode(w, blob)
}

// Read() reads a PKCS1 RSA private key in PEM format.
func Read(r io.Reader) (*PrivateKey, error) {
	var rsa = new (PrivateKey)

	body, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	blob, _ := pem.Decode(body)
	if blob == nil {
		return nil, errors.New("pem decode error")
	}
	if blob.Type != "RSA PRIVATE KEY" || blob.Bytes == nil {
		return nil, errors.New("invalid pem")
	}
	_, err = asn1.Unmarshal(blob.Bytes, rsa)
	if err != nil {
		return nil, err
	}

	return rsa, nil
}
