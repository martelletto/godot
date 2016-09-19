// Copyright (c) 2016 Pedro Martelletto. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.
//
// The x509 module exports functions that allow RSA X.509 public
// keys to be written and read.

package x509

import (
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"godot/rsa/pkcs1"
	"io"
	"io/ioutil"
)

// As per https://tools.ietf.org/rfc/rfc3279.txt, 2.3.1
type OID struct {
	OID		asn1.ObjectIdentifier
	NULL		asn1.RawValue
}

// As per https://tools.ietf.org/rfc/rfc3279.txt, 2.3.1
type RSA_PUBKEY struct {
	Type		OID
	Body		asn1.BitString
}

// As per https://tools.ietf.org/rfc/rfc3279.txt, 2.3.1
var rsaEncryption asn1.ObjectIdentifier = []int{1, 2, 840, 113549, 1, 1, 1}

// wrap() transforms a PKCS1 private key in a X.509 public key.
func wrap(rsa *pkcs1.PrivateKey) (*RSA_PUBKEY, error) {
	var x509 = new(RSA_PUBKEY)
	var rsaPub = new(pkcs1.PublicKey)
	var err error

	x509.Type.OID = rsaEncryption;
	x509.Type.NULL.Tag = 5 // NULL tag
	rsaPub.Modulus = rsa.Modulus
	rsaPub.PublicExponent = rsa.PublicExponent
	x509.Body.Bytes, err = asn1.Marshal(*rsaPub)
	if err != nil {
		return nil, err
	}

	return x509, nil
}

// unwrap() transforms a X.509 public key in a PKCS1 public key.
func unwrap(x509 *RSA_PUBKEY) (*pkcs1.PublicKey, error) {
	var rsaPub = new(pkcs1.PublicKey)

	if rsaEncryption.Equal(x509.Type.OID) == false ||
	   x509.Type.NULL.Tag != 5 ||
	   x509.Type.NULL.IsCompound != false ||
	   len(x509.Type.NULL.Bytes) != 0 {
		return nil, errors.New("invalid x509")
	}

	_, err := asn1.Unmarshal(x509.Body.Bytes, rsaPub)
	if err != nil {
		return nil, err
	}

	return rsaPub, nil
}

// WriteRSA() transforms a PKCS1 private key in a X.509 public key and
// writes it on w.
func WriteRSA(rsa *pkcs1.PrivateKey, w io.Writer) error {
	var blob = new(pem.Block)
	var err error

	x509, err := wrap(rsa)
	if err != nil {
		return err
	}
	blob.Type = "PUBLIC KEY"
	blob.Bytes, err = asn1.Marshal(*x509)
	if err != nil {
		return err
	}

	return pem.Encode(w, blob)
}

// ReadRSA() reads a X.509 public key from r, transforms it in a PKCS1
// public key, and returns it.
func ReadRSA(r io.Reader) (*pkcs1.PublicKey, error) {
	var x509 = new(RSA_PUBKEY)

	body, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	blob, _ := pem.Decode(body)
	if blob == nil {
		return nil, errors.New("pem decode error")
	}
	if blob.Type != "PUBLIC KEY" || blob.Bytes == nil {
		return nil, errors.New("invalid pem")
	}
	_, err = asn1.Unmarshal(blob.Bytes, x509)
	if err != nil {
		return nil, err
	}

	return unwrap(x509)
}
