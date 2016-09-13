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
	"fmt"
	"godot/pkcs1"
	"godot/util"
	"io"
	"io/ioutil"
	"os"
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

// wrap() transforms a PKCS1 private key into a X.509 public key.
func wrap(rsa *pkcs1.RSAPrivateKey) *RSA_PUBKEY {
	var x509 = new(RSA_PUBKEY)
	var rsaPub = new(pkcs1.RSAPublicKey)
	var err error

	x509.Type.OID = rsaEncryption;
	x509.Type.NULL.Tag = 5 // NULL tag
	rsaPub.Modulus = rsa.Modulus
	rsaPub.PublicExponent = rsa.PublicExponent
	x509.Body.Bytes, err = asn1.Marshal(*rsaPub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	return x509
}

// unwrap() transforms a X.509 public key into a PKCS1 public key.
func unwrap(x509 *RSA_PUBKEY) *pkcs1.RSAPublicKey {
	var rsaPub = new(pkcs1.RSAPublicKey)

	if rsaEncryption.Equal(x509.Type.OID) == false ||
	   x509.Type.NULL.Tag != 5 ||
	   x509.Type.NULL.IsCompound != false ||
	   len(x509.Type.NULL.Bytes) != 0 {
		fmt.Fprintf(os.Stderr, "invalid x509\n")
		os.Exit(1)
	}

	_, err := asn1.Unmarshal(x509.Body.Bytes, rsaPub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	return rsaPub
}

// WriteRSA() transforms a PKCS1 private key into a X.509 public key and writes
// it on 'w'.
func WriteRSA(rsa *pkcs1.RSAPrivateKey, w io.Writer) {
	var blob = new(pem.Block)
	var err error

	blob.Type = "PUBLIC KEY"
	blob.Bytes, err = asn1.Marshal(*wrap(rsa))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	util.WritePEM(blob, w)
}

// ReadRSA() reads a X.509 public key from 'r', transforms it into a PKCS1
// public key, and returns it.
func ReadRSA(r io.Reader) *pkcs1.RSAPublicKey {
	var x509 = new(RSA_PUBKEY)

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
	if blob.Type != "PUBLIC KEY" || blob.Bytes == nil {
		fmt.Fprintf(os.Stderr, "invalid pem\n")
		os.Exit(1)
	}
	_, err = asn1.Unmarshal(blob.Bytes, x509)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	return unwrap(x509)
}
