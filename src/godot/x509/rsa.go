package x509

import (
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"godot/pkcs1"
	"godot/util"
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

func NewRSA(rsa *pkcs1.RSAPrivateKey) *RSA_PUBKEY {
	var x509 = new(RSA_PUBKEY)
	var rsaPub = new(pkcs1.RSAPublicKey)
	var err error

	x509.Type.OID = []int{1, 2, 840, 113549, 1, 1, 1} // rsaEncryption
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

func WriteRSA(rsa *pkcs1.RSAPrivateKey, f *os.File) {
	var blob = new(pem.Block)
	var err error

	blob.Type = "PUBLIC KEY"
	blob.Bytes, err = asn1.Marshal(*NewRSA(rsa))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	util.WritePEM(blob, f)
}
