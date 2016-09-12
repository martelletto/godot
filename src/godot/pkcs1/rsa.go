package pkcs1

import (
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"godot/util"
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

func WriteRSA(rsa *RSAPrivateKey, f *os.File) {
	var blob = new(pem.Block)
	var err error

	blob.Type = "RSA PRIVATE KEY"
	blob.Bytes,err = asn1.Marshal(*rsa)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	util.WritePEM(blob, f)
}

func ReadRSA(in *os.File) *RSAPrivateKey {
	var rsa = new (RSAPrivateKey)

	body, err := ioutil.ReadAll(in)
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
