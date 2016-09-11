package rsa

import (
	"fmt"
	"encoding/asn1"
	"encoding/pem"
	"godot/rand"
	"godot/rsa/pss"
	"godot/usage"
	"io/ioutil"
	"math/big"
	"os"
)

// As per https://www.ietf.org/rfc/rfc3447.txt, A.1.2
type PKCS1_RSAPrivateKey struct {
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

// Internal representation of an RSA key pair.
type PrivateKey struct {
	n		 big.Int // modulus (pq)
	e		*big.Int // public exponent
	d		 big.Int // private exponent
	p		*big.Int // prime p
	q		*big.Int // prime q
	pMinus		 big.Int // p - 1
	qMinus		 big.Int // q - 1
	phi		 big.Int // (p - 1)*(q -1)
}

// As per https://www.ietf.org/rfc/rfc3447.txt, A.1.1
type PKCS1_RSAPublicKey struct {
	Modulus		*big.Int
	PublicExponent	*big.Int
}

// As per https://tools.ietf.org/rfc/rfc3279.txt, 2.3.1
type X509_OID struct {
	OID		asn1.ObjectIdentifier
	NULL		asn1.RawValue
}

// As per https://tools.ietf.org/rfc/rfc3279.txt, 2.3.1
type X509_RSA_PUBKEY struct {
	Type		X509_OID
	Body		asn1.BitString
}

func generateRSA(l int) *PrivateKey {
	var one = big.NewInt(1)
	var rsa = new(PrivateKey)

	rsa.p = rand.Prime(l/2)
	rsa.q = rand.Prime(l/2)
	rsa.n.Mul(rsa.p, rsa.q)
	rsa.e = big.NewInt(65537)
	rsa.pMinus.Sub(rsa.p, one)
	rsa.qMinus.Sub(rsa.q, one)
	rsa.phi.Mul(&rsa.pMinus, &rsa.qMinus)
	rsa.d.ModInverse(rsa.e, &rsa.phi)

	return rsa
}

func parseRSA(in *os.File) *PKCS1_RSAPrivateKey {
	var rsa = new (PKCS1_RSAPrivateKey)

	body, err := ioutil.ReadAll(in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	blob, _ := pem.Decode(body)
	if blob == nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	if blob.Type != "RSA PRIVATE KEY" || blob.Bytes == nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	_, err = asn1.Unmarshal(blob.Bytes, rsa)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	return rsa
}

func buildPKCS1(rsa *PrivateKey) *PKCS1_RSAPrivateKey {
	var pkcs1 = new(PKCS1_RSAPrivateKey)
	var e1, e2, c big.Int

	pkcs1.Version = big.NewInt(0)
	pkcs1.Modulus = &rsa.n
	pkcs1.PublicExponent = rsa.e
	pkcs1.PrivateExponent = &rsa.d
	pkcs1.Prime1 = rsa.p
	pkcs1.Prime2 = rsa.q
	// CRT auxiliary parameters
	e1.Mod(&rsa.d, &rsa.pMinus)
	e2.Mod(&rsa.d, &rsa.qMinus)
	c.ModInverse(rsa.q, rsa.p)
	pkcs1.Exponent1 = &e1
	pkcs1.Exponent2 = &e2
	pkcs1.Coefficient = &c

	return pkcs1
}

func buildPrivatePEM(pkcs1 *PKCS1_RSAPrivateKey) *pem.Block {
	var blob = new(pem.Block)
	var err error

	blob.Type = "RSA PRIVATE KEY"
	blob.Bytes, err = asn1.Marshal(*pkcs1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "asn1 encoding: %v\n", err)
		os.Exit(1)
	}

	return blob
}

func writePEM(blob *pem.Block, f *os.File) {
	err := pem.Encode(f, blob)
	if err != nil {
		fmt.Fprintf(os.Stderr, "PEM output: %v\n", blob)
		os.Exit(1)
	}
}

func createFile(path string) *os.File {
	f, err := os.OpenFile(path, os.O_WRONLY | os.O_CREATE | os.O_EXCL, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	return f
}

func openFile(path string) *os.File {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	s, err := f.Stat()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	if s.Mode() != 0400 && s.Mode() != 0600 {
		fmt.Fprintf(os.Stderr, "refusing to work with insecure key " +
		    "file %s\n", path)
		os.Exit(1)
	}

	return f
}

func closeFile(f *os.File) {
	err := f.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func buildPublicPEM(x509 *X509_RSA_PUBKEY) *pem.Block {
	var blob = new(pem.Block)
	var err error

	blob.Type = "PUBLIC KEY"
	blob.Bytes, err = asn1.Marshal(*x509)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	return blob
}

func buildX509(rsa *PKCS1_RSAPrivateKey) *X509_RSA_PUBKEY {
	var x509 = new(X509_RSA_PUBKEY)
	var rsaPub = new(PKCS1_RSAPublicKey)
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

func Sign(args []string) {
	if len(args) != 2 || args[0] != "--key"  {
		usage.Print();
		os.Exit(1);
	}

	rsa := parseRSA(openFile(args[1]))
	if len(rsa.Modulus.Bytes()) != 512 ||
	   len(rsa.PrivateExponent.Bytes()) != 512 {
		fmt.Fprintf(os.Stderr, "%s: invalid key size\n", args[1])
		os.Exit(1)
	}

	m := pss.Encode(os.Stdin, 4095)
	os.Stdout.Write(new(big.Int).Exp(m, rsa.PrivateExponent,
	    rsa.Modulus).Bytes())
}

func Pub(args []string) {
	var in *os.File = os.Stdin

	if len(args) != 0 {
		if len(args) != 2 || args[0] != "--key"  {
			usage.Print();
			os.Exit(1);
		}
		in = openFile(args[1])
	}

	writePEM(buildPublicPEM(buildX509(parseRSA(in))), os.Stdout)

	if in != os.Stdin {
		closeFile(in);
	}
}

func New(args []string) {
	var out *os.File = os.Stdout

	if len(args) != 0 {
		if len(args) != 2 || args[0] != "--out" {
			usage.Print();
			os.Exit(1)
		}
		out = createFile(args[1])
	}

	writePEM(buildPrivatePEM(buildPKCS1(generateRSA(4096))), out)

	if out != os.Stdout {
		closeFile(out)
	}
}
