package rsa

import (
	"fmt"
	"encoding/asn1"
	"encoding/pem"
	"godot/pkcs1"
	"godot/rand"
	"godot/rsa/pss"
	"godot/usage"
	"godot/util"
	"io/ioutil"
	"math/big"
	"os"
)

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

func createRSA(l int) *pkcs1.RSAPrivateKey {
	var rsa = new(pkcs1.RSAPrivateKey)

	rsa.Version = big.NewInt(0)
	rsa.Prime1 = rand.Prime(l/2) // prime p
	rsa.Prime2 = rand.Prime(l/2) // prime q
	rsa.Modulus = new(big.Int).Mul(rsa.Prime1, rsa.Prime2)
	rsa.PublicExponent = big.NewInt(65537)

	pMinus := new(big.Int).Sub(rsa.Prime1, big.NewInt(1))
	qMinus := new(big.Int).Sub(rsa.Prime1, big.NewInt(1))
	phi := new(big.Int).Mul(pMinus, qMinus)

	rsa.PrivateExponent = new(big.Int).ModInverse(rsa.PublicExponent, phi)
	// CRT auxiliary parameters
	rsa.Exponent1 = new(big.Int).Mod(rsa.PrivateExponent, pMinus)
	rsa.Exponent2 = new(big.Int).Mod(rsa.PrivateExponent, qMinus)
	rsa.Coefficient = new(big.Int).ModInverse(rsa.Prime2, rsa.Prime1)

	return rsa
}

func parseRSA(in *os.File) *pkcs1.RSAPrivateKey {
	var rsa = new (pkcs1.RSAPrivateKey)

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

func buildPrivatePEM(pkcs1 *pkcs1.RSAPrivateKey) *pem.Block {
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

func buildX509(rsa *pkcs1.RSAPrivateKey) *X509_RSA_PUBKEY {
	var x509 = new(X509_RSA_PUBKEY)
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

func readX509(in *os.File) *X509_RSA_PUBKEY {
	var x509 = new(X509_RSA_PUBKEY)

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
	if blob.Type != "PUBLIC KEY" || blob.Bytes == nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	_, err = asn1.Unmarshal(blob.Bytes, x509)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	return x509
}

func parseX509(x509 *X509_RSA_PUBKEY) *pkcs1.RSAPublicKey {
	var rsaPub = new(pkcs1.RSAPublicKey)

//	if x509.Type.OID != []int{1, 2, 840, 113549, 1, 1, 1} ||
//	   x509.Type.NULL.Tag != 5 {
//		fmt.Fprintf(os.Stderr, "invalid x509\n");
//		os.Exit(1);
//	}

	_, err := asn1.Unmarshal(x509.Body.Bytes, rsaPub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	return rsaPub
}

// getArg() retrieves a token from 'args' at index i + 1. The token must exist.
func getArg(args []string, i *int) string {
	if *i + 1 >= len(args) {
		usage.Print();
		os.Exit(1);
	}
	*i++;

	return args[*i]
}

func Verify(args []string) {
	var in, key *os.File

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-i":
			fallthrough
		case "--in":
			util.OpenFile(&in, getArg(args, &i))
		case "-k":
			fallthrough
		case "--key":
			util.OpenFile(&key, getArg(args, &i))
		default:
			usage.Print();
			os.Exit(1);
		}
	}

	if key == nil {
		usage.Print();
		os.Exit(1);
	}
	if in == nil {
		in = os.Stdin
	}

	rsa := parseX509(readX509(key))

	fmt.Println(rsa.Modulus)
	fmt.Println(rsa.PublicExponent)
}

func Sign(args []string) {
	var in, out, key *os.File

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-i":
			fallthrough
		case "--in":
			util.OpenFile(&in, getArg(args, &i))
		case "-k":
			fallthrough
		case "--key":
			util.OpenKey(&key, getArg(args, &i))
		case "-o":
			fallthrough
		case "--out":
			util.CreateFile(&out, getArg(args, &i))
		default:
			usage.Print();
			os.Exit(1);
		}
	}

	if key == nil {
		usage.Print();
		os.Exit(1);
	}
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = os.Stdout
	}

	rsa := parseRSA(key)
	if len(rsa.Modulus.Bytes()) != 512 ||
	   len(rsa.PrivateExponent.Bytes()) != 512 {
		fmt.Fprintf(os.Stderr, "%s: invalid key size\n", args[1])
		os.Exit(1)
	}

	m := pss.Encode(in, 4095)
	out.Write(new(big.Int).Exp(m, rsa.PrivateExponent, rsa.Modulus).Bytes())

	util.CloseFile(in)
	util.CloseFile(out)
}

func Pub(args []string) {
	var in, out *os.File

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-i":
			fallthrough
		case "--in":
			util.OpenKey(&in, getArg(args, &i))
		case "-o":
			fallthrough
		case "--out":
			util.CreateFile(&out, getArg(args, &i))
		default:
			usage.Print();
			os.Exit(1);
		}
	}

	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = os.Stdout
	}

	util.WritePEM(buildPublicPEM(buildX509(parseRSA(in))), out)
	util.CloseFile(in);
	util.CloseFile(out);
}

func New(args []string) {
	var out *os.File

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-o":
			fallthrough
		case "--out":
			util.CreateFile(&out, getArg(args, &i))
		default:
			usage.Print();
			os.Exit(1);
		}
	}

	if out == nil {
		out = os.Stdout
	}

	util.WritePEM(buildPrivatePEM(createRSA(4096)), out)

	util.CloseFile(out)
}
