package rsa

import (
	"fmt"
	"godot/pkcs1"
	"godot/rand"
	"godot/rsa/pss"
	"godot/usage"
	"godot/util"
	"godot/x509"
	"math/big"
	"os"
)

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

func Verify(args []string) {
	var in, key *os.File

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-i":
			fallthrough
		case "--in":
			util.OpenFile(&in, util.GetArg(args, &i))
		case "-k":
			fallthrough
		case "--key":
			util.OpenFile(&key, util.GetArg(args, &i))
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
}

func Sign(args []string) {
	var in, out, key *os.File

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-i":
			fallthrough
		case "--in":
			util.OpenFile(&in, util.GetArg(args, &i))
		case "-k":
			fallthrough
		case "--key":
			util.OpenKey(&key, util.GetArg(args, &i))
		case "-o":
			fallthrough
		case "--out":
			util.CreateFile(&out, util.GetArg(args, &i))
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

	rsa := pkcs1.ReadRSA(key)
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
			util.OpenKey(&in, util.GetArg(args, &i))
		case "-o":
			fallthrough
		case "--out":
			util.CreateFile(&out, util.GetArg(args, &i))
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

	x509.WriteRSA(pkcs1.ReadRSA(in), out)
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
			util.CreateFile(&out, util.GetArg(args, &i))
		default:
			usage.Print();
			os.Exit(1);
		}
	}

	if out == nil {
		out = os.Stdout
	}

	pkcs1.WriteRSA(createRSA(4096), out)
	util.CloseFile(out)
}
