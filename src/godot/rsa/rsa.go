// Copyright (c) 2016 Pedro Martelletto. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.
//
// The rsa module implements the core of the RSA algorithm.

package rsa

import (
	"fmt"
	"godot/pkcs1"
	"godot/rand"
	"godot/rsa/pss"
	"godot/util"
	"godot/x509"
	"math/big"
	"os"
)

// createRSA() creates a new RSA key pair.
func createRSA(l int) *pkcs1.PrivateKey {
	var rsa = new(pkcs1.PrivateKey)

	rsa.Version = big.NewInt(0)
	rsa.Prime1 = rand.Prime(l/2) // prime p
	rsa.Prime2 = rand.Prime(l/2) // prime q
	rsa.Modulus = new(big.Int).Mul(rsa.Prime1, rsa.Prime2)
	rsa.PublicExponent = big.NewInt(65537)

	pMinus := new(big.Int).Sub(rsa.Prime1, big.NewInt(1))
	qMinus := new(big.Int).Sub(rsa.Prime2, big.NewInt(1))
	phi := new(big.Int).Mul(pMinus, qMinus)

	rsa.PrivateExponent = new(big.Int).ModInverse(rsa.PublicExponent, phi)
	// CRT auxiliary parameters
	rsa.Exponent1 = new(big.Int).Mod(rsa.PrivateExponent, pMinus)
	rsa.Exponent2 = new(big.Int).Mod(rsa.PrivateExponent, qMinus)
	rsa.Coefficient = new(big.Int).ModInverse(rsa.Prime2, rsa.Prime1)

	return rsa
}

// verify() the entry point for the verification of a signature.
func verify(args []string) {
	var in, key, sig *os.File

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
		case "-s":
			fallthrough
		case "--sig":
			util.OpenFile(&sig, util.GetArg(args, &i))
		default:
			usageError()
		}
	}

	if key == nil || sig == nil {
		usageError()
	}
	if in == nil {
		in = os.Stdin
	}

	rsaPub := x509.ReadRSA(key)
	if len(rsaPub.Modulus.Bytes()) != 512 {
		fmt.Fprintf(os.Stderr, "invalid key size\n")
		os.Exit(1)
	}

	sigBody := util.ReadAll(sig)
	if len(sigBody) != 512 {
		fmt.Fprintf(os.Stderr, "invalid signature size\n")
		os.Exit(1)
	}

	// RSA verification
	s := new(big.Int).SetBytes(sigBody)
	m := new(big.Int).Exp(s, rsaPub.PublicExponent, rsaPub.Modulus)

	if pss.Verify(in, m.Bytes(), 4095) {
		fmt.Fprintf(os.Stdout, "good signature\n")
		os.Exit(0)
	} else {
		fmt.Fprintf(os.Stdout, "invalid signature\n")
		os.Exit(1)
	}

	util.CloseFile(in)
	util.CloseFile(key)
	util.CloseFile(sig)
}

// sign() the entry point for the generation of a signature.
func sign(args []string) {
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
			usageError()
		}
	}

	if key == nil {
		usageError()
	}
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = os.Stdout
	}

	rsa := pkcs1.Read(key)
	if len(rsa.Modulus.Bytes()) != 512 ||
	   len(rsa.PrivateExponent.Bytes()) != 512 {
		fmt.Fprintf(os.Stderr, "invalid key size\n")
		os.Exit(1)
	}

	// RSA signature generation
	m := pss.Encode(in, 4095)
	out.Write(new(big.Int).Exp(m, rsa.PrivateExponent, rsa.Modulus).Bytes())

	util.CloseFile(in)
	util.CloseFile(out)
}

// pubkey() is the entry point for the derivation of a public key.
func pubkey(args []string) {
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
			usageError()
		}
	}

	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = os.Stdout
	}

	x509.WriteRSA(pkcs1.Read(in), out)
	util.CloseFile(in);
	util.CloseFile(out);
}

// newkey() is the entry point for the generation of a private key.
func newkey(args []string) {
	var out *os.File

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-o":
			fallthrough
		case "--out":
			util.CreateFile(&out, util.GetArg(args, &i))
		default:
			usageError()
		}
	}

	if out == nil {
		out = os.Stdout
	}

	pkcs1.Write(createRSA(4096), out)
	util.CloseFile(out)
}

// Command() is the entry point for command line operations.
func Command(args []string) {
        // args[0] = "rsa"
        if len(args) < 2 {
                usageError()
        }

        // args[1] = new|pub|sign|verify
        switch args[1] {
        case "new":
                newkey(args[2:])
        case "pub":
                pubkey(args[2:])
        case "sign":
                sign(args[2:])
        case "verify":
                verify(args[2:])
        default:
                usageError()
        }

        os.Exit(0)
}
