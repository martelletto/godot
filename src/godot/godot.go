// Copyright (c) 2016 Pedro Martelletto. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

package main

import (
	"fmt"
	"godot/ecdsa"
	"godot/rsa"
	"godot/sha256"
	"godot/util"
	"io"
	"os"
)

type sigAlg interface {
	NewKey(l int, w io.Writer) error
	LoadPriv(r io.Reader) error
	LoadPub(r io.Reader) error
	WritePub(w io.Writer) error
	Sign(m io.Reader, w io.Writer) error
	Verify(t, m io.Reader) (bool, error)
	UsageError()
}

func usageError() {
	fmt.Fprintf(os.Stderr,
`godot implements digital signature primitives.

Usage:

	godot <command> [arguments]

The commands are:

    ecdsa	perform secp256k1 ECDSA operations
    rsa		perform 4096-bit RSA operations
    sha256	calculate a SHA-256 digest
    version	print godot's version number

Use "godot <command> help" for more information about a command.
`)
	os.Exit(1)
}

func printVersion() {
	fmt.Fprintf(os.Stdout, "godot 1.0\n")
}

func NewKey(args []string, a sigAlg) error {
	var out *os.File = os.Stdout

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-o":
			fallthrough
		case "--out":
			util.CreateFile(&out, os.Stdout,
			    util.GetArg(args, &i))
		default:
			a.UsageError()
		}
	}

	return a.NewKey(4096, out)
}

func PubKey(args []string, a sigAlg) error {
	var in  *os.File = os.Stdin
	var out *os.File = os.Stdout

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-i":
			fallthrough
		case "--in":
			util.OpenKey(&in, os.Stdin,
			    util.GetArg(args, &i))
		case "-o":
			fallthrough
		case "--out":
			util.CreateFile(&out, os.Stdout,
			    util.GetArg(args, &i))
		default:
			a.UsageError()
		}
	}

	err := a.LoadPriv(in)
	if err != nil {
		return err
	}

	return a.WritePub(out)
}

func Sign(args []string, a sigAlg) error {
	var in  *os.File = os.Stdin
	var out *os.File = os.Stdout
	var key *os.File

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-i":
			fallthrough
		case "--in":
			util.OpenFile(&in, os.Stdin,
			    util.GetArg(args, &i))
		case "-k":
			fallthrough
		case "--key":
			util.OpenKey(&key, nil,
			    util.GetArg(args, &i))
		case "-o":
			fallthrough
		case "--out":
			util.CreateFile(&out, os.Stdout,
			    util.GetArg(args, &i))
		default:
			a.UsageError()
		}
	}

	if key == nil {
		a.UsageError()
	}

	err := a.LoadPriv(key)
	if err != nil {
		return err
	}

	return a.Sign(in, out)
}

func Verify(args []string, a sigAlg) error {
	var in  *os.File = os.Stdin
	var key *os.File
	var sig *os.File

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-i":
			fallthrough
		case "--in":
			util.OpenFile(&in, os.Stdin,
			    util.GetArg(args, &i))
		case "-k":
			fallthrough
		case "--key":
			util.OpenFile(&key, nil,
			    util.GetArg(args, &i))
		case "-s":
			fallthrough
		case "--sig":
			util.OpenFile(&sig, nil,
			    util.GetArg(args, &i))
		default:
			a.UsageError()
		}
	}

	if key == nil || sig == nil {
		a.UsageError()
	}

	err := a.LoadPub(key)
	if err != nil {
		return err
	}

	ok, err := a.Verify(sig, in)
	if err != nil {
		return err
	}
	if ok == false {
		fmt.Fprintf(os.Stdout, "bad signature\n")
		os.Exit(1)
	} else {
		fmt.Fprintf(os.Stdout, "good signature\n")
		os.Exit(0)
	}

	return nil
}

func sigOp(args []string, a sigAlg) {
	var err error

	if len(args) < 2 {
		a.UsageError()
	}

	switch args[1] {
	case "new":
		err = NewKey(args[2:], a)
	case "pub":
		err = PubKey(args[2:], a)
	case "sign":
		err = Sign(args[2:], a)
	case "verify":
		err = Verify(args[2:], a)
	default:
		a.UsageError()
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func main() {
	if len(os.Args) < 2 {
		usageError()
	}

	switch os.Args[1] {
	case "ecdsa":
		sigOp(os.Args[1:], ecdsa.New())
	case "rsa":
		sigOp(os.Args[1:], rsa.New())
	case "sha256":
		sha256.Command(os.Args[1:])
	case "version":
		printVersion()
	default:
		usageError()
	}
}
