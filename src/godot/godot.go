// Copyright (c) 2016 Pedro Martelletto. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

package main

import (
	"fmt"
	"godot/rsa"
	"godot/sha256"
	"os"
)

func usageError() {
	fmt.Fprintf(os.Stderr,
`godot implements digital signature primitives.

Usage:

	godot <command> [arguments]

The commands are:

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

func main() {
	if len(os.Args) < 2 {
		usageError()
	}

	switch os.Args[1] {
	case "rsa":
		rsa.Command(os.Args[1:])
	case "sha256":
		sha256.Command(os.Args[1:])
	case "version":
		printVersion()
	default:
		usageError()
	}
}
