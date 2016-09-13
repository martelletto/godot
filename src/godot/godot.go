// Copyright (c) 2016 Pedro Martelletto
// All rights reserved.
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//
// This file implements godot's main function and option handling.

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
