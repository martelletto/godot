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
	"godot/usage"
	"godot/rsa"
	"os"
)

func getOpt() (string, []string) {
	if len(os.Args) < 3 || os.Args[1] != "rsa" {
		return "", make([]string, 0)
	} else {
		return os.Args[2], os.Args[3:]
	}
}

func main() {
	cmd, args := getOpt()
	switch cmd {
	case "new":
		rsa.New(args)
	case "pub":
		rsa.Pub(args)
	case "sign":
		rsa.Sign(args)
	case "verify":
		rsa.Verify(args)
	default:
		usage.Print();
		os.Exit(1)
	}
}
