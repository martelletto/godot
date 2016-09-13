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

package rsa

import (
	"fmt"
	"os"
)

func usageError() {
	fmt.Fprintf(os.Stderr,
`usage: godot rsa [command] [arguments]

The supported commands are:

godot rsa new [-o <file>]

	Creates a new 4096-bit RSA private key. If -o is specified,
	the key is written to <file> instead of stdout.

godot rsa pub [-i <file>] [-o <file>]

	Derives a public key from a private key. If -i is specified,
	the key is read from <file> instead of stdin. The key must be
	a 4096-bit RSA private key. If -o is specified, the public
	key is written to <file> instead of stdout.

godot rsa sign -k <file> [-i <file>] [-o <file>]

	Generates a 4096-bit RSA signature following the Probabilistic
	Signature Scheme (PSS) with SHA-256 as the digest mechanism.
	The -k parameter must be specified, and <file> must point to a
	4096-bit RSA private key. If -i is specified, the contents to
	be signed are read from <file> instead of stdin. If -o is
	specified, the resulting signature is written to <file> instead
	of stdout. The signature is always written in binary format.

godot rsa verify -k <file> -s <file> [-i <file>]

	Verifies a 4096-bit RSA PSS signature with SHA-256 as the
	digest mechanism. The -k and -s parameters must be specified
	and must point to a 4096-bit RSA public key and PSS signature
	respectively. If -i is specified, the data whose signature is
	being verified is read from <file> instead of stdin.

--{binary,in,key,out} can be used instead of -{b,i,k,o}.
`)
	os.Exit(1)
}
