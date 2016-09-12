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

package usage

import (
	"fmt"
	"os"
)

func toStderr(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
	fmt.Fprintln(os.Stderr)
}

// I apologize for not wrapping the following lines.
func Print() {
	toStderr("usage: %s rsa", os.Args[0])
	toStderr("       %s rsa new [--out <privkey>]", os.Args[0])
	toStderr("       %s rsa pub [--in <privkey>] [--out <pubkey>]", os.Args[0])
	toStderr("       %s rsa sign --key <privkey> [--in <file>] [--out <sig>]", os.Args[0])
	toStderr("       %s rsa verify --key <pubkey> --sig <sig> [--in <file>]", os.Args[0])
	toStderr("       %s version", os.Args[0])
}
