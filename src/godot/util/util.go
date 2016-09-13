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
// The util module is the customary placeholder for functions used elsewhere
// that don't belong anywhere.

package util

import (
	"fmt"
	"encoding/pem"
	"io"
	"io/ioutil"
	"os"
)

// CreateFile() creates a new, write-only, chmod 0600 file. Its first argument
// is a pointer to a *os.File. This pointer needs to be nil, or CreateFile()
// will fail.
func CreateFile(f **os.File, path string) {
	var err error

	if *f != nil { // prevent multiple invocations on the same pointer
		fmt.Fprintf(os.Stderr, "multiple use of options [ikos]\n")
		os.Exit(1);
	}

	*f, err = os.OpenFile(path, os.O_WRONLY | os.O_CREATE | os.O_EXCL, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

// OpenFile() is a simple wrapper around os.Open(). Its first argument is a
// pointer to a *os.File. This pointer needs to be nil, or OpenFile() will fail.
func OpenFile(f **os.File, path string) {
	var err error

	if *f != nil { // prevent multiple invocations on the same pointer
		fmt.Fprintf(os.Stderr, "multiple use of options [ikos]\n")
		os.Exit(1);
	}

	*f, err = os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

// OpenKey() opens a file and ensures sane permissions.
func OpenKey(f **os.File, path string) {
	OpenFile(f, path);

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
}

// CloseFile() is a simple wrapper around os.Close().
func CloseFile(f *os.File) {
	err := f.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

// GetArg() retrieves a token from 'args' at index i + 1. The token must exist.
func GetArg(args []string, i *int) string {
	if *i + 1 >= len(args) {
		fmt.Fprintf(os.Stderr, "option %s requires an argument",
		    args[*i])
		os.Exit(1);
	}
	*i++;

	return args[*i]
}

// ReadAll() is a simple wrapper around ioutil.ReadAll().
func ReadAll(r io.Reader) []byte {
	body, err := ioutil.ReadAll(r)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	return body
}

// WritePEM() is a simple wrapper around pem.Encode().
func WritePEM(blob *pem.Block, w io.Writer) {
	err := pem.Encode(w, blob)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", blob)
		os.Exit(1)
	}
}
