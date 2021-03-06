// Copyright (c) 2016 Pedro Martelletto. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

package util

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

// CreateFile() creates a new, write-only, chmod 0600 file. Its first
// argument is a pointer f to a *os.File. f needs to be equal to d (a
// default value for f), or CreateFile() will fail.
func CreateFile(f **os.File, d *os.File, path string) {
	var err error

	if *f != d { // prevent multiple invocations on *f
		fmt.Fprintf(os.Stderr, "multiple use of options [ikos]\n")
		os.Exit(1);
	}

	*f, err = os.OpenFile(path, os.O_WRONLY | os.O_CREATE | os.O_EXCL, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

// OpenFile() is a simple wrapper around os.Open(). Its first argument
// is a pointer f to a *os.File. f needs to be equal to d (a default
// value for f), or OpenFile() will fail.
func OpenFile(f **os.File, d *os.File, path string) {
	var err error

	if *f != d { // prevent multiple invocations on *f
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
func OpenKey(f **os.File, d *os.File, path string) {
	OpenFile(f, d, path);

	s, err := (*f).Stat()
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

// GetArg() retrieves a token from 'args' at index i + 1. The token
// must exist.
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
