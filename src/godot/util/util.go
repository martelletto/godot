package util

import (
	"fmt"
	"encoding/pem"
	"godot/usage"
	"os"
)

func CreateFile(f **os.File, path string) {
	var err error

	if *f != nil {
		// directives specifying files must be used at most once
		usage.Print();
		os.Exit(1);
	}

	*f, err = os.OpenFile(path, os.O_WRONLY | os.O_CREATE | os.O_EXCL, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func OpenFile(f **os.File, path string) {
	var err error

	if *f != nil {
		// directives specifying files must be used at most once
		usage.Print();
		os.Exit(1);
	}

	*f, err = os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

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
		usage.Print();
		os.Exit(1);
	}
	*i++;

	return args[*i]
}

func WritePEM(blob *pem.Block, f *os.File) {
	err := pem.Encode(f, blob)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", blob)
		os.Exit(1)
	}
}
