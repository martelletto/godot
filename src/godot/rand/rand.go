package rand

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
)

// Prime() obtains a random n-bit prime from /dev/urandom.
func Prime(n int) *big.Int {
	r, err := os.Open("/dev/urandom")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	x, err := rand.Prime(r, n)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	err = r.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	return x
}

// Bytes() reads n bytes from /dev/urandom.
func Bytes(n int) []byte {
	r, err := os.Open("/dev/urandom")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	var p = make([]byte, n)

	n, err = r.Read(p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	} else if n != len(p) {
		fmt.Fprintf(os.Stderr, "short read\n")
		os.Exit(1)
	}

	err = r.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	return p
}
