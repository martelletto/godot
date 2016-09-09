package usage

import (
	"fmt"
	"os"
)

func toStderr(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
	fmt.Fprintln(os.Stderr)
}

func Print() {
	toStderr("usage: %s rsa", os.Args[0])
	toStderr("       %s rsa new [--out <key>]", os.Args[0])
	toStderr("       %s rsa pub --key <key>", os.Args[0])
	toStderr("       %s rsa sign --key <key>", os.Args[0])
}
