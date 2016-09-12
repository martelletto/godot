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
	toStderr("       %s rsa new [--out <privkey>]", os.Args[0])
	toStderr("       %s rsa pub [--in <privkey>] [--out <pubkey>]", os.Args[0])
	toStderr("       %s rsa sign --key <privkey> [--in <file>] [--out <sig>]", os.Args[0])
	toStderr("       %s rsa verify --key <pubkey> --sig <sig> [--in <file>]", os.Args[0])
}
