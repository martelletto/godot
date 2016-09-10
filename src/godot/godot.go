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
	default:
		usage.Print();
		os.Exit(1)
	}
}
