// Command qbit-vault is the CLI entry point.
package main

import (
	"os"

	"github.com/QuBiit0/qbit-vault/internal/cli"
)

func main() {
	os.Exit(cli.Execute(os.Args[1:], os.Stdout, os.Stderr, os.Getenv))
}
