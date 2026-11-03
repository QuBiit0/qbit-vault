// Command gentle-vault is the CLI entry point.
package main

import (
	"os"

	"github.com/QuBiit0/gentle-vault/internal/cli"
)

func main() {
	os.Exit(cli.Execute(os.Args[1:], os.Stdout, os.Stderr, os.Getenv))
}
