// Package exitcode defines the process exit codes of gentle-vault
// (docs/CLI.md § Exit codes).
package exitcode

const (
	OK      = 0 // success
	Failure = 1 // generic failure / doctor warnings
	Usage   = 2 // usage error / doctor errors
	Refusal = 3 // typed refusal (contracts/secrets-broker/v1/CONTRACT.md)
	Locked  = 4 // vault locked
	Corrupt = 5 // vault corrupt / rollback detected
)
