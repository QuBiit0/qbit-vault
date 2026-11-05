// Package tui is the interactive terminal app (odd/tasks/tui.md). It never
// holds a secret value: the Backend it talks to has no type that can carry
// one, and every screen shows names, counts and status only.
package tui

// State is what the TUI knows about the vault without showing a value.
type State int

const (
	StateNone     State = iota // no vault at Home yet
	StateLocked                // a vault exists but cannot be opened without a prompt
	StateUnlocked              // a vault exists and is open
)

// Status summarizes the vault for the header, the splash and the menu.
// Secrets is -1 when it is unknown (locked vault).
type Status struct {
	State    State
	Home     string // vault directory, as it should be displayed
	KeyStore string // "keychain" or "passphrase"; empty when unknown or no vault
	Secrets  int
	Hosts    int // registered coding-agent hosts
}

// Backend is everything the screens built so far need. It grows with the
// screens that need more; it must never grow a method that returns a secret
// value.
type Backend interface {
	Status() (Status, error)
}
