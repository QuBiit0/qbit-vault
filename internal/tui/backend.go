// Package tui is the interactive terminal app (odd/tasks/tui.md). It never
// holds a secret value: the Backend it talks to has no type that can carry
// one, and every screen shows names, counts and status only.
package tui

import (
	"errors"

	tea "github.com/charmbracelet/bubbletea"
)

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

// ErrLocked is what Secrets and Grants return while the vault cannot be
// opened without a prompt. The screens turn it into the locked state.
var ErrLocked = errors.New("vault locked")

// Action is work that may need the terminal for a masked prompt (a secret
// value, a passphrase). The model runs it with tea.Exec, which suspends the
// TUI while it runs, or off the event loop when no prompt is involved. Its
// error text is shown to the user, so it must be safe to display.
type Action = tea.ExecCommand

// HostChoice is one coding agent the wizard can register with.
type HostChoice struct {
	Name     string
	Detected bool
	Steps    []string // the config edits registering makes, in order
}

// SetupPlan is what the wizard shows before anything is written.
type SetupPlan struct {
	Home     string // the directory that will be created
	Keychain string // the OS keychain that would hold the key, for the consequence line
	Hosts    []HostChoice
}

// SetupRequest is the user's choice: where the key lives and which hosts to
// register. It carries no secret: a passphrase is asked by the prompt backend.
type SetupRequest struct {
	Passphrase bool
	Hosts      []string
}

// Secret is the metadata of one stored secret. There is no value field and no
// way to add one.
type Secret struct {
	Name        string
	Layer       string // "global" or the project label
	Project     bool
	Description string
	Sensitive   bool
	Binaries    []string
	Hosts       []string
	Overrides   bool // a project secret that shadows a global one
	Unlinked    bool // synced from another device, no root on this one
	UpdatedAt   string
}

// SecretList is what the Secrets section shows.
type SecretList struct {
	Items   []Secret
	Project string // label of the repository the TUI runs in, "" outside one
}

// SecretRef addresses one secret.
type SecretRef struct {
	Name    string
	Project bool
}

// NewSecret is the metadata the add form collects. The value is typed later,
// in the prompt backend, never here.
type NewSecret struct {
	SecretRef
	Description string
	Sensitive   bool
}

// SecretEdit replaces the description and sensitive flag of a secret.
type SecretEdit struct {
	SecretRef
	Description string
	Sensitive   bool
}

// Grant is one active grant, read-only.
type Grant struct {
	Name    string
	Layer   string // "global" or "project:<label>"
	Key     string // opaque layer key, handed back to RevokeGrant
	Scope   string // once, session or project
	Session string // empty for the project scope
	Left    string // time left, "no expiry" or "1 use"
}

// GrantRef addresses the grants of one secret in one layer.
type GrantRef struct {
	Name string
	Key  string
}

// Backend is everything the screens need. It grows with the screens that
// need more; it must never grow a method that returns a secret value or
// creates or approves a grant (AGENTS.md invariant 6): granting happens in
// the prompt an agent's request triggers, never here.
type Backend interface {
	Status() (Status, error)

	SetupPlan() (SetupPlan, error)
	// Setup is `init` with the chosen key storage and hosts. With a
	// passphrase it asks for it in the prompt backend, so it must run under
	// tea.Exec.
	Setup(SetupRequest) Action

	Secrets() (SecretList, error)
	// AddSecret is `set`: it asks for the value in the prompt backend, so it
	// must run under tea.Exec. It never creates a grant.
	AddSecret(NewSecret) Action
	EditSecret(SecretEdit) error
	RemoveSecret(SecretRef) error
	// Unlock asks the passphrase in the prompt backend (run under tea.Exec).
	Unlock() Action

	Grants() ([]Grant, error)
	RevokeGrant(GrantRef) (int, error)
	RevokeAllGrants() (int, error)
}
