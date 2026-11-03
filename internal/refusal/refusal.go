// Package refusal defines the typed refusals of the broker contract
// (contracts/secrets-broker/v1/CONTRACT.md § Refusals) and their exit codes.
// Messages are built only from the secret name and fixed strings.
package refusal

import "github.com/QuBiit0/gentle-vault/internal/exitcode"

// Type is a refusal type from the contract.
type Type string

const (
	GrantRequired    Type = "grant_required"
	UnknownSecret    Type = "unknown_secret"
	UserDeclined     Type = "user_declined"
	RateLimited      Type = "rate_limited"
	ReasonTooVague   Type = "reason_too_vague"
	InvalidName      Type = "invalid_name"
	ScopeNotAllowed  Type = "scope_not_allowed"
	ScopeBinary      Type = "scope_binary"
	NoProject        Type = "no_project"
	DumpCommand      Type = "dump_command"
	NotModelCallable Type = "not_model_callable"
	VaultLocked      Type = "vault_locked"
	VaultCorrupt     Type = "vault_corrupt"
	Timeout          Type = "timeout"
	ContractMismatch Type = "contract_mismatch"
	Internal         Type = "internal"
)

type spec struct {
	retryable bool
	message   string // fixed text when there is no name
	named     string // fixed suffix after the name; empty means the message ignores the name
}

// Defaults follow the `retryable` column of the contract table; `internal`
// is "maybe" there and defaults to false.
var specs = map[Type]spec{
	GrantRequired:    {true, "no active grant for this secret", " has no active grant"},
	UnknownSecret:    {true, "unknown secret", " is not stored"},
	UserDeclined:     {false, "the user declined", ""},
	RateLimited:      {false, "too many requests; back off", ""},
	ReasonTooVague:   {true, "the reason is too vague", ""},
	InvalidName:      {false, "invalid secret name", ""},
	ScopeNotAllowed:  {false, "this scope is not allowed for a sensitive secret", ""},
	ScopeBinary:      {false, "the command's binary is not allowed for this secret", ""},
	NoProject:        {false, "not inside a repository", ""},
	DumpCommand:      {false, "the command is refused while secrets are injected", ""},
	NotModelCallable: {false, "this operation is not available to the model", ""},
	VaultLocked:      {true, "vault is locked", ""},
	VaultCorrupt:     {false, "vault is corrupt; run 'gentle-vault restore'", ""},
	Timeout:          {true, "the command timed out", ""},
	ContractMismatch: {false, "unsupported contract version", ""},
	Internal:         {false, "internal error", ""},
}

// order is the contract table order.
var order = []Type{
	GrantRequired, UnknownSecret, UserDeclined, RateLimited, ReasonTooVague,
	InvalidName, ScopeNotAllowed, ScopeBinary, NoProject, DumpCommand,
	NotModelCallable, VaultLocked, VaultCorrupt, Timeout, ContractMismatch, Internal,
}

// Types returns every refusal type in contract order.
func Types() []Type { return append([]Type(nil), order...) }

// Partial is the redacted output a timeout refusal carries (CONTRACT § exec).
type Partial struct {
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
}

// Refusal is the payload of a typed refusal. Name is nil when the refusal is
// not about one secret.
type Refusal struct {
	Type      Type     `json:"type"`
	Name      *string  `json:"name"`
	Message   string   `json:"message"`
	Retryable bool     `json:"retryable"`
	Partial   *Partial `json:"partial,omitempty"`
}

// Envelope is the wire form: {"ok":false,"refusal":{…}}.
type Envelope struct {
	OK      bool    `json:"ok"`
	Refusal Refusal `json:"refusal"`
}

// New builds a refusal with the fixed message and default retryability of its
// type. An empty name means "no secret"; callers must pass a name that has
// already passed validation, never raw user input.
func New(t Type, name string) Refusal {
	s := specs[t]
	r := Refusal{Type: t, Message: s.message, Retryable: s.retryable}
	if name != "" {
		n := name
		r.Name = &n
		if s.named != "" {
			r.Message = name + s.named
		}
	}
	return r
}

// WithMessage returns r with a different fixed message.
func (r Refusal) WithMessage(m string) Refusal { r.Message = m; return r }

// WithPartial returns r carrying the (already redacted) output a timed-out
// command produced before it was killed.
func (r Refusal) WithPartial(stdout, stderr string) Refusal {
	r.Partial = &Partial{Stdout: stdout, Stderr: stderr}
	return r
}

// WithRetryable returns r with an explicit retryable flag.
func (r Refusal) WithRetryable(b bool) Refusal { r.Retryable = b; return r }

// Error implements error. It returns the message only.
func (r Refusal) Error() string { return r.Message }

// Valid reports whether the type is one of the contract types.
func (r Refusal) Valid() bool { _, ok := specs[r.Type]; return ok }

// Envelope returns the JSON wire form of r.
func (r Refusal) Envelope() Envelope { return Envelope{OK: false, Refusal: r} }

// ExitCode maps the refusal to a process exit code (docs/CLI.md § Exit codes).
func (r Refusal) ExitCode() int {
	switch r.Type {
	case VaultLocked:
		return exitcode.Locked
	case VaultCorrupt:
		return exitcode.Corrupt
	default:
		return exitcode.Refusal
	}
}
