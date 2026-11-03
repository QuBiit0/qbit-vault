package vault

import (
	"errors"
	"fmt"
	"regexp"
)

// Typed refusals. Messages that name a secret carry the name only.
var (
	ErrNotFound    = errors.New("unknown_secret")
	ErrExists      = errors.New("secret_exists")
	ErrInvalidName = errors.New("invalid_name")
	ErrNoProject   = errors.New("no_project")
)

var nameRE = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

// checkName enforces R-VAULT-05. The rejected text is deliberately not echoed.
func checkName(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("%w: must match %s", ErrInvalidName, nameRE.String())
	}
	return nil
}

func withName(err error, name string) error { return fmt.Errorf("%w: %s", err, name) }

// Layer addresses one namespace of the vault: the global layer (the zero
// value) or the project bound to one canonical repository root.
type Layer struct {
	Project bool
	Root    string // canonical repository root; only meaningful when Project
	Label   string // display name (base name of the root); not part of identity
}

// Global returns the global layer.
func Global() Layer { return Layer{} }

func (l Layer) same(o Layer) bool {
	return l.Project == o.Project && (!l.Project || l.Root == o.Root)
}

// checkLayer rejects a project layer that is not bound to a root.
func checkLayer(l Layer) error {
	if l.Project && l.Root == "" {
		return ErrNoProject
	}
	return nil
}

// ValidName reports whether name is a legal secret name (R-VAULT-05). It lets
// callers reject a name before they need the vault.
func ValidName(name string) bool { return nameRE.MatchString(name) }
