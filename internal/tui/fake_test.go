package tui_test

import (
	"errors"

	"github.com/QuBiit0/qbit-vault/internal/tui"
)

// fakeBackend is the in-memory Backend of the model tests. It has no way to
// hold a secret value: the interface does not carry one.
type fakeBackend struct {
	status tui.Status
	err    error
	calls  int
}

func (f *fakeBackend) Status() (tui.Status, error) {
	f.calls++
	return f.status, f.err
}

var (
	noVault = tui.Status{State: tui.StateNone, Home: "~/.qbit-vault"}
	ready   = tui.Status{State: tui.StateUnlocked, Home: "~/.qbit-vault", KeyStore: "keychain", Secrets: 6, Hosts: 3}
	locked  = tui.Status{State: tui.StateLocked, Home: "~/.qbit-vault", Secrets: -1, Hosts: 2}
	errBoom = errors.New("backend failure")
)
