package tui_test

import (
	"errors"
	"io"

	"github.com/QuBiit0/qbit-vault/internal/tui"
)

// fakeAction is the Action of the fake backend: it records that it ran.
type fakeAction struct {
	name string
	ran  *[]string
	err  error
	// onRun lets a test change the fake's world when the action runs, as the
	// real command would.
	onRun func()
}

func (a *fakeAction) Run() error {
	*a.ran = append(*a.ran, a.name)
	if a.onRun != nil {
		a.onRun()
	}
	return a.err
}
func (a *fakeAction) SetStdin(io.Reader)  {}
func (a *fakeAction) SetStdout(io.Writer) {}
func (a *fakeAction) SetStderr(io.Writer) {}

// fakeBackend is the in-memory Backend of the model tests. It has no way to
// hold a secret value: the interface does not carry one.
type fakeBackend struct {
	status tui.Status
	err    error
	calls  int

	plan     tui.SetupPlan
	planErr  error
	setups   []tui.SetupRequest
	setupErr error
	// afterSetup is the status once the setup action has run.
	afterSetup *tui.Status

	secrets    tui.SecretList
	secretsErr error
	added      []tui.NewSecret
	edited     []tui.SecretEdit
	removed    []tui.SecretRef
	editErr    error
	removeErr  error
	addErr     error
	unlockErr  error
	afterUnlk  *tui.Status

	grants       []tui.Grant
	grantsErr    error
	revoked      []tui.GrantRef
	revokedAll   int
	revokeErr    error
	revokeResult int

	ran []string // names of the actions that ran, in order
}

func (f *fakeBackend) Status() (tui.Status, error) {
	f.calls++
	return f.status, f.err
}

func (f *fakeBackend) SetupPlan() (tui.SetupPlan, error) { return f.plan, f.planErr }

func (f *fakeBackend) Setup(r tui.SetupRequest) tui.Action {
	f.setups = append(f.setups, r)
	return &fakeAction{name: "setup", ran: &f.ran, err: f.setupErr, onRun: func() {
		if f.afterSetup != nil {
			f.status = *f.afterSetup
		}
	}}
}

func (f *fakeBackend) Secrets() (tui.SecretList, error) { return f.secrets, f.secretsErr }

func (f *fakeBackend) AddSecret(n tui.NewSecret) tui.Action {
	f.added = append(f.added, n)
	return &fakeAction{name: "add", ran: &f.ran, err: f.addErr, onRun: func() {
		if f.addErr == nil {
			f.secrets.Items = append(f.secrets.Items, tui.Secret{Name: n.Name, Layer: "global", Project: n.Project, Description: n.Description, Sensitive: n.Sensitive})
		}
	}}
}

func (f *fakeBackend) EditSecret(e tui.SecretEdit) error {
	f.edited = append(f.edited, e)
	return f.editErr
}

func (f *fakeBackend) RemoveSecret(r tui.SecretRef) error {
	f.removed = append(f.removed, r)
	if f.removeErr != nil {
		return f.removeErr
	}
	for i, s := range f.secrets.Items {
		if s.Name == r.Name && s.Project == r.Project {
			f.secrets.Items = append(f.secrets.Items[:i:i], f.secrets.Items[i+1:]...)
			break
		}
	}
	return nil
}

func (f *fakeBackend) Unlock() tui.Action {
	return &fakeAction{name: "unlock", ran: &f.ran, err: f.unlockErr, onRun: func() {
		if f.afterUnlk != nil {
			f.status = *f.afterUnlk
			f.secretsErr, f.grantsErr = nil, nil
		}
	}}
}

func (f *fakeBackend) Grants() ([]tui.Grant, error) { return f.grants, f.grantsErr }

func (f *fakeBackend) RevokeGrant(r tui.GrantRef) (int, error) {
	f.revoked = append(f.revoked, r)
	if f.revokeErr != nil {
		return 0, f.revokeErr
	}
	n := 0
	kept := f.grants[:0:0]
	for _, g := range f.grants {
		if g.Name == r.Name && g.Key == r.Key {
			n++
			continue
		}
		kept = append(kept, g)
	}
	f.grants = kept
	return n, nil
}

func (f *fakeBackend) RevokeAllGrants() (int, error) {
	f.revokedAll++
	if f.revokeErr != nil {
		return 0, f.revokeErr
	}
	n := len(f.grants)
	f.grants = nil
	return n, nil
}

var (
	noVault = tui.Status{State: tui.StateNone, Home: "~/.qbit-vault"}
	ready   = tui.Status{State: tui.StateUnlocked, Home: "~/.qbit-vault", KeyStore: "keychain", Secrets: 6, Hosts: 3}
	locked  = tui.Status{State: tui.StateLocked, Home: "~/.qbit-vault", Secrets: -1, Hosts: 2}
	errBoom = errors.New("backend failure")
)

// sampleSecrets is a vault with global and project secrets, one sensitive.
func sampleSecrets() tui.SecretList {
	return tui.SecretList{Project: "shop-api", Items: []tui.Secret{
		{Name: "GITHUB_TOKEN", Layer: "global", Description: "GitHub PAT for gh and git", Binaries: []string{"gh", "git"}, Hosts: []string{"api.github.com"}, UpdatedAt: "2026-11-03T18:20:00Z"},
		{Name: "NPM_TOKEN", Layer: "global", Description: "npm publish"},
		{Name: "DATABASE_URL", Layer: "shop-api", Project: true, Description: "primary database"},
		{Name: "STRIPE_SECRET_KEY", Layer: "shop-api", Project: true, Sensitive: true, Description: "payments"},
	}}
}

// sampleGrants is two live grants.
func sampleGrants() []tui.Grant {
	return []tui.Grant{
		{Name: "GITHUB_TOKEN", Layer: "global", Key: "global", Scope: "session", Session: "claude-code:7f3a21", Left: "11h 42m"},
		{Name: "DATABASE_URL", Layer: "project:shop-api", Key: "project:/work/shop-api", Scope: "project", Left: "no expiry"},
	}
}

// newReady is a backend with an open vault, secrets and grants.
func newReady() *fakeBackend {
	return &fakeBackend{status: ready, secrets: sampleSecrets(), grants: sampleGrants()}
}

// setupPlan is a machine where claude-code and codex are installed.
func setupPlan() tui.SetupPlan {
	return tui.SetupPlan{
		Home:     "~/.qbit-vault",
		Keychain: "Windows Credential Manager",
		Hosts: []tui.HostChoice{
			{Name: "claude-code", Detected: true, Steps: []string{"mcp", "hooks", "deny"}},
			{Name: "codex", Detected: true, Steps: []string{"mcp"}},
			{Name: "pi", Detected: false, Steps: []string{"mcp"}},
		},
	}
}
