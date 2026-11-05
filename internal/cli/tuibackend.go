package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/QuBiit0/qbit-vault/internal/exitcode"
	"github.com/QuBiit0/qbit-vault/internal/grants"
	"github.com/QuBiit0/qbit-vault/internal/keychain"
	"github.com/QuBiit0/qbit-vault/internal/tui"
	"github.com/QuBiit0/qbit-vault/internal/vault"
)

// tuiListed, when set, receives the entries a TUI listing has already wiped.
// Tests use it to look at their values; it is nil in the binary.
var tuiListed func([]vault.Entry)

// maxTUIError bounds the error text the TUI shows.
const maxTUIError = 160

// tuiBackend is the cli side of tui.Backend. It reads through the same session
// the commands use, opened without a prompt (a locked vault is tui.ErrLocked),
// and every change is the real command run in-process, so snapshots, atomic
// writes and the audit log are exactly the CLI's. Nothing it returns carries a
// secret value, and nothing in it creates a grant (AGENTS.md invariant 6).
type tuiBackend struct{ g *globals }

// open is the quiet session: the OS keychain or an unexpired unlock cache,
// never a prompt, because the TUI owns the terminal while it is showing.
func (b *tuiBackend) open() (*session, error) {
	s, err := b.g.openSessionQuiet()
	if errors.Is(err, errSessionLocked) {
		return nil, tui.ErrLocked
	}
	return s, err
}

// visible lists what the working directory can see, like `list` does: the
// metadata only. ListAll and List both load values, so the entries are wiped
// before anything else happens (the vault has no metadata-only listing).
func (b *tuiBackend) visible(s *session) (items []tui.Secret, project string, err error) {
	cwd, err := getwd()
	if err != nil {
		return nil, "", err
	}
	cur, perr := vault.ProjectLayer(cwd)
	switch {
	case perr == nil:
		project = oneLine(cur.Label)
	case !errors.Is(perr, vault.ErrNoProject):
		return nil, "", perr
	}
	entries, err := s.v.List(cwd)
	if err != nil {
		return nil, "", err
	}
	for _, e := range entries {
		items = append(items, tuiSecret(e))
	}
	wipeEntries(entries)
	if tuiListed != nil {
		tuiListed(entries)
	}
	return items, project, nil
}

func tuiSecret(e vault.Entry) tui.Secret {
	layer := "global"
	if e.Layer.Project {
		layer = oneLine(e.Layer.Label)
	}
	return tui.Secret{
		Name: e.Name, Layer: layer, Project: e.Layer.Project,
		Description: oneLine(e.Record.Description), Sensitive: e.Record.Sensitive,
		Binaries: oneLines(e.Record.Binaries), Hosts: oneLines(e.Record.Hosts),
		Overrides: e.OverridesGlobal, Unlinked: e.Unlinked, UpdatedAt: oneLine(e.Record.UpdatedAt),
	}
}

func oneLines(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = oneLine(s)
	}
	return out
}

// Status gives the header, the splash and the menu their facts.
func (b *tuiBackend) Status() (tui.Status, error) {
	home := b.g.Home()
	st := tui.Status{Home: home}
	if _, err := vault.ReadID(home); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return st, nil // no vault yet: StateNone
		}
		return tui.Status{}, err
	}
	if hs, err := vault.ReadHosts(home); err == nil {
		st.Hosts = len(hs)
	}
	s, err := b.open()
	switch {
	case errors.Is(err, tui.ErrLocked):
		st.State, st.Secrets = tui.StateLocked, -1
		return st, nil
	case err != nil:
		return tui.Status{}, err
	}
	defer s.close()
	items, _, err := b.visible(s)
	if err != nil {
		return tui.Status{}, err
	}
	st.Secrets = len(items)
	st.State, st.KeyStore = tui.StateUnlocked, "keychain"
	if s.mode == keychain.ModePassphrase {
		st.KeyStore = "passphrase"
	}
	return st, nil
}

// ---- setup ----

// SetupPlan lists what the wizard can register, read-only.
func (b *tuiBackend) SetupPlan() (tui.SetupPlan, error) {
	env := b.g.hostEnv()
	plan := tui.SetupPlan{Home: b.g.Home(), Keychain: keychainLabel(keychain.NewOS().Name())}
	for _, a := range hostRegistry(b.g).All() {
		h := tui.HostChoice{Name: a.Name(), Detected: a.Detect(env)}
		for _, st := range a.Steps(env) {
			h.Steps = append(h.Steps, st.Name)
		}
		plan.Hosts = append(plan.Hosts, h)
	}
	return plan, nil
}

// keychainLabel names the OS keychain for the consequence line.
func keychainLabel(mode string) string {
	switch keychain.Mode(mode) {
	case keychain.ModeWindows:
		return "Windows Credential Manager"
	case keychain.ModeMacOS:
		return "macOS Keychain"
	case keychain.ModeSecretSvc:
		return "Secret Service"
	}
	return mode
}

// Setup is `init` with the chosen key storage and hosts. A passphrase is asked
// by `init` itself, through the prompt backend, on the terminal the TUI gave up.
func (b *tuiBackend) Setup(req tui.SetupRequest) tui.Action {
	agents := agentsNone
	if len(req.Hosts) > 0 {
		agents = strings.Join(req.Hosts, ",")
	}
	args := []string{"init", "--agents", agents}
	if req.Passphrase {
		args = append(args, "--passphrase")
	}
	return tuiAction{func() error { return b.g.runCommand(args...) }}
}

// ---- secrets ----

// Secrets lists names and metadata.
func (b *tuiBackend) Secrets() (tui.SecretList, error) {
	s, err := b.open()
	if err != nil {
		return tui.SecretList{}, err
	}
	defer s.close()
	items, project, err := b.visible(s)
	if err != nil {
		return tui.SecretList{}, err
	}
	return tui.SecretList{Items: items, Project: project}, nil
}

func layerArg(project bool) string {
	if project {
		return "--project"
	}
	return "--global"
}

// AddSecret is `set` without --stdin: the value is asked in the prompt backend.
// A description or flag left empty is not passed, so replacing an existing
// secret keeps its metadata. No --grant is ever passed.
func (b *tuiBackend) AddSecret(n tui.NewSecret) tui.Action {
	args := []string{"set", layerArg(n.Project)}
	if n.Description != "" {
		args = append(args, "--description="+n.Description)
	}
	if n.Sensitive {
		args = append(args, "--sensitive")
	}
	args = append(args, "--", n.Name)
	return tuiAction{func() error { return b.g.runCommand(args...) }}
}

// quiet fails with tui.ErrLocked unless the vault opens without a prompt. The
// commands that run while the TUI owns the terminal check it first, so they
// can never reach a passphrase prompt over the screen.
func (b *tuiBackend) quiet() error {
	s, err := b.open()
	if err != nil {
		if errors.Is(err, tui.ErrLocked) {
			return fmt.Errorf("%w: unlock it first", err)
		}
		return tuiError(err.Error(), exitcode.Failure)
	}
	s.close()
	return nil
}

// EditSecret is `edit`.
func (b *tuiBackend) EditSecret(e tui.SecretEdit) error {
	if err := b.quiet(); err != nil {
		return err
	}
	return b.g.runCommand("edit", layerArg(e.Project), "--description="+e.Description, fmt.Sprintf("--sensitive=%t", e.Sensitive), "--", e.Name)
}

// RemoveSecret is `rm --yes`: the TUI has already asked.
func (b *tuiBackend) RemoveSecret(r tui.SecretRef) error {
	if err := b.quiet(); err != nil {
		return err
	}
	return b.g.runCommand("rm", layerArg(r.Project), "--yes", "--", r.Name)
}

// Unlock is `unlock`: it asks the passphrase through the prompt backend.
func (b *tuiBackend) Unlock() tui.Action {
	return tuiAction{func() error { return b.g.runCommand("unlock") }}
}

// ---- grants ----

// Grants lists the live grants. It cannot create one.
func (b *tuiBackend) Grants() ([]tui.Grant, error) {
	s, err := b.open()
	if err != nil {
		return nil, err
	}
	defer s.close()
	_, live, err := b.g.activeGrants(io.Discard, s)
	if err != nil {
		return nil, err
	}
	now := clock()
	out := make([]tui.Grant, 0, len(live))
	for _, gr := range live {
		layer := "global"
		if root, ok := grants.ProjectRootOf(gr.Layer); ok {
			layer = "project:" + oneLine(filepath.Base(root))
		}
		out = append(out, tui.Grant{
			Name: gr.Name, Layer: layer, Key: gr.Layer, Scope: string(gr.Scope),
			Session: oneLine(gr.Session), Left: leftText(gr, now),
		})
	}
	return out, nil
}

// leftText is the time a grant has left, "12h 0m", "10m 0s" or "no expiry".
func leftText(gr grants.Grant, now time.Time) string {
	if gr.ExpiresAt == nil {
		return "no expiry"
	}
	d := gr.ExpiresAt.Sub(now).Round(time.Second)
	switch {
	case d <= 0:
		return "expired"
	case d >= time.Hour:
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	case d >= time.Minute:
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%ds", int(d.Seconds()))
}

// RevokeGrant is `revoke NAME` for one layer, through the same revokeGrants
// the command uses (audited, with the grants store rewritten atomically).
func (b *tuiBackend) RevokeGrant(r tui.GrantRef) (int, error) {
	if r.Key == "" {
		return 0, errors.New("the grant has no layer")
	}
	return b.revoke(r.Name, r.Key, false)
}

// RevokeAllGrants is `revoke --all`.
func (b *tuiBackend) RevokeAllGrants() (int, error) { return b.revoke("", "", true) }

func (b *tuiBackend) revoke(name, layerKey string, all bool) (int, error) {
	s, err := b.open()
	if err != nil {
		return 0, err
	}
	defer s.close()
	n, err := b.g.revokeGrants(io.Discard, s, name, layerKey, all, false)
	if err != nil {
		return 0, tuiError(err.Error(), exitcode.Failure)
	}
	return n, nil
}

// ---- running the commands ----

// tuiAction is a tui.Action over a function. tea gives it the terminal's
// streams; it ignores them, because a prompt reads the controlling terminal
// itself and the command output is not shown.
type tuiAction struct{ run func() error }

func (a tuiAction) Run() error        { return a.run() }
func (tuiAction) SetStdin(io.Reader)  {}
func (tuiAction) SetStdout(io.Writer) {}
func (tuiAction) SetStderr(io.Writer) {}

// runCommand runs one CLI command in-process, with the same --home and
// session, and turns a failure into the one safe line the command printed.
// Callers put text the user typed (a secret name) after "--", so it is never
// parsed as a flag, and pass flag values in the --flag=value form.
func (g *globals) runCommand(args ...string) error {
	full := []string{"--home", g.Home()}
	if g.Session != "" {
		full = append(full, "--session", g.Session)
	}
	var out, errb bytes.Buffer
	if code := execute(append(full, args...), &out, &errb, g.getenv); code != exitcode.OK {
		return tuiError(errb.String(), code)
	}
	return nil
}

// tuiError is the first line of a command's stderr without its "error: "
// prefix, bounded and on one line. Those lines are fixed texts or name a
// secret, never a value. With nothing to show it points at doctor.
func tuiError(stderr string, code int) error {
	line, _, _ := strings.Cut(strings.TrimSpace(stderr), "\n")
	line = strings.TrimSpace(strings.TrimPrefix(oneLine(line), "error: "))
	if line == "" {
		line = fmt.Sprintf("the command did not finish cleanly (exit %d); run 'qbit-vault doctor'", code)
	}
	if r := []rune(line); len(r) > maxTUIError {
		line = string(r[:maxTUIError-1]) + "…"
	}
	return errors.New(line)
}
