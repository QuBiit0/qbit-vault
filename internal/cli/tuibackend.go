package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/qbitdevz/qbit-vault/internal/audit"
	"github.com/qbitdevz/qbit-vault/internal/exitcode"
	"github.com/qbitdevz/qbit-vault/internal/grants"
	"github.com/qbitdevz/qbit-vault/internal/hosts"
	"github.com/qbitdevz/qbit-vault/internal/keychain"
	"github.com/qbitdevz/qbit-vault/internal/selfupdate"
	"github.com/qbitdevz/qbit-vault/internal/tui"
	"github.com/qbitdevz/qbit-vault/internal/vault"
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

// EditSecret is `edit`. The description is passed only when the user changed
// it: the form shows it on one line, so an unchanged one stays as stored.
func (b *tuiBackend) EditSecret(e tui.SecretEdit) error {
	args := []string{"edit", layerArg(e.Project)}
	if !e.KeepDescription {
		args = append(args, "--description="+e.Description)
	}
	args = append(args, fmt.Sprintf("--sensitive=%t", e.Sensitive), "--", e.Name)
	return b.g.runCommandNoPrompt(args...)
}

// RemoveSecret is `rm --yes`: the TUI has already asked.
func (b *tuiBackend) RemoveSecret(r tui.SecretRef) error {
	return b.g.runCommandNoPrompt("rm", layerArg(r.Project), "--yes", "--", r.Name)
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

// ---- update ----

// tuiCheckTimeout bounds the open-time release check (S4.1); tests shorten it.
var tuiCheckTimeout = 5 * time.Second

// CheckUpdate asks the releases API for the latest release, like
// `update --check`. Only versions and the release notes link leave this
// function; the error is a fixed line, so no URL or response text is shown.
func (b *tuiBackend) CheckUpdate() (tui.UpdateInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), tuiCheckTimeout)
	defer cancel()
	rel, err := selfupdate.NewClient(Version, updateAPI(b.g.getenv)).Latest(ctx)
	if err != nil {
		return tui.UpdateInfo{}, errors.New("could not check for updates")
	}
	newer, err := selfupdate.Newer(Version, rel.Tag)
	if err != nil {
		newer = true
	}
	return tui.UpdateInfo{Current: Version, Latest: rel.Tag, URL: rel.URL, Available: newer}, nil
}

// Update is `update`: it confirms in the prompt backend, so it runs under
// tea.Exec. It reads no secret and creates no grant.
func (b *tuiBackend) Update() tui.Action {
	return tuiAction{func() error { return b.g.runCommand("update") }}
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
// parsed as a flag, and pass flag values in the --flag=value form. It may
// prompt: only the commands that run suspended (tea.Exec) use it.
func (g *globals) runCommand(args ...string) error {
	if code, stderr := g.execIn(g.getenv, args); code != exitcode.OK {
		return tuiError(stderr, code)
	}
	return nil
}

// runCommandNoPrompt is runCommand for the commands that run while the TUI is
// showing: it can never prompt, so a passphrase that is not cached is
// tui.ErrLocked (unlock first) instead of a prompt drawn over the screen. The
// mode closes the window between checking that the vault opens quietly and
// running the command, in which an unlock cache can expire.
func (g *globals) runCommandNoPrompt(args ...string) error {
	env := func(k string) string {
		if k == noPromptKey {
			return "1"
		}
		return g.getenv(k)
	}
	code, stderr := g.execIn(env, args)
	switch code {
	case exitcode.OK:
		return nil
	case exitcode.Locked:
		return fmt.Errorf("%w: unlock it first", tui.ErrLocked)
	}
	return tuiError(stderr, code)
}

func (g *globals) execIn(getenv func(string) string, args []string) (int, string) {
	full := []string{"--home", g.Home()}
	if g.Session != "" {
		full = append(full, "--session", g.Session)
	}
	var out, errb bytes.Buffer
	code := execute(append(full, args...), &out, &errb, getenv)
	return code, errb.String()
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

// ---- hosts ----

// stepStatus is a step's verdict in the words of the TUI, from the same
// hosts.Verify result `doctor` words as ok, drift or "not registered".
func stepStatus(err error) string {
	switch {
	case err == nil:
		return tui.StepOK
	case errors.Is(err, hosts.ErrDrift):
		return tui.StepDrift
	case errors.Is(err, hosts.ErrNotRegistered):
		return tui.StepMissing
	}
	return tui.StepUnreadable
}

// Hosts lists the coding agents of this build, in registry order, then the
// recorded ones it has no adapter for. Registered hosts are checked with
// hosts.Verify, the check behind doctor's host lines; it reads state.json and
// the host config files and writes nothing.
func (b *tuiBackend) Hosts() ([]tui.HostInfo, error) {
	home := b.g.Home()
	if _, err := vault.ReadID(home); err != nil {
		return nil, mapTUIErr(err)
	}
	recorded, err := vault.ReadHosts(home)
	if err != nil {
		return nil, tuiError("the hosts section of state.json is damaged; try 'qbit-vault restore'", exitcode.Failure)
	}
	env, reg := b.g.hostEnv(), hostRegistry(b.g)
	var out []tui.HostInfo
	for _, a := range reg.All() {
		state, isRecorded := recorded[a.Name()]
		info := tui.HostInfo{Name: a.Name(), Registered: isRecorded, Detected: a.Detect(env)}
		if isRecorded {
			for _, c := range hosts.Verify(env, a, state) {
				step := tui.HostStep{Name: c.Step, Status: stepStatus(c.Err)}
				if r, ok := state.Receipts[c.Step]; ok {
					step.File = oneLine(r.Path)
				}
				info.Steps = append(info.Steps, step)
			}
		} else {
			for _, s := range a.Steps(env) {
				info.Steps = append(info.Steps, tui.HostStep{Name: s.Name, Status: tui.StepMissing})
			}
		}
		out = append(out, info)
	}
	for _, e := range recordedHosts(reg, recorded) {
		if e.adapter == nil {
			out = append(out, tui.HostInfo{Name: oneLine(e.name), Registered: true, NoAdapter: true})
		}
	}
	return out, nil
}

// mapTUIErr shows a mapped command error as the one safe line the CLI would.
func mapTUIErr(err error) error {
	return tuiError(mapErr(err, "").Error(), exitcode.Failure)
}

// changedSteps names what Apply did to one host: the steps that changed a file.
func changedSteps(r hosts.Result) string {
	var names []string
	for _, s := range r.Steps {
		if s.Changed {
			names = append(names, s.Name)
		}
	}
	return strings.Join(names, ", ")
}

// applyFailures turns the failed hosts of an Apply into the CLI's message.
func applyFailures(results []hosts.Result, what string) error {
	var failed []string
	for _, r := range results {
		if r.Err() == nil {
			continue
		}
		step := r.FailedStep()
		if step == "" {
			step = "state"
		}
		failed = append(failed, r.Host+" ("+step+")")
	}
	if len(failed) == 0 {
		return nil
	}
	return tuiError(what+" failed: "+strings.Join(failed, ", "), exitcode.Failure)
}

// RepairHosts is `sync` for one recorded host, or for every recorded host
// when name is empty: hosts.Apply re-applies the registration steps, which
// repairs drift, and writes a file only when something differs. A host that
// is only detected is never registered by it.
func (b *tuiBackend) RepairHosts(name string) (string, error) {
	home := b.g.Home()
	if _, err := vault.ReadID(home); err != nil {
		return "", mapTUIErr(err)
	}
	recorded, err := vault.ReadHosts(home)
	if err != nil {
		return "", mapTUIErr(err)
	}
	reg := hostRegistry(b.g)
	var run []hosts.Adapter
	for _, e := range recordedHosts(reg, recorded) {
		if e.adapter != nil && (name == "" || e.name == name) {
			run = append(run, e.adapter)
		}
	}
	switch {
	case len(run) == 0 && name != "":
		return "", errors.New(oneLine(name) + " is not registered")
	case len(run) == 0:
		return "no hosts registered", nil
	}
	results := hosts.Apply(b.g.hostEnv(), run)
	if err := applyFailures(results, "host registration"); err != nil {
		return "", err
	}
	var parts []string
	for _, r := range results {
		if r.Changed() {
			parts = append(parts, "repaired "+r.Host+" ("+changedSteps(r)+")")
		}
	}
	switch {
	case len(parts) > 0:
		return strings.Join(parts, "; "), nil
	case name != "":
		return name + " is up to date", nil
	}
	return "every registered host is up to date", nil
}

// UninstallHost reverts one host's registration, as `uninstall` does for
// each host (hosts.RevertHost: a file we created goes back to its snapshot,
// otherwise only our entries are removed) and audits it. It never purges: the
// vault and its key stay. The TUI has already asked.
func (b *tuiBackend) UninstallHost(name string) (string, error) {
	home := b.g.Home()
	if _, err := vault.ReadID(home); err != nil {
		return "", mapTUIErr(err)
	}
	recorded, err := vault.ReadHosts(home)
	if err != nil {
		return "", mapTUIErr(err)
	}
	if _, ok := recorded[name]; !ok || name == "" {
		return "", errors.New(oneLine(name) + " is not registered")
	}
	a, ok := hostRegistry(b.g).Get(name)
	if !ok {
		return "", errors.New(oneLine(name) + ": this build has no adapter for it, so it is kept in state.json")
	}
	done, err := hosts.RevertHost(b.g.hostEnv(), a)
	if err != nil {
		step := "state"
		var re *hosts.RevertError
		if errors.As(err, &re) {
			step = re.Step
		}
		return "", errors.New(name + ": failed at " + step + "; it is kept in state.json")
	}
	var parts []string
	for _, d := range done {
		parts = append(parts, d.Step+" "+string(d.Outcome))
	}
	if len(parts) == 0 {
		parts = []string{"nothing to revert"}
	}
	b.g.record(io.Discard, audit.Record{Event: audit.EventUninstall, Detail: fmt.Sprintf("reverted 1 of %d hosts", len(recorded))})
	return "uninstalled " + name + " (" + strings.Join(parts, ", ") + ")", nil
}

// RegisterHost registers one detected host that is not recorded yet, the same
// hosts.Apply that `init --agents` runs. It never asks for or stores a secret.
func (b *tuiBackend) RegisterHost(name string) (string, error) {
	home := b.g.Home()
	if _, err := vault.ReadID(home); err != nil {
		return "", mapTUIErr(err)
	}
	recorded, err := vault.ReadHosts(home)
	if err != nil {
		return "", mapTUIErr(err)
	}
	a, ok := hostRegistry(b.g).Get(name)
	switch {
	case !ok:
		return "", errors.New("unknown host")
	case recorded[name].Receipts != nil:
		return "", errors.New(name + " is already registered")
	case !a.Detect(b.g.hostEnv()):
		return "", errors.New(name + " was not found on this machine")
	}
	results := hosts.Apply(b.g.hostEnv(), []hosts.Adapter{a})
	if err := applyFailures(results, "host registration"); err != nil {
		return "", err
	}
	return "registered " + name + " (" + changedSteps(results[0]) + ")", nil
}

// ---- audit ----

// Audit reads the newest records, oldest first, and the size of the log
// (the head's seq, which counts every record). Only the fields the screen
// shows leave this function: no command text, reason or detail.
func (b *tuiBackend) Audit() (tui.AuditLog, error) {
	home := b.g.Home()
	if _, err := os.Stat(home); err != nil {
		return tui.AuditLog{}, mapTUIErr(err)
	}
	recs, err := audit.Read(home, audit.Filter{Tail: defaultAuditTail})
	if err != nil {
		return tui.AuditLog{}, tuiError(err.Error(), exitcode.Failure)
	}
	log := tui.AuditLog{Total: len(recs)}
	if seq, _, ok := audit.ReadHead(home); ok {
		log.Total = max(int(seq), len(recs))
	}
	for _, r := range recs {
		log.Entries = append(log.Entries, tui.AuditEntry{
			Time: oneLine(r.TS), Event: oneLine(r.Event), Names: oneLines(r.Names),
			Layer: auditLayerText(r.Layer), By: oneLine(r.By),
		})
	}
	return log, nil
}

// auditLayerText is a record's layer with a project shown by its folder name.
func auditLayerText(layer string) string {
	if root, ok := grants.ProjectRootOf(layer); ok {
		return "project:" + oneLine(filepath.Base(root))
	}
	return oneLine(layer)
}

// VerifyAudit is `audit --verify` for the local chain: the same audit.Verify.
// The comparison with the server's anchors (a network call) is left to the
// command.
func (b *tuiBackend) VerifyAudit() (tui.AuditVerdict, error) {
	res, err := audit.Verify(b.g.Home())
	if err != nil {
		return tui.AuditVerdict{}, tuiError(err.Error(), exitcode.Failure)
	}
	v := tui.AuditVerdict{Valid: res.Valid, Records: res.Records}
	if res.Problem != nil {
		v.Line, v.Reason = res.Problem.Line, oneLine(res.Problem.Reason)
	}
	return v, nil
}

// ---- sync status ----

// SyncStatus is `remote status` without its output: state.json for the link,
// and the vault for the conflict count when it opens without a prompt; a
// locked vault shows the count of the last round, or none. It never contacts
// the server and never touches a code or a key.
func (b *tuiBackend) SyncStatus() (tui.SyncStatus, error) {
	home := b.g.Home()
	if _, err := vault.ReadID(home); err != nil {
		return tui.SyncStatus{}, mapTUIErr(err)
	}
	rem, err := vault.ReadRemote(home)
	switch {
	case err != nil:
		return tui.SyncStatus{}, mapTUIErr(err)
	case rem == nil:
		return tui.SyncStatus{}, nil
	}
	id, _ := vault.ReadDeviceID(home)
	st := tui.SyncStatus{Linked: true, Server: oneLine(rem.Server), Device: short(id), LastRound: oneLine(rem.LastPullAt),
		PendingPush: rem.PendingPush, Offline: b.g.remoteOff()}
	s, err := b.open()
	switch {
	case errors.Is(err, tui.ErrLocked):
		if rem.Summary.At != "" {
			st.Conflicts, st.Cached = rem.Summary.Conflicts, true
		} else {
			st.Conflicts = -1
		}
	case err != nil:
		return tui.SyncStatus{}, err
	default:
		defer s.close()
		if st.Conflicts, err = s.v.ConflictCount(); err != nil {
			return tui.SyncStatus{}, mapTUIErr(err)
		}
	}
	return st, nil
}

// ---- doctor ----

// Doctor is the report of `qbit-vault doctor`: the same checks, run the same
// way (no prompt, nothing written).
func (b *tuiBackend) Doctor() (tui.DoctorReport, error) {
	rep := b.g.runDoctor()
	out := tui.DoctorReport{OK: rep.OK, Checks: make([]tui.DoctorCheck, len(rep.Checks))}
	for i, c := range rep.Checks {
		out.Checks[i] = tui.DoctorCheck{Name: oneLine(c.Name), Status: string(c.Status), Detail: oneLine(c.Detail)}
	}
	return out, nil
}
