package tui_test

import (
	"errors"
	"io"

	"github.com/qbitdevz/qbit-vault/internal/tui"
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

	hosts       []tui.HostInfo
	hostsErr    error
	hostOpErr   error
	repaired    []string // names passed to RepairHosts ("" is all)
	uninstalled []string
	registered  []string
	hostsCalls  int
	audit       tui.AuditLog
	auditErr    error
	verdict     tui.AuditVerdict
	verifyErr   error
	verifyCalls int
	syncStatus  tui.SyncStatus
	syncErr     error
	doctor      tui.DoctorReport
	doctorErr   error
	doctorCalls int

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
			f.secretsErr, f.grantsErr, f.hostsErr, f.auditErr, f.syncErr, f.doctorErr = nil, nil, nil, nil, nil, nil
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

func (f *fakeBackend) Hosts() ([]tui.HostInfo, error) {
	f.hostsCalls++
	return f.hosts, f.hostsErr
}

func (f *fakeBackend) setHost(name string, fn func(*tui.HostInfo)) {
	for i := range f.hosts {
		if f.hosts[i].Name == name {
			steps := append([]tui.HostStep(nil), f.hosts[i].Steps...)
			f.hosts[i].Steps = steps
			fn(&f.hosts[i])
		}
	}
}

func (f *fakeBackend) RepairHosts(name string) (string, error) {
	f.repaired = append(f.repaired, name)
	if f.hostOpErr != nil {
		return "", f.hostOpErr
	}
	for i := range f.hosts {
		if name != "" && f.hosts[i].Name != name {
			continue
		}
		if !f.hosts[i].Registered {
			continue
		}
		f.setHost(f.hosts[i].Name, func(h *tui.HostInfo) {
			for j := range h.Steps {
				h.Steps[j].Status = tui.StepOK
			}
		})
	}
	if name == "" {
		return "repaired every registered host", nil
	}
	return "repaired " + name, nil
}

func (f *fakeBackend) UninstallHost(name string) (string, error) {
	f.uninstalled = append(f.uninstalled, name)
	if f.hostOpErr != nil {
		return "", f.hostOpErr
	}
	f.setHost(name, func(h *tui.HostInfo) {
		h.Registered = false
		for j := range h.Steps {
			h.Steps[j].Status, h.Steps[j].File = tui.StepMissing, ""
		}
	})
	return "uninstalled " + name, nil
}

func (f *fakeBackend) RegisterHost(name string) (string, error) {
	f.registered = append(f.registered, name)
	if f.hostOpErr != nil {
		return "", f.hostOpErr
	}
	f.setHost(name, func(h *tui.HostInfo) {
		h.Registered = true
		for j := range h.Steps {
			h.Steps[j].Status = tui.StepOK
		}
	})
	return "registered " + name, nil
}

func (f *fakeBackend) Audit() (tui.AuditLog, error) { return f.audit, f.auditErr }

func (f *fakeBackend) VerifyAudit() (tui.AuditVerdict, error) {
	f.verifyCalls++
	return f.verdict, f.verifyErr
}

func (f *fakeBackend) SyncStatus() (tui.SyncStatus, error) { return f.syncStatus, f.syncErr }

func (f *fakeBackend) Doctor() (tui.DoctorReport, error) {
	f.doctorCalls++
	return f.doctor, f.doctorErr
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
	return &fakeBackend{status: ready, secrets: sampleSecrets(), grants: sampleGrants(),
		hosts: sampleHosts(), audit: sampleAudit(), verdict: tui.AuditVerdict{Valid: true, Records: 412},
		syncStatus: tui.SyncStatus{Conflicts: -1}, doctor: sampleDoctor()}
}

// sampleHosts is claude-code with a drifted hook, a healthy codex and a pi
// that is installed but not registered, plus nothing else.
func sampleHosts() []tui.HostInfo {
	return []tui.HostInfo{
		{Name: "claude-code", Registered: true, Detected: true, Steps: []tui.HostStep{
			{Name: "mcp", Status: tui.StepOK, File: "/home/u/.claude.json"},
			{Name: "hooks", Status: tui.StepDrift, File: "/home/u/.claude/settings.json"},
			{Name: "deny-list", Status: tui.StepOK, File: "/home/u/.claude/settings.json"},
		}},
		{Name: "codex", Registered: true, Detected: true, Steps: []tui.HostStep{
			{Name: "mcp", Status: tui.StepOK, File: "/home/u/.codex/config.toml"},
		}},
		{Name: "pi", Registered: false, Detected: true, Steps: []tui.HostStep{
			{Name: "mcp", Status: tui.StepMissing},
		}},
	}
}

// sampleAudit is a short log; the entries carry no value.
func sampleAudit() tui.AuditLog {
	return tui.AuditLog{Total: 412, Entries: []tui.AuditEntry{
		{Time: "2026-11-05T09:14:02Z", Event: "grant", Names: []string{"NPM_TOKEN"}, Layer: "global", By: "user"},
		{Time: "2026-11-05T10:12:03Z", Event: "refusal", Names: []string{"STRIPE_SECRET_KEY"}, Layer: "project:/work/shop-api", By: "agent"},
		{Time: "2026-11-05T10:31:07Z", Event: "exec", Names: []string{"GITHUB_TOKEN"}, Layer: "global", By: "agent"},
	}}
}

// sampleDoctor has one of each status.
func sampleDoctor() tui.DoctorReport {
	return tui.DoctorReport{Checks: []tui.DoctorCheck{
		{Name: "vault", Status: "ok", Detail: "unlocked (keychain: keychain)"},
		{Name: "permissions", Status: "warn", Detail: "vault.enc: group-readable"},
		{Name: "audit", Status: "fail", Detail: "audit chain broken at line 3 (bad_hash); run 'qbit-vault audit --verify'"},
	}}
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
