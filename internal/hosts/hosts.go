// Package hosts registers qbit-vault with the coding agents (docs/INSTALL.md
// § init step by step, PRD R-INS-03..08, R-HOST-05). An Adapter describes one
// host as an ordered list of Steps; each step edits one config file through
// internal/filemerge (snapshot first, atomic, owned entries only) and hands
// back a receipt. Apply runs the steps and records the receipts in
// state.json; it is idempotent. Verify compares the receipts with the files
// without writing, for `doctor`; Revert undoes the steps for `uninstall`.
//
// Nothing here reads a secret or the environment for values, and nothing
// touches the network. Errors name hosts, steps and config paths, never file
// contents.
package hosts

import (
	"errors"
	"fmt"
	"time"

	"github.com/QuBiit0/qbit-vault/internal/filemerge"
	"github.com/QuBiit0/qbit-vault/internal/vault"
)

// Typed errors; match them with errors.Is.
var (
	// ErrDrift: the host config no longer holds our registration (a step's
	// Check found that applying it again would change the file).
	ErrDrift = errors.New("hosts: registration no longer matches the host config")
	// ErrNotRegistered: state.json has no receipt for a step the adapter has.
	ErrNotRegistered = errors.New("hosts: step is not registered")
	// ErrUnknownHost: no adapter with that name.
	ErrUnknownHost = errors.New("hosts: unknown host")
)

// Env is what steps need to know about the machine. Adapters derive their
// config locations from UserHome; snapshots go under VaultHome/backups.
type Env struct {
	VaultHome string // the vault directory
	UserHome  string // the user's home directory ("" when unknown)
}

// Step is one reversible edit of one config file.
type Step struct {
	// Name is stable across versions ("mcp", "hooks", "deny-list"): it keys
	// the receipt in state.json.
	Name string
	// Apply performs the edit through filemerge. prev is the receipt of an
	// earlier apply or nil. It must not write when nothing would change.
	Apply func(env Env, prev *filemerge.Receipt) (filemerge.Receipt, error)
	// Revert undoes Apply from its receipt (filemerge's 3-way revert).
	Revert func(env Env, r filemerge.Receipt) (filemerge.Outcome, error)
	// Check is read-only: nil when the file still holds our registration,
	// an error wrapping ErrDrift when it does not. See CheckJSON, CheckTOML.
	Check func(env Env, r filemerge.Receipt) error
}

// Adapter is one coding agent (Claude Code, Codex, Pi, ...).
type Adapter interface {
	// Name is the stable host name: [a-z0-9-], at most 32 characters.
	Name() string
	// Detect reports whether the host looks installed. Read-only.
	Detect(env Env) bool
	// Steps lists the edits in the order they are applied.
	Steps(env Env) []Step
}

// StepResult is the outcome of one step of Apply.
type StepResult struct {
	Name    string
	Changed bool // a config file was written
	Err     error
}

// Result is the outcome of Apply for one host.
type Result struct {
	Host     string
	Steps    []StepResult
	StateErr error // the receipts could not be read or saved
}

// Err returns the first failure of the host, nil when it fully registered.
func (r Result) Err() error {
	if r.StateErr != nil {
		return r.StateErr
	}
	for _, s := range r.Steps {
		if s.Err != nil {
			return s.Err
		}
	}
	return nil
}

// FailedStep names the step that failed, "" when none (or the state failed).
func (r Result) FailedStep() string {
	for _, s := range r.Steps {
		if s.Err != nil {
			return s.Name
		}
	}
	return ""
}

// Changed reports whether any config file was written.
func (r Result) Changed() bool {
	for _, s := range r.Steps {
		if s.Changed {
			return true
		}
	}
	return false
}

var now = time.Now

// Apply registers every adapter, in order. A host stops at its first failing
// step, which leaves its own file untouched and the earlier steps recorded;
// the next host still runs. Receipts are saved after each step that changed
// them, so a crash keeps what was done. A second run with nothing changed
// writes neither a config file nor state.json.
func Apply(env Env, adapters []Adapter) []Result {
	out := make([]Result, 0, len(adapters))
	for _, a := range adapters {
		out = append(out, applyHost(env, a))
	}
	return out
}

func applyHost(env Env, a Adapter) Result {
	res := Result{Host: a.Name()}
	all, err := vault.ReadHosts(env.VaultHome)
	if err != nil {
		res.StateErr = err
		return res
	}
	h, known := all[a.Name()]
	if h.Receipts == nil {
		h.Receipts = map[string]filemerge.Receipt{}
	}
	steps := a.Steps(env)
	if !known {
		h.RegisteredAt = now().UTC().Format(time.RFC3339)
	}
	save := func() error {
		h.Registered = h.Registered[:0:0]
		for _, s := range steps {
			if _, ok := h.Receipts[s.Name]; ok {
				h.Registered = append(h.Registered, s.Name)
			}
		}
		cp := h
		return vault.WriteHost(env.VaultHome, a.Name(), &cp)
	}
	for _, s := range steps {
		var prev *filemerge.Receipt
		if r, ok := h.Receipts[s.Name]; ok {
			prev = &r
		}
		r, err := s.Apply(env, prev)
		if err != nil {
			res.Steps = append(res.Steps, StepResult{Name: s.Name, Err: err})
			break
		}
		res.Steps = append(res.Steps, StepResult{Name: s.Name, Changed: r.Changed})
		r.Changed = false
		if prev == nil || *prev != r {
			h.Receipts[s.Name] = r
			if err := save(); err != nil {
				res.StateErr = err
				return res
			}
		}
	}
	return res
}

// StepCheck is the read-only verdict on one step.
type StepCheck struct {
	Step string
	Err  error // nil ok; ErrDrift; ErrNotRegistered; or another read failure
}

// Verify compares the recorded receipts of a host with its config files,
// without writing or prompting.
func Verify(env Env, a Adapter, h vault.HostState) []StepCheck {
	var out []StepCheck
	for _, s := range a.Steps(env) {
		r, ok := h.Receipts[s.Name]
		switch {
		case !ok:
			out = append(out, StepCheck{s.Name, ErrNotRegistered})
		case s.Check == nil:
			out = append(out, StepCheck{s.Name, nil})
		default:
			out = append(out, StepCheck{s.Name, s.Check(env, r)})
		}
	}
	return out
}

// StepRevert is what reverting one step did to its config file.
type StepRevert struct {
	Step    string
	Outcome filemerge.Outcome
}

// RevertError is a failed revert: the step that failed and why. The host
// stays in state.json.
type RevertError struct {
	Host, Step string
	Err        error
}

func (e *RevertError) Error() string {
	return fmt.Sprintf("hosts: revert %s %s: %v", e.Host, e.Step, e.Err)
}

func (e *RevertError) Unwrap() error { return e.Err }

// Revert undoes the registered steps of a host in reverse order and, when all
// succeeded, forgets the host in state.json. On a failure the record stays,
// so the revert can be retried.
func Revert(env Env, a Adapter) error {
	_, err := RevertHost(env, a)
	return err
}

// RevertHost is Revert that also reports, in the order undone, what each step
// did (filemerge's revert rule: restored, stripped, deleted, absent or
// unchanged). On a failure it returns the steps undone before it, and the
// error is a *RevertError.
func RevertHost(env Env, a Adapter) ([]StepRevert, error) {
	all, err := vault.ReadHosts(env.VaultHome)
	if err != nil {
		return nil, err
	}
	h, ok := all[a.Name()]
	if !ok {
		return nil, nil
	}
	var done []StepRevert
	steps := a.Steps(env)
	for i := len(steps) - 1; i >= 0; i-- {
		s := steps[i]
		r, ok := h.Receipts[s.Name]
		if !ok || s.Revert == nil {
			continue
		}
		out, err := s.Revert(env, r)
		if err != nil {
			return done, &RevertError{Host: a.Name(), Step: s.Name, Err: err}
		}
		done = append(done, StepRevert{Step: s.Name, Outcome: out})
	}
	return done, vault.WriteHost(env.VaultHome, a.Name(), nil)
}

// Registry is the set of adapters this build knows, in display order.
type Registry struct{ adapters []Adapter }

// NewRegistry returns a registry of the given adapters.
func NewRegistry(a ...Adapter) *Registry { return &Registry{adapters: a} }

// All returns every adapter.
func (r *Registry) All() []Adapter { return r.adapters }

// Names returns the adapter names.
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.adapters))
	for _, a := range r.adapters {
		out = append(out, a.Name())
	}
	return out
}

// Get returns the adapter with that name.
func (r *Registry) Get(name string) (Adapter, bool) {
	for _, a := range r.adapters {
		if a.Name() == name {
			return a, true
		}
	}
	return nil, false
}

// Detected returns the adapters whose host looks installed.
func (r *Registry) Detected(env Env) []Adapter {
	var out []Adapter
	for _, a := range r.adapters {
		if a.Detect(env) {
			out = append(out, a)
		}
	}
	return out
}

// Pick returns the named adapters in the order given, without duplicates. An
// unknown name is ErrUnknownHost (the name is not echoed).
func (r *Registry) Pick(names []string) ([]Adapter, error) {
	var out []Adapter
	seen := map[string]bool{}
	for _, n := range names {
		a, ok := r.Get(n)
		if !ok {
			return nil, ErrUnknownHost
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, a)
		}
	}
	return out, nil
}
