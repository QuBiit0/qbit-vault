// Package doctor builds the read-only health report of `qbit-vault doctor`
// (PRD R-INS-06, R-INS-07; docs/CLI.md § doctor). It reads state.json, file
// permissions and the host config files; it writes nothing, asks nothing and
// makes no network call. Details are fixed phrases: no secret, no config byte.
package doctor

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/qbitdevz/qbit-vault/internal/audit"
	"github.com/qbitdevz/qbit-vault/internal/hosts"
	"github.com/qbitdevz/qbit-vault/internal/perm"
	"github.com/qbitdevz/qbit-vault/internal/vault"
)

// Status of one check. Warn and Fail both make the report unhealthy.
type Status string

const (
	OK   Status = "ok"
	Warn Status = "warn"
	Fail Status = "fail"
)

// Check is one line of the report.
type Check struct {
	Name   string `json:"name"`
	Status Status `json:"status"`
	Detail string `json:"detail"`
}

// Report is the whole report; OK is true when every check is OK.
type Report struct {
	OK     bool    `json:"ok"`
	Checks []Check `json:"checks"`
}

// Problems counts the checks that are not OK.
func (r Report) Problems() int {
	n := 0
	for _, c := range r.Checks {
		if c.Status != OK {
			n++
		}
	}
	return n
}

// ErrLocked is what Inputs.Open returns for a vault that cannot be opened
// without a prompt. It is a normal state, not a problem.
var ErrLocked = errors.New("vault locked")

// Opened is what opening the vault without a prompt told doctor.
type Opened struct {
	Keychain    string // the key holder's name
	GrantsReset bool   // grants.enc was unreadable or rolled back
}

// Inputs are the facts doctor cannot get on its own.
type Inputs struct {
	Home     string
	Env      hosts.Env
	Registry *hosts.Registry
	// Open opens the vault without prompting and without repairing, reads
	// the grants store and closes it. nil error: unlocked; ErrLocked: locked;
	// any other error is reported with its (fixed) message.
	Open func() (Opened, error)
	// Prompt names the backend that asks the user out of band without
	// starting it. nil leaves the line out. The terminal ("tty") is the
	// default and says nothing, like audit and grants when they are fine, so
	// a healthy report stays short; a native dialog is named.
	Prompt func() (string, error)
}

// Run builds the report. It never writes.
func Run(in Inputs) Report {
	var cs []Check
	add := func(name string, st Status, detail string) { cs = append(cs, Check{name, st, detail}) }
	finish := func() Report {
		r := Report{Checks: cs}
		r.OK = r.Problems() == 0
		return r
	}

	if _, err := vault.ReadID(in.Home); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			add("vault", Fail, "no vault here; run 'qbit-vault init'")
		} else {
			add("vault", Fail, "state.json is unreadable or damaged; try 'qbit-vault restore'")
		}
		return finish()
	}

	opened, err := in.Open()
	switch {
	case err == nil:
		add("vault", OK, "unlocked (keychain: "+opened.Keychain+")")
	case errors.Is(err, ErrLocked):
		add("vault", OK, "locked (the key needs a prompt; run 'qbit-vault unlock')")
	default:
		add("vault", Fail, "cannot open the vault: "+err.Error())
	}

	if bad := permissionProblem(in.Home); bad != "" {
		add("permissions", Warn, bad)
	} else {
		add("permissions", OK, "owner-only")
	}

	if in.Prompt != nil {
		if name, perr := in.Prompt(); perr != nil {
			add("prompt", Warn, perr.Error())
		} else if name != "tty" {
			add("prompt", OK, name)
		}
	}

	if err == nil && opened.GrantsReset {
		add("grants", Warn, "grants.enc is unreadable or was rolled back; its grants are treated as none")
	}
	cs = append(cs, auditChecks(in.Home)...)
	cs = append(cs, hostChecks(in)...)
	cs = append(cs, syncChecks(in.Home)...)
	return finish()
}

// permissionProblem names the first vault file that is not owner-only.
func permissionProblem(home string) string {
	for _, name := range []string{"", "vault.enc", "key.enc", "state.json", "grants.enc", "audit.jsonl", "audit.head"} {
		p := filepath.Join(home, name)
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if ok, detail := perm.Check(p); !ok {
			if name == "" {
				name = "vault home"
			}
			return name + ": " + detail
		}
	}
	return ""
}

func hostChecks(in Inputs) []Check {
	recorded, err := vault.ReadHosts(in.Home)
	if err != nil {
		return []Check{{"hosts", Fail, "the hosts section of state.json is damaged"}}
	}
	names := make([]string, 0, len(recorded))
	for n := range recorded {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []Check
	for _, n := range names {
		a, ok := in.Registry.Get(n)
		if !ok {
			out = append(out, Check{"host." + n, Warn, "registered, but this build has no adapter for it"})
			continue
		}
		for _, c := range hosts.Verify(in.Env, a, recorded[n]) {
			name := "host." + n + "." + c.Step
			switch {
			case c.Err == nil:
				out = append(out, Check{name, OK, "registered"})
			case errors.Is(c.Err, hosts.ErrDrift):
				out = append(out, Check{name, Warn, "config changed since registration; run 'qbit-vault sync'"})
			case errors.Is(c.Err, hosts.ErrNotRegistered):
				out = append(out, Check{name, Warn, "not registered; run 'qbit-vault sync'"})
			default:
				out = append(out, Check{name, Warn, "cannot read the host config"})
			}
		}
	}
	return out
}

// auditChecks verifies the audit hash chain. Like grants, it says nothing
// while the log is fine, so a healthy report stays short; a vault with no log
// has nothing to verify.
func auditChecks(home string) []Check {
	for _, name := range []string{"audit.jsonl", "audit.head"} {
		if fi, err := os.Stat(filepath.Join(home, name)); err == nil && fi.Mode().IsRegular() {
			res, err := audit.Verify(home)
			switch {
			case err != nil:
				return []Check{{"audit", Fail, "the audit log cannot be read; run 'qbit-vault audit --verify'"}}
			case res.Problem != nil:
				return []Check{{"audit", Fail, fmt.Sprintf("audit chain broken at line %d (%s); run 'qbit-vault audit --verify'", res.Problem.Line, res.Problem.Reason)}}
			}
			return nil
		}
	}
	return nil
}

// syncChecks reports the sync state recorded in state.json; it never contacts
// the server. Nothing is reported when the vault does not sync.
func syncChecks(home string) []Check {
	rem, err := vault.ReadRemote(home)
	switch {
	case err != nil:
		return []Check{{"sync", Fail, "the remote section of state.json is damaged"}}
	case rem == nil:
		return nil
	}
	s := rem.Summary
	pending := ""
	if rem.PendingPush {
		pending = ", push pending"
	}
	if s.At == "" {
		return []Check{{"sync", OK, rem.Server + "; no sync round yet" + pending}}
	}
	detail := fmt.Sprintf("%s; %d devices, %d conflicts%s; last round %s", rem.Server, s.Devices, s.Conflicts, pending, s.At)
	if s.Conflicts > 0 {
		return []Check{{"sync", Warn, fmt.Sprintf("%d sync conflicts; run 'qbit-vault remote conflicts'", s.Conflicts)}}
	}
	return []Check{{"sync", OK, detail}}
}

// WriteHuman prints one line per check and a summary line:
//
//	<status padded to 4>  <name padded to the longest name>  <detail>
//	healthy | 1 problem | N problems
func (r Report) WriteHuman(w io.Writer) error {
	width := 0
	for _, c := range r.Checks {
		width = max(width, len(c.Name))
	}
	var b strings.Builder
	for _, c := range r.Checks {
		fmt.Fprintf(&b, "%-4s  %-*s  %s\n", c.Status, width, c.Name, c.Detail)
	}
	switch n := r.Problems(); n {
	case 0:
		b.WriteString("healthy\n")
	case 1:
		b.WriteString("1 problem\n")
	default:
		fmt.Fprintf(&b, "%d problems\n", n)
	}
	_, err := io.WriteString(w, b.String())
	return err
}
