package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/conformance"
	"github.com/qbitdevz/qbit-vault/internal/exitcode"
	"github.com/qbitdevz/qbit-vault/internal/grants"
	"github.com/qbitdevz/qbit-vault/internal/vault"
)

// Issue #42: secret_list showed a project grant that secret_exec then refused.
// The listing and the execution must decide with the same predicate, from the
// directory the caller is in (docs/STORAGE.md § Grants).

// pkgDir is the package directory, read before any test changes directory.
var pkgDir, _ = os.Getwd()

const (
	noteOtherDir   = "a project grant exists for another directory; call secret_request"
	noteOtherValue = "the grant is for an earlier value of this secret; call secret_request"
)

// listed returns the secret named name from a broker list issued in dir, and
// the raw response line.
func (w *world) listed(dir, name string) (map[string]any, string) {
	w.t.Helper()
	code, m, out := w.broker("list", envelope("list", dir, ""))
	if code != exitcode.OK || m["ok"] != true {
		w.t.Fatalf("list in %s: code=%d out=%s", dir, code, out)
	}
	// The additive grant_note validates against the pinned schema.
	sch, err := conformance.Load(filepath.Join(pkgDir, "..", "..", "contracts", "secrets-broker", "v1", "secrets-broker.v1.schema.json"))
	if err != nil {
		w.t.Fatal(err)
	}
	if _, err := sch.Response("list", []byte(out)); err != nil {
		w.t.Fatalf("list response breaks the contract schema: %v", err)
	}
	for _, s := range m["secrets"].([]any) {
		if e := s.(map[string]any); e["name"] == name {
			return e, out
		}
	}
	w.t.Fatalf("list in %s: %s is not listed: %s", dir, name, out)
	return nil, ""
}

// execIn runs a child that needs A from dir through the broker.
func (w *world) execIn(dir string) (int, map[string]any) {
	w.t.Helper()
	exe := child(w.t, "leaks", "TOKEN", 0)
	code, m, _ := w.broker("exec", envelope("exec", dir, `"command":`+jsonString(exe)+`,"secrets":[{"name":"TOKEN","from":"A"}]`))
	return code, m
}

func refusalMessage(m map[string]any) string {
	r, _ := m["refusal"].(map[string]any)
	s, _ := r["message"].(string)
	return s
}

// approveProjectGrant stores a global A and grants it "always in this
// project" from w.repo, the way the owner does through secret_request.
func (w *world) approveProjectGrant() {
	w.t.Helper()
	w.mustRun("TESTSECRET_global\n", "set", "A", "--global", "--stdin")
	withBackend(w.t, answers(pick(1)))
	code, m, _ := w.broker("request", reqFor(w.repo, ""))
	if code != exitcode.OK || m["grant"].(map[string]any)["scope"] != "project" {
		w.t.Fatalf("approval: code=%d m=%v", code, m)
	}
}

func TestListAndExecAgreeOnAProjectGrantOfAGlobalSecret(t *testing.T) {
	w := newWorld(t)
	w.approveProjectGrant()

	sub := filepath.Join(w.repo, "pkg", "api")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(w.repo, "vendor", "lib")
	if err := os.MkdirAll(filepath.Join(nested, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	other := w.mkRepo("other-repo")

	type tc struct {
		name, dir string
		applies   bool
	}
	cases := []tc{
		{"repository root", w.repo, true},
		{"subdirectory", sub, true},
		{"trailing separator", w.repo + string(filepath.Separator), true},
		{"dot segments", filepath.Join(sub, "..", ".."), true},
		{"another repository", other, false},
		{"outside any repository", w.outside, false},
		{"nested repository", nested, false},
	}
	// A real symlink to the repository and to a subdirectory of it: the grant
	// is bound to the resolved root, so every spelling reaches it.
	link := filepath.Join(filepath.Dir(w.repo), "shop-link")
	if err := os.Symlink(w.repo, link); err == nil {
		cases = append(cases, tc{"symlink to the repository", link, true}, tc{"symlink, subdirectory", filepath.Join(link, "pkg", "api"), true})
	} else {
		t.Logf("no symlinks here (%v): symlink cases skipped", err)
	}
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		cases = append(cases, tc{"other letter case", strings.ToUpper(w.repo), true})
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, out := w.listed(c.dir, "A")
			code, m := w.execIn(c.dir)
			if c.applies {
				g, _ := e["grant"].(map[string]any)
				if g["scope"] != "project" || g["expires_at"] != nil || len(g) != 2 {
					t.Fatalf("list grant=%v (%s)", e["grant"], out)
				}
				if _, has := e["grant_note"]; has {
					t.Fatalf("an applicable grant carries a note: %s", out)
				}
				if code != exitcode.OK || m["ok"] != true {
					t.Fatalf("list shows the grant but exec refuses: code=%d m=%v", code, m)
				}
				return
			}
			if e["grant"] != nil || !strings.Contains(out, `"grant":null`) {
				t.Fatalf("list shows a grant that exec would refuse: %s", out)
			}
			if e["grant_note"] != noteOtherDir {
				t.Fatalf("grant_note=%v", e["grant_note"])
			}
			if code != exitcode.Refusal || refusalType(m) != "grant_required" || !m["refusal"].(map[string]any)["retryable"].(bool) {
				t.Fatalf("exec: code=%d m=%v", code, m)
			}
			if got, want := refusalMessage(m), "A has a project grant for another directory; call secret_request"; got != want {
				t.Fatalf("message=%q, want %q", got, want)
			}
		})
	}
}

// The listing never spends a once grant: it is claimed by the exec that runs.
func TestListDoesNotConsumeAOnceGrant(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_once\n", "set", "A", "--global", "--stdin")
	withBackend(t, answers(yes()))
	w.mustRun("", "--session", brokerSession, "grant", "A", "--scope", "once")

	for i := 0; i < 3; i++ {
		e, out := w.listed(w.outside, "A")
		g, _ := e["grant"].(map[string]any)
		if g["scope"] != "once" {
			t.Fatalf("list %d: %s", i, out)
		}
	}
	if code, m := w.execIn(w.outside); code != exitcode.OK || m["ok"] != true {
		t.Fatalf("the once grant was spent by the listing: code=%d m=%v", code, m)
	}
	if e, out := w.listed(w.outside, "A"); e["grant"] != nil {
		t.Fatalf("a spent once grant is still listed: %s", out)
	}
	if code, m := w.execIn(w.outside); code != exitcode.Refusal || refusalType(m) != "grant_required" || refusalMessage(m) != "A has no active grant" {
		t.Fatalf("second exec: code=%d m=%v", code, m)
	}
}

// A grant of another session is not this session's.
func TestListAndExecAgreeOnASessionGrantOfAnotherSession(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_s\n", "set", "A", "--global", "--stdin")
	withBackend(t, answers(yes()))
	w.mustRun("", "--session", "pi:somebodyelse", "grant", "A", "--scope", "session")
	e, out := w.listed(w.outside, "A")
	if e["grant"] != nil {
		t.Fatalf("list: %s", out)
	}
	if code, m := w.execIn(w.outside); code != exitcode.Refusal || refusalMessage(m) != "A has no active grant" {
		t.Fatalf("exec: code=%d m=%v", code, m)
	}
}

// Replacing the value gives the record a new id and drops its grants: both
// sides say there is none.
func TestListAndExecAfterAValueReplace(t *testing.T) {
	w := newWorld(t)
	w.approveProjectGrant()
	w.mustRun("TESTSECRET_replacement\n", "set", "A", "--global", "--stdin")
	e, out := w.listed(w.repo, "A")
	if e["grant"] != nil {
		t.Fatalf("list after replace: %s", out)
	}
	if code, m := w.execIn(w.repo); code != exitcode.Refusal || refusalType(m) != "grant_required" {
		t.Fatalf("exec after replace: code=%d m=%v", code, m)
	}
}

// A grant that outlived its record (a crash between the vault write and the
// grants write) names an earlier record id: it is inert on both sides, and
// both say why.
func TestStaleGrantIsNamedOnBothSides(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_stale\n", "set", "A", "--global", "--stdin")
	g := &globals{getenv: envFrom(nil), home: w.home}
	s, err := g.openSession()
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.v.MutateGrants(func(body []byte, _ bool) ([]byte, error) {
		st, err := grants.Decode(body)
		if err != nil {
			return nil, err
		}
		if _, err := grants.Add(st, grants.Request{Name: "A", Layer: vault.Global().Key(), RecordID: "00000000000000000000000000000000", Scope: grants.ScopeSession, Session: brokerSession}, clock()); err != nil {
			return nil, err
		}
		return grants.Encode(st)
	})
	s.close()
	if err != nil {
		t.Fatal(err)
	}
	e, out := w.listed(w.outside, "A")
	if e["grant"] != nil || e["grant_note"] != noteOtherValue {
		t.Fatalf("list: %s", out)
	}
	code, m := w.execIn(w.outside)
	if code != exitcode.Refusal || refusalType(m) != "grant_required" || refusalMessage(m) != "A has a grant for an earlier value of it; call secret_request" {
		t.Fatalf("exec: code=%d m=%v", code, m)
	}
}

// A working directory that cannot be resolved (it was removed) lists nothing
// and runs nothing: neither side falls back to the unresolved path.
func TestListAndExecRefuseWhereTheDirectoryCannotBeResolved(t *testing.T) {
	w := newWorld(t)
	w.approveProjectGrant()
	if err := os.RemoveAll(w.repo); err != nil {
		t.Fatal(err)
	}
	code, m, out := w.broker("list", envelope("list", w.repo, ""))
	if code != exitcode.Refusal || m["ok"] != false || strings.Contains(out, "TESTSECRET_") || strings.Contains(out, `"grant"`) {
		t.Fatalf("list: code=%d out=%s", code, out)
	}
	if code, m := w.execIn(w.repo); code != exitcode.Refusal || m["ok"] != false {
		t.Fatalf("exec ran from a removed directory: code=%d m=%v", code, m)
	}
}
