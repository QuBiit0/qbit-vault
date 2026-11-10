package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/exitcode"
	"github.com/qbitdevz/qbit-vault/internal/grants"
	"github.com/qbitdevz/qbit-vault/internal/vault"
)

// A global secret can be granted "always in this project": the permission is
// bound to the repository it was approved in, survives new agent sessions
// there (a new MCP server is a new session), and never reaches another
// repository, a nested one included.

// checkIn evaluates the grants the way exec does: for the repository root of
// dir when there is one, with the given session.
func (w *world) checkIn(name, session, dir string) error {
	w.t.Helper()
	g := &globals{getenv: envFrom(nil), home: w.home}
	s, err := g.openSession()
	if err != nil {
		w.t.Fatal(err)
	}
	defer s.close()
	rec, _, err := s.v.Resolve(name, dir)
	if err != nil {
		w.t.Fatal(err)
	}
	rec.Value.Wipe()
	cwd := foldPath(dir)
	if root, ok, err := vault.ProjectRoot(dir); err == nil && ok {
		cwd = root
	}
	var d grants.Decision
	_, err = s.v.MutateGrants(func(body []byte, _ bool) ([]byte, error) {
		st, err := grants.Decode(body)
		if err != nil {
			return nil, err
		}
		d, _ = grants.Check(st, name, vault.Global().Key(), rec.ID, rec.Sensitive, session, cwd, clock())
		return nil, nil
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return d.Err
}

// mkRepo makes another repository next to the world's one.
func (w *world) mkRepo(name string) string {
	w.t.Helper()
	dir := filepath.Join(filepath.Dir(w.repo), name)
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o700); err != nil {
		w.t.Fatal(err)
	}
	return dir
}

func TestRequestGrantsAGlobalSecretForThisProject(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_global\n", "set", "A", "--global", "--stdin")
	f := withBackend(t, answers(pick(1)))
	code, m, _ := w.broker("request", reqFor(w.repo, ""))
	if code != exitcode.OK || m["grant"].(map[string]any)["scope"] != "project" {
		t.Fatalf("code=%d m=%v", code, m)
	}
	// Once, always in this project, or no: no session answer (a restarted
	// agent is a new session), and once preselected.
	want := []string{"Once: only the next command", "Always: in this project, until you revoke it", "Don't allow"}
	if strings.Join(f.Calls[0].Options, "|") != strings.Join(want, "|") || f.Calls[0].Default != 0 {
		t.Fatalf("options=%q default=%d", f.Calls[0].Options, f.Calls[0].Default)
	}
	// A new agent session in the same repository needs no new approval.
	if err := w.checkIn("A", "mcp:anothersession", w.repo); err != nil {
		t.Fatalf("new session in the repository: %v", err)
	}
	// Another repository, a nested one and no repository at all still ask.
	nested := filepath.Join(w.repo, "vendor", "lib")
	if err := os.MkdirAll(filepath.Join(nested, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{w.mkRepo("blog"), nested, w.outside} {
		if err := w.checkIn("A", brokerSession, dir); !errors.Is(err, grants.ErrGrantRequired) {
			t.Fatalf("%s: err = %v, want grant required", dir, err)
		}
	}
}

func TestOutsideARepositoryAGlobalSecretOffersNoProjectScope(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_global\n", "set", "A", "--global", "--stdin")
	f := withBackend(t, answers(pick(0)))
	if code, m, _ := w.broker("request", reqFor(w.outside, "")); code != exitcode.OK || m["grant"].(map[string]any)["scope"] != "once" {
		t.Fatalf("code=%d m=%v", code, m)
	}
	if o := f.Calls[0].Options; strings.Join(o, "|") != "Once: only the next command|Don't allow" {
		t.Fatalf("options=%q", o)
	}
}

func TestGrantCommandGrantsAGlobalSecretForThisProject(t *testing.T) {
	pinClock(t)
	asTerminal(t, true)
	w := newWorld(t)
	w.mustRun(fxVal, "set", "PLAIN_KEY", "--global", "--stdin")
	w.inRepo()
	if code, out, errs := w.run("y\n", "grant", "PLAIN_KEY", "--scope", "project"); code != exitcode.OK || out != "granted PLAIN_KEY (global): project, until revoked\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if err := w.checkIn("PLAIN_KEY", "mcp:anyone1", w.repo); err != nil {
		t.Fatalf("grant not usable in the repository: %v", err)
	}
}

// The broker's own prompt issues a token another call redeems, possibly
// with another cwd, so it never offers a project grant of a global secret.
func TestPromptCommandOffersNoProjectScopeForAGlobalSecret(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_global\n", "set", "A_KEY", "--global", "--stdin")
	w.inRepo()
	f := withBackend(t, answers(pick(0)))
	w.run("", "--session", sessA, "prompt", "--name", "A_KEY", "--reason", "run the release", "--layers", "global")
	for _, c := range f.Calls {
		for _, o := range c.Options {
			if strings.HasPrefix(o, "Project") {
				t.Fatalf("prompt offered %q", o)
			}
		}
	}
}

// A prompt token was issued by another call, maybe in another repository:
// redeeming it never binds a global secret to this one.
func TestGrantFromPromptTokenRefusesProjectScopeOnAGlobalSecret(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_global\n", "set", "A_KEY", "--global", "--stdin")
	w.inRepo()
	before := w.grantsState()
	code, _, errs := w.run("", "grant", "A_KEY", "--scope", "project", "--from-prompt-token", "tok_anything")
	if code != exitcode.Refusal || errs != "error: project scope needs a repository: run it inside one\n" {
		t.Fatalf("code=%d err=%q", code, errs)
	}
	if w.grantsState() != before {
		t.Fatal("a refused token grant changed the grants")
	}
}

// A broker call always carries its cwd; one without it must not fall back to
// the server process's directory for a repository binding.
func TestRepoRootOfABrokerCallWithoutCwdIsEmpty(t *testing.T) {
	w := newWorld(t)
	w.inRepo()
	g := &globals{getenv: envFrom(nil), home: w.home, broker: true}
	if r := g.repoRoot(); r != "" {
		t.Fatalf("repoRoot = %q, want none", r)
	}
	g.broker = false
	if r := g.repoRoot(); r == "" {
		t.Fatal("a CLI command in a repository found no root")
	}
}
