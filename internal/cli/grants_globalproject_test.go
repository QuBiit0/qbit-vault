package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/exitcode"
	"github.com/QuBiit0/qbit-vault/internal/grants"
	"github.com/QuBiit0/qbit-vault/internal/vault"
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
	f := withBackend(t, answers(pick(2)))
	code, m, _ := w.broker("request", reqFor(w.repo, ""))
	if code != exitcode.OK || m["grant"].(map[string]any)["scope"] != "project" {
		t.Fatalf("code=%d m=%v", code, m)
	}
	want := []string{"Once: only the next command", "Session: until the agent restarts (max 12h)", "Project: always in this project, until you revoke it", "Don't allow"}
	if strings.Join(f.Calls[0].Options, "|") != strings.Join(want, "|") || f.Calls[0].Default != 1 {
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
	f := withBackend(t, answers(pick(1)))
	if code, m, _ := w.broker("request", reqFor(w.outside, "")); code != exitcode.OK {
		t.Fatalf("code=%d m=%v", code, m)
	}
	if o := f.Calls[0].Options; len(o) != 3 || strings.HasPrefix(o[1], "Project") || o[2] != "Don't allow" {
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
