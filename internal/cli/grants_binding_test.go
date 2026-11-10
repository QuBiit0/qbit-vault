package cli

import (
	"os"
	"testing"
	"time"

	"github.com/qbitdevz/qbit-vault/internal/exitcode"
	"github.com/qbitdevz/qbit-vault/internal/grants"
)

// recordID reads the internal id of the record NAME resolves to, for
// assertions only; no command prints it.
func (w *world) recordID(name string) string {
	w.t.Helper()
	g := &globals{getenv: envFrom(nil), home: w.home}
	s, err := g.openSession()
	if err != nil {
		w.t.Fatal(err)
	}
	defer s.close()
	cwd, _ := os.Getwd()
	rec, _, err := s.v.Resolve(name, cwd)
	if err != nil {
		w.t.Fatal(err)
	}
	rec.Value.Wipe()
	return rec.ID
}

func TestGrantTokenBindsTTL(t *testing.T) {
	pinClock(t)
	asTerminal(t, false)
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	before := w.grantsState()
	refused := "error: " + msgNotModel + "\n"

	// A token issued for 1h does not buy a 12h (omitted) or a 2h grant, and
	// the failed attempt burns it.
	tok := w.issueTokenFor("A_KEY", "global", "", grants.ScopeSession, sessA, time.Hour)
	code, out, errs := w.run("", "--session", sessA, "grant", "A_KEY", "--scope", "session", "--from-prompt-token", tok)
	if code != exitcode.Refusal || out != "" || errs != refused {
		t.Fatalf("omitted ttl: code=%d out=%q err=%q", code, out, errs)
	}
	code, _, errs = w.run("", "--session", sessA, "grant", "A_KEY", "--scope", "session", "--ttl", "1h", "--from-prompt-token", tok)
	if code != exitcode.Refusal || errs != refused {
		t.Fatalf("burnt token: code=%d err=%q", code, errs)
	}
	if w.grantsState() != before {
		t.Fatal("a refused token created a grant")
	}

	// The matching ttl works and is what the grant gets.
	tok = w.issueTokenFor("A_KEY", "global", "", grants.ScopeSession, sessA, time.Hour)
	code, out, errs = w.run("", "--json", "--session", sessA, "grant", "A_KEY", "--scope", "session", "--ttl", "1h", "--from-prompt-token", tok)
	want := `{"ok":true,"grant":{"name":"A_KEY","layer":"global","scope":"session","session":"pi:sess-aaaa","expires_at":"2026-11-03T13:00:00Z"}}` + "\n"
	if code != 0 || out != want || errs != "" {
		t.Fatalf("matching ttl: code=%d out=%q err=%q", code, out, errs)
	}

	// Omitted ttl means the 12h default on both sides, explicit or not.
	tok = w.issueTokenFor("A_KEY", "global", "", grants.ScopeSession, sessA, 0)
	if code, _, errs = w.run("", "--session", sessA, "grant", "A_KEY", "--scope", "session", "--ttl", "12h", "--from-prompt-token", tok); code != 0 {
		t.Fatalf("default ttl spelled out: code=%d err=%q", code, errs)
	}
	tok = w.issueTokenFor("A_KEY", "global", "", grants.ScopeSession, sessA, 12*time.Hour)
	if code, _, errs = w.run("", "--session", sessA, "grant", "A_KEY", "--scope", "session", "--from-prompt-token", tok); code != 0 {
		t.Fatalf("default ttl omitted: code=%d err=%q", code, errs)
	}
}

func TestSetGrantTokenBindsTTL(t *testing.T) {
	pinClock(t)
	asTerminal(t, false)
	w := newWorld(t)
	before := w.snapshot()
	tok := w.issueTokenFor("NEW_KEY", "global", "", grants.ScopeSession, sessA, time.Hour)
	code, out, errs := w.run(fxVal, "--session", sessA, "set", "NEW_KEY", "--global", "--stdin", "--grant", "session", "--from-prompt-token", tok)
	if code != exitcode.Refusal || out != "" || errs != "error: "+msgNotModel+"\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if w.snapshot() != before {
		t.Fatal("a refused token stored a secret")
	}
}

func TestGrantTokenBoundToARecord(t *testing.T) {
	pinClock(t)
	asTerminal(t, false)
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	refused := "error: " + msgNotModel + "\n"

	// A token issued for another record instance (here: a stale id) is dead.
	stale := w.issueTokenFor("A_KEY", "global", "00000000000000000000000000000000", grants.ScopeSession, sessA, 0)
	if code, _, errs := w.run("", "--session", sessA, "grant", "A_KEY", "--scope", "session", "--from-prompt-token", stale); code != exitcode.Refusal || errs != refused {
		t.Fatalf("stale record token: code=%d err=%q", code, errs)
	}
	tok := w.issueTokenFor("A_KEY", "global", w.recordID("A_KEY"), grants.ScopeSession, sessA, 0)
	if code, _, errs := w.run("", "--session", sessA, "grant", "A_KEY", "--scope", "session", "--from-prompt-token", tok); code != 0 {
		t.Fatalf("matching record token: code=%d err=%q", code, errs)
	}
}

// A grant made before the record turned sensitive no longer authorizes it,
// and neither does a stale broad grant that somehow survived.
func TestSensitiveEditInvalidatesExecCheck(t *testing.T) {
	pinClock(t)
	asTerminal(t, true)
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	w.mustRun("y\n", "--session", sessA, "grant", "A_KEY", "--scope", "session")
	if err := w.execCheck("A_KEY", sessA); err != nil {
		t.Fatalf("fresh grant: %v", err)
	}
	w.mustRun("", "edit", "A_KEY", "--sensitive")
	if err := w.execCheck("A_KEY", sessA); err == nil {
		t.Fatal("a session grant still authorizes a sensitive record")
	}
}
