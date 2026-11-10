package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/qbitdevz/qbit-vault/internal/exitcode"
	"github.com/qbitdevz/qbit-vault/internal/grants"
	"github.com/qbitdevz/qbit-vault/internal/prompt"
	"github.com/qbitdevz/qbit-vault/internal/prompt/prompttest"
	"github.com/qbitdevz/qbit-vault/internal/refusal"
)

const (
	sessA = "pi:sess-aaaa"
	sessB = "pi:sess-bbbb"

	msgNotModel = "this operation is not available to the model"
	msgDeclined = "the user declined"
	msgScope    = "this scope is not allowed for a sensitive secret"
)

var gt0 = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

// pinClock freezes the CLI clock at gt0 for the test and returns a mover.
func pinClock(t *testing.T) (at func(time.Time)) {
	t.Helper()
	old := clock
	now := gt0
	clock = func() time.Time { return now }
	t.Cleanup(func() { clock = old })
	return func(n time.Time) { now = n }
}

// asTerminal makes the prompt seam offer (or not offer) a terminal. The
// simulated one reads its answers line by line from the command's stdin and
// writes the questions to its stderr; the real backend logic is in between.
func asTerminal(t *testing.T, on bool) {
	t.Helper()
	old := newPrompt
	newPrompt = func(g *globals) (prompt.Backend, error) {
		if !on {
			return nil, prompt.ErrNoTerminal
		}
		var in io.Reader = strings.NewReader("")
		if stdinOverride != nil {
			in = stdinOverride
		}
		return prompttest.Stream(in, g.stderr), nil
	}
	t.Cleanup(func() { newPrompt = old })
}

func grantPrompt(name, layer, who string, scope string) string {
	if layer == "global" {
		layer = "all projects"
	}
	return fmt.Sprintf("Grant %s (%s) to %s, scope %s? [y/N] ", name, layer, who, scope)
}

func refusalJSON(t *testing.T, typ refusal.Type, name string) string {
	t.Helper()
	return jsonOf(t, refusal.New(typ, name).Envelope())
}

// grantsState is the observable grants state: what `grants --json` prints.
func (w *world) grantsState() string {
	w.t.Helper()
	return w.mustRun("", "--json", "grants")
}

// issueToken issues a prompt token through the grants API, like the future
// prompt backend will.
func (w *world) issueToken(name, layer string, scope grants.Scope, session string) string {
	w.t.Helper()
	return w.issueTokenFor(name, layer, "", scope, session, 0)
}

// issueTokenFor is issueToken with the record id and ttl bindings.
func (w *world) issueTokenFor(name, layer, recordID string, scope grants.Scope, session string, ttl time.Duration) string {
	w.t.Helper()
	g := &globals{getenv: envFrom(nil), home: w.home}
	s, err := g.openSession()
	if err != nil {
		w.t.Fatal(err)
	}
	defer s.close()
	var tok string
	_, err = s.v.MutateGrants(func(body []byte, _ bool) ([]byte, error) {
		st, err := grants.Decode(body)
		if err != nil {
			return nil, err
		}
		tok = grants.IssueToken(st, name, layer, recordID, scope, session, ttl, clock())
		return grants.Encode(st)
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return tok
}

func (w *world) auditText() string {
	w.t.Helper()
	b, err := os.ReadFile(w.auditFile())
	if err != nil {
		w.t.Fatal(err)
	}
	return string(b)
}

func TestGrantSessionOnTerminal(t *testing.T) {
	pinClock(t)
	asTerminal(t, true)
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")

	code, out, errs := w.run("y\n", "--session", sessA, "grant", "A_KEY", "--scope", "session")
	want := "granted A_KEY (global): session, for pi:sess-aaaa, until 2026-11-04T00:00:00Z\n"
	if code != exitcode.OK || out != want || errs != grantPrompt("A_KEY", "global", sessA, "session") {
		t.Fatalf("code=%d\nstdout=%q\nstderr=%q", code, out, errs)
	}
	exp := fmt.Sprintf("%-5s  %-6s  %-7s  %-12s  %-20s  %s\n", "NAME", "LAYER", "SCOPE", "SESSION", "EXPIRES", "REMAINING") +
		fmt.Sprintf("%-5s  %-6s  %-7s  %-12s  %-20s  %s\n", "A_KEY", "global", "session", sessA, "2026-11-04T00:00:00Z", "12h0m0s")
	if code, out, errs = w.run("", "grants"); code != 0 || out != exp || errs != "" {
		t.Fatalf("grants: code=%d out=%q err=%q", code, out, errs)
	}
	if strings.Contains(out+errs+w.auditText(), "TESTSECRET_") {
		t.Fatal("a value leaked")
	}
}

func TestGrantJSONAndTTL(t *testing.T) {
	pinClock(t)
	asTerminal(t, true)
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	code, out, errs := w.run("yes\n", "--json", "--session", sessA, "grant", "A_KEY", "--scope", "session", "--ttl", "90m")
	want := `{"ok":true,"grant":{"name":"A_KEY","layer":"global","scope":"session","session":"pi:sess-aaaa","expires_at":"2026-11-03T13:30:00Z"}}` + "\n"
	if code != 0 || out != want || errs != grantPrompt("A_KEY", "global", sessA, "session") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	code, out, errs = w.run("Y\n", "--json", "--session", sessA, "grant", "A_KEY", "--scope", "once")
	want = `{"ok":true,"grant":{"name":"A_KEY","layer":"global","scope":"once","session":"pi:sess-aaaa","expires_at":"2026-11-03T12:10:00Z"}}` + "\n"
	if code != 0 || out != want || errs != grantPrompt("A_KEY", "global", sessA, "once") {
		t.Fatalf("once: code=%d out=%q err=%q", code, out, errs)
	}
}

func TestGrantProjectScope(t *testing.T) {
	pinClock(t)
	asTerminal(t, true)
	w := newWorld(t)
	w.inRepo()
	w.mustRun(fxVal, "set", "DB_URL", "--project", "--stdin")
	code, out, errs := w.run("y\n", "grant", "DB_URL", "--scope", "project")
	if code != 0 || out != "granted DB_URL (project shop-api): project, until revoked\n" || errs != grantPrompt("DB_URL", "project shop-api", "this project", "project") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	want := `{"ok":true,"grants":[{"name":"DB_URL","layer":"project","project":` + w.projectJSON() + `,"scope":"project","session":null,"expires_at":null,"remaining":null}]}` + "\n"
	if got := w.grantsState(); got != want {
		t.Fatalf("grants:\n got %s\nwant %s", got, want)
	}
	// Needs no session at all, and the same grant again just replaces it.
	if code, _, _ = w.run("y\n", "grant", "DB_URL", "--scope", "project"); code != 0 {
		t.Fatalf("second grant: code=%d", code)
	}
	var l struct{ Grants []json.RawMessage }
	if err := json.Unmarshal([]byte(w.grantsState()), &l); err != nil || len(l.Grants) != 1 {
		t.Fatalf("grants after a repeat: %v %d", err, len(l.Grants))
	}
	// Project grants are visible from anywhere.
	w.outRepo()
	if got := w.grantsState(); got != want {
		t.Fatalf("grants outside the repo: %s", got)
	}
}

func TestGrantDeclined(t *testing.T) {
	pinClock(t)
	asTerminal(t, true)
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	before := w.grantsState()
	for _, answer := range []string{"n\n", "\n", "", "nope\n", "yy\n", "yes please\n"} {
		code, out, errs := w.run(answer, "--session", sessA, "grant", "A_KEY", "--scope", "session")
		if code != exitcode.Refusal || out != "" || errs != grantPrompt("A_KEY", "global", sessA, "session")+"error: "+msgDeclined+"\n" {
			t.Fatalf("%q: code=%d out=%q err=%q", answer, code, out, errs)
		}
	}
	if w.grantsState() != before {
		t.Fatal("a declined grant created something")
	}
	got := w.records("--event", "refusal")
	if len(got) != 6 || got[0].Refusal != "user_declined" || got[0].Names[0] != "A_KEY" {
		t.Fatalf("refusals audited: %+v", got)
	}
	if len(w.records("--event", "grant")) != 0 {
		t.Fatal("a grant event was audited for a declined grant")
	}
}

func TestGrantNeedsTerminalOrToken(t *testing.T) {
	pinClock(t)
	asTerminal(t, false)
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	before := w.grantsState()

	code, out, errs := w.run("y\n", "--session", sessA, "grant", "A_KEY", "--scope", "session")
	if code != exitcode.Refusal || out != "" || errs != "error: "+msgNotModel+"\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	code, out, errs = w.run("y\n", "--json", "--session", sessA, "grant", "A_KEY", "--scope", "session")
	if code != exitcode.Refusal || out != refusalJSON(t, refusal.NotModelCallable, "A_KEY") || errs != "" {
		t.Fatalf("json: code=%d out=%q err=%q", code, out, errs)
	}
	if w.grantsState() != before {
		t.Fatal("a refused grant created something")
	}
	got := w.records("--event", "refusal")
	if len(got) != 2 || got[0].Refusal != "not_model_callable" {
		t.Fatalf("refusals audited: %+v", got)
	}
}

func TestGrantRefusesSensitiveBroadScopes(t *testing.T) {
	pinClock(t)
	asTerminal(t, true)
	w := newWorld(t)
	w.mustRun(fxVal, "set", "STRIPE_KEY", "--global", "--stdin", "--sensitive")
	w.mustRun(fxVal, "set", "PLAIN_KEY", "--global", "--stdin")
	before := w.grantsState()
	for _, scope := range []string{"session", "project"} {
		// Refused before any question is asked.
		code, out, errs := w.run("y\n", "--session", sessA, "grant", "STRIPE_KEY", "--scope", scope)
		if code != exitcode.Refusal || out != "" || errs != "error: "+msgScope+"\n" {
			t.Fatalf("%s: code=%d out=%q err=%q", scope, code, out, errs)
		}
	}
	// A project scope grant on a global record has no project to bind to.
	if code, _, errs := w.run("y\n", "grant", "PLAIN_KEY", "--scope", "project"); code != exitcode.Refusal || errs != "error: project scope needs a repository: run it inside one\n" {
		t.Fatalf("project on global: code=%d err=%q", code, errs)
	}
	if w.grantsState() != before {
		t.Fatal("a refused scope changed the grants")
	}
	// The sensitive secret still accepts once.
	if code, _, errs := w.run("y\n", "--session", sessA, "grant", "STRIPE_KEY", "--scope", "once"); code != 0 {
		t.Fatalf("sensitive once: code=%d err=%q", code, errs)
	}
}

func TestGrantUsageAndRefusals(t *testing.T) {
	pinClock(t)
	asTerminal(t, true)
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	before := w.grantsState()
	tests := []struct {
		name  string
		args  []string
		code  int
		stder string
	}{
		{"no scope", []string{"--session", sessA, "grant", "A_KEY"}, 2, usageErr("choose --scope once, session or project")},
		{"bad scope", []string{"--session", sessA, "grant", "A_KEY", "--scope", "forever"}, 2, usageErr("invalid scope: must be once, session or project")},
		{"no session", []string{"grant", "A_KEY", "--scope", "session"}, 2, usageErr("--session is required for the once and session scopes")},
		{"ttl with once", []string{"--session", sessA, "grant", "A_KEY", "--scope", "once", "--ttl", "5m"}, 2, usageErr("--ttl applies to the session scope only")},
		{"ttl too short", []string{"--session", sessA, "grant", "A_KEY", "--scope", "session", "--ttl", "59s"}, 2, usageErr(ttlHelp)},
		{"ttl too long", []string{"--session", sessA, "grant", "A_KEY", "--scope", "session", "--ttl", "25h"}, 2, usageErr(ttlHelp)},
		{"both layers", []string{"--session", sessA, "grant", "A_KEY", "--global", "--project", "--scope", "session"}, 2, usageErr("choose only one of --global and --project")},
		{"bad name", []string{"--session", sessA, "grant", "lower", "--scope", "session"}, 3, "error: invalid secret name\n"},
		{"unknown secret", []string{"--session", sessA, "grant", "NOPE_KEY", "--scope", "session"}, 3, "error: NOPE_KEY is not stored\n"},
		{"project outside a repo", []string{"--session", sessA, "grant", "A_KEY", "--project", "--scope", "session"}, 3, "error: not inside a repository\n"},
		{"missing name", []string{"grant", "--scope", "session"}, 2, usageErr("missing NAME")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out, errs := w.run("y\n", tt.args...)
			if code != tt.code || out != "" || errs != tt.stder {
				t.Fatalf("code=%d out=%q err=%q", code, out, errs)
			}
			if w.grantsState() != before {
				t.Fatal("refused input changed the grants")
			}
		})
	}
}

func TestGrantWithPromptToken(t *testing.T) {
	pinClock(t)
	asTerminal(t, false) // a token needs no terminal
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	tok := w.issueToken("A_KEY", "global", grants.ScopeSession, sessA)

	code, out, errs := w.run("", "--json", "--session", sessA, "grant", "A_KEY", "--scope", "session", "--from-prompt-token", tok)
	want := `{"ok":true,"grant":{"name":"A_KEY","layer":"global","scope":"session","session":"pi:sess-aaaa","expires_at":"2026-11-04T00:00:00Z"}}` + "\n"
	if code != 0 || out != want || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	grantsAfter := w.grantsState()

	// The token is single use.
	code, out, errs = w.run("", "--session", sessA, "grant", "A_KEY", "--scope", "session", "--from-prompt-token", tok)
	if code != exitcode.Refusal || out != "" || errs != "error: "+msgNotModel+"\n" {
		t.Fatalf("reuse: code=%d out=%q err=%q", code, out, errs)
	}
	if w.grantsState() != grantsAfter {
		t.Fatal("a reused token changed the grants")
	}

	// The audit trail names the grant and how it was confirmed, never the token.
	got := w.records("--event", "grant")
	if len(got) != 1 || got[0].Detail != "prompt token" || got[0].Scope != "session" || got[0].Layer != "global" ||
		got[0].ExpiresAt != "2026-11-04T00:00:00Z" || got[0].Names[0] != "A_KEY" || got[0].Session != sessA {
		t.Fatalf("grant audit: %+v", got)
	}
	if strings.Contains(w.auditText(), tok) {
		t.Fatal("the token reached the audit log")
	}
}

func TestGrantTokenBindingAndExpiry(t *testing.T) {
	at := pinClock(t)
	asTerminal(t, false)
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	w.mustRun(fxVal, "set", "B_KEY", "--global", "--stdin")
	before := w.grantsState()
	tests := []struct {
		name string
		mint func() string
		args []string
		wait time.Duration
	}{
		{"other name", func() string { return w.issueToken("B_KEY", "global", grants.ScopeSession, sessA) }, []string{"--session", sessA, "grant", "A_KEY", "--scope", "session"}, 0},
		{"other scope", func() string { return w.issueToken("A_KEY", "global", grants.ScopeOnce, sessA) }, []string{"--session", sessA, "grant", "A_KEY", "--scope", "session"}, 0},
		{"other session", func() string { return w.issueToken("A_KEY", "global", grants.ScopeSession, sessB) }, []string{"--session", sessA, "grant", "A_KEY", "--scope", "session"}, 0},
		{"other layer", func() string { return w.issueToken("A_KEY", "project:/x", grants.ScopeSession, sessA) }, []string{"--session", sessA, "grant", "A_KEY", "--scope", "session"}, 0},
		{"expired", func() string { return w.issueToken("A_KEY", "global", grants.ScopeSession, sessA) }, []string{"--session", sessA, "grant", "A_KEY", "--scope", "session"}, 2 * time.Minute},
		{"made up", func() string { return "TESTSECRET_not_a_token" }, []string{"--session", sessA, "grant", "A_KEY", "--scope", "session"}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			at(gt0)
			tok := tt.mint()
			at(gt0.Add(tt.wait))
			args := append(append([]string{}, tt.args...), "--from-prompt-token", tok)
			code, out, errs := w.run("", args...)
			if code != exitcode.Refusal || out != "" || errs != "error: "+msgNotModel+"\n" {
				t.Fatalf("code=%d out=%q err=%q", code, out, errs)
			}
			at(gt0)
			if w.grantsState() != before {
				t.Fatal("a refused token created a grant")
			}
			// A token used for the wrong request is dead.
			if code, _, _ = w.run("", append(append([]string{}, tt.args[:0]...), args...)...); code == 0 {
				t.Fatal("a burnt token worked")
			}
		})
	}
}

func TestGrantFailsClosedWhenAuditFails(t *testing.T) {
	pinClock(t)
	asTerminal(t, true)
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	before := w.grantsState()
	// A directory where the log should be makes every append fail.
	if err := os.Remove(w.auditFile()); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(w.auditFile(), 0o700); err != nil {
		t.Fatal(err)
	}
	code, out, errs := w.run("y\n", "--session", sessA, "grant", "A_KEY", "--scope", "session")
	if code != exitcode.Refusal || out != "" || errs != grantPrompt("A_KEY", "global", sessA, "session")+"error: internal error\n"+auditWarning {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if w.grantsState() != before {
		t.Fatal("a grant was created without its audit record (L4)")
	}
}

func TestRevoke(t *testing.T) {
	pinClock(t)
	asTerminal(t, true)
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	w.mustRun(fxVal, "set", "B_KEY", "--global", "--stdin")
	w.inRepo()
	w.mustRun(fxVal, "set", "A_KEY", "--project", "--stdin")
	w.outRepo()

	seed := func() {
		t.Helper()
		w.mustRun("y\n", "revoke", "--all")
		for _, a := range [][]string{
			{"--session", sessA, "grant", "A_KEY", "--global", "--scope", "session"},
			{"--session", sessB, "grant", "A_KEY", "--global", "--scope", "session"},
			{"--session", sessA, "grant", "B_KEY", "--scope", "once"},
		} {
			w.mustRun("y\n", a...)
		}
		w.inRepo()
		w.mustRun("y\n", "--session", sessA, "grant", "A_KEY", "--project", "--scope", "session")
		w.mustRun("y\n", "grant", "A_KEY", "--project", "--scope", "project")
		w.outRepo()
	}
	count := func() int {
		t.Helper()
		var l struct{ Grants []json.RawMessage }
		if err := json.Unmarshal([]byte(w.grantsState()), &l); err != nil {
			t.Fatal(err)
		}
		return len(l.Grants)
	}

	t.Run("by name and layer", func(t *testing.T) {
		seed()
		code, out, errs := w.run("", "revoke", "A_KEY", "--global")
		if code != 0 || out != "revoked 2 grants\n" || errs != "" {
			t.Fatalf("code=%d out=%q err=%q", code, out, errs)
		}
		if count() != 3 {
			t.Fatal("revoke touched other layers or names")
		}
		w.inRepo()
		code, out, _ = w.run("", "--json", "revoke", "A_KEY", "--project")
		w.outRepo()
		if code != 0 || out != `{"ok":true,"revoked":2}`+"\n" {
			t.Fatalf("json: code=%d out=%q", code, out)
		}
	})
	t.Run("by name in every layer", func(t *testing.T) {
		seed()
		if code, out, _ := w.run("", "revoke", "A_KEY"); code != 0 || out != "revoked 4 grants\n" {
			t.Fatalf("code=%d out=%q", code, out)
		}
		if code, out, _ := w.run("", "revoke", "A_KEY"); code != 0 || out != "revoked 0 grants\n" {
			t.Fatalf("again: code=%d out=%q", code, out)
		}
	})
	t.Run("session only", func(t *testing.T) {
		seed()
		code, out, errs := w.run("", "--session", sessA, "revoke", "--session-only")
		if code != 0 || out != "revoked 3 grants\n" || errs != "" {
			t.Fatalf("code=%d out=%q err=%q", code, out, errs)
		}
		var l struct {
			Grants []struct {
				Scope   string
				Session *string
			}
		}
		if err := json.Unmarshal([]byte(w.grantsState()), &l); err != nil || len(l.Grants) != 2 {
			t.Fatalf("left: %v %+v", err, l)
		}
		for _, g := range l.Grants {
			if g.Session != nil && *g.Session == sessA {
				t.Fatal("a grant of the revoked session survived")
			}
		}
	})
	t.Run("all", func(t *testing.T) {
		seed()
		if code, out, _ := w.run("", "--json", "revoke", "--all"); code != 0 || out != `{"ok":true,"revoked":5}`+"\n" {
			t.Fatalf("code=%d out=%q", code, out)
		}
		if code, out, _ := w.run("", "grants"); code != 0 || out != "no active grants\n" {
			t.Fatalf("grants: code=%d out=%q", code, out)
		}
	})
	t.Run("usage", func(t *testing.T) {
		seed()
		before := w.grantsState()
		tests := []struct {
			args  []string
			code  int
			stder string
		}{
			{[]string{"revoke"}, 2, usageErr("give exactly one of NAME, --all or --session-only")},
			{[]string{"revoke", "A_KEY", "--all"}, 2, usageErr("give exactly one of NAME, --all or --session-only")},
			{[]string{"revoke", "--all", "--session-only"}, 2, usageErr("give exactly one of NAME, --all or --session-only")},
			{[]string{"revoke", "--session-only"}, 2, usageErr("--session-only requires --session")},
			{[]string{"revoke", "--all", "--global"}, 2, usageErr("--global and --project apply to NAME only")},
			{[]string{"revoke", "A_KEY", "--global", "--project"}, 2, usageErr("choose only one of --global and --project")},
			{[]string{"revoke", "lower"}, 3, "error: invalid secret name\n"},
			{[]string{"revoke", "A_KEY", "--project"}, 3, "error: not inside a repository\n"},
		}
		for _, tt := range tests {
			code, out, errs := w.run("", tt.args...)
			if code != tt.code || out != "" || errs != tt.stder {
				t.Fatalf("%v: code=%d out=%q err=%q", tt.args, code, out, errs)
			}
		}
		if w.grantsState() != before {
			t.Fatal("refused input changed the grants")
		}
	})
	t.Run("audited", func(t *testing.T) {
		seed()
		w.mustRun("", "revoke", "B_KEY")
		got := w.records("--event", "revoke")
		last := got[len(got)-1]
		if last.Names[0] != "B_KEY" || last.Detail != "name revoked=1" || last.By != "user" {
			t.Fatalf("revoke audit: %+v", last)
		}
	})
	t.Run("audit failure does not block", func(t *testing.T) {
		seed()
		if err := os.Remove(w.auditFile()); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(w.auditFile(), 0o700); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(w.auditFile()) })
		code, out, errs := w.run("", "revoke", "--all")
		if code != 0 || out != "revoked 5 grants\n" || errs != auditWarning {
			t.Fatalf("code=%d out=%q err=%q", code, out, errs)
		}
	})
}

func TestGrantsListingAndExpiry(t *testing.T) {
	at := pinClock(t)
	asTerminal(t, true)
	w := newWorld(t)
	if code, out, errs := w.run("", "grants"); code != 0 || out != "no active grants\n" || errs != "" {
		t.Fatalf("empty: code=%d out=%q err=%q", code, out, errs)
	}
	if code, out, _ := w.run("", "--json", "grants"); code != 0 || out != `{"ok":true,"grants":[]}`+"\n" {
		t.Fatalf("empty json: code=%d out=%q", code, out)
	}
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	w.mustRun("y\n", "--session", sessA, "grant", "A_KEY", "--scope", "session", "--ttl", "10m")
	at(gt0.Add(4*time.Minute + 30*time.Second))
	want := `{"ok":true,"grants":[{"name":"A_KEY","layer":"global","project":null,"scope":"session","session":"pi:sess-aaaa","expires_at":"2026-11-03T12:10:00Z","remaining":"5m30s"}]}` + "\n"
	if code, out, errs := w.run("", "--json", "grants"); code != 0 || out != want || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	at(gt0.Add(10 * time.Minute))
	if code, out, _ := w.run("", "grants"); code != 0 || out != "no active grants\n" {
		t.Fatalf("expired grant still listed: code=%d out=%q", code, out)
	}
	if code, out, errs := w.run("", "grants", "extra"); code != 2 || out != "" || errs != usageErr("unexpected arguments") {
		t.Fatalf("extra arg: code=%d out=%q err=%q", code, out, errs)
	}
}

func TestDescribeShowsItsGrants(t *testing.T) {
	pinClock(t)
	asTerminal(t, true)
	w := newWorld(t)
	w.mustRun(fxVal+"g", "set", "DB_URL", "--global", "--stdin")
	w.inRepo()
	w.mustRun(fxVal+"p", "set", "DB_URL", "--project", "--stdin")
	w.outRepo()
	w.mustRun("y\n", "--session", sessA, "grant", "DB_URL", "--global", "--scope", "session")
	w.inRepo()
	w.mustRun("y\n", "grant", "DB_URL", "--project", "--scope", "project")

	// The global grant never shows on the project record, and the reverse.
	code, out, errs := w.run("", "describe", "DB_URL")
	if code != 0 || errs != "" || !strings.Contains(out, "  grants:      project, until revoked\n") || strings.Contains(out, sessA) {
		t.Fatalf("project describe: code=%d out=%q err=%q", code, out, errs)
	}
	_, out, _ = w.run("", "--json", "describe", "DB_URL", "--project")
	if !strings.Contains(out, `"grants":[{"scope":"project","session":null,"expires_at":null}]`) {
		t.Fatalf("project json: %s", out)
	}
	code, out, _ = w.run("", "describe", "DB_URL", "--global")
	if code != 0 || !strings.Contains(out, "  grants:      session, for pi:sess-aaaa, until 2026-11-04T00:00:00Z\n") {
		t.Fatalf("global describe: %q", out)
	}
	_, out, _ = w.run("", "--json", "describe", "DB_URL", "--global")
	if !strings.Contains(out, `"grants":[{"scope":"session","session":"pi:sess-aaaa","expires_at":"2026-11-04T00:00:00Z"}]`) {
		t.Fatalf("global json: %s", out)
	}
	w.mustRun("", "revoke", "DB_URL")
	if _, out, _ = w.run("", "--json", "describe", "DB_URL", "--global"); !strings.Contains(out, `"grants":[]`) {
		t.Fatalf("after revoke: %s", out)
	}
}

// A session grant without --ttl lives 12h; the bounds stay 1m to 24h.
func TestGrantSessionDefaultsTo12Hours(t *testing.T) {
	pinClock(t)
	asTerminal(t, true)
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	w.mustRun("y\n", "--session", sessA, "grant", "A_KEY", "--scope", "session")
	_, out, _ := w.run("", "--json", "--session", sessA, "grants")
	if !strings.Contains(out, `"expires_at":"2026-11-04T00:00:00Z","remaining":"12h0m0s"`) {
		t.Fatalf("grants: %s", out)
	}
	for _, ttl := range []string{"1m", "24h"} {
		if code, _, errs := w.run("y\n", "--session", sessA, "grant", "A_KEY", "--scope", "session", "--ttl", ttl); code != 0 {
			t.Fatalf("--ttl %s: code=%d err=%q", ttl, code, errs)
		}
	}
	cmd := newGrant(&globals{})
	if u := cmd.Flags().Lookup("ttl").Usage; !strings.Contains(u, "default 12h") {
		t.Fatalf("--ttl help: %q", u)
	}
}
