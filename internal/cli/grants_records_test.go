package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/exitcode"
	"github.com/QuBiit0/qbit-vault/internal/grants"
	"github.com/QuBiit0/qbit-vault/internal/keychain"
	"github.com/QuBiit0/qbit-vault/internal/refusal"
)

func TestSetGrantNeedsPromptToken(t *testing.T) {
	pinClock(t)
	asTerminal(t, true) // a terminal does not help: stdin carries the value
	w := newWorld(t)
	before := w.snapshot()
	tests := []struct {
		name string
		args []string
		err  string
	}{
		{"grant without token", []string{"--session", sessA, "set", "NEW_KEY", "--global", "--stdin", "--grant", "session"}, "--grant requires --from-prompt-token"},
		{"token without grant", []string{"--session", sessA, "set", "NEW_KEY", "--global", "--stdin", "--from-prompt-token", "x"}, "--from-prompt-token requires --grant"},
		{"bad scope", []string{"--session", sessA, "set", "NEW_KEY", "--global", "--stdin", "--grant", "forever", "--from-prompt-token", "x"}, "invalid scope: must be once, session or project"},
		{"no session", []string{"set", "NEW_KEY", "--global", "--stdin", "--grant", "session", "--from-prompt-token", "x"}, "--session is required for the once and session scopes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out, errs := w.run(fxVal+"\n", tt.args...)
			if code != exitcode.Usage || out != "" || errs != usageErr(tt.err) {
				t.Fatalf("code=%d out=%q err=%q", code, out, errs)
			}
			if w.snapshot() != before {
				t.Fatal("refused input stored something")
			}
		})
	}
}

func TestSetGrantWithToken(t *testing.T) {
	pinClock(t)
	asTerminal(t, false)
	w := newWorld(t)
	tok := w.issueToken("NEW_KEY", "global", grants.ScopeSession, sessA)
	code, out, errs := w.run(fxVal+"\n", "--session", sessA, "set", "NEW_KEY", "--global", "--stdin", "--grant", "session", "--from-prompt-token", tok)
	want := "stored NEW_KEY (global)\ngranted NEW_KEY (global): session, for pi:sess-aaaa, until 2026-11-04T00:00:00Z\n"
	if code != 0 || out != want || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if w.value("NEW_KEY") != fxVal {
		t.Fatal("value not stored")
	}
	tok = w.issueToken("JS_KEY", "global", grants.ScopeOnce, sessA)
	code, out, _ = w.run(fxVal, "--json", "--session", sessA, "set", "JS_KEY", "--global", "--stdin", "--grant", "once", "--from-prompt-token", tok)
	wantJSON := `{"ok":true,"name":"JS_KEY","layer":"global","project":null,"replaced":false,"grant":{"name":"JS_KEY","layer":"global","scope":"once","session":"pi:sess-aaaa","expires_at":"2026-11-03T12:10:00Z"}}` + "\n"
	if code != 0 || out != wantJSON {
		t.Fatalf("json: code=%d out=%q", code, out)
	}
	if got := w.records("--event", "grant"); len(got) != 2 || got[0].Detail != "prompt token" {
		t.Fatalf("grant audit: %+v", got)
	}
}

func TestSetGrantRefusalsStoreNothing(t *testing.T) {
	pinClock(t)
	asTerminal(t, false)
	w := newWorld(t)
	before := w.snapshot()

	// A token for the wrong request: nothing stored, the token is burnt.
	bad := w.issueToken("OTHER_KEY", "global", grants.ScopeSession, sessA)
	code, out, errs := w.run(fxVal, "--session", sessA, "set", "NEW_KEY", "--global", "--stdin", "--grant", "session", "--from-prompt-token", bad)
	if code != exitcode.Refusal || out != "" || errs != "error: "+msgNotModel+"\n" {
		t.Fatalf("bad token: code=%d out=%q err=%q", code, out, errs)
	}
	if w.snapshot() != before {
		t.Fatal("a refused token stored a secret")
	}

	// A sensitive secret refuses a session grant before the token is spent.
	tok := w.issueToken("NEW_KEY", "global", grants.ScopeSession, sessA)
	code, out, errs = w.run(fxVal, "--session", sessA, "set", "NEW_KEY", "--global", "--stdin", "--sensitive", "--grant", "session", "--from-prompt-token", tok)
	if code != exitcode.Refusal || out != "" || errs != "error: "+msgScope+"\n" {
		t.Fatalf("sensitive: code=%d out=%q err=%q", code, out, errs)
	}
	if w.snapshot() != before {
		t.Fatal("a refused scope stored a secret")
	}
	if code, _, errs = w.run(fxVal, "--session", sessA, "set", "NEW_KEY", "--global", "--stdin", "--grant", "session", "--from-prompt-token", tok); code != 0 {
		t.Fatalf("the token was spent by a refusal that happened before it: code=%d err=%q", code, errs)
	}
}

func TestReplacingAValueDropsItsGrants(t *testing.T) {
	pinClock(t)
	asTerminal(t, true)
	w := newWorld(t)
	w.mustRun(fxVal+"1", "set", "A_KEY", "--global", "--stdin")
	w.mustRun(fxVal+"1", "set", "B_KEY", "--global", "--stdin")
	for _, name := range []string{"A_KEY", "B_KEY"} {
		w.mustRun("y\n", "--session", sessA, "grant", name, "--scope", "session")
	}
	// Metadata edits keep grants.
	w.mustRun("", "edit", "A_KEY", "--description", "d")
	if strings.Count(w.grantsState(), `"name"`) != 2 {
		t.Fatal("edit dropped grants")
	}
	code, out, errs := w.run(fxVal+"2", "--json", "set", "A_KEY", "--global", "--stdin")
	want := `{"ok":true,"name":"A_KEY","layer":"global","project":null,"replaced":true,"grants_dropped":1}` + "\n"
	if code != 0 || out != want || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	state := w.grantsState()
	if strings.Contains(state, `"A_KEY"`) || !strings.Contains(state, `"B_KEY"`) {
		t.Fatalf("grants after replace: %s", state)
	}
	// Creating a record reports nothing dropped.
	if _, out, _ = w.run(fxVal, "--json", "set", "C_KEY", "--global", "--stdin"); strings.Contains(out, "grants_dropped") {
		t.Fatalf("first set: %s", out)
	}
}

func TestRmDropsItsGrants(t *testing.T) {
	pinClock(t)
	asTerminal(t, true)
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	w.mustRun(fxVal, "set", "B_KEY", "--global", "--stdin")
	w.inRepo()
	w.mustRun(fxVal, "set", "A_KEY", "--project", "--stdin")
	w.outRepo()
	w.mustRun("y\n", "--session", sessA, "grant", "A_KEY", "--global", "--scope", "session")
	w.mustRun("y\n", "--session", sessA, "grant", "A_KEY", "--global", "--scope", "once")
	w.mustRun("y\n", "--session", sessA, "grant", "B_KEY", "--scope", "session")
	w.inRepo()
	w.mustRun("y\n", "grant", "A_KEY", "--project", "--scope", "project")
	w.outRepo()

	code, out, errs := w.run("", "--json", "rm", "A_KEY", "--global", "--yes")
	if code != 0 || out != `{"ok":true,"name":"A_KEY","layer":"global","removed":true,"grants_dropped":2}`+"\n" || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	state := w.grantsState()
	if strings.Count(state, `"name"`) != 2 || !strings.Contains(state, `"layer":"project"`) {
		t.Fatalf("rm touched other records' grants: %s", state)
	}
	// Re-creating the same name does not resurrect the old grants.
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	if strings.Contains(w.mustRun("", "--json", "describe", "A_KEY", "--global"), `"scope"`) {
		t.Fatal("a re-created record inherited grants")
	}
	// A removal that grants nothing says nothing.
	if _, out, _ = w.run("", "--json", "rm", "A_KEY", "--global", "--yes"); strings.Contains(out, "grants_dropped") {
		t.Fatalf("out=%s", out)
	}
}

func TestMvDropsItsGrants(t *testing.T) {
	pinClock(t)
	asTerminal(t, true)
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	w.mustRun("y\n", "--session", sessA, "grant", "A_KEY", "--scope", "session")
	w.inRepo()
	code, out, errs := w.run("", "--json", "mv", "A_KEY", "--to", "project")
	want := `{"ok":true,"name":"A_KEY","from":"global","to":"project","project":` + w.projectJSON() + `,"grants_dropped":1}` + "\n"
	if code != 0 || out != want || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if got := w.grantsState(); got != `{"ok":true,"grants":[]}`+"\n" {
		t.Fatalf("grants after mv: %s", got)
	}
	// Moving back does not bring them back either.
	w.mustRun("", "mv", "A_KEY", "--to", "global")
	if got := w.grantsState(); got != `{"ok":true,"grants":[]}`+"\n" {
		t.Fatalf("grants after the round trip: %s", got)
	}
}

func TestRelinkDropsProjectGrants(t *testing.T) {
	pinClock(t)
	asTerminal(t, true)
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	w.mustRun("y\n", "--session", sessA, "grant", "A_KEY", "--global", "--scope", "session")
	w.inRepo()
	w.mustRun(fxVal, "set", "A_KEY", "--project", "--stdin")
	w.mustRun("y\n", "grant", "A_KEY", "--scope", "project")
	w.mustRun("y\n", "--session", sessA, "grant", "A_KEY", "--scope", "session")
	w.outRepo()
	moved := filepath.Join(filepath.Dir(w.repo), "shop-api-v2")
	if err := os.MkdirAll(filepath.Join(moved, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	code, out, errs := w.run("", "--json", "relink", w.repo, moved)
	want := jsonOf(t, relinkBody{OK: true, From: w.repo, To: moved, Secrets: 1, GrantsDropped: 2})
	if code != 0 || out != want || errs != "" {
		t.Fatalf("code=%d out=%q err=%q want=%q", code, out, errs, want)
	}
	if strings.Contains(out, "grants_rewritten") {
		t.Fatal("relink still reports rewritten grants")
	}
	// Nothing follows the layer to the new root; the global grant is untouched.
	state := w.grantsState()
	if strings.Contains(state, `"layer":"project"`) || strings.Count(state, `"name"`) != 1 {
		t.Fatalf("grants after relink: %s", state)
	}
	t.Chdir(moved)
	_, out, _ = w.run("", "describe", "A_KEY")
	if !strings.Contains(out, "  grants:      none\n") {
		t.Fatalf("describe from the new root: %q", out)
	}
}

func TestEditSensitiveDropsBroadGrants(t *testing.T) {
	pinClock(t)
	asTerminal(t, true)
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	w.mustRun(fxVal, "set", "B_KEY", "--global", "--stdin")
	for _, a := range [][]string{
		{"--session", sessA, "grant", "A_KEY", "--scope", "session"},
		{"--session", sessB, "grant", "A_KEY", "--scope", "session"},
		{"--session", sessA, "grant", "A_KEY", "--scope", "once"},
		{"--session", sessA, "grant", "B_KEY", "--scope", "session"},
	} {
		w.mustRun("y\n", a...)
	}
	// Edits that do not make it sensitive keep every grant.
	w.mustRun("", "edit", "A_KEY", "--description", "d")
	w.mustRun("", "edit", "A_KEY", "--sensitive=false")
	if strings.Count(w.grantsState(), `"name"`) != 4 {
		t.Fatal("a harmless edit dropped grants")
	}
	code, out, errs := w.run("", "--json", "edit", "A_KEY", "--sensitive")
	want := `{"ok":true,"name":"A_KEY","layer":"global","project":null,"updated":true,"grants_dropped":2}` + "\n"
	if code != 0 || out != want || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	state := w.grantsState()
	if strings.Count(state, `"scope":"session"`) != 1 || strings.Count(state, `"scope":"once"`) != 1 || !strings.Contains(state, `"B_KEY"`) {
		t.Fatalf("grants after edit --sensitive: %s", state)
	}
	// Already sensitive: nothing more to drop, nothing reported.
	if _, out, _ = w.run("", "--json", "edit", "A_KEY", "--sensitive"); strings.Contains(out, "grants_dropped") {
		t.Fatalf("out=%s", out)
	}
}

func TestEditSensitiveDropsProjectGrant(t *testing.T) {
	pinClock(t)
	asTerminal(t, true)
	w := newWorld(t)
	w.inRepo()
	w.mustRun(fxVal, "set", "A_KEY", "--project", "--stdin")
	w.mustRun("y\n", "grant", "A_KEY", "--scope", "project")
	code, out, _ := w.run("", "--json", "edit", "A_KEY", "--sensitive")
	if code != 0 || !strings.Contains(out, `"grants_dropped":1`) {
		t.Fatalf("code=%d out=%q", code, out)
	}
	if got := w.grantsState(); got != `{"ok":true,"grants":[]}`+"\n" {
		t.Fatalf("grants: %s", got)
	}
}

func TestProjectScopeOnGlobalHasItsOwnMessage(t *testing.T) {
	pinClock(t)
	asTerminal(t, true)
	w := newWorld(t)
	w.mustRun(fxVal, "set", "PLAIN_KEY", "--global", "--stdin")
	before := w.grantsState()
	const msg = "project scope needs a repository: run it inside one"
	code, out, errs := w.run("y\n", "grant", "PLAIN_KEY", "--scope", "project")
	if code != exitcode.Refusal || out != "" || errs != "error: "+msg+"\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	code, out, errs = w.run("y\n", "--json", "grant", "PLAIN_KEY", "--scope", "project")
	wantJSON := jsonOf(t, refusal.New(refusal.ScopeNotAllowed, "PLAIN_KEY").WithMessage(msg).Envelope())
	if code != exitcode.Refusal || out != wantJSON || errs != "" {
		t.Fatalf("json: code=%d out=%q err=%q", code, out, errs)
	}
	if w.grantsState() != before {
		t.Fatal("refusal changed the grants")
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestGrantsFileCorruptionIsResetAndAudited(t *testing.T) {
	pinClock(t)
	asTerminal(t, true)
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	w.mustRun("y\n", "--session", sessA, "grant", "A_KEY", "--scope", "session")
	path := filepath.Join(w.home, "grants.enc")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0x01
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	code, out, errs := w.run("", "grants")
	if code != 0 || out != "no active grants\n" || errs != grantsResetWarning {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	got := w.records("--event", "warning")
	if len(got) != 1 || got[0].Detail != "grants reset" {
		t.Fatalf("warning audit: %+v", got)
	}
	// Healed: the next read is quiet, and the next grant works.
	if code, out, errs = w.run("", "grants"); code != 0 || out != "no active grants\n" || errs != "" {
		t.Fatalf("after healing: code=%d out=%q err=%q", code, out, errs)
	}
	w.mustRun("y\n", "--session", sessA, "grant", "A_KEY", "--scope", "session")
	if strings.Contains(w.grantsState(), `"A_KEY"`) == false {
		t.Fatal("grant after a reset not stored")
	}
}

func TestGrantsRollbackDoesNotReviveAGrant(t *testing.T) {
	pinClock(t)
	asTerminal(t, true)
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	w.mustRun("y\n", "--session", sessA, "grant", "A_KEY", "--scope", "session")
	path := filepath.Join(w.home, "grants.enc")
	older, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	w.mustRun("", "revoke", "--all")
	if err := os.WriteFile(path, older, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := w.run("", "--json", "grants")
	if code != 0 || out != `{"ok":true,"grants":[]}`+"\n" || errs != grantsResetWarning {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if got := w.records("--event", "warning"); len(got) != 1 || got[0].Detail != "grants reset" {
		t.Fatalf("warning audit: %+v", got)
	}
}

func TestResetIsReportedByRecordOperationsToo(t *testing.T) {
	pinClock(t)
	asTerminal(t, true)
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	w.mustRun("y\n", "--session", sessA, "grant", "A_KEY", "--scope", "session")
	path := filepath.Join(w.home, "grants.enc")
	raw, _ := os.ReadFile(path)
	raw[len(raw)/2] ^= 0x01
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := w.run("", "rm", "A_KEY", "--yes")
	if code != 0 || out != "removed A_KEY (global)\n" || errs != grantsResetWarning {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
}

// TestEndToEndGrants drives the whole grants surface through Execute.
func TestEndToEndGrants(t *testing.T) {
	pinClock(t)
	asTerminal(t, true)
	w := newBareWorld(t)
	var all strings.Builder
	step := func(stdin string, wantCode int, wantOut, wantErr string, args ...string) {
		t.Helper()
		code, out, errs := w.run(stdin, args...)
		all.WriteString(out + errs)
		if code != wantCode || norm(out) != wantOut || errs != wantErr {
			t.Fatalf("%v:\ncode=%d (want %d)\nstdout=%q\nwant  =%q\nstderr=%q\nwant  =%q", args, code, wantCode, out, wantOut, errs, wantErr)
		}
	}
	const (
		none   = `{"ok":true,"grants":[]}` + "\n"
		sessQ  = "--session=" + sessA
		secret = fxVal + "_e2e"
	)
	step("", 0, "vault initialized at "+w.home+" (keychain: "+keychainName()+")\n", "", "init")
	step(secret, 0, "stored GITHUB_TOKEN (global)\n", "", "set", "GITHUB_TOKEN", "--global", "--stdin")
	step(secret, 0, "stored STRIPE_KEY (global)\n", "", "set", "STRIPE_KEY", "--global", "--stdin", "--sensitive")

	// grant (terminal, answer y) → grants → describe → revoke → grants.
	step("y\n", 0, "granted GITHUB_TOKEN (global): session, for pi:sess-aaaa, until TS\n",
		grantPrompt("GITHUB_TOKEN", "global", sessA, "session"), sessQ, "grant", "GITHUB_TOKEN", "--scope", "session")
	step("", 0, `{"ok":true,"grants":[{"name":"GITHUB_TOKEN","layer":"global","project":null,"scope":"session","session":"pi:sess-aaaa","expires_at":"TS","remaining":"12h0m0s"}]}`+"\n", "", "--json", "grants")
	_, out, _ := w.run("", "describe", "GITHUB_TOKEN")
	if !strings.Contains(norm(out), "  grants:      session, for pi:sess-aaaa, until TS\n") {
		t.Fatalf("describe: %q", out)
	}
	step("", 0, `{"ok":true,"revoked":1}`+"\n", "", "--json", "revoke", "GITHUB_TOKEN")
	step("", 0, none, "", "--json", "grants")

	// A grant through a token issued by the grants API; the token is single use.
	tok := w.issueToken("GITHUB_TOKEN", "global", grants.ScopeSession, sessA)
	asTerminal(t, false)
	step("", 0, "granted GITHUB_TOKEN (global): session, for pi:sess-aaaa, until TS\n", "",
		sessQ, "grant", "GITHUB_TOKEN", "--scope", "session", "--from-prompt-token", tok)
	step("", 3, "", "error: "+msgNotModel+"\n", sessQ, "grant", "GITHUB_TOKEN", "--scope", "session", "--from-prompt-token", tok)
	// Without a token and without a terminal: nothing.
	step("y\n", 3, "", "error: "+msgNotModel+"\n", sessQ, "grant", "GITHUB_TOKEN", "--scope", "once")
	asTerminal(t, true)

	// A sensitive secret refuses the session scope and accepts once.
	step("y\n", 3, "", "error: "+msgScope+"\n", sessQ, "grant", "STRIPE_KEY", "--scope", "session")
	step("y\n", 0, "granted STRIPE_KEY (global): once, for pi:sess-aaaa, until TS\n", grantPrompt("STRIPE_KEY", "global", sessA, "once"),
		sessQ, "grant", "STRIPE_KEY", "--scope", "once")

	// mv drops the grants of the moved record.
	w.inRepo()
	step("", 0, `{"ok":true,"name":"GITHUB_TOKEN","from":"global","to":"project","project":`+w.projectJSON()+`,"grants_dropped":1}`+"\n", "",
		"--json", "mv", "GITHUB_TOKEN", "--to", "project")
	_, out, _ = w.run("", "--json", "grants")
	if strings.Contains(out, "GITHUB_TOKEN") || !strings.Contains(out, "STRIPE_KEY") {
		t.Fatalf("grants after mv: %s", out)
	}

	// The audit chain is intact and records the grants without any value.
	step("", 0, `{"ok":true,"valid":true,"records":`+auditCount(t, w)+`}`+"\n", "", "--json", "audit", "--verify")
	events := map[string]int{}
	for _, r := range w.records() {
		events[r.Event]++
	}
	if events["grant"] != 3 || events["revoke"] != 1 || events["mv"] != 1 || events["refusal"] < 3 {
		t.Fatalf("audit events: %v", events)
	}
	if strings.Contains(all.String()+w.auditText(), "TESTSECRET_") || strings.Contains(all.String()+w.auditText(), tok) {
		t.Fatal("a value or token leaked")
	}
}

func auditCount(t *testing.T, w *world) string {
	t.Helper()
	return strings.TrimSpace(mustJSON(t, len(w.records())))
}

func keychainName() string { return string(keychain.NewOS().Name()) }
