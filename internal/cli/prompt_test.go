package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/exitcode"
	"github.com/QuBiit0/qbit-vault/internal/prompt"
	"github.com/QuBiit0/qbit-vault/internal/prompt/prompttest"
	"github.com/QuBiit0/qbit-vault/internal/refusal"
)

const (
	msgNoTTYSet  = "no controlling terminal available; use --stdin"
	msgCancelled = "error: cancelled\n"
)

// withBackend makes every prompt of the command go to f.
func withBackend(t *testing.T, f *prompttest.Fake) *prompttest.Fake {
	t.Helper()
	old := newPrompt
	newPrompt = func(*globals) (prompt.Backend, error) { return f, nil }
	t.Cleanup(func() { newPrompt = old })
	return f
}

func answers(as ...prompttest.Answer) *prompttest.Fake { return &prompttest.Fake{Script: as} }

func val(v string) prompttest.Answer    { return prompttest.Answer{Value: v} }
func pick(i int) prompttest.Answer      { return prompttest.Answer{Index: i} }
func yes() prompttest.Answer            { return prompttest.Answer{Yes: true} }
func no() prompttest.Answer             { return prompttest.Answer{} }
func cancel() prompttest.Answer         { return prompttest.Answer{Err: prompt.ErrCancelled} }
func (w *world) auditHas(s string) bool { return strings.Contains(w.auditText(), s) }

// noFixtures fails when s holds a test secret; it never prints s.
func noFixtures(t *testing.T, what string, s string) {
	t.Helper()
	if strings.Contains(s, "TESTSECRET_") {
		t.Fatalf("a test secret leaked into %s", what)
	}
}

func TestSetInteractiveOutsideRepo(t *testing.T) {
	w := newWorld(t)
	f := withBackend(t, answers(val(fxVal)))
	code, out, errs := w.run("", "set", "A_KEY")
	if code != exitcode.OK || out != "stored A_KEY (global)\n" || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if w.value("A_KEY") != fxVal {
		t.Fatal("stored value differs from the typed one")
	}
	if len(f.Calls) != 1 || f.Calls[0].Kind != "secret" {
		t.Fatalf("calls = %+v, want one secret prompt and no layer question", f.Calls)
	}
	want := prompt.SecretRequest{Name: "A_KEY", Reason: "manual entry", Host: "cli"}
	if !reflect.DeepEqual(f.Calls[0].Request, want) {
		t.Fatalf("request = %+v, want %+v", f.Calls[0].Request, want)
	}
	noFixtures(t, "stdout/stderr/audit", out+errs+w.auditText())
}

func TestSetInteractiveAsksLayerInsideRepo(t *testing.T) {
	w := newWorld(t)
	w.inRepo()
	f := withBackend(t, answers(pick(1), val(fxVal+"_p")))
	code, out, errs := w.run("", "--json", "set", "A_KEY")
	want := `{"ok":true,"name":"A_KEY","layer":"project","project":` + w.projectJSON() + `,"replaced":false}` + "\n"
	if code != exitcode.OK || out != want || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	c := f.Calls[0]
	if c.Kind != "choose" || c.Default != 0 || len(c.Options) != 2 || c.Options[0] != "global" || c.Options[1] != "this project (shop-api)" || !strings.Contains(c.Q, "A_KEY") {
		t.Fatalf("layer question = %+v", c)
	}
	if f.Calls[1].Request.Project != "shop-api" {
		t.Fatalf("request = %+v, want the project label", f.Calls[1].Request)
	}
	if w.value("A_KEY") != fxVal+"_p" {
		t.Fatal("project value missing")
	}

	withBackend(t, answers(pick(0), val(fxVal+"_g")))
	if code, out, _ = w.run("", "--json", "set", "B_KEY"); code != 0 || !strings.Contains(out, `"layer":"global"`) {
		t.Fatalf("global choice: code=%d out=%q", code, out)
	}
}

func TestSetInteractiveLayerFlagSkipsQuestion(t *testing.T) {
	w := newWorld(t)
	w.inRepo()
	f := withBackend(t, answers(val(fxVal)))
	if code, out, errs := w.run("", "set", "A_KEY", "--global"); code != 0 || out != "stored A_KEY (global)\n" || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if len(f.Calls) != 1 || f.Calls[0].Kind != "secret" {
		t.Fatalf("calls = %+v", f.Calls)
	}
}

func TestSetInteractiveReplaceReportsExisting(t *testing.T) {
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin", "--description", "keep me")
	f := withBackend(t, answers(val(fxVal+"_2")))
	code, out, _ := w.run("", "--json", "set", "A_KEY")
	if code != 0 || !strings.HasSuffix(out, `"replaced":true}`+"\n") {
		t.Fatalf("code=%d out=%q", code, out)
	}
	if !f.Calls[0].Request.Existing {
		t.Fatal("the prompt did not say the value is already stored")
	}
	_, out, _ = w.run("", "--json", "describe", "A_KEY")
	if !strings.Contains(out, `"description":"keep me"`) || w.value("A_KEY") != fxVal+"_2" {
		t.Fatalf("replace lost metadata or value: %s", out)
	}
}

func TestSetInteractiveRefusalsLeaveVaultUnchanged(t *testing.T) {
	big := strings.Repeat("a", 64*1024+1)
	tests := []struct {
		name   string
		repo   bool
		script []prompttest.Answer
		args   []string
		code   int
		err    string
		calls  int
	}{
		{"blank value", false, []prompttest.Answer{val("")}, []string{"set", "A_KEY"}, exitcode.Usage, usageErr("empty value"), 1},
		{"whitespace value", false, []prompttest.Answer{val(" \t ")}, []string{"set", "A_KEY"}, exitcode.Usage, usageErr("empty value"), 1},
		{"value too large", false, []prompttest.Answer{val(big)}, []string{"set", "A_KEY"}, exitcode.Usage, usageErr("value too large"), 1},
		{"cancel at the value", false, []prompttest.Answer{cancel()}, []string{"set", "A_KEY"}, exitcode.Failure, msgCancelled, 1},
		{"cancel at the layer", true, []prompttest.Answer{cancel()}, []string{"set", "A_KEY"}, exitcode.Failure, msgCancelled, 1},
		{"invalid name never prompts", false, nil, []string{"set", "TESTSECRET_x"}, exitcode.Refusal, "error: invalid secret name\n", 0},
		{"token without stdin", false, nil, []string{"set", "A_KEY", "--grant", "once", "--from-prompt-token", "t"}, exitcode.Usage, usageErr("--from-prompt-token needs --stdin"), 0},
		{"grant without session never prompts", false, nil, []string{"set", "A_KEY", "--grant", "once"}, exitcode.Usage, usageErr("--session is required for the once and session scopes"), 0},
		{"project grant on a global value never prompts", false, nil, []string{"set", "A_KEY", "--session", sessA, "--grant", "project"}, exitcode.Refusal, "error: project scope needs a repository: run it inside one\n", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newWorld(t)
			w.mustRun(fxVal, "set", "B_KEY", "--global", "--stdin")
			if tt.repo {
				w.inRepo()
			}
			before, grantsBefore := w.snapshot(), w.grantsState()
			f := withBackend(t, answers(tt.script...))
			code, out, errs := w.run("", tt.args...)
			if code != tt.code || out != "" || errs != tt.err {
				t.Fatalf("code=%d out=%q err=%q", code, out, errs)
			}
			if len(f.Calls) != tt.calls {
				t.Fatalf("calls = %d, want %d", len(f.Calls), tt.calls)
			}
			if w.snapshot() != before || w.grantsState() != grantsBefore {
				t.Fatal("the vault changed")
			}
			noFixtures(t, "output", out+errs)
		})
	}
}

func TestSetInteractiveNeedsTerminal(t *testing.T) {
	w := newWorld(t)
	before := w.snapshot()
	// The default seam of the tests has no terminal; stdin must not stand in.
	code, out, errs := w.run(fxVal+"\n", "set", "A_KEY")
	if code != exitcode.Usage || out != "" || errs != usageErr(msgNoTTYSet) {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	withBackend(t, &prompttest.Fake{Unavailable: true})
	code, out, errs = w.run(fxVal+"\n", "set", "A_KEY")
	if code != exitcode.Usage || out != "" || errs != usageErr(msgNoTTYSet) {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if w.snapshot() != before {
		t.Fatal("the vault changed")
	}
}

func TestSetInteractiveBadBackendEnv(t *testing.T) {
	w := newWorld(t)
	old := newPrompt
	newPrompt = func(g *globals) (prompt.Backend, error) {
		// A machine with no helper installed, whatever this one has.
		return prompt.SelectWith(prompt.Env{GOOS: "linux", Getenv: g.getenv, LookPath: func(string) (string, error) { return "", exec.ErrNotFound }, Exists: func(string) bool { return false }})
	}
	t.Cleanup(func() { newPrompt = old })
	var out, errb bytes.Buffer
	code := execute([]string{"--home", w.home, "set", "A_KEY"}, &out, &errb, envFrom(map[string]string{prompt.EnvBackend: "zenity"}))
	if code != exitcode.Usage || errb.String() != usageErr("prompt backend zenity is unavailable: zenity not found in /usr/bin, /bin, /usr/local/bin; use --stdin") {
		t.Fatalf("code=%d err=%q", code, errb.String())
	}
	errb.Reset()
	code = execute([]string{"--home", w.home, "set", "A_KEY"}, &out, &errb, envFrom(map[string]string{prompt.EnvBackend: "pigeon"}))
	if code != exitcode.Usage || !strings.Contains(errb.String(), prompt.EnvBackend) {
		t.Fatalf("code=%d err=%q", code, errb.String())
	}
}

func TestSetInteractiveGrant(t *testing.T) {
	pinClock(t)
	w := newWorld(t)
	f := withBackend(t, answers(val(fxVal), pick(0)))
	code, out, errs := w.run("", "--session", sessA, "set", "A_KEY", "--grant", "session")
	want := "stored A_KEY (global)\ngranted A_KEY (global): once, for pi:sess-aaaa, until 2026-11-03T12:10:00Z\n"
	if code != exitcode.OK || out != want || errs != "" {
		t.Fatalf("code=%d\nout=%q\nerr=%q", code, out, errs)
	}
	q := f.Calls[1]
	if q.Kind != "choose" || q.Default != 1 || len(q.Options) != 3 ||
		!strings.HasPrefix(q.Options[0], "Once:") || !strings.HasPrefix(q.Options[1], "Session:") || !strings.HasPrefix(q.Options[2], "No, just save") {
		t.Fatalf("scope question = %+v", q)
	}
	_, gout, _ := w.run("", "--json", "grants")
	if !strings.Contains(gout, `"name":"A_KEY"`) || !strings.Contains(gout, `"scope":"once"`) {
		t.Fatalf("grants = %s", gout)
	}
	if !w.auditHas(`"detail":"prompt token"`) {
		t.Fatalf("the grant audit record lacks the prompt detail:\n%s", w.auditText())
	}
	noFixtures(t, "output", out+errs+w.auditText())
}

func TestSetInteractiveGrantChoices(t *testing.T) {
	pinClock(t)
	tests := []struct {
		name      string
		repo      bool
		sensitive bool
		flag      string
		wantOpts  []string // prefixes
		wantDef   int
		answer    int
		wantOut   string
	}{
		{"project layer offers project, the user's --grant project preselected", true, false, "project", []string{"Once:", "Session:", "Always:", "No, just save"}, 2, 2,
			"stored A_KEY (project shop-api)\ngranted A_KEY (project shop-api): project, until revoked\n"},
		{"sensitive offers once only", false, true, "once", []string{"Once:", "No, just save"}, 0, 0,
			"stored A_KEY (global)\ngranted A_KEY (global): once, for pi:sess-aaaa, until TS\n"},
		{"no grant stores only", false, false, "session", []string{"Once:", "Session:", "No, just save"}, 1, 2,
			"stored A_KEY (global)\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newWorld(t)
			script := []prompttest.Answer{val(fxVal), pick(tt.answer)}
			args := []string{"--session", sessA, "set", "A_KEY", "--grant", tt.flag}
			if tt.repo {
				w.inRepo()
				script = append([]prompttest.Answer{pick(1)}, script...)
			}
			if tt.sensitive {
				args = append(args, "--sensitive")
			}
			f := withBackend(t, answers(script...))
			code, out, errs := w.run("", args...)
			if code != 0 || norm(out) != tt.wantOut || errs != "" {
				t.Fatalf("code=%d\nout=%q\nerr=%q", code, out, errs)
			}
			q := f.Calls[len(f.Calls)-1]
			if len(q.Options) != len(tt.wantOpts) || q.Default != tt.wantDef {
				t.Fatalf("question = %+v", q)
			}
			for i, p := range tt.wantOpts {
				if !strings.HasPrefix(q.Options[i], p) {
					t.Fatalf("option %d = %q, want prefix %q", i, q.Options[i], p)
				}
			}
			noFixtures(t, "output", out+errs+w.auditText())
		})
	}
}

func TestSetInteractiveGrantRefusedBeforeAnyPrompt(t *testing.T) {
	w := newWorld(t)
	before := w.snapshot()
	f := withBackend(t, answers())
	// A sensitive secret accepts the once scope only.
	code, out, errs := w.run("", "--session", sessA, "set", "A_KEY", "--sensitive", "--grant", "session")
	if code != exitcode.Refusal || out != "" || errs != "error: "+msgScope+"\n" || len(f.Calls) != 0 {
		t.Fatalf("code=%d out=%q err=%q calls=%d", code, out, errs, len(f.Calls))
	}
	if w.snapshot() != before {
		t.Fatal("the vault changed")
	}
}

func TestSetInteractiveGrantCancelStoresNothing(t *testing.T) {
	pinClock(t)
	w := newWorld(t)
	before, grantsBefore := w.snapshot(), w.grantsState()
	withBackend(t, answers(val(fxVal), cancel()))
	code, out, errs := w.run("", "--session", sessA, "set", "A_KEY", "--grant", "once")
	if code != exitcode.Failure || out != "" || errs != msgCancelled {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if w.snapshot() != before || w.grantsState() != grantsBefore {
		t.Fatal("a cancelled capture changed the vault")
	}
}

func TestInitPassphraseInteractive(t *testing.T) {
	h := newHarness(t)
	f := withBackend(t, answers(val(fxPass)))
	code, out, errs := h.run("", "--json", "init", "--passphrase")
	if code != exitcode.OK || errs != "" || out != initJSON(t, true, h.home, "passphrase-file") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if len(f.Calls) != 1 || f.Calls[0].Kind != "passphrase" || !f.Calls[0].Confirm {
		t.Fatalf("calls = %+v, want one confirmed passphrase prompt", f.Calls)
	}
	noFixtures(t, "output", out+errs)

	// Unlock asks once, without confirmation, and a cache is not available here.
	f = withBackend(t, answers(val(fxPass)))
	if code, out, _ := h.runExtra("", openProbe, "probe"); code != exitcode.OK || out != "opened\n" {
		t.Fatalf("unlock: code=%d out=%q", code, out)
	}
	if len(f.Calls) != 1 || f.Calls[0].Kind != "passphrase" || f.Calls[0].Confirm {
		t.Fatalf("unlock calls = %+v", f.Calls)
	}
}

func TestInitPassphraseInteractiveFailures(t *testing.T) {
	tests := []struct {
		name   string
		script prompttest.Answer
		code   int
		err    string
	}{
		{"mismatch", prompttest.Answer{Err: prompt.ErrMismatch}, exitcode.Usage, usageErr("passphrases do not match")},
		{"blank", val("  "), exitcode.Usage, usageErr("empty passphrase")},
		{"cancel", cancel(), exitcode.Failure, msgCancelled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			withBackend(t, answers(tt.script))
			code, out, errs := h.run("", "init", "--passphrase")
			if code != tt.code || out != "" || errs != tt.err {
				t.Fatalf("code=%d out=%q err=%q", code, out, errs)
			}
			for _, f := range []string{"vault.enc", "key.enc", "state.json"} {
				if _, err := os.Stat(filepath.Join(h.home, f)); !os.IsNotExist(err) {
					t.Fatalf("%s created by a failed init", f)
				}
			}
		})
	}
}

func TestInitPassphraseNeedsTerminalOrStdin(t *testing.T) {
	h := newHarness(t)
	code, out, errs := h.run("", "init", "--passphrase")
	if code != exitcode.Usage || out != "" || errs != usageErr("no controlling terminal available; use --passphrase-stdin") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
}

func TestUnlockPromptFailures(t *testing.T) {
	h := newHarness(t)
	h.mustRun(fxPass+"\n", "init", "--passphrase", "--passphrase-stdin")

	withBackend(t, answers(val(fxPass+"_wrong")))
	if code, _, errs := h.runExtra("", openProbe, "probe"); code != exitcode.Locked || errs != "error: vault is locked\n" {
		t.Fatalf("wrong passphrase: code=%d err=%q", code, errs)
	}
	withBackend(t, answers(cancel()))
	if code, out, errs := h.runExtra("", openProbe, "probe"); code != exitcode.Failure || out != "" || errs != msgCancelled {
		t.Fatalf("cancel: code=%d out=%q err=%q", code, out, errs)
	}
	withBackend(t, &prompttest.Fake{Unavailable: true})
	if code, _, errs := h.runExtra("", openProbe, "probe"); code != exitcode.Locked || errs != "error: vault is locked\n" {
		t.Fatalf("no terminal: code=%d err=%q", code, errs)
	}
}

func TestGrantConfirmationUsesBackend(t *testing.T) {
	pinClock(t)
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	const q = "Grant A_KEY (global) to pi:sess-aaaa, scope session?"

	f := withBackend(t, answers(yes()))
	code, out, errs := w.run("", "--session", sessA, "grant", "A_KEY", "--scope", "session")
	if code != 0 || errs != "" || !strings.HasPrefix(out, "granted A_KEY (global): session") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if len(f.Calls) != 1 || f.Calls[0].Kind != "confirm" || f.Calls[0].Q != q {
		t.Fatalf("calls = %+v", f.Calls)
	}
	w.mustRun("", "--session", sessA, "revoke", "A_KEY")

	for name, a := range map[string]prompttest.Answer{"no": no(), "cancel": cancel()} {
		withBackend(t, answers(a))
		code, out, errs = w.run("", "--session", sessA, "grant", "A_KEY", "--scope", "session")
		if code != exitcode.Refusal || out != "" || errs != "error: "+msgDeclined+"\n" {
			t.Fatalf("%s: code=%d out=%q err=%q", name, code, out, errs)
		}
	}
	withBackend(t, &prompttest.Fake{Unavailable: true})
	code, out, errs = w.run("", "--session", sessA, "grant", "A_KEY", "--scope", "session")
	if code != exitcode.Refusal || out != "" || errs != "error: "+msgNotModel+"\n" {
		t.Fatalf("no terminal: code=%d out=%q err=%q", code, out, errs)
	}
	if _, g, _ := w.run("", "--json", "grants"); strings.Contains(g, "A_KEY") {
		t.Fatalf("grants = %s", g)
	}
}

func TestRmConfirmation(t *testing.T) {
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	before := w.snapshot()

	for name, a := range map[string]prompttest.Answer{"no": no(), "cancel": cancel()} {
		f := withBackend(t, answers(a))
		code, out, errs := w.run("", "rm", "A_KEY")
		if code != exitcode.Failure || out != "" || errs != msgCancelled || len(f.Calls) != 1 {
			t.Fatalf("%s: code=%d out=%q err=%q calls=%d", name, code, out, errs, len(f.Calls))
		}
		if w.snapshot() != before {
			t.Fatalf("%s: the vault changed", name)
		}
	}
	withBackend(t, &prompttest.Fake{Unavailable: true})
	if code, out, errs := w.run("", "rm", "A_KEY"); code != exitcode.Usage || out != "" || errs != usageErr("confirmation required; pass --yes") {
		t.Fatalf("no terminal: code=%d out=%q err=%q", code, out, errs)
	}
	if w.snapshot() != before {
		t.Fatal("the vault changed")
	}

	f := withBackend(t, answers(yes()))
	code, out, errs := w.run("", "rm", "A_KEY")
	if code != 0 || out != "removed A_KEY (global)\n" || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if len(f.Calls) != 1 || f.Calls[0].Q != "Remove A_KEY (global)?" {
		t.Fatalf("calls = %+v", f.Calls)
	}

	// --yes never prompts.
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	f = withBackend(t, answers())
	if code, _, _ := w.run("", "rm", "A_KEY", "--yes"); code != 0 || len(f.Calls) != 0 {
		t.Fatalf("code=%d calls=%d", code, len(f.Calls))
	}
}

func TestMvOverwriteConfirmation(t *testing.T) {
	w := newWorld(t)
	w.mustRun(fxVal+"_g", "set", "A_KEY", "--global", "--stdin")
	w.inRepo()
	w.mustRun(fxVal+"_p", "set", "A_KEY", "--project", "--stdin")
	before := w.snapshot()

	for name, a := range map[string]prompttest.Answer{"no": no(), "cancel": cancel()} {
		withBackend(t, answers(a))
		code, out, errs := w.run("", "mv", "A_KEY", "--to", "global")
		if code != exitcode.Failure || out != "" || errs != msgCancelled {
			t.Fatalf("%s: code=%d out=%q err=%q", name, code, out, errs)
		}
		if w.snapshot() != before {
			t.Fatalf("%s: the vault changed", name)
		}
	}
	withBackend(t, &prompttest.Fake{Unavailable: true})
	if code, _, errs := w.run("", "mv", "A_KEY", "--to", "global"); code != exitcode.Usage || errs != usageErr("A_KEY already exists in global; pass --yes to overwrite") {
		t.Fatalf("no terminal: code=%d err=%q", code, errs)
	}

	f := withBackend(t, answers(yes()))
	code, out, errs := w.run("", "mv", "A_KEY", "--to", "global")
	if code != 0 || out != "moved A_KEY from project shop-api to global\n" || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if len(f.Calls) != 1 || f.Calls[0].Q != "A_KEY already exists in global; overwrite?" {
		t.Fatalf("calls = %+v", f.Calls)
	}
	if w.value("A_KEY") != fxVal+"_p" {
		t.Fatal("the move did not overwrite")
	}

	// Without a conflict nothing is asked.
	f = withBackend(t, answers())
	if code, _, _ := w.run("", "mv", "A_KEY", "--to", "project"); code != 0 || len(f.Calls) != 0 {
		t.Fatalf("code=%d calls=%d", code, len(f.Calls))
	}
}

var tokenRE = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

type promptOut struct {
	OK      bool   `json:"ok"`
	Token   string `json:"token"`
	Scope   string `json:"scope"`
	Layer   string `json:"layer"`
	ValueFD int    `json:"value_on_fd"`
}

func decodePrompt(t *testing.T, out string) promptOut {
	t.Helper()
	var p promptOut
	if err := json.Unmarshal([]byte(out), &p); err != nil || !p.OK || !tokenRE.MatchString(p.Token) {
		t.Fatalf("bad prompt output: %v", err)
	}
	return p
}

// fakeFD replaces the fd 3 seam with a buffer.
func fakeFD(t *testing.T) *bytes.Buffer {
	t.Helper()
	var b bytes.Buffer
	old := openValueFD
	openValueFD = func() (io.WriteCloser, error) { return nopCloser{&b}, nil }
	t.Cleanup(func() { openValueFD = old })
	return &b
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }

func TestPromptIssuesTokenForGrant(t *testing.T) {
	pinClock(t)
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	f := withBackend(t, answers(pick(1)))
	code, out, errs := w.run("", "--session", sessA, "prompt", "--name", "A_KEY", "--reason", "run the release")
	if code != exitcode.OK || errs != "" || !strings.HasSuffix(out, "\n") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	p := decodePrompt(t, out)
	if p.Scope != "session" || p.Layer != "global" || p.ValueFD != 0 {
		t.Fatalf("out = %q", out)
	}
	q := f.Calls[0]
	if q.Kind != "choose" || !strings.Contains(q.Q, "A_KEY") || !strings.Contains(q.Q, "run the release") ||
		len(q.Options) != 3 || !strings.HasPrefix(q.Options[0], "Once:") || !strings.HasPrefix(q.Options[1], "Session:") || !strings.HasPrefix(q.Options[2], "Don't allow") {
		t.Fatalf("question = %+v", q)
	}
	// The token is good for exactly the grant it was issued for.
	code, out, errs = w.run("", "--session", sessA, "grant", "A_KEY", "--scope", "session", "--from-prompt-token", p.Token)
	if code != 0 || errs != "" || !strings.HasPrefix(out, "granted A_KEY (global): session") {
		t.Fatalf("grant: code=%d out=%q err=%q", code, out, errs)
	}
	if !w.auditHas(`"detail":"prompt token"`) {
		t.Fatal("the grant was not audited as a prompt-token grant")
	}
	if code, _, _ = w.run("", "--session", sessA, "grant", "A_KEY", "--scope", "session", "--from-prompt-token", p.Token); code != exitcode.Refusal {
		t.Fatalf("a token must work once: code=%d", code)
	}
}

func TestPromptWithValueWritesFD3AndFeedsSet(t *testing.T) {
	pinClock(t)
	w := newWorld(t)
	fd := fakeFD(t)
	f := withBackend(t, answers(val(fxVal), pick(0)))
	code, out, errs := w.run("", "--session", sessA, "prompt", "--name", "A_KEY", "--reason", "new key", "--value", "--scopes", "once")
	if code != exitcode.OK || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	p := decodePrompt(t, out)
	if p.ValueFD != 3 || p.Scope != "once" || p.Layer != "global" {
		t.Fatalf("out = %q", out)
	}
	if fd.String() != fxVal {
		t.Fatal("the value was not written to fd 3 as typed")
	}
	noFixtures(t, "stdout/stderr", out+errs)
	if f.Calls[0].Kind != "secret" || f.Calls[0].Request.Reason != "new key" || f.Calls[0].Request.Host != "pi" || f.Calls[0].Request.Session != sessA {
		t.Fatalf("request = %+v", f.Calls[0].Request)
	}
	// What the host does next.
	code, out, errs = w.run(fd.String(), "--session", sessA, "set", "A_KEY", "--global", "--stdin", "--grant", "once", "--from-prompt-token", p.Token)
	if code != 0 || errs != "" || !strings.Contains(out, "granted A_KEY (global): once") {
		t.Fatalf("set: code=%d out=%q err=%q", code, out, errs)
	}
}

func TestPromptValueNeedsFD3(t *testing.T) {
	// Never wrap fd 3 in an *os.File here: on macOS it is often the runtime's
	// kqueue, and the file's finalizer would close it.
	if runtime.GOOS != "windows" && valueFDKindOK(valueFD) {
		t.Skip("fd 3 is a usable descriptor in this environment")
	}
	w := newWorld(t)
	f := withBackend(t, answers(val(fxVal), pick(0)))
	code, out, errs := w.run("", "--session", sessA, "prompt", "--name", "A_KEY", "--reason", "r", "--value")
	want := "--value needs file descriptor 3 to be open"
	if runtime.GOOS == "windows" {
		want = "--value is not supported on Windows (no file descriptor 3); capture with the host's own prompt and store with set --stdin"
	}
	if code != exitcode.Usage || out != "" || errs != usageErr(want) || len(f.Calls) != 0 {
		t.Fatalf("code=%d out=%q err=%q calls=%d", code, out, errs, len(f.Calls))
	}
}

func TestPromptRefusals(t *testing.T) {
	pinClock(t)
	tests := []struct {
		name   string
		repo   bool
		setup  func(*world)
		script []prompttest.Answer
		args   []string
		code   int
		out    string // exact stdout ("" = none)
		err    string
		calls  int
	}{
		{"deny", false, func(w *world) { w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin") }, []prompttest.Answer{pick(2)},
			[]string{"--session", sessA, "prompt", "--name", "A_KEY", "--reason", "r"}, exitcode.Refusal, "", "error: " + msgDeclined + "\n", 1},
		{"cancel", false, func(w *world) { w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin") }, []prompttest.Answer{cancel()},
			[]string{"--session", sessA, "prompt", "--name", "A_KEY", "--reason", "r"}, exitcode.Failure, "", msgCancelled, 1},
		{"unknown secret", false, nil, nil,
			[]string{"--session", sessA, "prompt", "--name", "NOPE_KEY", "--reason", "r"}, exitcode.Refusal, "", "error: " + refusal.New(refusal.UnknownSecret, "NOPE_KEY").Message + "\n", 0},
		{"invalid name", false, nil, nil,
			[]string{"--session", sessA, "prompt", "--name", "TESTSECRET_x", "--reason", "r"}, exitcode.Refusal, "", "error: invalid secret name\n", 0},
		{"missing reason", false, nil, nil,
			[]string{"--session", sessA, "prompt", "--name", "A_KEY"}, exitcode.Usage, "", usageErr("missing --reason"), 0},
		{"blank reason", false, nil, nil,
			[]string{"--session", sessA, "prompt", "--name", "A_KEY", "--reason", "  "}, exitcode.Usage, "", usageErr("missing --reason"), 0},
		{"missing name", false, nil, nil,
			[]string{"--session", sessA, "prompt", "--reason", "r"}, exitcode.Usage, "", usageErr("missing --name"), 0},
		{"bad scope", false, nil, nil,
			[]string{"--session", sessA, "prompt", "--name", "A_KEY", "--reason", "r", "--scopes", "forever"}, exitcode.Usage, "", usageErr("invalid --scopes: must be once, session or project"), 0},
		{"bad layer", false, nil, nil,
			[]string{"--session", sessA, "prompt", "--name", "A_KEY", "--reason", "r", "--layers", "team"}, exitcode.Usage, "", usageErr("invalid --layers: must be global or project"), 0},
		{"no session for once", false, func(w *world) { w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin") }, nil,
			[]string{"prompt", "--name", "A_KEY", "--reason", "r", "--scopes", "once,session"}, exitcode.Usage, "", usageErr("--session is required for the once and session scopes"), 0},
		{"project layer outside a repository", false, func(w *world) { w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin") }, nil,
			[]string{"--session", sessA, "prompt", "--name", "A_KEY", "--reason", "r", "--layers", "project"}, exitcode.Refusal, "", "error: not inside a repository\n", 0},
		{"sensitive offers once only", false, func(w *world) { w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin", "--sensitive") }, []prompttest.Answer{pick(1)},
			[]string{"--session", sessA, "prompt", "--name", "A_KEY", "--reason", "r"}, exitcode.Refusal, "", "error: " + msgDeclined + "\n", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newWorld(t)
			if tt.setup != nil {
				tt.setup(w)
			}
			if tt.repo {
				w.inRepo()
			}
			before, grantsBefore := w.snapshot(), w.grantsState()
			f := withBackend(t, answers(tt.script...))
			code, out, errs := w.run("", tt.args...)
			if code != tt.code || out != tt.out || errs != tt.err || len(f.Calls) != tt.calls {
				t.Fatalf("code=%d out=%q err=%q calls=%d", code, out, errs, len(f.Calls))
			}
			if w.snapshot() != before || w.grantsState() != grantsBefore {
				t.Fatal("the vault changed")
			}
			if tt.name == "sensitive offers once only" {
				if o := f.Calls[0].Options; len(o) != 2 || !strings.HasPrefix(o[0], "Once:") || !strings.HasPrefix(o[1], "Don't allow") {
					t.Fatalf("options = %v", o)
				}
			}
		})
	}
}

func TestPromptAsksLayerAndRestrictsScopes(t *testing.T) {
	pinClock(t)
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	w.inRepo()
	w.mustRun(fxVal, "set", "A_KEY", "--project", "--stdin")
	// project layer (index 1), then the only scope offered is project.
	f := withBackend(t, answers(pick(1), pick(0)))
	code, out, errs := w.run("", "prompt", "--name", "A_KEY", "--reason", "r", "--scopes", "project", "--layers", "global,project")
	if code != 0 || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if p := decodePrompt(t, out); p.Scope != "project" || p.Layer != "project" {
		t.Fatalf("out = %q", out)
	}
	if l := f.Calls[0]; l.Kind != "choose" || len(l.Options) != 2 || l.Options[0] != "All projects (global)" || l.Options[1] != "Only this project (shop-api)" || l.Default != 0 {
		t.Fatalf("layer question = %+v", l)
	}
	if s := f.Calls[1]; len(s.Options) != 2 || !strings.HasPrefix(s.Options[0], "Always:") || !strings.HasPrefix(s.Options[1], "Don't allow") {
		t.Fatalf("scope question = %+v", s)
	}
}

func TestPromptNeedsTerminal(t *testing.T) {
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	code, out, errs := w.run("", "--session", sessA, "prompt", "--name", "A_KEY", "--reason", "r")
	if code != exitcode.Usage || out != "" || errs != usageErr("no controlling terminal available") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
}

func TestPromptEscapesReasonInQuestion(t *testing.T) {
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	var buf bytes.Buffer
	old := newPrompt
	newPrompt = func(g *globals) (prompt.Backend, error) {
		return prompttest.Stream(strings.NewReader("1\n"), &buf), nil
	}
	t.Cleanup(func() { newPrompt = old })
	code, _, errs := w.run("", "--session", sessA, "prompt", "--name", "A_KEY", "--reason", "x\x1b[2J\nfake: line")
	if code != 0 || errs != "" {
		t.Fatalf("code=%d err=%q", code, errs)
	}
	if strings.Contains(buf.String(), "\x1b") || strings.Count(buf.String(), "fake: line") != 1 {
		t.Fatalf("the reason was not escaped: %q", buf.String())
	}
}

func TestPromptRefusalShapeInJSON(t *testing.T) {
	w := newWorld(t)
	withBackend(t, answers())
	code, out, _ := w.run("", "--json", "--session", sessA, "prompt", "--name", "NOPE_KEY", "--reason", "r")
	if code != exitcode.Refusal || out != jsonOf(t, refusal.New(refusal.UnknownSecret, "NOPE_KEY").Envelope()) {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

const msgTrailing = "the input continued after Enter; paste a single line, or use --stdin for multi-line values"

func TestPromptTimeoutIsCancelledAndChangesNothing(t *testing.T) {
	w := newWorld(t)
	w.mustRun(fxVal, "set", "B_KEY", "--global", "--stdin")
	before, grantsBefore := w.snapshot(), w.grantsState()
	timedOut := prompttest.Answer{Err: prompt.ErrTimeout}
	cmds := map[string][]string{
		"set":     {"set", "A_KEY"},
		"rm":      {"rm", "B_KEY"},
		"grant":   {"--session", sessA, "grant", "B_KEY", "--scope", "once"},
		"prompt":  {"--session", sessA, "prompt", "--name", "B_KEY", "--reason", "r"},
		"set+grp": {"--session", sessA, "set", "A_KEY", "--grant", "once"},
	}
	for name, args := range cmds {
		t.Run(name, func(t *testing.T) {
			withBackend(t, answers(timedOut))
			code, out, errs := w.run("", args...)
			if code != exitcode.Failure || out != "" || errs != "error: prompt timed out\n" {
				t.Fatalf("code=%d out=%q err=%q", code, out, errs)
			}
			if w.snapshot() != before || w.grantsState() != grantsBefore {
				t.Fatal("the vault changed")
			}
		})
	}
	withBackend(t, answers(timedOut))
	code, out, _ := w.run("", "--json", "set", "A_KEY")
	if code != exitcode.Failure || out != `{"ok":false,"error":{"code":"cancelled","message":"prompt timed out"}}`+"\n" {
		t.Fatalf("json: code=%d out=%q", code, out)
	}
}

func TestTrailingInputIsAUsageErrorAndWritesNothing(t *testing.T) {
	w := newWorld(t)
	before := w.snapshot()
	withBackend(t, answers(prompttest.Answer{Err: prompt.ErrTrailingInput}))
	code, out, errs := w.run("", "set", "A_KEY")
	if code != exitcode.Usage || out != "" || errs != usageErr(msgTrailing) {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if w.snapshot() != before {
		t.Fatal("the vault changed")
	}
	h := newHarness(t)
	withBackend(t, answers(prompttest.Answer{Err: prompt.ErrTrailingInput}))
	if code, out, errs = h.run("", "init", "--passphrase"); code != exitcode.Usage || out != "" || errs != usageErr(msgTrailing) {
		t.Fatalf("init: code=%d out=%q err=%q", code, out, errs)
	}
	if _, err := os.Stat(filepath.Join(h.home, "key.enc")); !os.IsNotExist(err) {
		t.Fatal("a key file was created")
	}
}

func TestBadPromptTimeoutEnvIsUsage(t *testing.T) {
	w := newWorld(t)
	old := newPrompt
	newPrompt = func(g *globals) (prompt.Backend, error) { return prompt.Select(g.getenv) }
	t.Cleanup(func() { newPrompt = old })
	var out, errb bytes.Buffer
	code := execute([]string{"--home", w.home, "set", "A_KEY"}, &out, &errb, envFrom(map[string]string{prompt.EnvTimeout: "9s"}))
	if code != exitcode.Usage || out.Len() != 0 || !strings.Contains(errb.String(), prompt.EnvTimeout) {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errb.String())
	}
}

func TestPromptAuditRecords(t *testing.T) {
	pinClock(t)
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	run := func(a prompttest.Answer) {
		withBackend(t, answers(a))
		w.run("", "--session", sessA, "prompt", "--name", "A_KEY", "--reason", "TESTSECRET_reason_must_not_be_audited")
	}
	run(pick(0))                                   // issued, once
	run(pick(2))                                   // denied
	run(cancel())                                  // cancelled
	run(prompttest.Answer{Err: prompt.ErrTimeout}) // timed out counts as cancelled
	recs := w.auditEvents("prompt")
	if len(recs) != 4 {
		t.Fatalf("%d prompt records, want 4", len(recs))
	}
	for i, want := range []string{"issued", "denied", "cancelled", "cancelled"} {
		r := recs[i]
		if r.Outcome != want || len(r.Names) != 1 || r.Names[0] != "A_KEY" || r.Session != sessA || r.Layer != "global" || r.By != "user" {
			t.Fatalf("record %d = %+v, want outcome %s", i, r, want)
		}
		if r.Reason != "" || r.Detail != "" {
			t.Fatalf("record %d carries free text: %+v", i, r)
		}
	}
	if recs[0].Scope != "once" || recs[1].Scope != "" {
		t.Fatalf("scopes = %q, %q", recs[0].Scope, recs[1].Scope)
	}
	noFixtures(t, "audit", w.auditText())
	// A refused request (unknown secret) never reached the user: no prompt record.
	withBackend(t, answers())
	w.run("", "--session", sessA, "prompt", "--name", "NOPE_KEY", "--reason", "r")
	if n := len(w.auditEvents("prompt")); n != 4 {
		t.Fatalf("%d prompt records after a refused request", n)
	}
}

func TestInteractiveSetAuditsManualEntry(t *testing.T) {
	w := newWorld(t)
	withBackend(t, answers(val(fxVal)))
	w.mustRun("", "set", "A_KEY")
	w.mustRun(fxVal, "set", "B_KEY", "--global", "--stdin")
	recs := w.auditEvents("capture")
	if len(recs) != 2 || recs[0].Reason != "manual entry" || recs[1].Reason != "" {
		t.Fatalf("capture records = %+v", recs)
	}
}

// TestEveryBackendComesFromSelect keeps a command from opening the terminal
// backend by hand and so skipping the native dialog (L2).
func TestEveryBackendComesFromSelect(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("glob: %v", err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(src), "prompt.New(") {
			t.Errorf("%s builds a prompt backend without prompt.Select", f)
		}
	}
}

// The scope the user typed on their own command line wins over the session
// preselection, which is for scopes an agent only suggests.
func TestSetGrantFlagIsTheUsersChoice(t *testing.T) {
	pinClock(t)
	w := newWorld(t)
	f := withBackend(t, answers(val(fxVal), pick(0)))
	if code, out, errs := w.run("", "--session", sessA, "set", "A_KEY", "--grant", "once"); code != exitcode.OK {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if q := f.Calls[1]; q.Kind != "choose" || q.Default != 0 || !strings.HasPrefix(q.Options[0], "Once:") {
		t.Fatalf("scope question = %+v", q)
	}
}

// The standalone prompt (an agent asking through the host) preselects
// session like the broker's request.
func TestPromptPreselectsSession(t *testing.T) {
	pinClock(t)
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	f := withBackend(t, answers(pick(1)))
	if code, out, errs := w.run("", "--session", sessA, "prompt", "--name", "A_KEY", "--reason", "run the release"); code != exitcode.OK {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if q := f.Calls[0]; q.Default != 1 || !strings.HasPrefix(q.Options[1], "Session: until the agent restarts (max 12h)") {
		t.Fatalf("question = %+v", q)
	}
}
