package cli

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/QuBiit0/gentle-vault/internal/audit"
	"github.com/QuBiit0/gentle-vault/internal/refusal"
)

const (
	xv = "TESTSECRET_exec_0123456789" // value tail "3456789"
	xg = "TESTSECRET_global_0000AAA"  // value tail "0000AAA"
	xp = "TESTSECRET_project_000BBBB" // value tail "000BBBB"
)

// execWorld is a world ready to exec: the grant question can be answered.
func newExecWorld(t *testing.T) *world {
	t.Helper()
	w := newWorld(t)
	asTerminal(t, true)
	return w
}

func (w *world) setSecret(name, value string, flags ...string) {
	w.t.Helper()
	w.mustRun(value+"\n", append([]string{"set", name, "--stdin"}, flags...)...)
}

func (w *world) grantTo(session, name, scope string, flags ...string) {
	w.t.Helper()
	args := append([]string{"--session", session, "grant", name, "--scope", scope}, flags...)
	w.mustRun("y\n", args...)
}

// execArgs builds the full argument list of an exec invocation.
func execArgs(session string, secrets []string, command string, extra ...string) []string {
	args := []string{}
	if session != "" {
		args = append(args, "--session", session)
	}
	args = append(args, "exec")
	for _, s := range secrets {
		args = append(args, "--secret", s)
	}
	args = append(args, extra...)
	return append(args, "--", command)
}

func (w *world) auditRecords() []audit.Record {
	w.t.Helper()
	recs, err := audit.Read(w.home, audit.Filter{})
	if err != nil {
		w.t.Fatal(err)
	}
	return recs
}

func (w *world) auditEvents(event string) []audit.Record {
	var out []audit.Record
	for _, r := range w.auditRecords() {
		if r.Event == event {
			out = append(out, r)
		}
	}
	return out
}

func marker(t *testing.T) string { return filepath.Join(t.TempDir(), "marker") }

func ran(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func nl(s string) string { return strings.ReplaceAll(s, "\r\n", "\n") }

// wantRefusal runs args in human and --json mode and checks the refusal, the
// exit code, that nothing reached the wrong stream and that the audit log got
// one refusal record per run.
func (w *world) wantRefusal(typ refusal.Type, name string, args ...string) {
	w.t.Helper()
	before := len(w.auditEvents(audit.EventRefusal))
	startedBefore := countStarted(w.auditEvents(audit.EventExec))
	rf := refusal.New(typ, name)
	code, out, errs := w.run("", args...)
	if code != 3 || out != "" || errs != "error: "+rf.Message+"\n" {
		w.t.Fatalf("human: code=%d stdout=%q stderr=%q, want a %s refusal", code, out, errs, typ)
	}
	code, out, errs = w.run("", append([]string{"--json"}, args...)...)
	if code != 3 || out != jsonOf(w.t, rf.Envelope()) || errs != "" {
		w.t.Fatalf("json: code=%d stdout=%q stderr=%q", code, out, errs)
	}
	recs := w.auditEvents(audit.EventRefusal)
	if len(recs)-before != 2 {
		w.t.Fatalf("expected two refusal records, got %d", len(recs)-before)
	}
	last := recs[len(recs)-1]
	if last.Refusal != string(typ) || last.Session != sessA {
		w.t.Fatalf("refusal record %+v", last)
	}
	if name != "" && !slices.Equal(last.Names, []string{name}) {
		w.t.Fatalf("refusal record names %v", last.Names)
	}
	if countStarted(w.auditEvents(audit.EventExec)) != startedBefore {
		w.t.Fatal("a refused command must not leave a started record")
	}
}

func countStarted(recs []audit.Record) int {
	n := 0
	for _, r := range recs {
		if r.Outcome == "started" {
			n++
		}
	}
	return n
}

func TestExecUsageErrors(t *testing.T) {
	many := []string{}
	for i := 1; i <= 17; i++ {
		many = append(many, "--secret", "SECRET_"+strconv.Itoa(i))
	}
	tests := []struct {
		name string
		args []string
		msg  string
	}{
		{"no session", []string{"exec", "--secret", "GITHUB_TOKEN", "--", "x"}, "--session is required"},
		{"no secret", []string{"--session", sessA, "exec", "--", "x"}, "at least one --secret is required"},
		{"too many secrets", append([]string{"--session", sessA, "exec"}, append(many, "--", "x")...), "at most 16 --secret flags"},
		{"lowercase name", []string{"--session", sessA, "exec", "--secret", "github", "--", "x"}, "invalid --secret: use NAME or ENV=NAME with valid names"},
		{"bad env name", []string{"--session", sessA, "exec", "--secret", "a-b=GITHUB_TOKEN", "--", "x"}, "invalid --secret: use NAME or ENV=NAME with valid names"},
		{"two equals", []string{"--session", sessA, "exec", "--secret", "A=B=C", "--", "x"}, "invalid --secret: use NAME or ENV=NAME with valid names"},
		{"empty env", []string{"--session", sessA, "exec", "--secret", "=GITHUB_TOKEN", "--", "x"}, "invalid --secret: use NAME or ENV=NAME with valid names"},
		{"duplicate env", []string{"--session", sessA, "exec", "--secret", "GITHUB_TOKEN", "--secret", "GITHUB_TOKEN", "--", "x"}, "duplicate environment variable in --secret"},
		{"timeout too small", []string{"--session", sessA, "exec", "--secret", "GITHUB_TOKEN", "--timeout", "500ms", "--", "x"}, "invalid --timeout: must be between 1s and 1h"},
		{"timeout too large", []string{"--session", sessA, "exec", "--secret", "GITHUB_TOKEN", "--timeout", "2h", "--", "x"}, "invalid --timeout: must be between 1s and 1h"},
		{"bad shell", []string{"--session", sessA, "exec", "--secret", "GITHUB_TOKEN", "--shell", "zsh", "--", "x"}, "invalid --shell: must be auto, sh, bash, cmd or pwsh"},
		{"no dash", []string{"--session", sessA, "exec", "--secret", "GITHUB_TOKEN", "x"}, "missing command: put it after --"},
		{"nothing after dash", []string{"--session", sessA, "exec", "--secret", "GITHUB_TOKEN", "--"}, "command must be 1 to 16384 bytes"},
		{"blank command", []string{"--session", sessA, "exec", "--secret", "GITHUB_TOKEN", "--", "   "}, "command must be 1 to 16384 bytes"},
		{"command too long", []string{"--session", sessA, "exec", "--secret", "GITHUB_TOKEN", "--", strings.Repeat("a", 16385)}, "command must be 1 to 16384 bytes"},
		{"bad cwd", []string{"--session", sessA, "exec", "--secret", "GITHUB_TOKEN", "--cwd", filepath.Join(t.TempDir(), "nope"), "--", "x"}, "invalid --cwd: not a directory"},
	}
	if runtime.GOOS != "windows" {
		tests = append(tests, struct {
			name string
			args []string
			msg  string
		}{"cmd shell off Windows", []string{"--session", sessA, "exec", "--secret", "GITHUB_TOKEN", "--shell", "cmd", "--", "x"}, "shell not available on this system"})
	}
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xv, "--global")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out, errs := w.run("", tt.args...)
			if code != 2 || out != "" || errs != usageErr(tt.msg) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errs)
			}
		})
	}
	if n := len(w.auditEvents(audit.EventExec)); n != 0 {
		t.Fatalf("usage errors must not be audited as exec (%d records)", n)
	}
}

func TestExecNotInitialized(t *testing.T) {
	w := newBareWorld(t)
	code, out, errs := w.run("", execArgs(sessA, []string{"GITHUB_TOKEN"}, "x")...)
	if code != 1 || out != "" || errs != "error: no vault here; run 'gentle-vault init'\n" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errs)
	}
}

func TestExecRefusalsNeverRun(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xv, "--global")
	mk := marker(t)
	run := child(t, "mark", mk, 0)

	t.Run("unknown_secret", func(t *testing.T) {
		w.wantRefusal(refusal.UnknownSecret, "NOPE_TOKEN", execArgs(sessA, []string{"NOPE_TOKEN"}, run)...)
	})
	t.Run("grant_required", func(t *testing.T) {
		w.wantRefusal(refusal.GrantRequired, "GITHUB_TOKEN", execArgs(sessA, []string{"GITHUB_TOKEN"}, run)...)
	})
	t.Run("grant_required for another session", func(t *testing.T) {
		w.grantTo(sessB, "GITHUB_TOKEN", "session")
		w.wantRefusal(refusal.GrantRequired, "GITHUB_TOKEN", execArgs(sessA, []string{"GITHUB_TOKEN"}, run)...)
	})
	w.grantTo(sessA, "GITHUB_TOKEN", "session")
	t.Run("dump_command", func(t *testing.T) {
		for _, c := range []string{"env; " + run, "printenv | cat; " + run, "echo $GITHUB_TOKEN; " + run, "sudo env; " + run} {
			w.wantRefusal(refusal.DumpCommand, "", execArgs(sessA, []string{"GITHUB_TOKEN"}, c)...)
		}
	})
	t.Run("dump_command names the injected env var", func(t *testing.T) {
		w.wantRefusal(refusal.DumpCommand, "", execArgs(sessA, []string{"GH_TOKEN=GITHUB_TOKEN"}, "echo ${GH_TOKEN}; "+run)...)
	})
	if ran(mk) {
		t.Fatal("a refused command ran")
	}
}

func TestExecDumpGuardNegativeCases(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xv, "--global")
	w.grantTo(sessA, "GITHUB_TOKEN", "session")
	mk := marker(t)
	// Allowed: echo of something that is not an injected name, and set -e.
	c := "echo $HOME > /dev/null; set -e; " + child(t, "mark", mk, 0)
	code, out, errs := w.run("", execArgs(sessA, []string{"GITHUB_TOKEN"}, c)...)
	if code != 0 || errs != "" || !ran(mk) {
		t.Fatalf("code=%d stdout=%q stderr=%q ran=%v", code, out, errs, ran(mk))
	}
}

func TestExecUserDumpGuardExtension(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xv, "--global")
	w.grantTo(sessA, "GITHUB_TOKEN", "session")
	mk := marker(t)
	run := child(t, "mark", mk, 0)
	if err := os.WriteFile(filepath.Join(w.home, "dumpguard.yaml"), []byte("format: gentle-vault-dumpguard/1\npatterns:\n  - '^mytool\\s+--dump$'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w.wantRefusal(refusal.DumpCommand, "", execArgs(sessA, []string{"GITHUB_TOKEN"}, "mytool --dump; "+run)...)
	// The defaults still apply next to the user's file.
	w.wantRefusal(refusal.DumpCommand, "", execArgs(sessA, []string{"GITHUB_TOKEN"}, "env; "+run)...)
	if ran(mk) {
		t.Fatal("a refused command ran")
	}
}

func TestExecMalformedDumpGuardFileFailsClosed(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xv, "--global")
	w.grantTo(sessA, "GITHUB_TOKEN", "session")
	mk := marker(t)
	run := child(t, "mark", mk, 0)
	if err := os.WriteFile(filepath.Join(w.home, "dumpguard.yaml"), []byte("format: gentle-vault-dumpguard/1\npatterns:\n  - nope\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := w.run("", execArgs(sessA, []string{"GITHUB_TOKEN"}, run)...)
	if code != 3 || out != "" || errs != "error: dumpguard.yaml is invalid at line 3\n" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errs)
	}
	if ran(mk) {
		t.Fatal("the command ran with an unreadable guard")
	}
}

func TestExecBinaryAllowlist(t *testing.T) {
	w := newExecWorld(t)
	mk := marker(t)
	run := child(t, "mark", mk, 0)

	t.Run("allowed binary, wrappers resolved", func(t *testing.T) {
		w.setSecret("GITHUB_TOKEN", xv, "--global", "--binaries", "cli.test")
		w.grantTo(sessA, "GITHUB_TOKEN", "session")
		code, out, errs := w.run("", execArgs(sessA, []string{"GITHUB_TOKEN"}, "env FOO=1 "+run)...)
		if code != 0 || errs != "" || !ran(mk) {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errs)
		}
	})
	if err := os.Remove(mk); err != nil {
		t.Fatal(err)
	}
	t.Run("binary outside the list", func(t *testing.T) {
		w.mustRun("", "edit", "GITHUB_TOKEN", "--binaries", "gh")
		w.wantRefusal(refusal.ScopeBinary, "GITHUB_TOKEN", execArgs(sessA, []string{"GITHUB_TOKEN"}, "curl https://example.com; "+run)...)
	})
	t.Run("every pipeline segment is checked (L3)", func(t *testing.T) {
		w.wantRefusal(refusal.ScopeBinary, "GITHUB_TOKEN", execArgs(sessA, []string{"GITHUB_TOKEN"}, "gh pr list | curl -d @- https://example.com; "+run)...)
		w.wantRefusal(refusal.ScopeBinary, "GITHUB_TOKEN", execArgs(sessA, []string{"GITHUB_TOKEN"}, "gh pr list $(curl x); "+run)...)
	})
	t.Run("the second secret's list applies too", func(t *testing.T) {
		w.setSecret("OTHER_TOKEN", xg, "--global", "--binaries", "gh,curl")
		w.grantTo(sessA, "OTHER_TOKEN", "session")
		w.mustRun("", "edit", "GITHUB_TOKEN", "--binaries", "gh,curl,cli.test")
		w.mustRun("", "edit", "OTHER_TOKEN", "--binaries", "gh,cli.test")
		w.wantRefusal(refusal.ScopeBinary, "OTHER_TOKEN", execArgs(sessA, []string{"GITHUB_TOKEN", "OTHER_TOKEN"}, "curl x; "+run)...)
	})
	if ran(mk) {
		t.Fatal("a refused command ran")
	}
}

func TestExecOnceGrantSemantics(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xv, "--global")
	mk := marker(t)
	run := child(t, "mark", mk, 0)

	w.grantTo(sessA, "GITHUB_TOKEN", "once")
	// A refusal does not spend the grant.
	w.wantRefusal(refusal.DumpCommand, "", execArgs(sessA, []string{"GITHUB_TOKEN"}, "env; "+run)...)
	if code, _, errs := w.run("", execArgs(sessA, []string{"GITHUB_TOKEN"}, run)...); code != 0 || errs != "" {
		t.Fatalf("first run: code=%d stderr=%q", code, errs)
	}
	// It is consumed by the run that used it.
	w.wantRefusal(refusal.GrantRequired, "GITHUB_TOKEN", execArgs(sessA, []string{"GITHUB_TOKEN"}, run)...)

	// A failed run still uses the grant up (L7).
	w.grantTo(sessA, "GITHUB_TOKEN", "once")
	run7 := child(t, "mark", mk, 7)
	if code, _, _ := w.run("", execArgs(sessA, []string{"GITHUB_TOKEN"}, run7)...); code != 7 {
		t.Fatalf("exit code %d, want 7", code)
	}
	w.wantRefusal(refusal.GrantRequired, "GITHUB_TOKEN", execArgs(sessA, []string{"GITHUB_TOKEN"}, run)...)
}

func TestExecOnceGrantsAreNotSpentWhenAnotherSecretIsRefused(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xv, "--global")
	w.setSecret("OTHER_TOKEN", xg, "--global")
	w.grantTo(sessA, "GITHUB_TOKEN", "once")
	run := child(t, "mark", marker(t), 0)
	w.wantRefusal(refusal.GrantRequired, "OTHER_TOKEN", execArgs(sessA, []string{"GITHUB_TOKEN", "OTHER_TOKEN"}, run)...)
	if code, _, errs := w.run("", execArgs(sessA, []string{"GITHUB_TOKEN"}, run)...); code != 0 || errs != "" {
		t.Fatalf("the once grant of the first secret was spent: code=%d stderr=%q", code, errs)
	}
}

func TestExecLayersAndCwd(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xg, "--global")
	w.inRepo()
	w.setSecret("GITHUB_TOKEN", xp, "--project")
	sub := filepath.Join(w.repo, "pkg", "deep")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	env := child(t, "env", "GITHUB_TOKEN", 0)

	// Only the global record is granted: the project override is not.
	w.outRepo()
	w.grantTo(sessA, "GITHUB_TOKEN", "session")
	w.wantRefusal(refusal.GrantRequired, "GITHUB_TOKEN", execArgs(sessA, []string{"GITHUB_TOKEN"}, env, "--cwd", sub)...)
	code, out, _ := w.run("", execArgs(sessA, []string{"GITHUB_TOKEN"}, env)...)
	if code != 0 || nl(out) != "GITHUB_TOKEN=...0000AAA\n" {
		t.Fatalf("outside the repo the global record resolves: code=%d out=%q", code, out)
	}

	// A project-scope grant covers the repository from any depth, however the
	// path is cased on a case-insensitive file system (S6).
	w.inRepo()
	w.mustRun("y\n", "grant", "GITHUB_TOKEN", "--project", "--scope", "project")
	for _, cwd := range []string{w.repo, sub, strings.ToUpper(sub)} {
		if cwd == strings.ToUpper(sub) && runtime.GOOS != "windows" && runtime.GOOS != "darwin" {
			continue
		}
		code, out, errs := w.run("", execArgs(sessA, []string{"GITHUB_TOKEN"}, env, "--cwd", cwd)...)
		if code != 0 || nl(out) != "GITHUB_TOKEN=...000BBBB\n" || errs != "" {
			t.Fatalf("cwd %q: code=%d out=%q err=%q", filepath.Base(cwd), code, out, errs)
		}
	}
}

func TestExecEnvironment(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xv, "--global")
	w.setSecret("OTHER_TOKEN", xg, "--global")
	w.grantTo(sessA, "GITHUB_TOKEN", "session")
	t.Setenv("GITHUB_TOKEN", "TESTSECRET_parentenv_0000000")
	t.Setenv("OTHER_TOKEN", "TESTSECRET_parentother_000000")
	run := child(t, "env", "GH_TOKEN,GITHUB_TOKEN,OTHER_TOKEN", 0)
	before := os.Environ()

	code, out, errs := w.run("", execArgs(sessA, []string{"GH_TOKEN=GITHUB_TOKEN"}, run)...)
	want := "GH_TOKEN=...3456789\nGITHUB_TOKEN=<unset>\nOTHER_TOKEN=<unset>\n"
	if code != 0 || nl(out) != want || errs != "" {
		t.Fatalf("code=%d out=%q err=%q\nwant %q", code, out, errs, want)
	}
	if !slices.Equal(before, os.Environ()) {
		t.Fatal("exec changed the parent environment")
	}
}

func TestExecJoinsArgumentsWithSpaces(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xv, "--global")
	w.grantTo(sessA, "GITHUB_TOKEN", "session")
	run := child(t, "args", "", 0)
	args := []string{"--session", sessA, "exec", "--secret", "GITHUB_TOKEN", "--", run, "a", "b c"}
	code, out, errs := w.run("", args...)
	if code != 0 || nl(out) != "a,b,c\n" || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
}

func TestExecExitCodePassthrough(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xv, "--global")
	w.grantTo(sessA, "GITHUB_TOKEN", "session")
	for _, c := range []int{1, 7, 42} {
		run := child(t, "args", "", c)
		code, out, errs := w.run("", execArgs(sessA, []string{"GITHUB_TOKEN"}, run)...)
		if code != c || nl(out) != "\n" || errs != "" {
			t.Fatalf("exit %d: code=%d out=%q err=%q", c, code, out, errs)
		}
		code, out, errs = w.run("", append([]string{"--json"}, execArgs(sessA, []string{"GITHUB_TOKEN"}, run)...)...)
		if code != c || errs != "" || !strings.HasPrefix(out, `{"ok":true,"exit_code":`+strconv.Itoa(c)+`,"stdout":`) {
			t.Fatalf("json exit %d: code=%d out=%q err=%q", c, code, out, errs)
		}
	}
}

func TestExecJSONObject(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xv, "--global")
	w.grantTo(sessA, "GITHUB_TOKEN", "session")
	run := child(t, "leaks", "GITHUB_TOKEN", 0)
	code, out, errs := w.run("", append([]string{"--json"}, execArgs(sessA, []string{"GITHUB_TOKEN"}, run)...)...)
	if code != 0 || errs != "" || strings.Count(out, "\n") != 1 {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if !strings.HasPrefix(out, `{"ok":true,"exit_code":0,"stdout":`) {
		t.Fatalf("field order: %q", out)
	}
	var body struct {
		OK         bool   `json:"ok"`
		ExitCode   int    `json:"exit_code"`
		Stdout     string `json:"stdout"`
		Stderr     string `json:"stderr"`
		DurationMS *int64 `json:"duration_ms"`
		Redactions int    `json:"redactions"`
		Truncated  *bool  `json:"truncated"`
	}
	if err := json.Unmarshal([]byte(out), &body); err != nil {
		t.Fatal(err)
	}
	wantOut := "raw:[REDACTED:GITHUB_TOKEN]\nb64:[REDACTED:GITHUB_TOKEN]\nb64u:[REDACTED:GITHUB_TOKEN]\npct:[REDACTED:GITHUB_TOKEN]\njson:[REDACTED:GITHUB_TOKEN]\nsplit:[REDACTED:GITHUB_TOKEN]\ndone\n"
	if nl(body.Stdout) != wantOut || nl(body.Stderr) != "err:[REDACTED:GITHUB_TOKEN]\n" {
		t.Fatalf("stdout=%q stderr=%q", body.Stdout, body.Stderr)
	}
	if body.DurationMS == nil || body.Truncated == nil || *body.Truncated || body.Redactions < 7 {
		t.Fatalf("shape: %+v", body)
	}
}

func TestExecHumanStreamsRedactedOutput(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xv, "--global")
	w.grantTo(sessA, "GITHUB_TOKEN", "session")
	run := child(t, "leaks", "GITHUB_TOKEN", 0)
	for _, extra := range [][]string{nil, {"--stream"}} {
		code, out, errs := w.run("", execArgs(sessA, []string{"GITHUB_TOKEN"}, run, extra...)...)
		if code != 0 || strings.Contains(out+errs, "TESTSECRET_") {
			t.Fatalf("%v: code=%d", extra, code)
		}
		if !strings.HasPrefix(nl(out), "raw:[REDACTED:GITHUB_TOKEN]\n") || nl(errs) != "err:[REDACTED:GITHUB_TOKEN]\n" {
			t.Fatalf("%v: out=%q err=%q", extra, out, errs)
		}
	}
}

func TestExecNDJSONStream(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xv, "--global")
	w.grantTo(sessA, "GITHUB_TOKEN", "session")
	run := child(t, "leaks", "GITHUB_TOKEN", 3)
	code, out, errs := w.run("", append([]string{"--json"}, execArgs(sessA, []string{"GITHUB_TOKEN"}, run, "--stream")...)...)
	if code != 3 || errs != "" {
		t.Fatalf("code=%d err=%q", code, errs)
	}
	lines := strings.Split(strings.TrimSuffix(nl(out), "\n"), "\n")
	var stdout, stderr strings.Builder
	for _, l := range lines[:len(lines)-1] {
		var c struct{ Stream, Chunk string }
		if err := json.Unmarshal([]byte(l), &c); err != nil {
			t.Fatalf("chunk line %q: %v", l, err)
		}
		switch c.Stream {
		case "stdout":
			stdout.WriteString(c.Chunk)
		case "stderr":
			stderr.WriteString(c.Chunk)
		default:
			t.Fatalf("unknown stream in %q", l)
		}
	}
	if !strings.HasPrefix(nl(stdout.String()), "raw:[REDACTED:GITHUB_TOKEN]\n") || nl(stderr.String()) != "err:[REDACTED:GITHUB_TOKEN]\n" {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	var last struct {
		ExitCode   *int   `json:"exit_code"`
		DurationMS *int64 `json:"duration_ms"`
		Redactions *int   `json:"redactions"`
	}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &last); err != nil || last.ExitCode == nil || *last.ExitCode != 3 || last.DurationMS == nil || last.Redactions == nil || *last.Redactions < 7 {
		t.Fatalf("final record %q: %v", lines[len(lines)-1], err)
	}
	if !strings.HasPrefix(lines[len(lines)-1], `{"exit_code":3,"duration_ms":`) {
		t.Fatalf("final record order: %q", lines[len(lines)-1])
	}
}

func TestExecTimeout(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xv, "--global")
	w.grantTo(sessA, "GITHUB_TOKEN", "session")
	run := child(t, "partial-sleep", "", 0)

	code, out, errs := w.run("", append([]string{"--json"}, execArgs(sessA, []string{"GITHUB_TOKEN"}, run, "--timeout", "2s")...)...)
	var env struct {
		OK      bool            `json:"ok"`
		Refusal refusal.Refusal `json:"refusal"`
	}
	if code != 3 || errs != "" || json.Unmarshal([]byte(out), &env) != nil {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if env.OK || env.Refusal.Type != refusal.Timeout || !env.Refusal.Retryable || env.Refusal.Partial == nil ||
		nl(env.Refusal.Partial.Stdout) != "PARTIAL_OUT\n" || env.Refusal.Partial.Stderr != "" {
		t.Fatalf("envelope %q", out)
	}

	code, out, errs = w.run("", execArgs(sessA, []string{"GITHUB_TOKEN"}, run, "--timeout", "2s")...)
	if code != 3 || nl(out) != "PARTIAL_OUT\n" || errs != "error: the command timed out\n" {
		t.Fatalf("human: code=%d out=%q err=%q", code, out, errs)
	}
	fin := w.auditEvents(audit.EventExec)
	if last := fin[len(fin)-1]; last.Outcome != "finished" || last.Detail != "timeout" {
		t.Fatalf("finished record %+v", last)
	}
	if rs := w.auditEvents(audit.EventRefusal); len(rs) != 2 || rs[1].Refusal != "timeout" {
		t.Fatalf("refusal records %+v", rs)
	}
}

func TestExecAuditRecords(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xv, "--global", "--hosts", "api.github.com")
	w.grantTo(sessA, "GITHUB_TOKEN", "session")
	run := child(t, "leaks", "GITHUB_TOKEN", 4)
	// The command text embeds the value on purpose: the log must not keep it.
	command := run + " # " + xv + " https://api.github.com/x"
	code, _, _ := w.run("", execArgs(sessA, []string{"GITHUB_TOKEN"}, command)...)
	if code != 4 {
		t.Fatalf("code %d", code)
	}
	recs := w.auditEvents(audit.EventExec)
	if len(recs) != 2 {
		t.Fatalf("want a started and a finished record, got %d", len(recs))
	}
	st, fin := recs[0], recs[1]
	if st.Outcome != "started" || st.Session != sessA || !slices.Equal(st.Names, []string{"GITHUB_TOKEN"}) || st.Layer != "global" ||
		st.Cwd == "" || !strings.Contains(st.Command, "[REDACTED:GITHUB_TOKEN]") || st.Detail != "" || st.ExitCode != nil {
		t.Fatalf("started record %+v", st)
	}
	if fin.Outcome != "finished" || fin.ExitCode == nil || *fin.ExitCode != 4 || fin.DurationMS == nil || fin.Redactions < 7 || fin.Session != sessA {
		t.Fatalf("finished record %+v", fin)
	}
	raw, err := os.ReadFile(filepath.Join(w.home, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "TESTSECRET_") {
		t.Fatal("the audit log holds a value")
	}
	if res, err := audit.Verify(w.home); err != nil || !res.Valid {
		t.Fatalf("chain broken after exec: %+v %v", res, err)
	}
}

func TestExecHostsAdvisory(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xv, "--global", "--hosts", "api.github.com")
	w.grantTo(sessA, "GITHUB_TOKEN", "session")
	run := child(t, "args", "", 0)
	for _, tt := range []struct{ tail, detail string }{
		{"# https://api.github.com/x", ""},
		{"# https://evil.example.net/x", "hosts warning"},
	} {
		if code, _, errs := w.run("", execArgs(sessA, []string{"GITHUB_TOKEN"}, run+" "+tt.tail)...); code != 0 || errs != "" {
			t.Fatalf("a hosts warning must not refuse: code=%d err=%q", code, errs)
		}
		recs := w.auditEvents(audit.EventExec)
		started := recs[len(recs)-2]
		if started.Outcome != "started" || started.Detail != tt.detail {
			t.Fatalf("%q: started record %+v", tt.tail, started)
		}
	}
}

func TestExecShortValueWarning(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", "short", "--global")
	w.grantTo(sessA, "GITHUB_TOKEN", "session")
	run := child(t, "args", "", 0)
	if code, _, errs := w.run("", execArgs(sessA, []string{"GITHUB_TOKEN"}, run)...); code != 0 || errs != "" {
		t.Fatalf("code=%d err=%q", code, errs)
	}
	ws := w.auditEvents(audit.EventWarning)
	if len(ws) != 1 || ws[0].Detail != "short value" || !slices.Equal(ws[0].Names, []string{"GITHUB_TOKEN"}) {
		t.Fatalf("warning records %+v", ws)
	}
}

func TestExecFailsClosedWhenTheAuditLogCannotBeWritten(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xv, "--global")
	w.grantTo(sessA, "GITHUB_TOKEN", "once")
	mk := marker(t)
	run := child(t, "mark", mk, 0)

	logPath := filepath.Join(w.home, "audit.jsonl")
	saved := logPath + ".saved"
	if err := os.Rename(logPath, saved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(logPath, 0o700); err != nil {
		t.Fatal(err)
	}
	code, out, errs := w.run("", execArgs(sessA, []string{"GITHUB_TOKEN"}, run)...)
	if code != 3 || out != "" || errs != "error: internal error\nwarning: audit log write failed\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if ran(mk) {
		t.Fatal("the command ran although its start could not be audited")
	}
	// Nothing was spent: with the log back, the same once grant still works.
	if err := os.Remove(logPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(saved, logPath); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := w.run("", execArgs(sessA, []string{"GITHUB_TOKEN"}, run)...); code != 0 || errs != "" || !ran(mk) {
		t.Fatalf("code=%d err=%q ran=%v", code, errs, ran(mk))
	}
}

func TestExecFinishedRecordIsBestEffort(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xv, "--global")
	w.grantTo(sessA, "GITHUB_TOKEN", "session")
	run := child(t, "sabotage-audit", w.home, 5)
	code, _, errs := w.run("", execArgs(sessA, []string{"GITHUB_TOKEN"}, run)...)
	if code != 5 || errs != "warning: audit log write failed\n" {
		t.Fatalf("code=%d err=%q", code, errs)
	}
}

func TestExecInheritsStdin(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xv, "--global")
	w.grantTo(sessA, "GITHUB_TOKEN", "session")
	run := child(t, "cat", "", 0)
	stdinOverride = strings.NewReader("hello from stdin")
	t.Cleanup(func() { stdinOverride = nil })
	var out, errb strings.Builder
	code := execute(append([]string{"--home", w.home}, execArgs(sessA, []string{"GITHUB_TOKEN"}, run)...), &out, &errb, envFrom(nil))
	if code != 0 || out.String() != "hello from stdin" {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errb.String())
	}
}

// TestExecLeakBattery runs the value through every output mode and then scans
// every byte the run produced, plus the whole vault home, for the value in the
// encodings the redactor models (TESTING.md § Leak battery).
func TestExecLeakBattery(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xv, "--global")
	w.grantTo(sessA, "GITHUB_TOKEN", "session")
	run := child(t, "leaks", "GITHUB_TOKEN", 0)
	command := run + " # " + xv

	var captured strings.Builder
	for _, asJSON := range []bool{false, true} {
		for _, extra := range [][]string{nil, {"--stream"}} {
			args := execArgs(sessA, []string{"GITHUB_TOKEN"}, command, extra...)
			if asJSON {
				args = append([]string{"--json"}, args...)
			}
			_, out, errs := w.run("", args...)
			captured.WriteString(out + errs)
		}
	}
	_, out, errs := w.run("", "--session", sessA, "exec", "--secret", "GITHUB_TOKEN", "--", "echo", "$GITHUB_TOKEN")
	captured.WriteString(out + errs)
	_, out, errs = w.run("", "--json", "list")
	captured.WriteString(out + errs)

	needles := map[string]string{
		"raw":  xv,
		"b64":  base64.StdEncoding.EncodeToString([]byte(xv)),
		"b64u": base64.URLEncoding.EncodeToString([]byte(xv)),
		"pct":  url.QueryEscape(xv),
	}
	check := func(where string, data []byte) {
		for enc, n := range needles {
			if strings.Contains(string(data), n) {
				t.Errorf("%s holds the value (%s)", where, enc)
			}
		}
	}
	check("captured output", []byte(captured.String()))
	err := filepath.WalkDir(w.home, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		check(filepath.Base(p), b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// childPath is the test binary as a bare, unquoted path: cmd and pwsh
// commands under an allowlist cannot contain quotes (F1).
func childPath(t *testing.T, mode, arg string) string {
	t.Helper()
	t.Setenv(envChild, mode)
	t.Setenv(envChildArg, arg)
	t.Setenv(envChildExit, "0")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(exe, " \t&()^%!;'`$@{}") {
		t.Skipf("test binary path %q needs quoting", exe)
	}
	return exe
}

// F1: with --shell cmd or pwsh the POSIX segmentation does not see the
// commands the shell chains, so an allowlist only admits one simple command.
func TestExecAllowlistUnderCmdAndPwsh(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("cmd is Windows only; pwsh paths are covered by dumpguard.SimpleProgram tests")
	}
	for _, shell := range []string{"cmd", "pwsh"} {
		t.Run(shell, func(t *testing.T) {
			w := newExecWorld(t)
			w.setSecret("GITHUB_TOKEN", xv, "--global", "--binaries", "gh")
			w.grantTo(sessA, "GITHUB_TOKEN", "session")
			mk := marker(t)
			exe := childPath(t, "mark", mk)
			bypasses := []string{
				"gh x \\& " + exe,
				"gh --version | " + exe,
				`gh "a\" & ` + exe + ` & \"b"`,
				`gh "a\" ; ` + exe + ` ; \"b"`,
				"gh x & " + exe,
				"gh x\n" + exe,
			}
			if shell == "pwsh" {
				bypasses = append(bypasses, "gh x ; "+exe) // ';' only chains in pwsh
			}
			for _, c := range bypasses {
				code, out, errs := w.run("", execArgs(sessA, []string{"GITHUB_TOKEN"}, c, "--shell", shell)...)
				if code == 2 {
					t.Skipf("%s is not available: %s%s", shell, out, errs)
				}
				if code != 3 || !strings.Contains(out+errs, refusal.New(refusal.ScopeBinary, "GITHUB_TOKEN").Message) {
					t.Errorf("%q: code=%d out=%q err=%q, want scope_binary", c, code, out, errs)
				}
				if ran(mk) {
					t.Fatalf("%q ran the second command", c)
				}
			}
			// A program outside the list is refused even when simple.
			code, _, _ := w.run("", execArgs(sessA, []string{"GITHUB_TOKEN"}, exe, "--shell", shell)...)
			if code != 3 || ran(mk) {
				t.Fatalf("a simple command outside the list: code=%d ran=%v", code, ran(mk))
			}
			// One simple allowlisted command still runs.
			w.mustRun("", "edit", "GITHUB_TOKEN", "--binaries", "gh,cli.test")
			code, out, errs := w.run("", execArgs(sessA, []string{"GITHUB_TOKEN"}, exe+" --version", "--shell", shell)...)
			if code != 0 || !ran(mk) {
				t.Fatalf("plain allowlisted command: code=%d out=%q err=%q ran=%v", code, out, errs, ran(mk))
			}
		})
	}
}

// F1: the guard sees what cmd and pwsh would chain, and without an allowlist
// the shell choice changes nothing else.
func TestExecDumpGuardUnderCmdAndPwsh(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("cmd is Windows only")
	}
	for _, shell := range []string{"cmd", "pwsh"} {
		t.Run(shell, func(t *testing.T) {
			w := newExecWorld(t)
			w.setSecret("GITHUB_TOKEN", xv, "--global")
			w.grantTo(sessA, "GITHUB_TOKEN", "session")
			for _, c := range []string{`echo "a\" & printenv & \"b"`, `echo "a\" ; env ; \"b"`, "pri^ntenv"} {
				code, out, errs := w.run("", execArgs(sessA, []string{"GITHUB_TOKEN"}, c, "--shell", shell)...)
				if code == 2 {
					t.Skipf("%s is not available: %s%s", shell, out, errs)
				}
				if code != 3 || !strings.Contains(out+errs, refusal.New(refusal.DumpCommand, "").Message) {
					t.Errorf("%q: code=%d out=%q err=%q, want dump_command", c, code, out, errs)
				}
			}
		})
	}
}

// F1: sh and bash keep their POSIX segmentation: a quoted ';' is one word.
func TestExecAllowlistUnderBashUnchanged(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xv, "--global", "--binaries", "cli.test")
	w.grantTo(sessA, "GITHUB_TOKEN", "session")
	mk := marker(t)
	run := child(t, "mark", mk, 0)
	code, out, errs := w.run("", execArgs(sessA, []string{"GITHUB_TOKEN"}, run+" 'a;b' && "+run, "--shell", "bash")...)
	if code != 0 || !ran(mk) {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	w.wantRefusal(refusal.ScopeBinary, "GITHUB_TOKEN", execArgs(sessA, []string{"GITHUB_TOKEN"}, run+" && curl x", "--shell", "bash")...)
}
