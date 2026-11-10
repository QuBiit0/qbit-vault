package cli

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/audit"
	"github.com/qbitdevz/qbit-vault/internal/runner"
)

// S6 (dogfood 1): the words after -- were joined with spaces and no quoting,
// so `sh -c 'printf "%s" "$X" | wc -c'` reached the shell as
// `sh -c printf "%s" "$X" | wc -c`: printf without operands and a count of 0.
func TestExecKeepsTheWordsOfAnArgvCommandApart(t *testing.T) {
	if !runner.PosixShellAvailable() {
		t.Skip("no POSIX shell on this machine")
	}
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xv, "--global")
	w.grantTo(sessA, "GITHUB_TOKEN", "session")
	tail := func(s string) string { return strings.TrimSpace(nl(s)) }

	args := []string{"--session", sessA, "exec", "--secret", "GITHUB_TOKEN", "--"}
	for _, tt := range []struct {
		name string
		argv []string
		want string
	}{
		{"sh -c with a printf format and the length expansion", []string{"sh", "-c", `printf "%s" "${#GITHUB_TOKEN}"`}, strconv.Itoa(len(xv))},
		{"sh -c with two operands", []string{"sh", "-c", `printf "%s|%s" a b`}, "a|b"},
		{"a word with a single quote", []string{"sh", "-c", `printf "%s" "it's"`}, "it's"},
		{"plain words are unchanged", []string{"printf", "%s", "x"}, "x"},
	} {
		code, out, errs := w.run("", append(append([]string(nil), args...), tt.argv...)...)
		noFixtures(t, tt.name, out+errs)
		if code != 0 || tail(out) != tt.want {
			t.Errorf("%s: code=%d stdout=%q stderr=%q, want %q", tt.name, code, out, errs, tt.want)
		}
	}
}

// PowerShell reads U+2018 U+2019 U+201A U+201B as single quotes: a word with
// one must not close the quoting and run what follows.
func TestJoinCommandPwshRunsNoSecondCommand(t *testing.T) {
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("pwsh is not installed")
	}
	word := "a ’; Write-Output INJECTED ; ‘ b"
	out, err := exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-Command", joinCommand([]string{"Write-Output", word}, runner.ShellPwsh)).CombinedOutput()
	if err != nil {
		t.Fatalf("pwsh: %v: %s", err, out)
	}
	// The console code page may turn the typographic quotes into ASCII ones on
	// the way in, so compare the shape: one line, the text after the quote
	// printed as text, no second command run.
	got := strings.TrimSpace(string(out))
	if strings.ContainsAny(got, "\r\n") || !strings.HasPrefix(got, "a ") || !strings.Contains(got, "; Write-Output INJECTED ; ") || !strings.HasSuffix(got, " b") {
		t.Errorf("pwsh printed %q, want the word on one line, literally", got)
	}
}

func TestJoinCommand(t *testing.T) {
	for _, tt := range []struct {
		name  string
		shell runner.Shell
		words []string
		want  string
	}{
		{"one word is the command as is", runner.ShellSh, []string{`echo "a b" | wc`}, `echo "a b" | wc`},
		{"words without blanks stay verbatim", runner.ShellSh, []string{"echo", "$X", "|", "wc", "&&", "true"}, "echo $X | wc && true"},
		{"a word with blanks is quoted", runner.ShellSh, []string{"sh", "-c", `printf "%s" x`}, `sh -c 'printf "%s" x'`},
		{"single quotes inside", runner.ShellBash, []string{"echo", "it's here"}, `echo 'it'\''s here'`},
		{"an empty word", runner.ShellSh, []string{"echo", "", "x"}, "echo '' x"},
		{"a newline counts as a blank", runner.ShellSh, []string{"echo", "a\nb"}, "echo 'a\nb'"},
		{"pwsh doubles single quotes", runner.ShellPwsh, []string{"echo", "it's here"}, "echo 'it''s here'"},
		{"pwsh doubles the typographic single quotes", runner.ShellPwsh, []string{"echo", "a ’; Write-Output INJECTED ; ‘ b"}, "echo 'a ’’; Write-Output INJECTED ; ‘‘ b'"},
		{"pwsh doubles the low and reversed quotes", runner.ShellPwsh, []string{"echo", "a ‚ ‛ b"}, "echo 'a ‚‚ ‛‛ b'"},
		{"cmd uses double quotes", runner.ShellCmd, []string{"echo", "a b"}, `echo "a b"`},
		{"cmd leaves a word with a double quote", runner.ShellCmd, []string{"echo", `a "b"`}, `echo a "b"`},
	} {
		if got := joinCommand(tt.words, tt.shell); got != tt.want {
			t.Errorf("%s: got %q, want %q", tt.name, got, tt.want)
		}
	}
}

// D3 (dogfood 1): a once grant is spent when the child process starts, not
// before. A command that is refused or cannot start leaves it usable.

func swapRun(t *testing.T, f func(context.Context, runner.Spec) (runner.Result, error)) {
	t.Helper()
	old := runCommand
	runCommand = f
	t.Cleanup(func() { runCommand = old })
}

func neverStarts(context.Context, runner.Spec) (runner.Result, error) {
	return runner.Result{}, runner.ErrStart
}

func (w *world) onceStillWorks(session, name, run string) {
	w.t.Helper()
	code, out, errs := w.run("", execArgs(session, []string{name}, run)...)
	if code != 0 || errs != "" {
		w.t.Fatalf("the once grant was lost: code=%d stdout=%q stderr=%q", code, out, errs)
	}
}

func TestExecOnceGrantSurvivesACommandThatNeverStarts(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xv, "--global", "--binaries", "cli.test")
	run := child(t, "mark", marker(t), 0)
	w.grantTo(sessA, "GITHUB_TOKEN", "once")

	// Refused before the start: guard, allowlist, usage.
	w.wantRefusal("dump_command", "", execArgs(sessA, []string{"GITHUB_TOKEN"}, "env; "+run)...)
	w.wantRefusal("scope_binary", "GITHUB_TOKEN", execArgs(sessA, []string{"GITHUB_TOKEN"}, "curl x; "+run)...)
	if code, _, _ := w.run("", execArgs(sessA, []string{"GITHUB_TOKEN"}, run, "--timeout", "0s")...); code != 2 {
		t.Fatalf("bad timeout: code %d", code)
	}

	// Past the claim but before the process exists.
	swapRun(t, neverStarts)
	code, out, errs := w.run("", execArgs(sessA, []string{"GITHUB_TOKEN"}, run)...)
	noFixtures(t, "exec output", out+errs)
	if code != 3 {
		t.Fatalf("start failure: code=%d stdout=%q stderr=%q", code, out, errs)
	}
	swapRun(t, runner.Run)
	w.onceStillWorks(sessA, "GITHUB_TOKEN", run)
	// And now it is spent, because the child ran.
	w.wantRefusal("grant_required", "GITHUB_TOKEN", execArgs(sessA, []string{"GITHUB_TOKEN"}, run)...)

	// The audit shows the attempt that did not start.
	var notStarted int
	for _, r := range w.auditEvents(audit.EventExec) {
		noFixtures(t, "audit record", r.Command+r.Detail)
		if r.Outcome == "error" && r.Detail == "not started" {
			notStarted++
		}
	}
	if notStarted != 1 {
		t.Fatalf("%d 'not started' records, want 1", notStarted)
	}
}

func TestExecOnceGrantIsSpentByAChildThatStartsAndFails(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xv, "--global")
	run := child(t, "mark", marker(t), 7)
	w.grantTo(sessA, "GITHUB_TOKEN", "once")
	if code, _, _ := w.run("", execArgs(sessA, []string{"GITHUB_TOKEN"}, run)...); code != 7 {
		t.Fatalf("exit code %d, want 7", code)
	}
	w.wantRefusal("grant_required", "GITHUB_TOKEN", execArgs(sessA, []string{"GITHUB_TOKEN"}, run)...)
}

// While one exec holds the once grant (its child is running) another exec of
// the same session cannot use it: one grant, one child.
func TestExecOnceGrantIsHeldWhileTheChildRuns(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xv, "--global")
	run := child(t, "mark", marker(t), 0)
	w.grantTo(sessA, "GITHUB_TOKEN", "once")

	inRun, release := make(chan struct{}), make(chan struct{})
	var starts atomic.Int32
	swapRun(t, func(ctx context.Context, s runner.Spec) (runner.Result, error) {
		starts.Add(1)
		close(inRun)
		<-release
		return runner.Result{Started: true}, nil
	})
	done := make(chan int)
	go func() {
		code, _, _ := w.run("", execArgs(sessA, []string{"GITHUB_TOKEN"}, run)...)
		done <- code
	}()
	<-inRun
	w.wantRefusal("grant_required", "GITHUB_TOKEN", execArgs(sessA, []string{"GITHUB_TOKEN"}, run)...)
	close(release)
	if code := <-done; code != 0 {
		t.Fatalf("first exec: code %d", code)
	}
	if starts.Load() != 1 {
		t.Fatalf("%d children for one once grant", starts.Load())
	}
}

func TestBrokerExecOnceGrantFollowsTheSameRules(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("A", xv, "--global")
	w.grantTo(brokerSession, "A", "once")
	run := child(t, "mark", marker(t), 0)
	req := func(command string) string {
		return envelope("exec", w.outside, `"command":`+jsonString(command)+`,"secrets":[{"name":"A"}]`)
	}

	// A dump command is refused and the grant stays.
	if _, m, _ := w.broker("exec", req("env; "+run)); refusalType(m) != "dump_command" {
		t.Fatalf("dump: %v", m)
	}
	// A start failure leaves it too.
	swapRun(t, neverStarts)
	if _, m, _ := w.broker("exec", req(run)); refusalType(m) == "" {
		t.Fatalf("start failure answered %v", m)
	}
	swapRun(t, runner.Run)
	if code, m, out := w.broker("exec", req(run)); code != 0 || m["ok"] != true {
		t.Fatalf("the once grant was lost: %s", out)
	}
	// Used by a child that ran: gone.
	if _, m, _ := w.broker("exec", req(run)); refusalType(m) != "grant_required" {
		t.Fatalf("second exec: %v", m)
	}
}
