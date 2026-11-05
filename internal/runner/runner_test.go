package runner

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/QuBiit0/qbit-vault/internal/redact"
	"github.com/QuBiit0/qbit-vault/internal/secret"
)

func TestMain(m *testing.M) {
	if mode := os.Getenv(envHelper); mode != "" {
		helperMain(mode)
	}
	os.Exit(m.Run())
}

// A value with characters that make every encoding differ from the raw text.
const fixture = `TESTSECRET_a"b\c/d+e f`

func self(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return `"` + filepath.ToSlash(exe) + `"`
}

// helper selects the child's mode for the next Run (the child inherits it).
func helper(t *testing.T, mode, arg string) {
	t.Helper()
	t.Setenv(envHelper, mode)
	t.Setenv(envArg, arg)
}

func redactorFor(t *testing.T, vals ...secret.Secret) *redact.Redactor {
	t.Helper()
	r, err := redact.New(vals)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func spec(t *testing.T, vals map[string]secret.Secret) Spec {
	t.Helper()
	var list []secret.Secret
	for _, v := range vals {
		list = append(list, v)
	}
	return Spec{Command: self(t), Env: vals, Redactor: redactorFor(t, list...), Timeout: time.Minute}
}

func TestRunInjectsAndScrubs(t *testing.T) {
	t.Setenv("QBV_TEST_API_TOKEN", "TESTSECRET_parent_api")
	t.Setenv("QBV_TEST_OTHER", "TESTSECRET_parent_other")
	t.Setenv("QBV_TEST_KEEP", "kept")
	helper(t, "env", "QBV_TEST_API_TOKEN,QBV_TEST_OTHER,QBV_TEST_KEEP,QBV_TEST_GH")
	before := os.Environ()

	s := spec(t, map[string]secret.Secret{"QBV_TEST_GH": secret.New("GITHUB_TOKEN", []byte("TESTSECRET_injected_value"))})
	s.ScrubNames = []string{"QBV_TEST_API_TOKEN", "QBV_TEST_OTHER"}
	res, err := Run(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	out := res.Stdout
	for _, want := range []string{"QBV_TEST_API_TOKEN=<unset>", "QBV_TEST_OTHER=<unset>", "QBV_TEST_KEEP=kept"} {
		if !strings.Contains(out, want) {
			t.Errorf("child output misses %q", want)
		}
	}
	if !strings.Contains(out, "QBV_TEST_GH=[REDACTED:GITHUB_TOKEN]") {
		t.Error("the injected variable must be visible in the child (and redacted on the way out)")
	}
	if strings.Contains(out, "TESTSECRET_") {
		t.Error("output holds a fixture")
	}
	if !slices.Equal(before, os.Environ()) {
		t.Error("the parent environment changed")
	}
	if os.Getenv("QBV_TEST_GH") != "" {
		t.Error("the value leaked into the parent")
	}
}

func TestRunInjectedReplacesSameNamedParentVariable(t *testing.T) {
	t.Setenv("QBV_TEST_GH", "TESTSECRET_parent_gh")
	helper(t, "env", "QBV_TEST_GH")
	s := spec(t, map[string]secret.Secret{"QBV_TEST_GH": secret.New("GITHUB_TOKEN", []byte("TESTSECRET_injected_value"))})
	res, err := Run(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ReplaceAll(res.Stdout, "\r\n", "\n") != "QBV_TEST_GH=[REDACTED:GITHUB_TOKEN]\n" {
		t.Fatalf("unexpected output %q", res.Stdout)
	}
}

func TestRunScrubIsCaseInsensitiveOnWindowsOnly(t *testing.T) {
	t.Setenv("QBV_TEST_CASE", "TESTSECRET_parent_case")
	helper(t, "env", "QBV_TEST_CASE")
	s := spec(t, nil)
	s.ScrubNames = []string{"qbv_test_case"}
	res, err := Run(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	gone := strings.Contains(res.Stdout, "QBV_TEST_CASE=<unset>")
	if runtime.GOOS == "windows" && !gone {
		t.Error("Windows variable names are case-insensitive: the scrub must remove it")
	}
	if runtime.GOOS != "windows" && gone {
		t.Error("POSIX variable names are case-sensitive: a differently cased name must stay")
	}
}

func TestValuesNeverInArgv(t *testing.T) {
	file := filepath.Join(t.TempDir(), "argv")
	helper(t, "argv", file)
	s := spec(t, map[string]secret.Secret{"QBV_TEST_GH": secret.New("GITHUB_TOKEN", []byte(fixture))})
	if _, err := Run(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("TESTSECRET_")) {
		t.Fatal("the value reached the child's argv")
	}
	path, args, err := buildArgv(ShellAuto, "echo hi")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(path+strings.Join(args, " "), "TESTSECRET_") {
		t.Fatal("argv built from the spec holds a value")
	}
}

func leaks(out string) []string {
	var found []string
	j, _ := json.Marshal(fixture)
	for name, enc := range map[string]string{
		"raw":     fixture,
		"base64":  base64.StdEncoding.EncodeToString([]byte(fixture)),
		"base64u": base64.URLEncoding.EncodeToString([]byte(fixture)),
		"percent": url.QueryEscape(fixture),
		"json":    string(j[1 : len(j)-1]),
	} {
		if strings.Contains(out, enc) {
			found = append(found, name)
		}
	}
	return found
}

func TestRunRedactsEveryEncodingCapture(t *testing.T) {
	helper(t, "encodings", "QBV_TEST_GH")
	s := spec(t, map[string]secret.Secret{"QBV_TEST_GH": secret.New("GITHUB_TOKEN", []byte(fixture))})
	res, err := Run(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if l := leaks(res.Stdout); len(l) > 0 {
		t.Fatalf("stdout leaks the value in: %v", l)
	}
	if l := leaks(res.Stderr); len(l) > 0 {
		t.Fatalf("stderr leaks the value in: %v", l)
	}
	if res.Redactions < 6 {
		t.Fatalf("redactions %d, want at least 6 (5 on stdout, 1 on stderr)", res.Redactions)
	}
	if !strings.Contains(res.Stdout, "[REDACTED:GITHUB_TOKEN]") || !strings.Contains(res.Stderr, "[REDACTED:GITHUB_TOKEN]") {
		t.Fatal("redaction markers missing")
	}
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestRunRedactsEveryEncodingStreaming(t *testing.T) {
	helper(t, "encodings", "QBV_TEST_GH")
	s := spec(t, map[string]secret.Secret{"QBV_TEST_GH": secret.New("GITHUB_TOKEN", []byte(fixture))})
	var out, errw syncBuf
	s.Stdout, s.Stderr = &out, &errw
	res, err := Run(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if l := leaks(out.String()); len(l) > 0 {
		t.Fatalf("stdout leaks the value in: %v", l)
	}
	if l := leaks(errw.String()); len(l) > 0 {
		t.Fatalf("stderr leaks the value in: %v", l)
	}
	if res.Stdout != "" || res.Stderr != "" {
		t.Fatal("streaming mode must not also capture")
	}
	if res.Redactions < 6 {
		t.Fatalf("redactions %d, want at least 6", res.Redactions)
	}
}

func TestRunRedactsValueSplitAcrossWrites(t *testing.T) {
	helper(t, "split", "QBV_TEST_GH")
	s := spec(t, map[string]secret.Secret{"QBV_TEST_GH": secret.New("GITHUB_TOKEN", []byte(fixture))})
	res, err := Run(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if l := leaks(res.Stdout); len(l) > 0 {
		t.Fatalf("split value leaked in: %v", l)
	}
	if strings.ReplaceAll(res.Stdout, "\r\n", "\n") != "pre [REDACTED:GITHUB_TOKEN] post\n" {
		t.Fatalf("unexpected output %q", res.Stdout)
	}
}

func TestRunExitCodePassthrough(t *testing.T) {
	for _, code := range []int{0, 1, 7, 42} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			helper(t, "exit", strconv.Itoa(code))
			res, err := Run(context.Background(), spec(t, nil))
			if err != nil {
				t.Fatal(err)
			}
			if res.ExitCode != code || res.TimedOut {
				t.Fatalf("exit %d timedout %v, want %d", res.ExitCode, res.TimedOut, code)
			}
		})
	}
}

func TestRunTimeoutKillsTreeAndKeepsPartialOutput(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	helper(t, "tree", pidFile)
	s := spec(t, nil)
	s.Timeout = 4 * time.Second
	start := time.Now()
	res, err := Run(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if !res.TimedOut {
		t.Fatal("TimedOut not set")
	}
	if time.Since(start) > 30*time.Second {
		t.Fatal("the run did not stop at the timeout")
	}
	if !strings.Contains(res.Stdout, "started") {
		t.Fatalf("partial output lost: %q", res.Stdout)
	}
	b, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal("the grandchild never started")
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	deadline := time.Now().Add(10 * time.Second)
	for alive(pid) {
		if time.Now().After(deadline) {
			t.Fatal("the grandchild survived the timeout")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestRunTimeoutPartialOutputBothStreams(t *testing.T) {
	helper(t, "partial-sleep", "")
	s := spec(t, nil)
	s.Timeout = 3 * time.Second
	res, err := Run(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if !res.TimedOut || !strings.Contains(res.Stdout, "PARTIAL_OUT") || !strings.Contains(res.Stderr, "PARTIAL_ERR") {
		t.Fatalf("timedout=%v stdout=%q stderr=%q", res.TimedOut, res.Stdout, res.Stderr)
	}
}

func TestRunCancelKillsChild(t *testing.T) {
	helper(t, "sleep", "")
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(2 * time.Second)
		cancel()
	}()
	start := time.Now()
	res, err := Run(ctx, spec(t, nil))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v, want context.Canceled", err)
	}
	if res.TimedOut || time.Since(start) > 30*time.Second {
		t.Fatalf("timedout=%v after %s", res.TimedOut, time.Since(start))
	}
}

func TestRunCaptureKeepsTail(t *testing.T) {
	helper(t, "chunks", "5000")
	s := spec(t, nil)
	s.CaptureLimit = 300
	res, err := Run(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated {
		t.Fatal("Truncated not set")
	}
	if len(res.Stdout) > 300 {
		t.Fatalf("captured %d bytes over the limit", len(res.Stdout))
	}
	if !strings.HasSuffix(strings.TrimRight(res.Stdout, "\r\n"), "TAILMARK") {
		t.Fatal("the tail was not kept")
	}
}

func TestRunCaptureUnderLimitIsNotTruncated(t *testing.T) {
	helper(t, "chunks", "100")
	res, err := Run(context.Background(), spec(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if res.Truncated || !strings.Contains(res.Stdout, "TAILMARK") {
		t.Fatalf("truncated=%v", res.Truncated)
	}
}

func TestDefaultCaptureLimitIsOneMiB(t *testing.T) {
	if DefaultCaptureLimit != 1<<20 {
		t.Fatalf("DefaultCaptureLimit = %d", DefaultCaptureLimit)
	}
}

func TestRunInheritsStdin(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.WriteString("from-stdin\n")
	w.Close()
	old := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = old; r.Close() }()
	helper(t, "cat", "")
	res, err := Run(context.Background(), spec(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Stdout, "from-stdin") {
		t.Fatalf("stdin not inherited: %q", res.Stdout)
	}
}

func TestRunDir(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	helper(t, "pwd", "")
	s := spec(t, nil)
	s.Dir = dir
	res, err := Run(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.TrimSpace(res.Stdout)
	if !strings.EqualFold(filepath.Base(got), filepath.Base(dir)) {
		t.Fatalf("child ran in %q, want %q", got, dir)
	}
}

func TestRunRefusesBadSpecs(t *testing.T) {
	good := spec(t, nil)
	tests := map[string]func(*Spec){
		"no redactor":   func(s *Spec) { s.Redactor = nil },
		"empty command": func(s *Spec) { s.Command = "" },
		"unknown shell": func(s *Spec) { s.Shell = "zsh" },
		"bad env name":  func(s *Spec) { s.Env = map[string]secret.Secret{"A=B": secret.New("X", []byte("v"))} },
		"nul in value":  func(s *Spec) { s.Env = map[string]secret.Secret{"QBV_X": secret.New("X", []byte("a\x00b"))} },
	}
	for name, mut := range tests {
		t.Run(name, func(t *testing.T) {
			s := good
			mut(&s)
			if _, err := Run(context.Background(), s); err == nil {
				t.Fatal("expected an error")
			} else if strings.Contains(err.Error(), "TESTSECRET_") {
				t.Fatal("error leaks a fixture")
			}
		})
	}
}

func TestShellSelection(t *testing.T) {
	if runtime.GOOS != "windows" {
		path, args, err := buildArgv(ShellAuto, "echo hi")
		if err != nil || path != "/bin/sh" || !slices.Equal(args, []string{"-c", "echo hi"}) {
			t.Fatalf("auto on POSIX: %q %q %v", path, args, err)
		}
		if _, _, err := buildArgv(ShellCmd, "x"); !errors.Is(err, ErrShellUnavailable) {
			t.Fatalf("cmd on POSIX: %v", err)
		}
	}
	if _, err := lookBash(); err == nil {
		path, args, err := buildArgv(ShellBash, "echo hi")
		if err != nil || !strings.Contains(strings.ToLower(filepath.Base(path)), "bash") || !slices.Equal(args, []string{"-c", "echo hi"}) {
			t.Fatalf("bash: %q %q %v", path, args, err)
		}
	}
	if _, _, err := buildArgv("fish", "x"); !errors.Is(err, ErrUnknownShell) {
		t.Fatalf("unknown shell: %v", err)
	}
}

func TestShellAutoOnWindowsPrefersBashOverCmd(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows only")
	}
	path, args, err := buildArgv(ShellAuto, "echo hi")
	if err != nil {
		t.Fatal(err)
	}
	if _, lookErr := lookBash(); lookErr == nil {
		if !strings.Contains(strings.ToLower(filepath.Base(path)), "bash") || args[0] != "-c" {
			t.Fatalf("auto with bash on PATH: %q %q", path, args)
		}
		if strings.Contains(strings.ToLower(filepath.ToSlash(path)), "/windows/system32/") {
			t.Fatal("the WSL launcher must never be chosen")
		}
	} else if !strings.Contains(strings.ToLower(filepath.Base(path)), "cmd") {
		t.Fatalf("auto without bash: %q", path)
	}
}

func TestRunWithBashShell(t *testing.T) {
	if _, err := lookBash(); err != nil {
		t.Skip("bash not available")
	}
	helper(t, "exit", "7")
	s := spec(t, nil)
	s.Shell = ShellBash
	res, err := Run(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 7 {
		t.Fatalf("exit %d", res.ExitCode)
	}
}

// A command with quotes and backslashes must reach the shell unchanged on
// every platform (on Windows, Git Bash decodes quoting differently from Go).
func TestRunCommandQuotingRoundTrip(t *testing.T) {
	if _, err := lookBash(); err != nil && runtime.GOOS == "windows" {
		t.Skip("bash not available")
	}
	for _, tt := range []struct{ command, want string }{
		{`printf '%s' "say \"hi\" and \\ done"`, `say "hi" and \ done`},
		{`printf '%s' 'a "b" c'`, `a "b" c`},
		{`"printf" '%s' x`, `x`},
		{`printf '%s' "tab	end\\"`, "tab\tend\\"},
	} {
		s := spec(t, nil)
		s.Command = tt.command
		s.Stdin = strings.NewReader("")
		res, err := Run(context.Background(), s)
		if err != nil || res.Stdout != tt.want {
			t.Errorf("command %q: out %q err %v, want %q", tt.command, res.Stdout, err, tt.want)
		}
	}
}

func TestCheckShell(t *testing.T) {
	if err := CheckShell(ShellAuto); err != nil {
		t.Fatalf("auto: %v", err)
	}
	if err := CheckShell(""); err != nil {
		t.Fatalf("empty means auto: %v", err)
	}
	if err := CheckShell("zsh"); !errors.Is(err, ErrUnknownShell) {
		t.Fatalf("unknown: %v", err)
	}
	if runtime.GOOS != "windows" {
		if err := CheckShell(ShellCmd); !errors.Is(err, ErrShellUnavailable) {
			t.Fatalf("cmd on POSIX: %v", err)
		}
	}
}

func TestResolveShell(t *testing.T) {
	for _, sh := range []Shell{ShellSh, ShellBash, ShellCmd, ShellPwsh} {
		if got := Resolve(sh); got != sh {
			t.Errorf("Resolve(%q) = %q", sh, got)
		}
	}
	want := ShellSh
	if runtime.GOOS == "windows" {
		want = ShellCmd
		if _, err := lookBash(); err == nil {
			want = ShellBash
		}
	}
	for _, auto := range []Shell{ShellAuto, ""} {
		if got := Resolve(auto); got != want {
			t.Errorf("Resolve(%q) = %q, want %q", auto, got, want)
		}
	}
}

// F5: a child killed by a signal reports 128+signal (POSIX).
func TestRunSignalledChildExitsWith128PlusSignal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("signals are POSIX only; Windows reports the OS exit code")
	}
	helper(t, "selfkill", "")
	res, err := Run(context.Background(), spec(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 128+9 {
		t.Fatalf("exit code %d, want 137", res.ExitCode)
	}
}

// D3 (dogfood 1): Started tells a command that ran from one that never did.
func TestRunReportsWhetherTheChildStarted(t *testing.T) {
	helper(t, "exit", "3")
	res, err := Run(context.Background(), spec(t, nil))
	if err != nil || !res.Started || res.ExitCode != 3 {
		t.Fatalf("a child that exits 3: %+v err %v", res, err)
	}

	s := spec(t, nil)
	s.Dir = filepath.Join(t.TempDir(), "missing")
	if res, err := Run(context.Background(), s); !errors.Is(err, ErrStart) || res.Started {
		t.Fatalf("a directory that does not exist: %+v err %v", res, err)
	}
	s = spec(t, map[string]secret.Secret{"BAD=NAME": secret.New("X", []byte("TESTSECRET_x"))})
	if res, err := Run(context.Background(), s); !errors.Is(err, ErrBadEnv) || res.Started {
		t.Fatalf("a bad variable name: %+v err %v", res, err)
	}
	s = spec(t, nil)
	s.Shell = "fish"
	if res, err := Run(context.Background(), s); !errors.Is(err, ErrUnknownShell) || res.Started {
		t.Fatalf("an unknown shell: %+v err %v", res, err)
	}
}
