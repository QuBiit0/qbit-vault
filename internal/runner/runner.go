// Package runner runs one command as a child process with vault secrets in
// its environment and nowhere else (PRD R-EXEC-01, R-EXEC-04, R-EXEC-05,
// R-EXEC-09; AGENTS.md invariants 1, 2, 4 and 5).
//
// The child gets the parent environment minus the names the caller asks to
// scrub, plus the injected values. Values travel only through that
// environment: never argv, never the parent's own environment. Go's os/exec
// takes the environment as strings, so those copies cannot be wiped; this is
// accepted, like the GC copies noted in docs/STORAGE.md (L6).
//
// Output goes through redact.StreamWriter before it reaches the caller, in
// capture mode (a bounded tail kept in Result) or streaming mode (redacted
// chunks written to the caller's writers as they arrive). The child inherits
// stdin. On timeout or cancellation the whole process tree is killed (a POSIX
// process group, a Windows job object). That reaches every process still in
// the group or the job; a descendant that left its group (setsid, a double
// fork into a new session) is not reached on POSIX.
package runner

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/QuBiit0/qbit-vault/internal/redact"
	"github.com/QuBiit0/qbit-vault/internal/secret"
)

// DefaultCaptureLimit is the per-stream cap in capture mode (CONTRACT § exec).
const DefaultCaptureLimit = 1 << 20

// waitDelay bounds how long Run waits for output pipes that a surviving
// descendant keeps open after the child exited.
const waitDelay = 2 * time.Second

// Typed failures. None of them contains a command, a value or a path.
var (
	ErrNoRedactor       = errors.New("runner: a redactor is required")
	ErrEmptyCommand     = errors.New("runner: empty command")
	ErrBadEnv           = errors.New("runner: invalid environment variable")
	ErrUnknownShell     = errors.New("runner: unknown shell")
	ErrShellUnavailable = errors.New("runner: shell not available on this system")
	ErrStart            = errors.New("runner: cannot start the command")
)

// Shell selects how Command is interpreted.
type Shell string

const (
	ShellAuto Shell = "auto"
	ShellSh   Shell = "sh"
	ShellBash Shell = "bash"
	ShellCmd  Shell = "cmd"
	ShellPwsh Shell = "pwsh"
)

// Spec is one command to run.
type Spec struct {
	Command string
	// Shell is auto when empty (L5: /bin/sh -c on POSIX; on Windows bash -c
	// when bash is on PATH, else cmd /d /s /c).
	Shell Shell
	Dir   string
	// Env maps the variable name in the child to the value injected.
	Env map[string]secret.Secret
	// ScrubNames are removed from the inherited environment (every vault
	// secret name); case-insensitive on Windows. Names in Env are replaced.
	ScrubNames []string
	// Timeout is the wall-clock limit; zero means none.
	Timeout  time.Duration
	Redactor *redact.Redactor
	// Stdin defaults to the process stdin (inherited).
	Stdin io.Reader
	// Stdout and Stderr, when set, receive the redacted output as it
	// arrives (streaming mode) and Result keeps none of it. When nil the
	// output is captured. Each writer is called from its own goroutine; pass
	// distinct, or synchronized, writers.
	Stdout, Stderr io.Writer
	// CaptureLimit caps each captured stream, keeping the tail; zero means
	// DefaultCaptureLimit.
	CaptureLimit int
}

// Result is what a run produced. Stdout and Stderr hold redacted output in
// capture mode only.
type Result struct {
	// Started reports whether the operating system created the child
	// process. False means the command was never run: nothing it could have
	// done with the injected values happened.
	Started    bool
	ExitCode   int
	Duration   time.Duration
	Redactions int
	Stdout     string
	Stderr     string
	Truncated  bool
	TimedOut   bool
}

// tail keeps the last limit bytes written to it.
type tail struct {
	limit     int
	buf       []byte
	truncated bool
}

func (t *tail) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.limit {
		n := copy(t.buf, t.buf[len(t.buf)-t.limit:])
		clear(t.buf[n:])
		t.buf = t.buf[:n]
		t.truncated = true
	}
	return len(p), nil
}

// Run executes the spec. A timeout is a normal Result with TimedOut set; a
// cancelled ctx kills the tree and returns the partial Result with ctx's
// error.
func Run(ctx context.Context, s Spec) (Result, error) {
	if s.Redactor == nil {
		return Result{}, ErrNoRedactor
	}
	if strings.TrimSpace(s.Command) == "" {
		return Result{}, ErrEmptyCommand
	}
	path, args, err := buildArgv(s.Shell, s.Command)
	if err != nil {
		return Result{}, err
	}
	env, err := buildEnv(os.Environ(), s.ScrubNames, s.Env)
	if err != nil {
		return Result{}, err
	}

	cmd := exec.Command(path, args...)
	cmd.Dir = s.Dir
	cmd.Env = withShellOnPath(env)
	cmd.WaitDelay = waitDelay
	if s.Stdin != nil {
		cmd.Stdin = s.Stdin
	} else {
		cmd.Stdin = os.Stdin
	}

	limit := s.CaptureLimit
	if limit <= 0 {
		limit = DefaultCaptureLimit
	}
	var outTail, errTail *tail
	dstOut, dstErr := s.Stdout, s.Stderr
	if dstOut == nil {
		outTail = &tail{limit: limit}
		dstOut = outTail
	}
	if dstErr == nil {
		errTail = &tail{limit: limit}
		dstErr = errTail
	}
	outW, errW := s.Redactor.Writer(dstOut), s.Redactor.Writer(dstErr)
	cmd.Stdout, cmd.Stderr = outW, errW
	prepare(cmd, path, args)

	start := time.Now()
	if err := cmd.Start(); err != nil {
		return Result{}, ErrStart
	}
	env = nil // the strings live on in cmd.Env until cmd is dropped
	tr, err := attach(cmd)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return Result{Started: true}, ErrStart
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var timeout <-chan time.Time
	if s.Timeout > 0 {
		timer := time.NewTimer(s.Timeout)
		defer timer.Stop()
		timeout = timer.C
	}
	var (
		waitErr  error
		timedOut bool
		ctxErr   error
	)
	select {
	case waitErr = <-done:
	case <-timeout:
		timedOut = true
		tr.kill()
		waitErr = <-done
	case <-ctx.Done():
		ctxErr = ctx.Err()
		tr.kill()
		waitErr = <-done
	}
	tr.release()
	_ = outW.Close()
	_ = errW.Close()

	res := Result{
		Started:    true,
		Duration:   time.Since(start),
		Redactions: outW.Count() + errW.Count(),
		TimedOut:   timedOut,
	}
	if outTail != nil {
		res.Stdout, res.Truncated = string(outTail.buf), outTail.truncated
	}
	if errTail != nil {
		res.Stderr = string(errTail.buf)
		res.Truncated = res.Truncated || errTail.truncated
	}
	var ee *exec.ExitError
	switch {
	case errors.As(waitErr, &ee):
		res.ExitCode = exitCode(ee.ProcessState)
	case waitErr == nil, errors.Is(waitErr, exec.ErrWaitDelay):
	default:
		if ctxErr == nil && !timedOut {
			return res, errors.New("runner: output stream failed")
		}
	}
	return res, ctxErr
}

// exitCode is the child's exit status; death by signal is 128+signal, the
// shell convention.
func exitCode(ps *os.ProcessState) int {
	code := ps.ExitCode()
	if code == -1 {
		if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal())
		}
	}
	return code
}

func envKey(name string) string {
	if runtime.GOOS == "windows" {
		return strings.ToUpper(name)
	}
	return name
}

// buildEnv is base minus the scrubbed and injected names, plus the injected
// values (sorted by name for a stable environment).
func buildEnv(base, scrub []string, inject map[string]secret.Secret) ([]string, error) {
	drop := make(map[string]bool, len(scrub)+len(inject))
	for _, n := range scrub {
		drop[envKey(n)] = true
	}
	names := make([]string, 0, len(inject))
	for n, v := range inject {
		if n == "" || strings.ContainsAny(n, "=\x00") {
			return nil, ErrBadEnv
		}
		raw := v.Reveal()
		bad := strings.IndexByte(string(raw), 0) >= 0
		clear(raw)
		if bad {
			return nil, ErrBadEnv
		}
		drop[envKey(n)] = true
		names = append(names, n)
	}
	out := make([]string, 0, len(base)+len(names))
	for _, kv := range base {
		// A leading '=' is part of the name (Windows "=C:" entries).
		i := strings.IndexByte(kv[min(1, len(kv)):], '=')
		name := kv
		if i >= 0 {
			name = kv[:i+min(1, len(kv))]
		}
		if drop[envKey(name)] {
			continue
		}
		out = append(out, kv)
	}
	sort.Strings(names)
	for _, n := range names {
		raw := inject[n].Reveal()
		out = append(out, n+"="+string(raw))
		clear(raw)
	}
	return out, nil
}
