package prompt

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/QuBiit0/qbit-vault/internal/secret"
)

// The native backends ask in a dialog of the desktop session instead of the
// terminal, so an agent that owns the terminal (R9) cannot answer. Each one
// drives a helper program: PowerShell/WinForms, osascript, zenity or kdialog.
//
// What travels where (L3): the helper script or argv holds the request text
// (name, reason, host, session, layer), never a value. The value comes back on
// the helper's own stdout, a private pipe between the two processes that the
// agent does not see; it is read as bytes and wiped after use. The helper's
// environment is the broker's own, with nothing added.

// dialogKind is what a dialog asks for.
type dialogKind int

const (
	dialogSecret dialogKind = iota
	dialogChoose
	dialogConfirm
)

// dialog is one question, as plain text safe to show: every piece of
// requester text went through escape, so it holds no control characters. The
// builders still encode it for their own language.
type dialog struct {
	kind    dialogKind
	title   string
	text    string // lines separated by \n
	options []string
	def     int
	visible bool        // a secret dialog for a text field: no masking
	fields  []formField // a form dialog's boxes
}

// command is a helper invocation. Stdin holds the script, when the helper
// reads one; it holds no secret. Env, when empty, is the caller's own.
type command struct {
	Path  string
	Args  []string
	Stdin []byte
	Env   []string
}

// result is what a helper did. Stdout may hold a secret: wipe it.
type result struct {
	Stdout, Stderr []byte
	Exit           int
}

// runner starts a helper and waits for it. It returns an error when the helper
// cannot start or ctx ends first; a helper that exits non-zero is a result.
type runner func(ctx context.Context, c command) (result, error)

// status is how a helper's exit reads for the question asked.
type status int

const (
	statusOK     status = iota // the user answered
	statusNo                   // the user declined a yes/no question
	statusCancel               // the user closed the dialog
	statusFail                 // the helper itself failed
)

// tool is one helper program.
type tool interface {
	name() string
	// program is the executable looked up on PATH.
	program() string
	// build is pure: path and the dialog in, the command out.
	build(path string, d dialog) command
	// classify reads a finished helper's exit.
	classify(d dialog, r result) status
}

func toolByName(name string) tool {
	switch name {
	case "osascript":
		return osascriptTool{}
	case "powershell":
		return powershellTool{}
	case "zenity":
		return zenityTool{}
	case "kdialog":
		return kdialogTool{}
	}
	return nil
}

// Env is what SelectWith looks at, so tests can stand in for any platform.
type Env struct {
	GOOS     string
	Getenv   func(string) string
	LookPath func(string) (string, error)
	// Interactive reports whether this is a desktop session (Windows: not
	// session 0). Nil counts as true.
	Interactive func() bool
	// Exists reports whether a file is there (system helper locations).
	Exists func(string) bool
	// SystemRoot is the Windows directory from the system API; "" if unknown.
	SystemRoot func() string

	run runner // tests; nil means execRunner
}

// nativeFor picks the native backend for the platform when a desktop session
// is available, or nil (L2).
func nativeFor(e Env) (tool, string) {
	look := func(t tool) (tool, string) {
		if p, err := locate(e, t); err == nil {
			return t, p
		}
		return nil, ""
	}
	switch e.GOOS {
	case "windows":
		if e.Interactive != nil && !e.Interactive() {
			return nil, ""
		}
		return look(powershellTool{})
	case "darwin":
		// Over SSH there is no GUI to show a dialog on, unless the shell
		// runs inside a GUI app (Terminal, iTerm): those export
		// __CFBundleIdentifier or TERM_PROGRAM, and ssh does not forward them.
		ssh := e.Getenv("SSH_CONNECTION") != "" || e.Getenv("SSH_TTY") != ""
		gui := e.Getenv("__CFBundleIdentifier") != "" || e.Getenv("TERM_PROGRAM") != ""
		if ssh && !gui {
			return nil, ""
		}
		return look(osascriptTool{})
	case "linux":
		if e.Getenv("DISPLAY") == "" && e.Getenv("WAYLAND_DISPLAY") == "" {
			return nil, ""
		}
		if t, p := look(zenityTool{}); t != nil {
			return t, p
		}
		return look(kdialogTool{})
	}
	return nil, ""
}

// forced resolves a backend named by QBIT_VAULT_PROMPT. A named backend
// that cannot run is an error, never a quiet fall back to the terminal.
func forced(e Env, t tool) (string, error) {
	if t.name() == "powershell" && e.Interactive != nil && !e.Interactive() {
		return "", unavailableError{"prompt backend powershell is unavailable: this is not an interactive desktop session"}
	}
	p, err := locate(e, t)
	if err != nil {
		return "", unavailableError{fmt.Sprintf("prompt backend %s is unavailable: %v", t.name(), err)}
	}
	return p, nil
}

// Fixed locations of the system helpers. They are never looked up on PATH:
// anything that can put a file earlier on PATH could otherwise stand in for
// the dialog and receive the value. zenity and kdialog have no fixed
// location on Linux (distributions and package managers differ), so they
// are looked up on PATH.
const (
	winSystemRoot = `C:\Windows`
	winPowerShell = `\System32\WindowsPowerShell\v1.0\powershell.exe`
	wslPowerShell = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
	osascriptPath = "/usr/bin/osascript"
)

// linuxHelperDirs are the only places zenity and kdialog are looked up, in
// order.
var linuxHelperDirs = []string{"/usr/bin", "/bin", "/usr/local/bin"}

// locate finds the helper of t, or says where it looked.
func locate(e Env, t tool) (string, error) {
	has := func(p string) bool {
		if e.Exists != nil {
			return e.Exists(p)
		}
		st, err := os.Stat(p)
		return err == nil && !st.IsDir()
	}
	var p string
	switch {
	case t.name() == "powershell" && e.GOOS == "windows":
		root := ""
		if e.SystemRoot != nil {
			root = e.SystemRoot()
		}
		if root == "" {
			root = winSystemRoot
		}
		p = strings.TrimRight(root, `\/`) + winPowerShell
	case t.name() == "powershell" && e.GOOS == "linux": // WSL
		p = wslPowerShell
	case t.name() == "osascript" && e.GOOS == "darwin":
		p = osascriptPath
	case t.name() == "powershell" || t.name() == "osascript":
		return "", fmt.Errorf("%s is not available on %s", t.program(), e.GOOS)
	default:
		// zenity and kdialog have no single fixed location on Linux, but they
		// are never taken from PATH either: a caller who controls PATH could
		// substitute a helper that answers by itself.
		for _, dir := range linuxHelperDirs {
			if c := dir + "/" + t.program(); has(c) {
				return c, nil
			}
		}
		return "", fmt.Errorf("%s not found in %s", t.program(), strings.Join(linuxHelperDirs, ", "))
	}
	if !has(p) {
		return "", fmt.Errorf("%s not found at %s", t.program(), p)
	}
	return p, nil
}

// newNative builds the backend over the helper at path. run is called for
// every dialog; each dialog is bounded by timeout.
func newNative(t tool, path string, run runner, timeout time.Duration) Backend {
	return &native{t: t, path: path, run: run, timeout: timeout}
}

type native struct {
	t       tool
	path    string
	run     runner
	timeout time.Duration
}

func (n *native) Name() string { return n.t.name() }

func (n *native) failed() error {
	return unavailableError{"the " + n.t.name() + " dialog failed"}
}

// ask runs one dialog. The caller wipes r.Stdout. A "no" to a question comes
// back as statusNo with a nil error.
func (n *native) ask(d dialog) (result, status, error) {
	return n.askWith(n.t.build(n.path, d), d)
}

// askWith runs a built helper command for dialog d.
func (n *native) askWith(c command, d dialog) (result, status, error) {
	ctx, cancel := context.WithTimeout(context.Background(), n.timeout)
	defer cancel()
	r, err := n.run(ctx, c)
	if err != nil {
		clear(r.Stdout)
		if errors.Is(err, context.DeadlineExceeded) {
			return result{}, statusFail, ErrTimeout
		}
		if errors.Is(err, ErrTooLarge) {
			return result{}, statusFail, ErrTooLarge
		}
		return result{}, statusFail, unavailableError{"cannot start the " + n.t.name() + " dialog"}
	}
	st := n.t.classify(d, r)
	switch st {
	case statusFail:
		clear(r.Stdout)
		return result{}, st, n.failed()
	case statusCancel:
		clear(r.Stdout)
		return result{}, st, ErrCancelled
	case statusNo:
		clear(r.Stdout)
		return result{}, st, nil
	}
	return r, st, nil
}

// read asks for a masked value and returns it as a secret named name.
func (n *native) read(name string, d dialog, kind inputKind) (secret.Secret, error) {
	r, st, err := n.ask(d)
	if err != nil {
		return secret.Secret{}, err
	}
	if st != statusOK {
		return secret.Secret{}, ErrCancelled
	}
	defer clear(r.Stdout)
	return secret.New(name, normalize(r.Stdout, kind)), nil
}

func (n *native) Secret(req SecretRequest) (secret.Secret, error) {
	return n.read(req.Name, secretDialog(req), valueInput)
}

func (n *native) Passphrase(confirm bool) (secret.Secret, error) {
	first, err := n.read("passphrase", passphraseDialog(false), passphraseInput)
	if err != nil || !confirm {
		return first, err
	}
	second, err := n.read("passphrase", passphraseDialog(true), passphraseInput)
	defer second.Wipe()
	if err != nil {
		first.Wipe()
		return secret.Secret{}, err
	}
	a, b := first.Reveal(), second.Reveal()
	defer clear(a)
	defer clear(b)
	if subtle.ConstantTimeCompare(a, b) != 1 {
		first.Wipe()
		return secret.Secret{}, ErrMismatch
	}
	return first, nil
}

func (n *native) Choose(q string, options []string, def int) (int, error) {
	if def < 0 || def >= len(options) {
		return 0, errors.New("prompt: default choice out of range")
	}
	r, st, err := n.ask(chooseDialog(q, options, def))
	if err != nil {
		return 0, err
	}
	if st != statusOK {
		return 0, ErrCancelled
	}
	defer clear(r.Stdout)
	i, ok := parseChoice(r.Stdout, len(options))
	if !ok {
		return 0, ErrCancelled
	}
	return i, nil
}

func (n *native) Confirm(q string) (bool, error) {
	_, st, err := n.ask(confirmDialog(q))
	if err != nil {
		if errors.Is(err, ErrCancelled) {
			return false, nil
		}
		return false, err
	}
	return st == statusOK, nil
}

// parseChoice reads the 1-based number a helper printed, at the start of its
// output, as a 0-based index into n options.
func parseChoice(out []byte, n int) (int, bool) {
	out = bytes.TrimSpace(out)
	end := 0
	for end < len(out) && out[end] >= '0' && out[end] <= '9' {
		end++
	}
	i, err := strconv.Atoi(string(out[:end]))
	if err != nil || i < 1 || i > n {
		return 0, false
	}
	return i - 1, true
}

// maxStderr bounds the helper stderr kept for classifying a failure.
const maxStderr = 4096

type capWriter struct{ b []byte }

func (w *capWriter) Write(p []byte) (int, error) {
	if room := maxStderr - len(w.b); room > 0 {
		w.b = append(w.b, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

// execRunner runs the helper as a child process. Its stdout is read into one
// buffer sized up front, so the value is never copied by a growing buffer; the
// rest of an oversized output is discarded.
func execRunner(ctx context.Context, c command) (result, error) {
	cmd := exec.CommandContext(ctx, c.Path, c.Args...)
	if len(c.Env) > 0 {
		cmd.Env = c.Env
	}
	cmd.Stdin = bytes.NewReader(c.Stdin)
	cmd.WaitDelay = 2 * time.Second
	detach(cmd)
	var errOut capWriter
	cmd.Stderr = &errOut
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return result{}, err
	}
	if err := cmd.Start(); err != nil {
		return result{}, err
	}
	buf := make([]byte, maxInput)
	n, _ := io.ReadFull(pipe, buf)
	over := n == len(buf)
	if over {
		_, _ = io.Copy(io.Discard, pipe)
	}
	werr := cmd.Wait()
	if ctx.Err() != nil {
		clear(buf)
		return result{}, ctx.Err()
	}
	if over {
		// Refuse rather than return a truncated value.
		clear(buf)
		return result{}, ErrTooLarge
	}
	res := result{Stdout: buf[:n], Stderr: errOut.b}
	var ee *exec.ExitError
	switch {
	case werr == nil:
	case errors.As(werr, &ee):
		res.Exit = ee.ExitCode()
	default:
		clear(buf)
		return result{}, werr
	}
	return res, nil
}
