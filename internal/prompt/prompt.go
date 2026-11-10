// Package prompt asks the user for secret values, passphrases and
// confirmations out of band: from the controlling terminal, never from the
// process stdin or the model's output (docs/PRD.md § 5.2, odd/tasks/tty-prompt.md).
//
// A value is read as bytes with echo off and handed back as a secret.Secret;
// nothing the user types is ever written back to the terminal.
package prompt

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/qbitdevz/qbit-vault/internal/secret"
)

// EnvBackend is the environment variable that forces a prompt backend.
const EnvBackend = "QBIT_VAULT_PROMPT"

// EnvTimeout sets how long a prompt waits for the user, as a Go duration.
const EnvTimeout = "QBIT_VAULT_PROMPT_TIMEOUT"

// The prompt timeout when EnvTimeout is unset, and its bounds.
const (
	DefaultTimeout = 5 * time.Minute
	MinTimeout     = 10 * time.Second
	MaxTimeout     = time.Hour
)

var (
	// ErrCancelled means the user gave up (Ctrl-C, end of input).
	ErrCancelled = errors.New("cancelled")
	// ErrUnavailable means the backend cannot ask: there is no controlling
	// terminal, or the native helper is missing or failed.
	ErrUnavailable = errors.New("prompt backend unavailable")
	// ErrMismatch means the two passphrase entries differ.
	ErrMismatch = errors.New("passphrases do not match")
	// ErrUnknownBackend means QBIT_VAULT_PROMPT names no backend.
	ErrUnknownBackend = errors.New("unknown prompt backend")
	// ErrTimeout means the user did not answer in time.
	ErrTimeout = errors.New("No answer in time; nothing was saved.")
	// ErrBadTimeout means QBIT_VAULT_PROMPT_TIMEOUT is not a duration in bounds.
	ErrBadTimeout = errors.New("invalid prompt timeout")
	// ErrTrailingInput means more input followed Enter in a hidden read, as
	// with a multi-line paste. The extra text is discarded, not left for the
	// next program on the terminal.
	ErrTrailingInput = errors.New("the input continued after Enter; paste a single line, or use --stdin for multi-line values")
	// ErrTooLarge means the input exceeded the read bound; it is refused and
	// wiped, never truncated.
	ErrTooLarge = errors.New("the value is too large (over 64 KiB)")
)

// unavailableError is an ErrUnavailable with its own message.
type unavailableError struct{ msg string }

func (e unavailableError) Error() string        { return e.msg }
func (e unavailableError) Is(target error) bool { return target == ErrUnavailable }

// ErrNoTerminal is the ErrUnavailable of a process without a controlling
// terminal.
var ErrNoTerminal = unavailableError{"no controlling terminal available"}

// SecretRequest is what the capture prompt shows next to the input (R-CAP-02).
type SecretRequest struct {
	Name    string
	Reason  string // verbatim from the requester; escaped when shown
	Host    string
	Session string
	Project string // project label, "" for the global layer
	// Existing reports that a value is already stored under Name.
	Existing bool
	// Label names the field in a capture of several (default the name).
	Label string
	// Visible is a text field (R-CAP-09): shown while typed, not masked.
	Visible bool
	// Field and Fields place this box in a capture of several: "Field of
	// Fields". Fields <= 1 is a single capture.
	Field, Fields int
	// Description is the requester's description of the field (escaped
	// when shown).
	Description string
	// Stored names the other fields of the request that are already stored
	// and get no box (R-CAP-08).
	Stored []string
	// Heading turns the request into a plain question (the joiner's
	// confirmation code): the heading and Reason, none of the request lines
	// of a capture.
	Heading string
}

// PassphraseRequest says what a passphrase prompt protects, so the user does
// not type the wrong secret.
type PassphraseRequest struct {
	// Heading names the dialog (default Label).
	Heading string
	// Label is the question of the first entry.
	Label string
	// Again is the question of the second entry, when Confirm is set.
	Again string
	// Confirm asks twice and refuses two different entries.
	Confirm bool
}

// The passphrases qbit-vault asks for.
var (
	// VaultPassphrase unlocks or creates the vault key (passphrase mode).
	VaultPassphrase = PassphraseRequest{Heading: "Vault passphrase", Label: "Vault passphrase", Again: "Type the passphrase again"}
	// ExportPassphrase protects an export file; ask it Twice.
	ExportPassphrase = PassphraseRequest{Heading: "Export passphrase", Label: "Export passphrase (protects this backup file)", Again: "Type the export passphrase again"}
	// ImportPassphrase opens an export file.
	ImportPassphrase = PassphraseRequest{Heading: "Export passphrase", Label: "Passphrase of the export file"}
)

// Twice is r asked twice.
func (r PassphraseRequest) Twice() PassphraseRequest {
	r.Confirm = true
	return r
}

// again is the question of the second entry.
func (r PassphraseRequest) again() string {
	if r.Again != "" {
		return r.Again
	}
	return "Type the passphrase again"
}

// heading is the title line of a passphrase dialog.
func (r PassphraseRequest) heading() string {
	if r.Heading != "" {
		return r.Heading
	}
	return r.Label
}

// Backend asks the user. Every method blocks until the user answers.
type Backend interface {
	Name() string
	// Secret reads a masked value. The caller wipes it.
	Secret(req SecretRequest) (secret.Secret, error)
	// Choose shows a numbered menu and returns the chosen index; def is the
	// index taken on an empty answer.
	Choose(q string, options []string, def int) (int, error)
	// Confirm asks a yes/no question; only y or yes answers true.
	Confirm(q string) (bool, error)
	// Passphrase reads a masked passphrase, twice when req.Confirm is set.
	Passphrase(req PassphraseRequest) (secret.Secret, error)
}

// Terminal is the seam under the tty backend: a console with an echoed line
// read and a hidden one. Reads return io.EOF at the end of input, ErrCancelled
// on Ctrl-C and ctx.Err() when ctx ends first (the terminal must be left as it
// was found); a hidden read that was followed by more input returns
// ErrTrailingInput. The line terminator is not part of the result.
type Terminal interface {
	io.Writer
	ReadLine(ctx context.Context) ([]byte, error)
	ReadHidden(ctx context.Context) ([]byte, error)
	Close() error
}

// Select picks the backend for this machine: QBIT_VAULT_PROMPT when it is
// set, else the platform's native dialog when a desktop session is available,
// else the terminal (L2). The wait is bounded by QBIT_VAULT_PROMPT_TIMEOUT.
func Select(getenv func(string) string) (Backend, error) {
	return SelectWith(Env{GOOS: runtime.GOOS, Getenv: getenv, LookPath: exec.LookPath, Interactive: interactiveSession, SystemRoot: systemRoot})
}

// SelectWith is Select over an Env, for tests.
func SelectWith(e Env) (Backend, error) {
	timeout := DefaultTimeout
	if v := e.Getenv(EnvTimeout); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < MinTimeout || d > MaxTimeout {
			return nil, fmt.Errorf("%w: %s must be a duration between %s and %s", ErrBadTimeout, EnvTimeout, MinTimeout, MaxTimeout)
		}
		timeout = d
	}
	run := e.run
	if run == nil {
		run = execRunner
	}
	switch name := e.Getenv(EnvBackend); name {
	case "":
		if t, path := nativeFor(e); t != nil {
			return newNative(t, path, run, timeout), nil
		}
		return New(openConsole, Timeout(timeout)), nil
	case "tty":
		return New(openConsole, Timeout(timeout)), nil
	case "osascript", "powershell", "zenity", "kdialog":
		t := toolByName(name)
		path, err := forced(e, t)
		if err != nil {
			return nil, err
		}
		return newNative(t, path, run, timeout), nil
	default:
		if b, ok := testBackend(name, e); ok {
			return b, nil
		}
		return nil, fmt.Errorf("%w: %s=%q; use tty, osascript, powershell, zenity or kdialog", ErrUnknownBackend, EnvBackend, name)
	}
}

// Describe names the backend Select would pick, for `doctor`: the backend
// name, with " (WSL)" for the Windows dialog reached from Linux. It starts
// no helper and shows nothing. A backend named by QBIT_VAULT_PROMPT that
// cannot run is an error, as it is for any command.
func Describe(getenv func(string) string) (string, error) {
	return describeWith(Env{GOOS: runtime.GOOS, Getenv: getenv, LookPath: exec.LookPath, Interactive: interactiveSession, SystemRoot: systemRoot})
}

func describeWith(e Env) (string, error) {
	b, err := SelectWith(e)
	if err != nil {
		return "", err
	}
	if n, ok := b.(*native); ok && e.GOOS == "linux" && n.t.name() == "powershell" {
		return n.t.name() + " (WSL)", nil
	}
	return b.Name(), nil
}

// New builds the terminal backend over open, which is called for every
// prompt and whose terminal is closed when the prompt ends.
func New(open func() (Terminal, error), opts ...Option) Backend {
	b := &tty{open: open, timeout: DefaultTimeout}
	for _, o := range opts {
		o(b)
	}
	return b
}

// Option configures New.
type Option func(*tty)

// Timeout bounds how long one prompt waits for the user (DefaultTimeout).
func Timeout(d time.Duration) Option { return func(b *tty) { b.timeout = d } }

type tty struct {
	open    func() (Terminal, error)
	timeout time.Duration
	ctx     context.Context // ends every prompt with it; nil is never
}

// WithContext implements Contexter.
func (b *tty) WithContext(ctx context.Context) Backend {
	c := *b
	c.ctx = ctx
	return &c
}

func (*tty) Name() string { return "tty" }

// with opens the terminal for one prompt.
func (b *tty) with(fn func(context.Context, Terminal) error) error {
	t, err := b.open()
	if err != nil {
		if errors.Is(err, ErrUnavailable) {
			return err
		}
		return ErrNoTerminal
	}
	defer t.Close()
	ctx, cancel := context.WithTimeout(base(b.ctx), b.timeout)
	defer cancel()
	return fn(ctx, t)
}

// readErr maps a terminal read failure.
func readErr(err error) error {
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, ErrCancelled), errors.Is(err, context.Canceled):
		return ErrCancelled
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, ErrTimeout):
		return ErrTimeout
	case errors.Is(err, ErrTrailingInput):
		return ErrTrailingInput
	default:
		return unavailableError{"cannot read from the terminal"}
	}
}

func (b *tty) Secret(req SecretRequest) (secret.Secret, error) {
	var out secret.Secret
	err := b.with(func(ctx context.Context, t Terminal) error {
		label := "Value"
		if req.Heading != "" {
			_, _ = io.WriteString(t, "QBit Vault: "+escape(req.Heading)+"\n  "+escape(req.Reason)+"\n")
			label = "Answer"
		} else {
			_, _ = io.WriteString(t, Header(req))
		}
		read := t.ReadHidden
		if req.Visible {
			_, _ = io.WriteString(t, label+" (shown while you type): ")
			read = t.ReadLine
		} else {
			_, _ = io.WriteString(t, label+" (hidden): ")
		}
		raw, err := read(ctx)
		if err != nil {
			return readErr(err)
		}
		defer clear(raw)
		out = secret.New(req.Name, normalize(raw, valueInput))
		return nil
	})
	return out, err
}

func (b *tty) Passphrase(req PassphraseRequest) (secret.Secret, error) {
	var out secret.Secret
	err := b.with(func(ctx context.Context, t Terminal) error {
		for try := 1; ; try++ {
			_, _ = io.WriteString(t, req.Label+": ")
			first, err := t.ReadHidden(ctx)
			if err != nil {
				return readErr(err)
			}
			defer clear(first)
			if !req.Confirm {
				out = secret.New("passphrase", first)
				return nil
			}
			_, _ = io.WriteString(t, req.again()+": ")
			second, err := t.ReadHidden(ctx)
			if err != nil {
				return readErr(err)
			}
			defer clear(second)
			if subtle.ConstantTimeCompare(first, second) == 1 {
				out = secret.New("passphrase", first)
				return nil
			}
			_, _ = io.WriteString(t, mismatchText+"\n")
			if try == maxPassphraseTries {
				return ErrMismatch
			}
		}
	})
	return out, err
}

// maxPassphraseTries bounds how many times a new passphrase is asked twice
// when the two entries differ; the last mismatch is ErrMismatch.
const maxPassphraseTries = 3

// mismatchText is what the user is told when the two entries differ.
const mismatchText = "Passphrases do not match."

// maxChoiceTries bounds how many invalid menu answers are tolerated.
const maxChoiceTries = 5

func (b *tty) Choose(q string, options []string, def int) (int, error) {
	if def < 0 || def >= len(options) {
		return 0, errors.New("prompt: default choice out of range")
	}
	chosen := 0
	err := b.with(func(ctx context.Context, t Terminal) error {
		var m strings.Builder
		m.WriteString(escapeLines(q) + "\n")
		for i, o := range options {
			fmt.Fprintf(&m, "  %d) %s\n", i+1, escape(o))
		}
		_, _ = io.WriteString(t, m.String())
		for range maxChoiceTries {
			fmt.Fprintf(t, "Choice [%d]: ", def+1)
			line, err := t.ReadLine(ctx)
			if err != nil {
				return readErr(err)
			}
			s := strings.TrimSpace(string(line))
			if s == "" {
				chosen = def
				return nil
			}
			if n, err := strconv.Atoi(s); err == nil && n >= 1 && n <= len(options) {
				chosen = n - 1
				return nil
			}
			fmt.Fprintf(t, "Type a number from 1 to %d, or press Enter for the default.\n", len(options))
		}
		return ErrCancelled
	})
	return chosen, err
}

func (b *tty) Confirm(q string) (bool, error) {
	yes := false
	err := b.with(func(ctx context.Context, t Terminal) error {
		_, _ = io.WriteString(t, escapeLines(q)+" [y/N] ")
		line, err := t.ReadLine(ctx)
		if err != nil {
			return readErr(err)
		}
		switch strings.ToLower(strings.TrimSpace(string(line))) {
		case "y", "yes":
			yes = true
		}
		return nil
	})
	return yes, err
}

// headerRow is one line of the request: a label and its text.
type headerRow struct{ label, value string }

// headerRows are the lines of a capture request, every text escaped. The
// terminal prints them as text and the Windows dialog lays them out as a
// grid. withValue adds whether the value is new or replaces the saved one.
func headerRows(req SecretRequest, withValue bool) []headerRow {
	saved := "all projects"
	if req.Project != "" {
		saved = "project " + escape(req.Project)
	}
	rows := []headerRow{
		{"Who", Requester(req.Host, req.Session)},
		{"Secret", escape(req.Name)},
		{"Why", escape(req.Reason)},
		{"Saved in", saved},
	}
	if req.Description != "" {
		rows = append(rows, headerRow{"About", escape(req.Description)})
	}
	if len(req.Stored) > 0 {
		names := make([]string, len(req.Stored))
		for i, n := range req.Stored {
			names[i] = escape(n)
		}
		rows = append(rows, headerRow{"Already saved", strings.Join(names, ", ") + " (not asked again)"})
	}
	if req.Fields > 1 {
		label := req.Label
		if label == "" {
			label = req.Name
		}
		rows = append(rows, headerRow{"Field", fmt.Sprintf("%d of %d (%s)", req.Field, req.Fields, escape(label))})
	}
	if withValue {
		value := "new"
		if req.Existing {
			value = "replaces the saved value"
		}
		rows = append(rows, headerRow{"Value", value})
	}
	return rows
}

// rowsText prints rows one per line, the values in a column.
func rowsText(rows []headerRow) string {
	var b strings.Builder
	for _, r := range rows {
		l := r.label + ":"
		if len(l) < 10 {
			l += strings.Repeat(" ", 10-len(l))
		} else {
			l += " "
		}
		b.WriteString("  " + l + r.value + "\n")
	}
	return b.String()
}

// Header renders what the capture prompt shows before the input, in plain
// words: who asks, the secret, why, where it is saved and whether the value
// is new. Every piece of text is escaped, so a reason cannot paint over the
// terminal or add a line of its own (R4).
func Header(req SecretRequest) string {
	return "QBit Vault: secret request\n" + rowsText(headerRows(req, true))
}

// Requester names who is asking, for a person: the agent by its product name
// and the first characters of the session, enough to match the audit log.
func Requester(host, session string) string {
	var who string
	switch host {
	case "":
		who = "an agent"
	case "claude", "claude-code":
		who = "Claude Code"
	case "codex":
		who = "Codex"
	case "pi":
		who = "Pi"
	case "mcp":
		who = "your agent"
	case "cli":
		return "you (qbit-vault)"
	default:
		who = escape(host)
	}
	_, id, found := strings.Cut(session, ":")
	if !found {
		id = session
	}
	if id == "" {
		return who
	}
	if r := []rune(id); len(r) > 8 {
		id = string(r[:8])
	}
	return who + " (session " + escape(id) + ")"
}

// Escape makes s safe to put in a question or dialog text: control
// characters, bidi overrides and invalid UTF-8 become visible escapes, and no
// line break is left, so text taken from an agent (its reason) stays on its
// own line.
func Escape(s string) string { return escape(s) }

// escapeLines escapes each line of s and keeps the line breaks: a question is
// laid out by its caller (who wants what, then the reason), and what the
// caller took from an agent was already made one line with Escape.
func escapeLines(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = escape(l)
	}
	return strings.Join(lines, "\n")
}

// escape makes s safe to print on one terminal line: control characters,
// format characters (bidi overrides) and invalid UTF-8 become visible
// escapes.
func escape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && n == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case unicode.IsControl(r) && r < 0x100:
			fmt.Fprintf(&b, `\x%02x`, r)
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), unicode.Is(unicode.Zl, r), unicode.Is(unicode.Zp, r):
			if r > 0xffff {
				fmt.Fprintf(&b, `\U%08x`, r)
			} else {
				fmt.Fprintf(&b, `\u%04x`, r)
			}
		default:
			b.WriteRune(r)
		}
		i += n
	}
	return b.String()
}
