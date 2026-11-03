// Package prompt asks the user for secret values, passphrases and
// confirmations out of band: from the controlling terminal, never from the
// process stdin or the model's output (docs/PRD.md § 5.2, odd/tasks/tty-prompt.md).
//
// A value is read as bytes with echo off and handed back as a secret.Secret;
// nothing the user types is ever written back to the terminal.
package prompt

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/QuBiit0/gentle-vault/internal/secret"
)

// EnvBackend is the environment variable that forces a prompt backend.
const EnvBackend = "GENTLE_VAULT_PROMPT"

var (
	// ErrCancelled means the user gave up (Ctrl-C, end of input).
	ErrCancelled = errors.New("cancelled")
	// ErrUnavailable means the backend cannot ask: there is no controlling
	// terminal, or the backend does not exist in this release.
	ErrUnavailable = errors.New("prompt backend unavailable")
	// ErrMismatch means the two passphrase entries differ.
	ErrMismatch = errors.New("passphrases do not match")
	// ErrUnknownBackend means GENTLE_VAULT_PROMPT names no backend.
	ErrUnknownBackend = errors.New("unknown prompt backend")
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
	// Passphrase reads a masked passphrase, twice when confirm is true.
	Passphrase(confirm bool) (secret.Secret, error)
}

// Terminal is the seam under the tty backend: a console with an echoed line
// read and a hidden one. Reads return io.EOF at the end of input and
// ErrCancelled on Ctrl-C; the line terminator is not part of the result.
type Terminal interface {
	io.Writer
	ReadLine() ([]byte, error)
	ReadHidden() ([]byte, error)
	Close() error
}

// Select picks the backend named by GENTLE_VAULT_PROMPT: the terminal one
// when it is unset or `tty`. The native dialogs arrive with slice 1.10.
func Select(getenv func(string) string) (Backend, error) {
	switch name := getenv(EnvBackend); name {
	case "", "tty":
		return New(openConsole), nil
	case "osascript", "powershell", "zenity", "kdialog":
		return nil, unavailableError{"prompt backend " + name + " arrives in a later release"}
	default:
		return nil, fmt.Errorf("%w: %s=%q", ErrUnknownBackend, EnvBackend, name)
	}
}

// New builds the terminal backend over open, which is called for every
// prompt and whose terminal is closed when the prompt ends.
func New(open func() (Terminal, error)) Backend { return &tty{open: open} }

type tty struct {
	open func() (Terminal, error)
}

func (*tty) Name() string { return "tty" }

// with opens the terminal for one prompt.
func (b *tty) with(fn func(Terminal) error) error {
	t, err := b.open()
	if err != nil {
		if errors.Is(err, ErrUnavailable) {
			return err
		}
		return ErrNoTerminal
	}
	defer t.Close()
	return fn(t)
}

// readErr maps a terminal read failure.
func readErr(err error) error {
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, ErrCancelled):
		return ErrCancelled
	default:
		return unavailableError{"cannot read from the terminal"}
	}
}

func (b *tty) Secret(req SecretRequest) (secret.Secret, error) {
	var out secret.Secret
	err := b.with(func(t Terminal) error {
		_, _ = io.WriteString(t, Header(req))
		_, _ = io.WriteString(t, "Value (input is hidden): ")
		raw, err := t.ReadHidden()
		if err != nil {
			return readErr(err)
		}
		defer clear(raw)
		out = secret.New(req.Name, bytes.TrimSpace(raw))
		return nil
	})
	return out, err
}

func (b *tty) Passphrase(confirm bool) (secret.Secret, error) {
	var out secret.Secret
	err := b.with(func(t Terminal) error {
		_, _ = io.WriteString(t, "Passphrase (input is hidden): ")
		first, err := t.ReadHidden()
		if err != nil {
			return readErr(err)
		}
		defer clear(first)
		if confirm {
			_, _ = io.WriteString(t, "Confirm passphrase: ")
			second, err := t.ReadHidden()
			if err != nil {
				return readErr(err)
			}
			defer clear(second)
			if subtle.ConstantTimeCompare(first, second) != 1 {
				_, _ = io.WriteString(t, "Passphrases do not match.\n")
				return ErrMismatch
			}
		}
		out = secret.New("passphrase", first)
		return nil
	})
	return out, err
}

// maxChoiceTries bounds how many invalid menu answers are tolerated.
const maxChoiceTries = 5

func (b *tty) Choose(q string, options []string, def int) (int, error) {
	if def < 0 || def >= len(options) {
		return 0, errors.New("prompt: default choice out of range")
	}
	chosen := 0
	err := b.with(func(t Terminal) error {
		var m strings.Builder
		m.WriteString(escape(q) + "\n")
		for i, o := range options {
			fmt.Fprintf(&m, "  %d) %s\n", i+1, escape(o))
		}
		_, _ = io.WriteString(t, m.String())
		for range maxChoiceTries {
			fmt.Fprintf(t, "Choice [%d]: ", def+1)
			line, err := t.ReadLine()
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
			_, _ = io.WriteString(t, "invalid choice\n")
		}
		return ErrCancelled
	})
	return chosen, err
}

func (b *tty) Confirm(q string) (bool, error) {
	yes := false
	err := b.with(func(t Terminal) error {
		_, _ = io.WriteString(t, escape(q)+" [y/N] ")
		line, err := t.ReadLine()
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

// Header renders what the capture prompt shows before the input: the name,
// the requester's reason, who asks, the layer and whether the value is new.
// Every piece of text is escaped, so a reason cannot paint over the terminal
// or add a line of its own (R4).
func Header(req SecretRequest) string {
	orDash := func(s string) string {
		if s == "" {
			return "-"
		}
		return escape(s)
	}
	layer, value := "global", "new"
	if req.Project != "" {
		layer = "project " + escape(req.Project)
	}
	if req.Existing {
		value = "already stored (it will be replaced)"
	}
	var b strings.Builder
	b.WriteString("gentle-vault: secret capture\n")
	fmt.Fprintf(&b, "  name:    %s\n", escape(req.Name))
	fmt.Fprintf(&b, "  reason:  %s\n", escape(req.Reason))
	fmt.Fprintf(&b, "  from:    host %s, session %s\n", orDash(req.Host), orDash(req.Session))
	fmt.Fprintf(&b, "  layer:   %s\n", layer)
	fmt.Fprintf(&b, "  value:   %s\n", value)
	return b.String()
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
