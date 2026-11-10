//go:build e2eprompt

package prompt

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/qbitdevz/qbit-vault/internal/secret"
)

// The scripted backend is for the Docker e2e battery (docs/TESTING.md § Tier
// 2). It exists only in binaries built with -tags e2eprompt; a release build
// has no code for it (scripted_off.go), so QBIT_VAULT_PROMPT=scripted is an
// unknown backend there.
//
// Every answer comes from a file, one line per prompt, in the order asked.
// When the file has no unread line the backend waits for the driver to append
// one (the joining device needs the confirmation code another device shows
// after the join has started), up to EnvScriptedWait. Passphrases never come
// from that queue: they are the first line of EnvScriptedPassphrase, so the
// driver need not know how often a command unlocks the vault. What was asked
// and shown is appended to the transcript, never an answer.
const (
	// EnvScriptedAnswers names the file of answers, one per line.
	EnvScriptedAnswers = "QBIT_VAULT_SCRIPTED_ANSWERS"
	// EnvScriptedTranscript names the file asked and shown text is appended to.
	EnvScriptedTranscript = "QBIT_VAULT_SCRIPTED_TRANSCRIPT"
	// EnvScriptedPassphrase names the file whose first line is the passphrase.
	EnvScriptedPassphrase = "QBIT_VAULT_SCRIPTED_PASSPHRASE_FILE"
	// EnvScriptedWait is how long to wait for a missing answer (Go duration,
	// default 60s).
	EnvScriptedWait = "QBIT_VAULT_SCRIPTED_WAIT"
)

func testBackend(name string, e Env) (Backend, bool) {
	if name != "scripted" {
		return nil, false
	}
	return scripted{env: e}, true
}

type scripted struct {
	env Env
	ctx context.Context // a cancelled call stops waiting for an answer
}

// WithContext implements Contexter.
func (s scripted) WithContext(ctx context.Context) Backend {
	s.ctx = ctx
	return s
}

// consumed counts the answers this process has taken from the queue.
var consumed int

func (scripted) Name() string { return "scripted" }

func (s scripted) log(format string, a ...any) {
	path := s.env.Getenv(EnvScriptedTranscript)
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, format+"\n", a...)
}

// next returns the next unread answer line.
func (s scripted) next() (string, error) {
	path := s.env.Getenv(EnvScriptedAnswers)
	if path == "" {
		return "", ErrNoTerminal
	}
	wait := 60 * time.Second
	if v := s.env.Getenv(EnvScriptedWait); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			wait = d
		}
	}
	deadline := time.Now().Add(wait)
	for {
		if raw, err := os.ReadFile(path); err == nil {
			// Only complete lines count: the driver may be mid-append.
			if i := bytes.LastIndexByte(raw, '\n'); i >= 0 {
				lines := strings.Split(string(raw[:i]), "\n")
				if consumed < len(lines) {
					line := strings.TrimSuffix(lines[consumed], "\r")
					consumed++
					return line, nil
				}
			}
		}
		if time.Now().After(deadline) {
			s.log("EXHAUSTED")
			return "", ErrCancelled
		}
		select {
		case <-base(s.ctx).Done():
			return "", ErrCancelled
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (s scripted) Secret(req SecretRequest) (secret.Secret, error) {
	s.log("ASK secret name=%s visible=%t reason=%s", strconv.Quote(req.Name), req.Visible, strconv.Quote(req.Reason))
	line, err := s.next()
	if err != nil {
		return secret.Secret{}, err
	}
	return secret.New(req.Name, []byte(line)), nil
}

func (s scripted) Choose(q string, options []string, def int) (int, error) {
	s.log("ASK choose q=%s options=%s default=%d", strconv.Quote(q), strconv.Quote(strings.Join(options, "|")), def)
	line, err := s.next()
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || n < 1 || n > len(options) {
		return def, nil
	}
	return n - 1, nil
}

func (s scripted) Confirm(q string) (bool, error) {
	s.log("ASK confirm q=%s", strconv.Quote(q))
	line, err := s.next()
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	}
	return false, nil
}

func (s scripted) Passphrase(req PassphraseRequest) (secret.Secret, error) {
	s.log("ASK passphrase confirm=%t label=%s", req.Confirm, strconv.Quote(req.Label))
	raw, err := os.ReadFile(s.env.Getenv(EnvScriptedPassphrase))
	if err != nil {
		return secret.Secret{}, ErrNoTerminal
	}
	defer clear(raw)
	line, _, _ := bytes.Cut(raw, []byte("\n"))
	return secret.New("passphrase", bytes.TrimSuffix(line, []byte("\r"))), nil
}

// Show implements Shower: the text is written to the transcript, one line
// per text line, so the driver can read the recovery key and confirmation code.
func (s scripted) Show(title, text string) error {
	s.log("SHOW %s", title)
	for _, l := range strings.Split(text, "\n") {
		s.log("| %s", l)
	}
	s.log("END")
	return nil
}
