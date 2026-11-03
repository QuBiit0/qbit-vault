// Package prompttest holds prompt backends for tests: a scripted Fake and a
// Stream that plays the terminal over a reader and a writer. Neither touches
// a real terminal.
package prompttest

import (
	"context"
	"errors"
	"io"

	"github.com/QuBiit0/gentle-vault/internal/prompt"
	"github.com/QuBiit0/gentle-vault/internal/secret"
)

// Answer is one scripted reply. A Fake method uses the field it needs.
type Answer struct {
	Value string // Secret and Passphrase
	Index int    // Choose
	Yes   bool   // Confirm
	Err   error  // fails the call instead
}

// Call records one prompt the Fake was asked, never an answer.
type Call struct {
	Kind    string // secret, choose, confirm or passphrase
	Request prompt.SecretRequest
	Q       string
	Options []string
	Default int
	Confirm bool // Passphrase: asked twice
}

// ErrScriptExhausted is returned when the Fake is asked more than scripted.
var ErrScriptExhausted = errors.New("prompttest: script exhausted")

// Fake answers from Script, in order, and records the Calls. When
// Unavailable is set every call fails with prompt.ErrUnavailable.
type Fake struct {
	Script      []Answer
	Calls       []Call
	Unavailable bool
}

// Name implements prompt.Backend.
func (*Fake) Name() string { return "fake" }

func (f *Fake) pop(c Call) (Answer, error) {
	f.Calls = append(f.Calls, c)
	if f.Unavailable {
		return Answer{}, prompt.ErrNoTerminal
	}
	if len(f.Script) == 0 {
		return Answer{}, ErrScriptExhausted
	}
	a := f.Script[0]
	f.Script = f.Script[1:]
	return a, a.Err
}

// Secret implements prompt.Backend.
func (f *Fake) Secret(req prompt.SecretRequest) (secret.Secret, error) {
	a, err := f.pop(Call{Kind: "secret", Request: req})
	if err != nil {
		return secret.Secret{}, err
	}
	return secret.New(req.Name, []byte(a.Value)), nil
}

// Choose implements prompt.Backend.
func (f *Fake) Choose(q string, options []string, def int) (int, error) {
	a, err := f.pop(Call{Kind: "choose", Q: q, Options: append([]string(nil), options...), Default: def})
	if err != nil {
		return 0, err
	}
	return a.Index, nil
}

// Confirm implements prompt.Backend.
func (f *Fake) Confirm(q string) (bool, error) {
	a, err := f.pop(Call{Kind: "confirm", Q: q})
	return a.Yes, err
}

// Passphrase implements prompt.Backend.
func (f *Fake) Passphrase(confirm bool) (secret.Secret, error) {
	a, err := f.pop(Call{Kind: "passphrase", Confirm: confirm})
	if err != nil {
		return secret.Secret{}, err
	}
	return secret.New("passphrase", []byte(a.Value)), nil
}

// Stream is the real terminal backend over in and out: the prompts are
// written to out and the answers read line by line from in, hidden ones
// included (nothing is echoed to out either way). For tests that script a
// whole conversation as text.
func Stream(in io.Reader, out io.Writer) prompt.Backend {
	return prompt.New(func() (prompt.Terminal, error) { return &stream{in: in, out: out}, nil })
}

type stream struct {
	in  io.Reader
	out io.Writer
}

func (s *stream) Write(p []byte) (int, error) { return s.out.Write(p) }
func (*stream) Close() error                  { return nil }

func (s *stream) ReadLine(context.Context) ([]byte, error) {
	var buf []byte
	var one [1]byte
	for {
		n, err := s.in.Read(one[:])
		if n == 1 {
			if one[0] == '\n' {
				if l := len(buf); l > 0 && buf[l-1] == '\r' {
					buf = buf[:l-1]
				}
				return buf, nil
			}
			buf = append(buf, one[0])
			continue
		}
		if err != nil {
			if err == io.EOF && len(buf) > 0 {
				return buf, nil
			}
			return nil, err
		}
	}
}

func (s *stream) ReadHidden(ctx context.Context) ([]byte, error) { return s.ReadLine(ctx) }
