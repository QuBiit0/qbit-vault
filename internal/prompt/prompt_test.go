package prompt

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const (
	fxValue = "TESTSECRET_prompt_value_0123456789"
	fxPass  = "TESTSECRET_prompt_pass_0123456789"
	ctrlC   = "\x03" // scripted line: the user pressed Ctrl-C
)

// memTerm is a scripted terminal: each read consumes one line.
type memTerm struct {
	lines  []string
	block  bool   // with no lines left, block until the prompt deadline
	trail  bool   // the next hidden read reports input after Enter
	hidden []bool // for every read, whether it was a hidden one
	out    bytes.Buffer
	closed bool
}

func (m *memTerm) Write(p []byte) (int, error) { return m.out.Write(p) }
func (m *memTerm) Close() error                { m.closed = true; return nil }

func (m *memTerm) next(ctx context.Context, hidden bool) ([]byte, error) {
	m.hidden = append(m.hidden, hidden)
	if hidden && m.trail {
		return nil, ErrTrailingInput
	}
	if len(m.lines) == 0 {
		if m.block {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return nil, io.EOF
	}
	l := m.lines[0]
	m.lines = m.lines[1:]
	if l == ctrlC {
		return nil, ErrCancelled
	}
	return []byte(l), nil
}

func (m *memTerm) ReadLine(ctx context.Context) ([]byte, error)   { return m.next(ctx, false) }
func (m *memTerm) ReadHidden(ctx context.Context) ([]byte, error) { return m.next(ctx, true) }

func backendOf(lines ...string) (Backend, *memTerm) {
	t := &memTerm{lines: lines}
	return New(func() (Terminal, error) { return t, nil }), t
}

var req = SecretRequest{
	Name: "GITHUB_TOKEN", Reason: "run the release", Host: "claude-code",
	Session: "claude-code:sess-aaaa", Project: "shop-api",
}

func TestHeaderContent(t *testing.T) {
	tests := []struct {
		name string
		req  SecretRequest
		want []string
	}{
		{"project new", req, []string{"QBit Vault: secret request\n", "  Who:      Claude Code (session sess-aaa)\n", "  Secret:   GITHUB_TOKEN\n", "  Why:      run the release\n", "  Saved in: project shop-api\n", "  Value:    new\n"}},
		{"global stored", SecretRequest{Name: "A_KEY", Reason: "r", Host: "pi", Session: "pi:s-1234", Existing: true}, []string{"  Who:      Pi (session s-1234)\n", "  Saved in: all projects\n", "  Value:    replaces the saved value\n"}},
		{"no host or session", SecretRequest{Name: "A_KEY", Reason: "r"}, []string{"  Who:      an agent\n", "  Saved in: all projects\n"}},
		{"cli", SecretRequest{Name: "A_KEY", Reason: "r", Host: "cli", Session: "cli:abcdefghij"}, []string{"  Who:      you (qbit-vault)\n"}},
		{"mcp", SecretRequest{Name: "A_KEY", Reason: "r", Host: "mcp", Session: "mcp:1d54cd6db0bd3631"}, []string{"  Who:      your agent (session 1d54cd6d)\n"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := Header(tt.req)
			for _, w := range tt.want {
				if !strings.Contains(h, w) {
					t.Errorf("header lacks %q:\n%s", w, h)
				}
			}
		})
	}
	if strings.Contains(Header(req), "global") {
		t.Error("a project request must not say global")
	}
	if strings.Contains(Header(req), "replaces") {
		t.Error("a new value must not say it replaces one")
	}
	if strings.Contains(Header(req), "claude-code:") {
		t.Error("the raw session id is internal: only its short form is shown")
	}
}

func TestHeaderEscapesReason(t *testing.T) {
	bad := SecretRequest{
		Name:    "A_KEY",
		Reason:  "ok\x1b[2J\x1b]0;pwned\x07\nName:    FAKE_NAME\r\u202e\u0085",
		Host:    "h\x1b[31m",
		Session: "s\nfake",
		Project: "p\x1b",
	}
	h := Header(bad)
	for _, forbidden := range []string{"\x1b", "\x07", "\r", "\u202e", "\u0085"} {
		if strings.Contains(h, forbidden) {
			t.Errorf("header contains raw %q", forbidden)
		}
	}
	for _, want := range []string{`\x1b[2J`, `\n`, `\r`, `\u202e`} {
		if !strings.Contains(h, want) {
			t.Errorf("header lacks escaped %q:\n%s", want, h)
		}
	}
	// The reason cannot add a line: the header has exactly its own lines.
	good := strings.Count(Header(req), "\n")
	if got := strings.Count(h, "\n"); got != good {
		t.Errorf("header has %d lines, want %d:\n%s", got, good, h)
	}
}

func TestSecretTrimsAndNeverEchoes(t *testing.T) {
	b, term := backendOf("  " + fxValue + " \t")
	got, err := b.Secret(req)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	v := got.Reveal()
	if string(v) != fxValue {
		t.Errorf("value not trimmed to the typed bytes (len %d)", len(v))
	}
	if strings.Contains(term.out.String(), "TESTSECRET_") {
		t.Error("the value reached the terminal writer")
	}
	if len(term.hidden) != 1 || !term.hidden[0] {
		t.Errorf("the value must be read with echo off, reads = %v", term.hidden)
	}
	if !strings.Contains(term.out.String(), "GITHUB_TOKEN") || !strings.Contains(term.out.String(), "run the release") {
		t.Error("the header was not shown")
	}
	if !term.closed {
		t.Error("terminal not closed")
	}
	if got.Name() != "GITHUB_TOKEN" {
		t.Errorf("secret name = %q", got.Name())
	}
}

func TestSecretBlankIsEmpty(t *testing.T) {
	for _, in := range []string{"", "   ", "\t "} {
		b, _ := backendOf(in)
		got, err := b.Secret(req)
		if err != nil || got.Len() != 0 {
			t.Errorf("%q: len=%d err=%v, want an empty secret", in, got.Len(), err)
		}
	}
}

func TestSecretCancel(t *testing.T) {
	for name, lines := range map[string][]string{"ctrl-c": {ctrlC}, "eof": nil} {
		t.Run(name, func(t *testing.T) {
			b, term := backendOf(lines...)
			got, err := b.Secret(req)
			if !errors.Is(err, ErrCancelled) || got.Len() != 0 {
				t.Fatalf("err = %v, len = %d", err, got.Len())
			}
			if !term.closed {
				t.Error("terminal not closed")
			}
		})
	}
}

func TestPassphrase(t *testing.T) {
	t.Run("confirm matches", func(t *testing.T) {
		b, term := backendOf(fxPass, fxPass)
		got, err := b.Passphrase(VaultPassphrase.Twice())
		if err != nil || string(got.Reveal()) != fxPass {
			t.Fatalf("err = %v", err)
		}
		if len(term.hidden) != 2 || !term.hidden[0] || !term.hidden[1] {
			t.Errorf("reads = %v, want two hidden", term.hidden)
		}
		if strings.Contains(term.out.String(), "TESTSECRET_") {
			t.Error("the passphrase reached the terminal writer")
		}
	})
	t.Run("mismatch", func(t *testing.T) {
		b, term := backendOf(fxPass, fxPass+"x", fxPass, fxPass+"x", fxPass, fxPass+"x")
		got, err := b.Passphrase(VaultPassphrase.Twice())
		if !errors.Is(err, ErrMismatch) || got.Len() != 0 {
			t.Fatalf("err = %v, len = %d", err, got.Len())
		}
		if strings.Contains(term.out.String(), "TESTSECRET_") {
			t.Error("the passphrase reached the terminal writer")
		}
	})
	t.Run("asked once without confirm", func(t *testing.T) {
		b, term := backendOf(fxPass)
		got, err := b.Passphrase(VaultPassphrase)
		if err != nil || string(got.Reveal()) != fxPass || len(term.hidden) != 1 {
			t.Fatalf("err = %v, reads = %v", err, term.hidden)
		}
	})
	t.Run("cancel at either question", func(t *testing.T) {
		for _, lines := range [][]string{{ctrlC}, {fxPass, ctrlC}, {fxPass}} {
			b, _ := backendOf(lines...)
			if _, err := b.Passphrase(VaultPassphrase.Twice()); !errors.Is(err, ErrCancelled) {
				t.Errorf("%d lines: err = %v", len(lines), err)
			}
		}
	})
	t.Run("surrounding space is kept", func(t *testing.T) {
		b, _ := backendOf(" a b ")
		got, err := b.Passphrase(VaultPassphrase)
		if err != nil || string(got.Reveal()) != " a b " {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestChoose(t *testing.T) {
	opts := []string{"global", "this project (shop-api)"}
	tests := []struct {
		name    string
		lines   []string
		def     int
		want    int
		err     error
		invalid bool // the "Type a number" message is expected
	}{
		{"empty takes the default", []string{""}, 0, 0, nil, false},
		{"empty takes another default", []string{"  "}, 1, 1, nil, false},
		{"number", []string{"2"}, 0, 1, nil, false},
		{"number with spaces", []string{" 1 "}, 1, 0, nil, false},
		{"out of range then valid", []string{"3", "2"}, 0, 1, nil, true},
		{"zero then text then valid", []string{"0", "abc", "1"}, 1, 0, nil, true},
		{"eof", nil, 0, 0, ErrCancelled, false},
		{"ctrl-c", []string{ctrlC}, 0, 0, ErrCancelled, false},
		{"too many invalid answers", []string{"9", "9", "9", "9", "9", "9", "9"}, 0, 0, ErrCancelled, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, term := backendOf(tt.lines...)
			got, err := b.Choose("Where does it live?", opts, tt.def)
			if !errors.Is(err, tt.err) || (err == nil && got != tt.want) {
				t.Fatalf("got %d, %v; want %d, %v", got, err, tt.want, tt.err)
			}
			o := term.out.String()
			if !strings.Contains(o, "Where does it live?") || !strings.Contains(o, "1) global") || !strings.Contains(o, "2) this project (shop-api)") {
				t.Errorf("menu not rendered:\n%s", o)
			}
			if strings.Contains(o, "Type a number from 1 to 2, or press Enter for the default.\n") != tt.invalid {
				t.Errorf("invalid-choice message present = %v, want %v", !tt.invalid, tt.invalid)
			}
			for _, h := range term.hidden {
				if h {
					t.Error("a menu answer must be echoed")
				}
			}
		})
	}
}

func TestChooseDefaultMarked(t *testing.T) {
	b, term := backendOf("")
	if _, err := b.Choose("q?", []string{"a", "b"}, 1); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(term.out.String(), "[2]") {
		t.Errorf("default not shown:\n%s", term.out.String())
	}
}

func TestChooseRejectsBadDefault(t *testing.T) {
	b, _ := backendOf("")
	for _, def := range []int{-1, 2} {
		if _, err := b.Choose("q?", []string{"a", "b"}, def); err == nil {
			t.Errorf("default %d accepted", def)
		}
	}
}

func TestConfirm(t *testing.T) {
	tests := []struct {
		name  string
		lines []string
		want  bool
		err   error
	}{
		{"y", []string{"y"}, true, nil},
		{"yes any case", []string{" YeS "}, true, nil},
		{"n", []string{"n"}, false, nil},
		{"empty is no", []string{""}, false, nil},
		{"other text is no", []string{"sure"}, false, nil},
		{"eof", nil, false, ErrCancelled},
		{"ctrl-c", []string{ctrlC}, false, ErrCancelled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, term := backendOf(tt.lines...)
			got, err := b.Confirm("Remove A_KEY?")
			if got != tt.want || !errors.Is(err, tt.err) {
				t.Fatalf("got %v, %v", got, err)
			}
			if !strings.Contains(term.out.String(), "Remove A_KEY? [y/N] ") {
				t.Errorf("question not shown: %q", term.out.String())
			}
		})
	}
}

func TestQuestionsAreEscaped(t *testing.T) {
	b, term := backendOf("")
	_, _ = b.Confirm("Grant X\x1b[2J?")
	_, _ = b.Choose("pick\x1b[2J", []string{"a\x1b"}, 0)
	if strings.Contains(term.out.String(), "\x1b") {
		t.Error("a control character reached the terminal")
	}
}

func TestUnavailableTerminal(t *testing.T) {
	b := New(func() (Terminal, error) { return nil, ErrNoTerminal })
	if _, err := b.Secret(req); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Secret: %v", err)
	}
	if _, err := b.Choose("q", []string{"a"}, 0); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Choose: %v", err)
	}
	if _, err := b.Confirm("q"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Confirm: %v", err)
	}
	if _, err := b.Passphrase(VaultPassphrase); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Passphrase: %v", err)
	}
	if got := ErrNoTerminal.Error(); got != "no controlling terminal available" {
		t.Errorf("message = %q", got)
	}
	if b.Name() != "tty" {
		t.Errorf("Name = %q", b.Name())
	}
}

func TestReadHidden(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
		err  error
	}{
		{"plain", "abc\r", "abc", nil},
		{"lf ends", "abc\n", "abc", nil},
		{"backspace", "abx\x7fc\r", "abc", nil},
		{"backspace 0x08", "abx\x08c\r", "abc", nil},
		{"backspace past start", "\x7f\x7fa\r", "a", nil},
		{"backspace removes a whole rune", "a\u00e9\x7fb\r", "ab", nil},
		{"non-ascii kept", "p\u00e1s\r", "p\u00e1s", nil},
		{"arrow keys ignored", "a\x1b[Db\x1b[A\r", "ab", nil},
		{"bracketed paste markers ignored", "\x1b[200~pw\x1b[201~\r", "pw", nil},
		{"other controls ignored", "a\x00\x01b\r", "ab", nil},
		{"ctrl-c", "abc\x03", "", ErrCancelled},
		{"ctrl-d on empty", "\x04", "", ErrCancelled},
		{"ctrl-d with text is ignored", "ab\x04c\r", "abc", nil},
		{"eof on empty", "", "", io.EOF},
		{"eof with text ends input", "abc", "abc", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var w bytes.Buffer
			got, err := readHidden(strings.NewReader(tt.in), &w, func() {})
			if !errors.Is(err, tt.err) || string(got) != tt.want {
				t.Fatalf("got %q, %v; want %q, %v", got, err, tt.want, tt.err)
			}
			if strings.ContainsAny(w.String(), "abcpwsx\u00e1") {
				t.Errorf("typed characters were echoed: %q", w.String())
			}
		})
	}
}

func TestReadHiddenBoundsInput(t *testing.T) {
	got, err := readHidden(strings.NewReader(strings.Repeat("a", maxInput*2)+"\r"), io.Discard, func() {})
	if !errors.Is(err, ErrTooLarge) || got != nil {
		t.Fatalf("len = %d, err = %v, want ErrTooLarge", len(got), err)
	}
	got, err = readHidden(strings.NewReader(strings.Repeat("a", maxInput)+""), io.Discard, func() {})
	if err != nil || len(got) != maxInput {
		t.Fatalf("at the bound: len = %d, err = %v", len(got), err)
	}
}

func TestReadLine(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
		err  error
	}{
		{"lf", "yes\n", "yes", nil},
		{"crlf", "yes\r\n", "yes", nil},
		{"leaves the rest unread", "1\n2\n", "1", nil},
		{"eof with text", "yes", "yes", nil},
		{"eof empty", "", "", io.EOF},
		{"blank line", "\n", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := strings.NewReader(tt.in)
			got, err := readLine(r)
			if !errors.Is(err, tt.err) || string(got) != tt.want {
				t.Fatalf("got %q, %v; want %q, %v", got, err, tt.want, tt.err)
			}
			if tt.name == "leaves the rest unread" && r.Len() != 2 {
				t.Errorf("readLine over-read: %d bytes left", r.Len())
			}
		})
	}
}

func TestSelect(t *testing.T) {
	env := func(v string) Env {
		return Env{GOOS: "linux", LookPath: exec.LookPath, Getenv: func(k string) string {
			if k == EnvBackend {
				return v
			}
			return ""
		}}
	}
	for _, v := range []string{"", "tty"} {
		b, err := SelectWith(env(v))
		if err != nil || b == nil || b.Name() != "tty" {
			t.Errorf("%q: %v, %v", v, b, err)
		}
	}
	b, err := SelectWith(env("carrier-pigeon"))
	if b != nil || err == nil || errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), EnvBackend) || !strings.Contains(err.Error(), "carrier-pigeon") {
		t.Errorf("unknown: %v, %v", b, err)
	}
}

func TestReadHiddenRefusesInputAfterEnter(t *testing.T) {
	tests := []struct {
		name string
		in   string
		ok   bool // accepted
	}{
		{"second pasted line", "line1\rline2\r", false},
		{"second line after lf", "line1\nline2\n", false},
		{"partial second line", "line1\rrest", false},
		{"crlf is one line ending", "line1\r\n", true},
		{"plain enter", "line1\r", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flushed := 0
			var w bytes.Buffer
			got, err := readHidden(strings.NewReader(tt.in), &w, func() { flushed++ })
			if flushed == 0 {
				t.Error("pending terminal input was not flushed")
			}
			if tt.ok {
				if err != nil || string(got) != "line1" {
					t.Fatalf("got %q, %v", got, err)
				}
				return
			}
			if !errors.Is(err, ErrTrailingInput) || got != nil {
				t.Fatalf("got %q, %v; want ErrTrailingInput and nothing", got, err)
			}
			if strings.Contains(w.String(), "line") {
				t.Error("pasted text was echoed")
			}
		})
	}
}

func TestReadHiddenFlushesOnCancel(t *testing.T) {
	flushed := 0
	if _, err := readHidden(strings.NewReader("ab\x03rest"), io.Discard, func() { flushed++ }); !errors.Is(err, ErrCancelled) || flushed == 0 {
		t.Fatalf("err = %v, flushed = %d", err, flushed)
	}
}

func TestTrailingInputRefusesValueAndPassphrase(t *testing.T) {
	for name, call := range map[string]func(Backend) (int, error){
		"secret":     func(b Backend) (int, error) { s, err := b.Secret(req); return s.Len(), err },
		"passphrase": func(b Backend) (int, error) { s, err := b.Passphrase(VaultPassphrase.Twice()); return s.Len(), err },
	} {
		t.Run(name, func(t *testing.T) {
			term := &memTerm{trail: true}
			n, err := call(New(func() (Terminal, error) { return term, nil }))
			if !errors.Is(err, ErrTrailingInput) || n != 0 {
				t.Fatalf("err = %v, len = %d", err, n)
			}
		})
	}
	const want = "the input continued after Enter; paste a single line, or use --stdin for multi-line values"
	if ErrTrailingInput.Error() != want {
		t.Errorf("message = %q", ErrTrailingInput.Error())
	}
}

func TestTimeout(t *testing.T) {
	calls := map[string]func(Backend) error{
		"secret":     func(b Backend) error { _, err := b.Secret(req); return err },
		"passphrase": func(b Backend) error { _, err := b.Passphrase(VaultPassphrase); return err },
		"choose":     func(b Backend) error { _, err := b.Choose("q", []string{"a"}, 0); return err },
		"confirm":    func(b Backend) error { _, err := b.Confirm("q"); return err },
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			term := &memTerm{block: true}
			b := New(func() (Terminal, error) { return term, nil }, Timeout(30*time.Millisecond))
			start := time.Now()
			err := call(b)
			if !errors.Is(err, ErrTimeout) || err.Error() != "No answer in time; nothing was saved." {
				t.Fatalf("err = %v", err)
			}
			if time.Since(start) > 5*time.Second {
				t.Error("the prompt did not time out promptly")
			}
			if !term.closed {
				t.Error("terminal not closed")
			}
			if errors.Is(err, ErrCancelled) {
				t.Error("a timeout is its own error")
			}
		})
	}
}

func TestSelectTimeoutEnv(t *testing.T) {
	env := func(v string) func(string) string {
		return func(k string) string {
			if k == EnvTimeout {
				return v
			}
			return ""
		}
	}
	for _, v := range []string{"", "10s", "90s", "1h", "5m"} {
		if _, err := SelectWith(Env{GOOS: "freebsd", LookPath: exec.LookPath, Getenv: env(v)}); err != nil {
			t.Errorf("%q: %v", v, err)
		}
	}
	for _, v := range []string{"9s", "1h1s", "0", "-5m", "abc", "5"} {
		b, err := SelectWith(Env{GOOS: "freebsd", LookPath: exec.LookPath, Getenv: env(v)})
		if b != nil || !errors.Is(err, ErrBadTimeout) || !strings.Contains(err.Error(), EnvTimeout) {
			t.Errorf("%q: %v, %v", v, b, err)
		}
	}
	if DefaultTimeout != 5*time.Minute {
		t.Errorf("default = %v", DefaultTimeout)
	}
}
