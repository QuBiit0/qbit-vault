package prompt

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// S7.2: a command the user runs names the user, without the subcommand.
func TestRequesterForTheUser(t *testing.T) {
	if got := Requester("cli", "cli:abcdefghij"); got != "you (qbit-vault)" {
		t.Errorf("Requester(cli) = %q", got)
	}
}

// S7.3: a passphrase prompt says what it protects, once and again.
func TestPassphraseLabelsOnTheTerminal(t *testing.T) {
	tests := []struct {
		name string
		req  PassphraseRequest
		want []string
	}{
		{"vault", VaultPassphrase, []string{"Vault passphrase: "}},
		{"vault twice", VaultPassphrase.Twice(), []string{"Vault passphrase: ", "Type the passphrase again: "}},
		{"export twice", ExportPassphrase.Twice(), []string{"Export passphrase (protects this backup file): ", "Type the export passphrase again: "}},
		{"import", ImportPassphrase, []string{"Passphrase of the export file: "}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines := []string{fxPass}
			if tt.req.Confirm {
				lines = append(lines, fxPass)
			}
			b, term := backendOf(lines...)
			if _, err := b.Passphrase(tt.req); err != nil {
				t.Fatal(err)
			}
			if got, want := term.out.String(), strings.Join(tt.want, ""); got != want {
				t.Errorf("terminal = %q, want %q", got, want)
			}
		})
	}
}

func TestPassphraseDialogs(t *testing.T) {
	d := passphraseDialog(ExportPassphrase, false)
	if d.title != "QBit Vault" || d.heading != "Export passphrase" || d.text != "Export passphrase (protects this backup file):" {
		t.Errorf("export dialog = %q / %q / %q", d.title, d.heading, d.text)
	}
	if a := passphraseDialog(ExportPassphrase, true); a.text != "Type the export passphrase again:" || a.heading != "Export passphrase" {
		t.Errorf("again dialog = %q / %q", a.heading, a.text)
	}
	if v := passphraseDialog(VaultPassphrase, false); v.heading != "Vault passphrase" || v.text != "Vault passphrase:" {
		t.Errorf("vault dialog = %q / %q", v.heading, v.text)
	}
	if i := passphraseDialog(ImportPassphrase, false); i.heading != "Export passphrase" || i.text != "Passphrase of the export file:" {
		t.Errorf("import dialog = %q / %q", i.heading, i.text)
	}
}

// S7.5: the form header has no Value line; each box says whether it is hidden.
func TestFormHeaderHasNoValueLine(t *testing.T) {
	reqs := []SecretRequest{
		{Name: "HOST", Reason: "r", Host: "claude", Visible: true},
		{Name: "TOKEN", Reason: "r", Host: "claude", Existing: true},
	}
	d := formDialog(reqs)
	if strings.Contains(d.text, "Value:") || strings.Contains(d.text, "as you type") {
		t.Errorf("form text has a Value line:\n%s", d.text)
	}
	if len(d.fields) != 2 || d.fields[0].label != "HOST (shown while you type)" || d.fields[1].label != "TOKEN (hidden)" {
		t.Errorf("fields = %+v", d.fields)
	}
	if d.title != "QBit Vault" || d.heading != "Secret request" {
		t.Errorf("title/heading = %q / %q", d.title, d.heading)
	}
}

// S7.11: Ctrl-C at a cooked terminal read is a cancel, not a dead process.
func TestConsoleReadLineInterrupt(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	sig := make(chan os.Signal, 1)
	stopped := false
	c := &console{in: r, out: w, interrupts: func() (<-chan os.Signal, func()) {
		return sig, func() { stopped = true }
	}}
	go func() {
		time.Sleep(50 * time.Millisecond)
		sig <- os.Interrupt
	}()
	_, err = c.ReadLine(context.Background())
	if !errors.Is(err, ErrCancelled) {
		t.Fatalf("ReadLine after Ctrl-C = %v, want ErrCancelled", err)
	}
	if !stopped {
		t.Error("the interrupt handler was not released")
	}
}

func TestConsoleReadLineStillReads(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	sig := make(chan os.Signal, 1)
	c := &console{in: r, out: w, interrupts: func() (<-chan os.Signal, func()) { return sig, func() {} }}
	_, _ = w.WriteString("y\n")
	got, err := c.ReadLine(context.Background())
	w.Close()
	if err != nil || string(got) != "y" {
		t.Fatalf("got %q, %v", got, err)
	}
}

// S7.12: a kdialog-only Linux cannot show a secret safely, so the recovery
// key and the pairing code go to the terminal instead.
func TestKdialogShowFallsBackToTheTerminal(t *testing.T) {
	f := &fakeRun{res: []result{ok("")}}
	n := newNative(kdialogTool{}, "/usr/bin/kdialog", f.run, time.Minute).(*native)
	term := &memTerm{lines: []string{""}}
	n.open = func() (Terminal, error) { return term, nil }
	if err := n.Show("Recovery key", "Write it down.\n\n"+fxShown); err != nil {
		t.Fatal(err)
	}
	if len(f.cmds) != 0 {
		t.Errorf("kdialog ran %d commands", len(f.cmds))
	}
	out := term.out.String()
	if !strings.Contains(out, "Recovery key") || !strings.Contains(out, fxShown) || !strings.Contains(out, "Press Enter when done. ") {
		t.Errorf("terminal = %q", out)
	}
	// No terminal either: nothing can show it.
	n.open = func() (Terminal, error) { return nil, ErrNoTerminal }
	if err := n.Show("Recovery key", fxShown); !errors.Is(err, ErrUnavailable) {
		t.Errorf("no terminal: %v", err)
	}
}
