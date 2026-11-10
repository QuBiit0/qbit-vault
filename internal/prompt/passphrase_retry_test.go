package prompt

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// S4.4: a new passphrase that does not match its confirmation is asked again;
// the third mismatch in a row is the existing mismatch error.
const wrongPass = fxPass + "x"

func TestTTYPassphraseMismatchAsksAgain(t *testing.T) {
	t.Run("matches on the third try", func(t *testing.T) {
		b, term := backendOf(fxPass, wrongPass, fxPass, wrongPass, fxPass, fxPass)
		got, err := b.Passphrase(VaultPassphrase.Twice())
		if err != nil || string(got.Reveal()) != fxPass {
			t.Fatalf("err = %v", err)
		}
		if len(term.hidden) != 6 {
			t.Errorf("reads = %d, want 6", len(term.hidden))
		}
		out := term.out.String()
		if strings.Count(out, "Passphrases do not match.") != 2 || strings.Contains(out, "TESTSECRET_") {
			t.Errorf("out = %q", out)
		}
	})
	t.Run("third mismatch fails", func(t *testing.T) {
		b, term := backendOf(fxPass, wrongPass, fxPass, wrongPass, fxPass, wrongPass, fxPass, fxPass)
		got, err := b.Passphrase(VaultPassphrase.Twice())
		if !errors.Is(err, ErrMismatch) || got.Len() != 0 {
			t.Fatalf("err = %v, len = %d", err, got.Len())
		}
		if len(term.hidden) != 6 {
			t.Errorf("reads = %d, want 6: no fourth try", len(term.hidden))
		}
		if strings.Count(term.out.String(), "Passphrases do not match.") != 3 || strings.Contains(term.out.String(), "TESTSECRET_") {
			t.Errorf("out = %q", term.out.String())
		}
	})
	t.Run("cancel while retrying", func(t *testing.T) {
		b, _ := backendOf(fxPass, wrongPass, ctrlC)
		if _, err := b.Passphrase(VaultPassphrase.Twice()); !errors.Is(err, ErrCancelled) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("a single entry is never retried", func(t *testing.T) {
		b, term := backendOf(fxPass)
		if _, err := b.Passphrase(VaultPassphrase); err != nil || len(term.hidden) != 1 {
			t.Fatalf("err = %v reads = %d", err, len(term.hidden))
		}
	})
}

func TestNativePassphraseMismatchAsksAgain(t *testing.T) {
	line := func(s string) result { return ok(s + "\n") }
	t.Run("matches on the second try", func(t *testing.T) {
		f := &fakeRun{res: []result{line(fxPass), line(wrongPass), line(fxPass), line(fxPass)}}
		got, err := nativeOf(zenityTool{}, f).Passphrase(ExportPassphrase.Twice())
		if err != nil || string(got.Reveal()) != fxPass || len(f.cmds) != 4 {
			t.Fatalf("err = %v dialogs = %d", err, len(f.cmds))
		}
		first, retry := strings.Join(f.cmds[0].Args, " "), strings.Join(f.cmds[2].Args, " ")
		if strings.Contains(first, "do not match") || !strings.Contains(retry, "Passphrases do not match. Try again.") || !strings.Contains(retry, "Export passphrase") {
			t.Errorf("first = %q\nretry = %q", first, retry)
		}
	})
	t.Run("third mismatch fails and wipes", func(t *testing.T) {
		a, b := []byte(fxPass+"\n"), []byte(wrongPass+"\n")
		res := []result{}
		for range 3 {
			res = append(res, result{Stdout: bytes.Clone(a)}, result{Stdout: bytes.Clone(b)})
		}
		res = append(res, line(fxPass)) // a fourth dialog would take this
		f := &fakeRun{res: res}
		got, err := nativeOf(zenityTool{}, f).Passphrase(VaultPassphrase.Twice())
		if !errors.Is(err, ErrMismatch) || got.Len() != 0 || len(f.cmds) != 6 {
			t.Fatalf("err = %v len = %d dialogs = %d", err, got.Len(), len(f.cmds))
		}
		for _, c := range f.cmds {
			if strings.Contains(strings.Join(c.Args, " ")+string(c.Stdin), "TESTSECRET_") {
				t.Fatal("a passphrase reached a helper's argv or stdin")
			}
		}
	})
	t.Run("cancel while retrying", func(t *testing.T) {
		f := &fakeRun{res: []result{line(fxPass), line(wrongPass), {Exit: 1}}}
		if _, err := nativeOf(zenityTool{}, f).Passphrase(VaultPassphrase.Twice()); !errors.Is(err, ErrCancelled) {
			t.Fatalf("err = %v", err)
		}
	})
}

// Every native helper says why the first entry is asked again.
func TestRetryDialogSaysWhy(t *testing.T) {
	d := retryDialog(VaultPassphrase)
	if d.heading != "Vault passphrase" || !strings.HasPrefix(d.text, "Passphrases do not match. Try again.\n\n") || !strings.HasSuffix(d.text, "Vault passphrase:") {
		t.Fatalf("dialog = %+v", d)
	}
	if ok, no := d.buttons(); ok != "Continue" || no != "Cancel" {
		t.Errorf("buttons = %q / %q", ok, no)
	}
	if s := string(powershellTool{}.build("powershell.exe", d).Stdin); !strings.Contains(s, "$text = Dec "+psString(d.text)) {
		t.Errorf("powershell script lacks the retry text")
	}
}
