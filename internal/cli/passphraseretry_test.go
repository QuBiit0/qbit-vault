package cli

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/exitcode"
	"github.com/QuBiit0/qbit-vault/internal/prompt"
	"github.com/QuBiit0/qbit-vault/internal/prompt/prompttest"
)

// S4.4: through the real terminal backend, a new export passphrase that does
// not match its confirmation is asked again; the third mismatch fails with the
// existing message and writes nothing.
func TestExportPassphraseMismatchIsAskedAgain(t *testing.T) {
	const good, bad = fxExport, fxExport + "x"
	stream := func(lines ...string) *bytes.Buffer {
		var out bytes.Buffer
		in := strings.NewReader(strings.Join(lines, "\n") + "\n")
		old := newPrompt
		newPrompt = func(*globals) (prompt.Backend, error) { return prompttest.Stream(in, &out), nil }
		t.Cleanup(func() { newPrompt = old })
		return &out
	}

	t.Run("second try matches", func(t *testing.T) {
		w := newWorld(t)
		w.seedExport()
		file := exportFile(t)
		prompts := stream(good, bad, good, good)
		code, out, errs := w.run("", "export", file)
		if code != exitcode.OK || errs != "keep the file and its passphrase in different places; anyone with both can read every secret\n" {
			t.Fatalf("code=%d out=%q err=%q", code, out, errs)
		}
		if strings.Count(prompts.String(), "Passphrases do not match.") != 1 || strings.Contains(prompts.String(), "TESTSECRET_") {
			t.Fatalf("prompts = %q", prompts.String())
		}
		if st, err := os.Stat(file); err != nil || st.Size() == 0 {
			t.Fatalf("no export file: %v", err)
		}
		noFixtures(t, "export output", out+errs)
	})
	t.Run("third mismatch fails", func(t *testing.T) {
		w := newWorld(t)
		w.seedExport()
		before := w.snapshot()
		file := exportFile(t)
		prompts := stream(good, bad, good, bad, good, bad, good, good)
		code, out, errs := w.run("", "export", file)
		if code != exitcode.Usage || out != "" || errs != usageErr("passphrases do not match") {
			t.Fatalf("code=%d out=%q err=%q", code, out, errs)
		}
		if strings.Count(prompts.String(), "Passphrases do not match.") != 3 {
			t.Fatalf("prompts = %q", prompts.String())
		}
		if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("a file was written")
		}
		if w.snapshot() != before {
			t.Fatal("the vault changed")
		}
	})
}
