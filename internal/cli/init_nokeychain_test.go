package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"

	"github.com/QuBiit0/qbit-vault/internal/exitcode"
	"github.com/QuBiit0/qbit-vault/internal/prompt/prompttest"
)

// noKeychain plays a machine without an OS keychain (WSL, a headless Linux
// box without Secret Service) for one test.
func noKeychain(t *testing.T) {
	t.Helper()
	keyring.MockInitWithError(errors.New("no secret service"))
	t.Cleanup(keyring.MockInit)
}

const noKeychainNote = "no OS keychain found (WSL or a headless Linux?): the master key is protected by the passphrase you just set; 'qbit-vault unlock' opens it\n"

// Plain init without a keychain asks for a passphrase instead of failing.
func TestInitWithoutAKeychainFallsBackToAPassphrase(t *testing.T) {
	noKeychain(t)
	h := newHarness(t)
	f := withBackend(t, answers(val(fxPass)))
	code, out, errs := h.run("", "init")
	want := "vault initialized at " + h.home + " (keychain: passphrase-file)\n" + noKeychainNote
	if code != exitcode.OK || errs != "" || out != want {
		t.Fatalf("code=%d out=%q err=%q want=%q", code, out, errs, want)
	}
	if len(f.Calls) != 1 || f.Calls[0].Kind != "passphrase" || !f.Calls[0].Confirm {
		t.Fatalf("calls = %+v, want one confirmed passphrase prompt", f.Calls)
	}
	if _, err := os.Stat(filepath.Join(h.home, "key.enc")); err != nil {
		t.Fatalf("key.enc missing: %v", err)
	}
	noFixtures(t, "output", out+errs)
}

// The JSON result names the mode; the note is for humans only.
func TestInitWithoutAKeychainJSON(t *testing.T) {
	noKeychain(t)
	h := newHarness(t)
	withBackend(t, answers(val(fxPass)))
	code, out, errs := h.run("", "--json", "init")
	if code != exitcode.OK || errs != "" || out != initJSON(t, true, h.home, "passphrase-file") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
}

// With no way to ask (no terminal, no dialog) the error names the fix and
// nothing is created.
func TestInitWithoutAKeychainOrAPromptNamesTheFix(t *testing.T) {
	noKeychain(t)
	h := newHarness(t)
	withBackend(t, &prompttest.Fake{Unavailable: true})
	code, out, errs := h.run("", "init")
	if code != exitcode.Usage || out != "" || !strings.HasPrefix(errs, "error: no OS keychain found and no terminal to ask for a passphrase; run 'qbit-vault init --passphrase --passphrase-stdin'\n") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if _, err := os.Stat(filepath.Join(h.home, "key.enc")); !os.IsNotExist(err) {
		t.Fatal("a key file was written")
	}
	if _, err := os.Stat(filepath.Join(h.home, "vault.enc")); !os.IsNotExist(err) {
		t.Fatal("a vault was written")
	}
}

// A machine with a keychain keeps using it and is never asked anything.
func TestInitWithAKeychainAsksNothing(t *testing.T) {
	h := newHarness(t)
	f := withBackend(t, answers())
	code, out, errs := h.run("", "init")
	if code != exitcode.OK || errs != "" || strings.Contains(out, "no OS keychain") || !strings.Contains(out, "(keychain: ") || strings.Contains(out, "passphrase-file") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("asked %+v", f.Calls)
	}
}
