package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/zalando/go-keyring"

	"github.com/QuBiit0/gentle-vault/internal/exitcode"
	"github.com/QuBiit0/gentle-vault/internal/keychain"
	"github.com/QuBiit0/gentle-vault/internal/refusal"
)

var openProbe = []func(*globals) *cobra.Command{probe}

func TestInitCreatesEmptyVault(t *testing.T) {
	h := newHarness(t)
	mode := keychain.NewOS().Name()
	code, out, errs := h.run("", "init")
	want := "vault initialized at " + h.home + " (keychain: " + mode + ")\n"
	if code != exitcode.OK || out != want || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	for _, f := range []string{"vault.enc", "state.json"} {
		if _, err := os.Stat(filepath.Join(h.home, f)); err != nil {
			t.Fatalf("%s missing: %v", f, err)
		}
	}
	if code, out, _ := h.runExtra("", openProbe, "probe"); code != exitcode.OK || out != "opened\n" {
		t.Fatalf("initialized vault does not open: code=%d out=%q", code, out)
	}
}

func TestInitJSON(t *testing.T) {
	h := newHarness(t)
	code, out, errs := h.run("", "--json", "init")
	want := initJSON(t, true, h.home, keychain.NewOS().Name())
	if code != exitcode.OK || errs != "" || out != want {
		t.Fatalf("code=%d out=%q err=%q want=%q", code, out, errs, want)
	}
}

func TestInitIsIdempotent(t *testing.T) {
	h := newHarness(t)
	h.mustRun("", "init")
	before, err := os.ReadFile(filepath.Join(h.home, "vault.enc"))
	if err != nil {
		t.Fatal(err)
	}
	code, out, errs := h.run("", "init")
	if code != exitcode.OK || out != "vault already initialized at "+h.home+"\n" || errs != "" {
		t.Fatalf("human: code=%d out=%q err=%q", code, out, errs)
	}
	code, out, errs = h.run("", "--json", "init")
	want := initJSON(t, false, h.home, "")
	if code != exitcode.OK || errs != "" || out != want {
		t.Fatalf("json: code=%d out=%q err=%q want=%q", code, out, errs, want)
	}
	after, _ := os.ReadFile(filepath.Join(h.home, "vault.enc"))
	if string(before) != string(after) {
		t.Fatal("second init rewrote the vault")
	}
}

func TestInitRemovesOrphanKeyWhenVaultInitFails(t *testing.T) {
	h := newHarness(t)
	const id = "6f9619ff-8b86-4d11-b42d-00c04fc964ff"
	old := newVaultID
	newVaultID = func() string { return id }
	t.Cleanup(func() { newVaultID = old })
	// A vault file without state.json makes vault.Init refuse with ErrExists.
	if err := os.MkdirAll(h.home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.home, "vault.enc"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := h.run("", "--json", "init")
	want := jsonOf(t, refusal.New(refusal.VaultCorrupt, "").Envelope())
	if code != exitcode.Corrupt || out != want || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if _, err := keyring.Get("gentle-vault", "master:"+id); err == nil {
		t.Fatal("orphan key left in the keychain")
	}
	if b, _ := os.ReadFile(filepath.Join(h.home, "vault.enc")); string(b) != "x" {
		t.Fatal("existing vault file was modified")
	}
}

func TestInitPassphraseMode(t *testing.T) {
	h := newHarness(t)
	code, out, errs := h.run(fxPass+"\n", "--json", "init", "--passphrase", "--passphrase-stdin")
	want := initJSON(t, true, h.home, "passphrase-file")
	if code != exitcode.OK || errs != "" || out != want {
		t.Fatalf("code=%d out=%q err=%q want=%q", code, out, errs, want)
	}
	if strings.Contains(out+errs, "TESTSECRET_") {
		t.Fatal("passphrase echoed")
	}
	if _, err := os.Stat(filepath.Join(h.home, "key.enc")); err != nil {
		t.Fatalf("key.enc missing: %v", err)
	}
	// No prompt exists yet and no cache is available: opening is locked.
	code, _, errs = h.runExtra("", openProbe, "probe")
	if code != exitcode.Locked || errs != "error: vault is locked\n" {
		t.Fatalf("code=%d err=%q", code, errs)
	}
}

func TestInitPassphraseUsageErrors(t *testing.T) {
	tests := []struct {
		name  string
		stdin string
		args  []string
		msg   string
	}{
		{"passphrase without stdin flag", "", []string{"init", "--passphrase"}, "no controlling terminal available; use --passphrase-stdin"},
		{"stdin flag without passphrase", fxPass + "\n", []string{"init", "--passphrase-stdin"}, "--passphrase-stdin requires --passphrase"},
		{"empty passphrase", "\n", []string{"init", "--passphrase", "--passphrase-stdin"}, "empty passphrase"},
		{"blank passphrase", "   \n", []string{"init", "--passphrase", "--passphrase-stdin"}, "empty passphrase"},
		{"extra argument", "", []string{"init", "TESTSECRET_x"}, "unexpected arguments"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			code, out, errs := h.run(tt.stdin, tt.args...)
			if code != exitcode.Usage || out != "" || errs != "error: "+tt.msg+"\n"+helpHint {
				t.Fatalf("code=%d out=%q err=%q", code, out, errs)
			}
			if _, err := os.Stat(filepath.Join(h.home, "vault.enc")); !os.IsNotExist(err) {
				t.Fatal("rejected input created a vault")
			}
			if _, err := os.Stat(filepath.Join(h.home, "key.enc")); !os.IsNotExist(err) {
				t.Fatal("rejected input created a key file")
			}
		})
	}
}

// initJSON is the exact expected stdout of a successful init.
func initJSON(t *testing.T, initialized bool, home, kc string) string {
	t.Helper()
	return jsonOf(t, initBody{OK: true, Initialized: initialized, Home: home, Keychain: kc})
}
