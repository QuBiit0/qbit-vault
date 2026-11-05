package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/exitcode"
	"github.com/QuBiit0/qbit-vault/internal/keychain"
	"github.com/QuBiit0/qbit-vault/internal/vault"
)

// masterKey reads the stored master key (keychain mode), for assertions.
func (w *world) masterKey() string {
	w.t.Helper()
	id, err := vault.ReadID(w.home)
	if err != nil {
		w.t.Fatal(err)
	}
	k, _, err := keychain.Unlock(w.home, id, keychain.Options{})
	if err != nil {
		w.t.Fatal(err)
	}
	defer k.Wipe()
	return string(k.Reveal())
}

func TestRekeyKeychainMode(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_a\n", "set", "A", "--stdin")
	f := withBackend(t, answers(yes()))
	w.mustRun("", "--session", "cli:test1", "grant", "A", "--scope", "session")
	before := w.masterKey()
	code, out, errs := w.run("", "rekey")
	if code != exitcode.OK || errs != "" || out != "master key rotated (keychain: "+osMode()+")\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if w.masterKey() == before {
		t.Fatal("the master key did not change")
	}
	if w.value("A") != "TESTSECRET_a" {
		t.Fatal("value lost in rekey")
	}
	if out := w.mustRun("", "--json", "--session", "cli:test1", "grants"); !strings.Contains(out, `"name":"A"`) {
		t.Fatalf("grant lost in rekey: %s", out)
	}
	if !w.auditHas(`"event":"rekey"`) {
		t.Fatal("rekey not audited")
	}
	// Backups made before the rekey still restore (retired key).
	old := w.backupIDs()[len(w.backupIDs())-1]
	w.mustRun("", "restore", "--from", old, "--yes")
	code, out, errs = w.run("", "--json", "rekey")
	if code != exitcode.OK || errs != "" || out != `{"ok":true,"rekeyed":true,"keychain":"`+osMode()+`"}`+"\n" {
		t.Fatalf("json: code=%d out=%q err=%q", code, out, errs)
	}
	if len(f.Calls) != 1 {
		t.Fatalf("rekey asked something in keychain mode: %+v", f.Calls[1:])
	}
	noFixtures(t, "rekey output", out+errs+w.auditText())
}

func TestRekeyPassphraseModeAsksAndVerifies(t *testing.T) {
	w := passphraseWorld(t)
	withBackend(t, answers(val(fxPass)))
	w.mustRun("TESTSECRET_a\n", "set", "A", "--stdin")
	before, _ := os.ReadFile(filepath.Join(w.home, "key.enc"))
	vaultBefore, _ := os.ReadFile(filepath.Join(w.home, "vault.enc"))

	// Unlock passphrase right, staging passphrase wrong: nothing changes.
	withBackend(t, answers(val(fxPass), val("TESTSECRET_wrong_passphrase")))
	code, out, errs := w.run("", "rekey")
	if code != exitcode.Locked || out != "" || errs != "error: vault is locked\n" {
		t.Fatalf("wrong passphrase: code=%d out=%q err=%q", code, out, errs)
	}
	if now, _ := os.ReadFile(filepath.Join(w.home, "vault.enc")); string(now) != string(vaultBefore) {
		t.Fatal("refused rekey changed the vault")
	}
	if _, err := os.Stat(filepath.Join(w.home, "key.next.enc")); !os.IsNotExist(err) {
		t.Fatal("refused rekey left a staged key")
	}

	f := withBackend(t, answers(val(fxPass), val(fxPass)))
	code, out, errs = w.run("", "rekey")
	if code != exitcode.OK || errs != "" || out != "master key rotated (keychain: passphrase-file)\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if len(f.Calls) != 2 {
		t.Fatalf("calls=%d, want unlock + staging", len(f.Calls))
	}
	if after, _ := os.ReadFile(filepath.Join(w.home, "key.enc")); string(after) == string(before) {
		t.Fatal("key.enc not replaced")
	}
	if _, err := os.Stat(filepath.Join(w.home, "key.next.enc")); !os.IsNotExist(err) {
		t.Fatal("staged key left after rekey")
	}
	withBackend(t, answers(val(fxPass)))
	if w.value("A") != "TESTSECRET_a" {
		t.Fatal("value lost")
	}
}

func TestInterruptedRekeyFinishesOnNextCommand(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_a\n", "set", "A", "--stdin")
	id, _ := vault.ReadID(w.home)
	cur, _, err := keychain.Unlock(w.home, id, keychain.Options{})
	if err != nil {
		t.Fatal(err)
	}
	next, _ := keychain.NewKey()
	// Crash after re-sealing, before the key was promoted.
	if err := keychain.Stage(w.home, id, cur, next, keychain.Options{}); err != nil {
		t.Fatal(err)
	}
	if err := vault.Rekey(w.home, cur, next); err != nil {
		t.Fatal(err)
	}
	code, out, errs := w.run("", "list")
	if code != exitcode.OK || errs != "warning: an interrupted rekey was finished\n" || !strings.Contains(out, "A") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if w.masterKey() != string(next.Reveal()) {
		t.Fatal("staged key not promoted")
	}
	if has, _ := keychain.HasStaged(w.home, id, keychain.Options{}); has {
		t.Fatal("staged key left")
	}
	if !w.auditHas(`"detail":"interrupted rekey finished"`) {
		t.Fatal("recovery not audited")
	}
	if code, _, errs := w.run("", "list"); code != exitcode.OK || errs != "" {
		t.Fatalf("second command: code=%d err=%q", code, errs)
	}
}

func TestRekeyRefusedOnRolledBackVault(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_a\n", "set", "A", "--stdin")
	w.mustRun("TESTSECRET_b\n", "set", "B", "--stdin")
	old := w.backupIDs()[0]
	data, _ := os.ReadFile(filepath.Join(w.home, "backups", old, "vault.enc"))
	if err := os.WriteFile(filepath.Join(w.home, "vault.enc"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	before := w.masterKey()
	code, out, errs := w.run("", "rekey")
	if code != exitcode.Corrupt || out != "" || errs != "error: vault is corrupt; run 'qbit-vault restore'\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	id, _ := vault.ReadID(w.home)
	if has, _ := keychain.HasStaged(w.home, id, keychain.Options{}); has || w.masterKey() != before {
		t.Fatal("refused rekey changed the keys")
	}
	h := newHarness(t)
	if code, _, errs := h.run("", "rekey"); code != exitcode.Failure || errs != "error: no vault here; run 'qbit-vault init'\n" {
		t.Fatalf("no vault: code=%d err=%q", code, errs)
	}
	if code, _, errs := w.run("", "rekey", "x"); code != exitcode.Usage || errs != usageErr("unexpected arguments") {
		t.Fatalf("args: code=%d err=%q", code, errs)
	}
}

// interruptRekey leaves w as a crash after re-sealing, before promotion.
func (w *world) interruptRekey() {
	w.t.Helper()
	id, _ := vault.ReadID(w.home)
	cur, _, err := keychain.Unlock(w.home, id, keychain.Options{})
	if err != nil {
		w.t.Fatal(err)
	}
	next, _ := keychain.NewKey()
	if err := keychain.Stage(w.home, id, cur, next, keychain.Options{}); err != nil {
		w.t.Fatal(err)
	}
	if err := vault.Rekey(w.home, cur, next); err != nil {
		w.t.Fatal(err)
	}
}

// W2: restore and unlock finish an interrupted rekey first, instead of
// sealing under the old key or reporting a corrupt vault.
func TestRestoreAndUnlockFinishInterruptedRekey(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_a\n", "set", "A", "--stdin")
	w.mustRun("TESTSECRET_b\n", "set", "B", "--stdin")
	w.interruptRekey()
	code, out, errs := w.run("", "unlock")
	if code != exitcode.OK || errs != "warning: an interrupted rekey was finished\n" || !strings.HasPrefix(out, "unlocked:") {
		t.Fatalf("unlock: code=%d out=%q err=%q", code, out, errs)
	}

	w2 := newWorld(t)
	w2.mustRun("TESTSECRET_a\n", "set", "A", "--stdin")
	w2.mustRun("TESTSECRET_b\n", "set", "B", "--stdin")
	id := w2.backupIDs()[0]
	w2.interruptRekey()
	code, _, errs = w2.run("", "restore", "--from", id, "--yes")
	if code != exitcode.OK || errs != "warning: an interrupted rekey was finished\n" {
		t.Fatalf("restore: code=%d err=%q", code, errs)
	}
	if w2.names() != "A" {
		t.Fatal("restore did not apply")
	}
	// Every snapshot, including the one restore just made, still opens.
	for _, b := range w2.backupIDs() {
		if code, _, errs := w2.run("", "restore", "--from", b, "--yes"); code != exitcode.OK {
			t.Fatalf("backup %s unreadable after recovery: %q", b, errs)
		}
	}
}
