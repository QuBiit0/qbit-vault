package vault

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func storedGrants(t *testing.T, v *Vault) (string, bool) {
	t.Helper()
	var got string
	reset, err := v.ReadGrants(func(b []byte) error { got = string(b); return nil })
	if err != nil {
		t.Fatal(err)
	}
	return got, reset
}

func TestRekeyResealsEverythingAndKeepsGrants(t *testing.T) {
	v, home := newVault(t)
	mustPut(t, v, Global(), "A", rec("TESTSECRET_a"))
	if _, err := v.MutateGrants(func([]byte, bool) ([]byte, error) { return []byte(`{"grants":[]}`), nil }); err != nil {
		t.Fatal(err)
	}
	before := len(backupsOf(t, home))
	if err := Rekey(home, testKey(1), testKey(2)); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(home, testKey(1)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("old key still opens the vault: %v", err)
	}
	v2, err := Open(home, testKey(2))
	if err != nil {
		t.Fatal(err)
	}
	r, _, err := v2.Resolve("A", t.TempDir())
	if err != nil || !sameValue(r, "TESTSECRET_a") {
		t.Fatalf("value after rekey: %v", err)
	}
	if body, reset := storedGrants(t, v2); reset || body != `{"grants":[]}` {
		t.Fatalf("grants after rekey: reset=%v body=%q", reset, body)
	}
	// The old envelope is a backup, and the retired key opens it.
	ids := backupsOf(t, home)
	if len(ids) != before+1 {
		t.Fatalf("backups %d -> %d", before, len(ids))
	}
	old, err := os.ReadFile(filepath.Join(home, "backups", ids[len(ids)-1], vaultFile))
	if err != nil {
		t.Fatal(err)
	}
	if pt, _, err := openWithAny(home, testKey(2), old); err != nil {
		t.Fatalf("old envelope: %v", err)
	} else {
		clear(pt)
	}
}

func TestRekeyIsIdempotentAndResumable(t *testing.T) {
	v, home := newVault(t)
	mustPut(t, v, Global(), "A", rec("TESTSECRET_a"))
	if _, err := v.MutateGrants(func([]byte, bool) ([]byte, error) { return []byte(`{"g":1}`), nil }); err != nil {
		t.Fatal(err)
	}
	// Crash after the vault step: grants and retired are still on key 1.
	if err := v.locked(false, func() error { return rekeyVault(home, testKey(1), testKey(2)) }); err != nil {
		t.Fatal(err)
	}
	mid := len(backupsOf(t, home))
	if err := Rekey(home, testKey(1), testKey(2)); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if got := len(backupsOf(t, home)); got != mid {
		t.Fatalf("resume re-sealed the vault again: %d -> %d backups", mid, got)
	}
	v2, err := Open(home, testKey(2))
	if err != nil {
		t.Fatal(err)
	}
	if body, reset := storedGrants(t, v2); reset || body != `{"g":1}` {
		t.Fatalf("grants after resume: reset=%v body=%q", reset, body)
	}
	if keys, err := retiredKeys(home, testKey(2)); err != nil || len(keys) != 1 {
		t.Fatalf("retired after resume: %d %v", len(keys), err)
	}
	// A third run changes nothing.
	vaultBefore, _ := os.ReadFile(filepath.Join(home, vaultFile))
	if err := Rekey(home, testKey(1), testKey(2)); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(filepath.Join(home, vaultFile)); string(after) != string(vaultBefore) {
		t.Fatal("a finished rekey rewrote the vault")
	}
}

func TestRekeyRefusesRolledBackOrForeignVault(t *testing.T) {
	v, home := newVault(t)
	mustPut(t, v, Global(), "A", rec("TESTSECRET_a"))
	mustPut(t, v, Global(), "B", rec("TESTSECRET_b"))
	ids := backupsOf(t, home)
	vaultPath := filepath.Join(home, vaultFile)
	old, _ := os.ReadFile(filepath.Join(home, "backups", ids[0], vaultFile))
	if err := os.WriteFile(vaultPath, old, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Rekey(home, testKey(1), testKey(2)); !errors.Is(err, ErrRollback) {
		t.Fatalf("rolled back: %v", err)
	}
	if now, _ := os.ReadFile(vaultPath); string(now) != string(old) {
		t.Fatal("refused rekey changed the vault")
	}
	if err := Rekey(home, testKey(7), testKey(8)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("foreign keys: %v", err)
	}
}

// W3: a retired list that cannot be read (not one that fails to decrypt) is
// an error, never silently replaced by an empty list.
func TestRekeyKeepsRetiredListOnReadError(t *testing.T) {
	_, home := newVault(t)
	if err := os.MkdirAll(filepath.Join(home, keysDir, retiredFile, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := Rekey(home, testKey(1), testKey(2)); err == nil {
		t.Fatal("rekey went on with an unreadable retired list")
	}
	if fi, err := os.Stat(filepath.Join(home, keysDir, retiredFile)); err != nil || !fi.IsDir() {
		t.Fatal("the unreadable retired list was overwritten")
	}
}

// W4: a rekey refused before anything was re-sealed says so.
func TestRekeyNotStartedSentinel(t *testing.T) {
	v, home := newVault(t)
	mustPut(t, v, Global(), "A", rec("TESTSECRET_a"))
	if err := Rekey(home, testKey(7), testKey(8)); !errors.Is(err, ErrRekeyNotStarted) || !errors.Is(err, ErrCorrupt) {
		t.Fatalf("foreign keys: %v", err)
	}
	mustPut(t, v, Global(), "B", rec("TESTSECRET_b"))
	ids := backupsOf(t, home)
	old, _ := os.ReadFile(filepath.Join(home, "backups", ids[0], vaultFile))
	if err := os.WriteFile(filepath.Join(home, vaultFile), old, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Rekey(home, testKey(1), testKey(2)); !errors.Is(err, ErrRekeyNotStarted) || !errors.Is(err, ErrRollback) {
		t.Fatalf("rolled back: %v", err)
	}
}
