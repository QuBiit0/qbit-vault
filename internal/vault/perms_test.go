package vault

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/perm"
)

func wantPrivate(t *testing.T, what, path string) {
	t.Helper()
	if ok, detail := perm.Check(path); !ok {
		t.Errorf("%s is not owner-only: %s", what, detail)
	}
}

// Every file and directory the vault writes is owner-only (R-VAULT-03): the
// home, vault.enc, state.json, the backups tree and, while it exists, the
// lock file and the temp file about to replace a target.
func TestVaultFilesAreOwnerOnly(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	// A pre-existing home with default (possibly wide) permissions.
	if err := os.Mkdir(home, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(home, 0o755); err != nil {
		t.Fatal(err)
	}
	wasPrivate, _ := perm.Check(home)

	var sawLock, sawTemp bool
	old := beforeRename
	beforeRename = func(tmp, target string) error {
		wantPrivate(t, "temp file", tmp)
		sawTemp = true
		wantPrivate(t, "lock file", filepath.Join(home, lockFile))
		sawLock = true
		return nil
	}
	t.Cleanup(func() { beforeRename = old })

	v, err := Init(home, testID, testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	mustPut(t, v, Global(), "A_KEY", rec("v"))
	mustPut(t, v, Global(), "B_KEY", rec("w")) // the second save makes a snapshot

	if !sawLock || !sawTemp {
		t.Fatal("the rename hook never ran")
	}
	if wasPrivate {
		t.Log("temp dir was already private; the tightening check is vacuous here")
	}
	wantPrivate(t, "home", home)
	for _, f := range []string{vaultFile, stateFile} {
		wantPrivate(t, f, filepath.Join(home, f))
	}
	backups := filepath.Join(home, "backups")
	wantPrivate(t, "backups", backups)
	snaps, err := os.ReadDir(backups)
	if err != nil || len(snaps) == 0 {
		t.Fatalf("no snapshots to check: %v", err)
	}
	for _, s := range snaps {
		dir := filepath.Join(backups, s.Name())
		wantPrivate(t, "snapshot dir", dir)
		files, _ := os.ReadDir(dir)
		if len(files) == 0 {
			t.Fatal("empty snapshot")
		}
		for _, f := range files {
			wantPrivate(t, "snapshot file", filepath.Join(dir, f.Name()))
		}
	}
}

func TestOpenedVaultTightensAWideHome(t *testing.T) {
	v, home := newVault(t)
	mustPut(t, v, Global(), "A_KEY", rec("v"))
	if err := os.Chmod(home, 0o755); err != nil {
		t.Fatal(err)
	}
	if ok, _ := perm.Check(home); ok {
		t.Skip("cannot widen the home on this platform")
	}
	mustPut(t, v, Global(), "B_KEY", rec("w"))
	wantPrivate(t, "home", home)
}
