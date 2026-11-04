package vault

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/QuBiit0/gentle-vault/internal/secret"
)

// backupsOf lists the snapshot ids, oldest first.
func backupsOf(t *testing.T, home string) []string {
	t.Helper()
	bs, err := ListBackups(home)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, len(bs))
	for i, b := range bs {
		ids[len(bs)-1-i] = b.ID // ListBackups is newest first
	}
	return ids
}

func names(t *testing.T, v *Vault) []string {
	t.Helper()
	all, err := v.ListAll()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range all {
		e.Record.Value.Wipe()
		out = append(out, e.Name)
	}
	return out
}

func TestListBackups(t *testing.T) {
	v, home := newVault(t)
	if bs, err := ListBackups(home); err != nil || len(bs) != 0 {
		t.Fatalf("fresh vault: %v %v", bs, err)
	}
	mustPut(t, v, Global(), "A", rec("TESTSECRET_a"))
	mustPut(t, v, Global(), "B", rec("TESTSECRET_b"))
	bs, err := ListBackups(home)
	if err != nil || len(bs) != 2 {
		t.Fatalf("backups=%v err=%v", bs, err)
	}
	if bs[0].ID <= bs[1].ID {
		t.Fatalf("not newest first: %v", bs)
	}
	for _, b := range bs {
		if !ValidBackupID(b.ID) || len(b.Files) != 2 || b.Files[0] != "state.json" || b.Files[1] != "vault.enc" {
			t.Fatalf("backup %+v", b)
		}
	}
	// Foreign directories and files are ignored.
	if err := os.MkdirAll(filepath.Join(home, "backups", "not-a-snapshot"), 0o700); err != nil {
		t.Fatal(err)
	}
	if bs2, _ := ListBackups(home); len(bs2) != 2 {
		t.Fatalf("foreign dir listed: %v", bs2)
	}
	if bs, err := ListBackups(filepath.Join(home, "missing")); err != nil || bs != nil {
		t.Fatalf("missing home: %v %v", bs, err)
	}
}

func TestValidBackupID(t *testing.T) {
	for _, ok := range []string{"20261103T141500.123456789Z", "20261103T141500.123456789Z-001"} {
		if !ValidBackupID(ok) {
			t.Errorf("%s rejected", ok)
		}
	}
	for _, bad := range []string{"", "..", "../x", "20261103T141500Z", "20261103T141500.123456789Z-1", "TESTSECRET_x"} {
		if ValidBackupID(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestRestoreBringsBackOlderStateAndMovesCounterForward(t *testing.T) {
	v, home := newVault(t)
	mustPut(t, v, Global(), "A", rec("TESTSECRET_a"))
	mustPut(t, v, Global(), "B", rec("TESTSECRET_b")) // snapshot: vault with A only
	mustPut(t, v, Global(), "C", rec("TESTSECRET_c")) // snapshot: A and B
	ids := backupsOf(t, home)
	before := len(ids)
	if err := Restore(home, ids[1], testKey(1)); err != nil { // the "A only" snapshot
		t.Fatal(err)
	}
	v2, err := Open(home, testKey(1))
	if err != nil {
		t.Fatalf("Open after restore: %v", err)
	}
	if got := names(t, v2); len(got) != 1 || got[0] != "A" {
		t.Fatalf("restored names=%v", got)
	}
	r, _, err := v2.Resolve("A", t.TempDir())
	if err != nil || !sameValue(r, "TESTSECRET_a") {
		t.Fatalf("value after restore: %v", err)
	}
	// The pre-restore state is itself a new snapshot.
	if after := backupsOf(t, home); len(after) != before+1 {
		t.Fatalf("backups %d -> %d", before, len(after))
	}
	// Restoring again from the newest snapshot gives A, B, C back.
	newest := backupsOf(t, home)[len(backupsOf(t, home))-1]
	if err := Restore(home, newest, testKey(1)); err != nil {
		t.Fatal(err)
	}
	if got := names(t, v2); len(got) != 3 {
		t.Fatalf("second restore names=%v", got)
	}
}

func TestRestoreRecoversCorruptAndRolledBackVault(t *testing.T) {
	v, home := newVault(t)
	mustPut(t, v, Global(), "A", rec("TESTSECRET_a"))
	mustPut(t, v, Global(), "B", rec("TESTSECRET_b"))
	ids := backupsOf(t, home)
	vaultPath := filepath.Join(home, vaultFile)
	if err := os.WriteFile(vaultPath, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(home, testKey(1)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("setup: %v", err)
	}
	if err := Restore(home, ids[len(ids)-1], testKey(1)); err != nil {
		t.Fatalf("restore over corrupt vault: %v", err)
	}
	if _, err := Open(home, testKey(1)); err != nil {
		t.Fatalf("Open: %v", err)
	}
	// Rollback: an older vault.enc copied over the live one trips the counter;
	// restore still moves it forward.
	old, err := os.ReadFile(filepath.Join(home, "backups", ids[0], vaultFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vaultPath, old, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(home, testKey(1)); !errors.Is(err, ErrRollback) {
		t.Fatalf("setup rollback: %v", err)
	}
	if err := Restore(home, ids[0], testKey(1)); err != nil {
		t.Fatalf("restore over rollback: %v", err)
	}
	if _, err := Open(home, testKey(1)); err != nil {
		t.Fatalf("Open after rollback restore: %v", err)
	}
}

func TestRestoreUsesSnapshotStateWhenLiveStateIsUnreadable(t *testing.T) {
	v, home := newVault(t)
	mustPut(t, v, Global(), "A", rec("TESTSECRET_a"))
	mustPut(t, v, Global(), "B", rec("TESTSECRET_b"))
	ids := backupsOf(t, home)
	if err := os.WriteFile(filepath.Join(home, stateFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, err := ReadBackupID(home, ids[0])
	if err != nil || id != testID {
		t.Fatalf("ReadBackupID=%q %v", id, err)
	}
	if err := Restore(home, ids[0], testKey(1)); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadID(home); err != nil || got != testID {
		t.Fatalf("state after restore: %q %v", got, err)
	}
}

func TestRestoreRefusals(t *testing.T) {
	v, home := newVault(t)
	mustPut(t, v, Global(), "A", rec("TESTSECRET_a"))
	mustPut(t, v, Global(), "B", rec("TESTSECRET_b"))
	ids := backupsOf(t, home)
	live, _ := os.ReadFile(filepath.Join(home, vaultFile))
	if err := Restore(home, "20200101T000000.000000000Z", testKey(1)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown id: %v", err)
	}
	if err := Restore(home, "../../etc", testKey(1)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("path-like id: %v", err)
	}
	if err := Restore(home, ids[0], testKey(9)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("foreign key: %v", err)
	}
	if now, _ := os.ReadFile(filepath.Join(home, vaultFile)); string(now) != string(live) {
		t.Fatal("a refused restore changed the vault")
	}
}

func TestRetiredKeyOpensOldBackup(t *testing.T) {
	v, home := newVault(t)
	mustPut(t, v, Global(), "A", rec("TESTSECRET_a"))
	mustPut(t, v, Global(), "B", rec("TESTSECRET_b"))
	ids := backupsOf(t, home) // sealed with key 1
	// Simulate a rekey to key 2: re-seal the live pair and retire key 1.
	if err := Rekey(home, testKey(1), testKey(2)); err != nil {
		t.Fatal(err)
	}
	keys, err := retiredKeys(home, testKey(2))
	if err != nil || len(keys) != 1 || string(keys[0].Reveal()) != string(testKey(1).Reveal()) {
		t.Fatalf("retired=%d err=%v", len(keys), err)
	}
	if err := Restore(home, ids[1], testKey(2)); err != nil { // the "A only" snapshot
		t.Fatalf("restore of a key-1 backup under key 2: %v", err)
	}
	v2, err := Open(home, testKey(2))
	if err != nil {
		t.Fatal(err)
	}
	if got := names(t, v2); len(got) != 1 || got[0] != "A" {
		t.Fatalf("names=%v", got)
	}
}

func TestRetiredStoreCapsAndSkipsDuplicates(t *testing.T) {
	_, home := newVault(t)
	cur := testKey(1)
	for i := 0; i < maxRetired+5; i++ {
		next := secret.New("master", fill(byte(10+i)))
		if err := Rekey(home, cur, next); err != nil {
			t.Fatalf("rekey %d: %v", i, err)
		}
		cur = next
	}
	keys, err := retiredKeys(home, cur)
	if err != nil || len(keys) != maxRetired {
		t.Fatalf("retired=%d err=%v", len(keys), err)
	}
	// Rekey to the same key retires nothing new.
	if err := Rekey(home, cur, cur); err != nil {
		t.Fatal(err)
	}
	if again, _ := retiredKeys(home, cur); len(again) != maxRetired {
		t.Fatalf("same-key rekey changed retired: %d", len(again))
	}
	if _, err := retiredKeys(home, testKey(1)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("retired opened with a stale key: %v", err)
	}
}

func fill(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}
