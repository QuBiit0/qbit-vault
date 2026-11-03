package vault

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const (
	helperEnv     = "GENTLE_VAULT_TEST_HELPER"
	helperHomeEnv = "GENTLE_VAULT_TEST_HOME"
	helperTagEnv  = "GENTLE_VAULT_TEST_TAG"
	putsPerWorker = 15
)

// TestHelperPuts is the body of the child processes started by
// TestConcurrentPutsAcrossProcesses; it does nothing in a normal run.
func TestHelperPuts(t *testing.T) {
	if os.Getenv(helperEnv) != "1" {
		t.Skip("helper process only")
	}
	v, err := Open(os.Getenv(helperHomeEnv), testKey(1))
	if err != nil {
		t.Fatalf("helper Open: %v", err)
	}
	tag := os.Getenv(helperTagEnv)
	for i := range putsPerWorker {
		if err := v.Put(Global(), fmt.Sprintf("P%s_%02d", tag, i), rec("TESTSECRET_helper")); err != nil {
			t.Fatalf("helper Put %d: %v", i, err)
		}
	}
}

func countNames(t *testing.T, v *Vault) map[string]bool {
	t.Helper()
	all, err := v.ListAll()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, e := range all {
		got[e.Name] = true
	}
	return got
}

func TestConcurrentPutsAcrossHandles(t *testing.T) {
	v, home := newVault(t)
	v2, err := Open(home, testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for tag, h := range map[string]*Vault{"A": v, "B": v2} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range putsPerWorker {
				if err := h.Put(Global(), fmt.Sprintf("G%s_%02d", tag, i), rec("TESTSECRET_x")); err != nil {
					t.Errorf("Put: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	if got := countNames(t, v); len(got) != 2*putsPerWorker {
		t.Fatalf("%d names survived, want %d (lost update)", len(got), 2*putsPerWorker)
	}
}

func TestConcurrentPutsAcrossProcesses(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns processes")
	}
	v, home := newVault(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for _, tag := range []string{"X", "Y"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cmd := exec.Command(exe, "-test.run=^TestHelperPuts$", "-test.count=1")
			cmd.Env = append(os.Environ(), helperEnv+"=1", helperHomeEnv+"="+home, helperTagEnv+"="+tag)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("helper %s: %v\n%s", tag, err, out)
			}
		}()
	}
	wg.Wait()
	got := countNames(t, v)
	for _, tag := range []string{"X", "Y"} {
		for i := range putsPerWorker {
			if n := fmt.Sprintf("P%s_%02d", tag, i); !got[n] {
				t.Fatalf("%s lost across processes", n)
			}
		}
	}
	if len(got) != 2*putsPerWorker {
		t.Fatalf("%d names, want %d", len(got), 2*putsPerWorker)
	}
}

func writeLock(t *testing.T, home string, age time.Duration) string {
	t.Helper()
	p := filepath.Join(home, lockFile)
	if err := os.WriteFile(p, []byte("99999\n"+time.Now().UTC().Format(time.RFC3339)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-age)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	return p
}

func shortLock(t *testing.T) {
	t.Helper()
	prev := lockTimeout
	lockTimeout = 300 * time.Millisecond
	t.Cleanup(func() { lockTimeout = prev })
}

func TestHeldLockGivesErrLocked(t *testing.T) {
	v, home := newVault(t)
	shortLock(t)
	p := writeLock(t, home, 0)
	start := time.Now()
	err := v.Put(Global(), "A", rec("TESTSECRET_x"))
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("Put err = %v, want ErrLocked", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("took %v, not bounded", d)
	}
	if !strings.Contains(err.Error(), "vault is busy") || strings.Contains(err.Error(), home) {
		t.Fatalf("message = %q", err)
	}
	if _, err := Open(home, testKey(1)); !errors.Is(err, ErrLocked) {
		t.Fatalf("Open err = %v, want ErrLocked", err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal("held lock was removed")
	}
}

func TestStaleLockIsBroken(t *testing.T) {
	v, home := newVault(t)
	shortLock(t)
	p := writeLock(t, home, 60*time.Second)
	if err := v.Put(Global(), "A", rec("TESTSECRET_x")); err != nil {
		t.Fatalf("Put with stale lock: %v", err)
	}
	if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lock not released: %v", err)
	}
}

func TestLockReleasedOnPanicAndError(t *testing.T) {
	v, home := newVault(t)
	func() {
		defer func() { _ = recover() }()
		_ = v.mutate(func(*body) error { panic("boom") })
	}()
	if _, err := os.Stat(filepath.Join(home, lockFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lock left after panic: %v", err)
	}
	if err := v.Remove(Global(), "MISSING"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, lockFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lock left after error: %v", err)
	}
}

// transientRenameErr returns an error the rename retry treats as transient on
// this platform.
func transientRenameErr(t *testing.T, tmp, target string) error {
	t.Helper()
	if runtime.GOOS == "windows" {
		return &os.LinkError{Op: "rename", Old: tmp, New: target, Err: syscall.Errno(32)}
	}
	errBusy := errors.New("sharing violation")
	prev := isTransientFS
	isTransientFS = func(err error) bool { return errors.Is(err, errBusy) || prev(err) }
	t.Cleanup(func() { isTransientFS = prev })
	return &os.LinkError{Op: "rename", Old: tmp, New: target, Err: errBusy}
}

func TestRenameRetriesTransientErrors(t *testing.T) {
	v, _ := newVault(t)
	prev := renameFile
	t.Cleanup(func() { renameFile = prev })
	calls := 0
	renameFile = func(from, to string) error {
		calls++
		if calls <= 2 {
			return transientRenameErr(t, from, to)
		}
		return prev(from, to)
	}
	if err := v.Put(Global(), "A", rec("TESTSECRET_x")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if calls < 3 {
		t.Fatalf("rename called %d times", calls)
	}
	if _, _, err := v.Resolve("A", t.TempDir()); err != nil {
		t.Fatal(err)
	}
}

func TestRenameGivesUpWithFileNameOnly(t *testing.T) {
	v, home := newVault(t)
	if err := v.Put(Global(), "KEEP", rec("TESTSECRET_x")); err != nil {
		t.Fatal(err)
	}
	prevBudget := renameBudget
	renameBudget = 100 * time.Millisecond
	prev := renameFile
	t.Cleanup(func() { renameFile = prev; renameBudget = prevBudget })
	renameFile = func(from, to string) error { return transientRenameErr(t, from, to) }

	err := v.Put(Global(), "NEW", rec("TESTSECRET_y"))
	if err == nil {
		t.Fatal("want error")
	}
	if !strings.Contains(err.Error(), "vault.enc") {
		t.Fatalf("error lacks file name: %v", err)
	}
	if strings.Contains(err.Error(), home) || strings.Contains(err.Error(), ".tmp.") {
		t.Fatalf("error leaks path: %v", err)
	}
	renameFile = prev
	got := countNames(t, v)
	if !got["KEEP"] || got["NEW"] {
		t.Fatalf("vault not intact: %v", got)
	}
}

func TestRepairCreatesNoSnapshot(t *testing.T) {
	s := newTestStore(t)
	for _, b := range []string{"v1", "v2"} {
		if err := s.save([]byte(b)); err != nil {
			t.Fatal(err)
		}
	}
	before := backupDirs(t, s.home)
	statePath := filepath.Join(s.home, "state.json")
	st, err := loadState(s.home)
	if err != nil {
		t.Fatal(err)
	}
	st.Writes = 1
	b, _ := st.marshal()
	if err := os.WriteFile(statePath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.load(); err != nil {
		t.Fatal(err)
	}
	if after := backupDirs(t, s.home); len(after) != len(before) {
		t.Fatalf("repair changed snapshots: %v -> %v", before, after)
	}
	if readState(t, s.home)["writes"] != float64(2) {
		t.Fatal("state not repaired")
	}
}

func TestFailedSaveRemovesItsSnapshot(t *testing.T) {
	s := newTestStore(t)
	if err := s.save([]byte("v1")); err != nil {
		t.Fatal(err)
	}
	before := backupDirs(t, s.home)
	prev := beforeRename
	beforeRename = func(string, string) error { return errors.New("simulated crash") }
	err := s.save([]byte("v2"))
	beforeRename = prev
	if err == nil {
		t.Fatal("want error")
	}
	if after := backupDirs(t, s.home); len(after) != len(before) {
		t.Fatalf("failed save left snapshot: %v -> %v", before, after)
	}
}

func TestSnapshotDirsUniqueOnSameTick(t *testing.T) {
	s := newTestStore(t)
	fixed := time.Date(2026, 11, 3, 14, 15, 0, 123456789, time.UTC)
	prev := snapshotClock
	snapshotClock = func() time.Time { return fixed }
	t.Cleanup(func() { snapshotClock = prev })
	for range 4 {
		if err := s.save([]byte("body")); err != nil {
			t.Fatal(err)
		}
	}
	dirs := backupDirs(t, s.home)
	if len(dirs) != 3 {
		t.Fatalf("dirs = %v, want 3 distinct", dirs)
	}
	seen := map[string]bool{}
	for _, d := range dirs {
		if seen[d] {
			t.Fatalf("duplicate %s", d)
		}
		seen[d] = true
		if entries, _ := os.ReadDir(filepath.Join(s.home, "backups", d)); len(entries) != 2 {
			t.Fatalf("%s holds %d files, want 2", d, len(entries))
		}
	}
}

func TestTempNamesUniqueAcrossHandles(t *testing.T) {
	home := t.TempDir()
	prev := beforeRename
	t.Cleanup(func() { beforeRename = prev })
	seen := map[string]bool{}
	beforeRename = func(tmp, _ string) error {
		if seen[tmp] {
			return fmt.Errorf("temp name %s reused", filepath.Base(tmp))
		}
		seen[tmp] = true
		return nil
	}
	for range 5 {
		if err := replaceFile(home, "vault.enc", []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) != 5 {
		t.Fatalf("%d distinct temp names, want 5", len(seen))
	}
}

func TestLeftoverTempCleanedBySave(t *testing.T) {
	s := newTestStore(t)
	if err := s.save([]byte("v1")); err != nil {
		t.Fatal(err)
	}
	leftovers := []string{
		filepath.Join(s.home, "vault.enc.tmp.4242.deadbeef"),
		filepath.Join(s.home, "state.json.tmp.4242.deadbeef"),
	}
	for _, p := range leftovers {
		if err := os.WriteFile(p, []byte("half"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.save([]byte("v2")); err != nil {
		t.Fatal(err)
	}
	for _, p := range leftovers {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s survived: %v", filepath.Base(p), err)
		}
	}
}
