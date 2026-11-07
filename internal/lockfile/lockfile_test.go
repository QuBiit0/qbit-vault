package lockfile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/QuBiit0/qbit-vault/internal/perm"
)

var fast = Options{Timeout: 300 * time.Millisecond, StaleAfter: 30 * time.Second, Poll: 5 * time.Millisecond}

func plant(t *testing.T, dir, name string, age time.Duration) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("99999\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-age)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAcquireAndRelease(t *testing.T) {
	dir := t.TempDir()
	release, err := Acquire(dir, "x.lock", fast)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "x.lock")
	if ok, detail := perm.Check(p); !ok {
		t.Errorf("lock file not owner-only: %s", detail)
	}
	if _, err := Acquire(dir, "x.lock", fast); !errors.Is(err, ErrBusy) {
		t.Fatalf("second Acquire err = %v, want ErrBusy", err)
	}
	release()
	if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lock left after release: %v", err)
	}
	release2, err := Acquire(dir, "x.lock", fast)
	if err != nil {
		t.Fatalf("re-acquire: %v", err)
	}
	release2()
}

func TestBusyIsBoundedAndNameFree(t *testing.T) {
	dir := t.TempDir()
	p := plant(t, dir, "held.lock", 0)
	start := time.Now()
	_, err := Acquire(dir, "held.lock", fast)
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("err = %v, want ErrBusy", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("took %v, not bounded", d)
	}
	if strings.Contains(err.Error(), dir) || strings.Contains(err.Error(), "held") {
		t.Fatalf("message = %q", err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal("held lock was removed")
	}
}

func TestStaleLockIsBroken(t *testing.T) {
	dir := t.TempDir()
	p := plant(t, dir, "s.lock", time.Minute)
	release, err := Acquire(dir, "s.lock", fast)
	if err != nil {
		t.Fatalf("stale lock not broken: %v", err)
	}
	release()
	if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lock left: %v", err)
	}
}

// B-F3: a lock stamped far in the future (clock skew, a copied home) is stale
// too; one only slightly ahead is a live lock whose clock runs fast.
func TestFutureLockIsStaleBeyondTheStaleAge(t *testing.T) {
	dir := t.TempDir()
	p := plant(t, dir, "f.lock", -time.Minute)
	release, err := Acquire(dir, "f.lock", fast)
	if err != nil {
		t.Fatalf("future lock not broken: %v", err)
	}
	release()
	if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lock left: %v", err)
	}

	p = plant(t, dir, "g.lock", -5*time.Second)
	if _, err := Acquire(dir, "g.lock", fast); !errors.Is(err, ErrBusy) {
		t.Fatalf("a lock a few seconds ahead is live: %v", err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("live lock removed: %v", err)
	}
}

func TestReleasedOnPanic(t *testing.T) {
	dir := t.TempDir()
	func() {
		defer func() { _ = recover() }()
		release, err := Acquire(dir, "p.lock", fast)
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		panic("boom")
	}()
	if _, err := os.Stat(filepath.Join(dir, "p.lock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lock left after panic: %v", err)
	}
}

func TestReleaseLeavesSomeoneElsesLock(t *testing.T) {
	dir := t.TempDir()
	release, err := Acquire(dir, "o.lock", fast)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "o.lock")
	if err := os.WriteFile(p, []byte("someone else\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	release()
	if _, err := os.Stat(p); err != nil {
		t.Fatal("release removed a lock that is no longer ours")
	}
}

func TestMissingDirIsNotExist(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "absent")
	_, err := Acquire(dir, "m.lock", fast)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v, want ErrNotExist", err)
	}
	if strings.Contains(err.Error(), "absent") {
		t.Fatalf("message leaks the path: %q", err)
	}
}

// B-F10: between judging a lock stale and removing it, another process can
// break it and take a fresh one; the breaker must not delete that live lock.
func TestStaleBreakDoesNotRemoveALockTakenMeanwhile(t *testing.T) {
	dir := t.TempDir()
	p := plant(t, dir, "r.lock", time.Hour)
	beforeBreak = func() {
		if err := os.WriteFile(p, []byte("fresh holder\n"), 0o600); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { beforeBreak = func() {} })
	if _, err := Acquire(dir, "r.lock", fast); !errors.Is(err, ErrBusy) {
		t.Fatalf("Acquire = %v, want ErrBusy: the fresh lock is live", err)
	}
	if b, _ := os.ReadFile(p); string(b) != "fresh holder\n" {
		t.Fatalf("the live lock was removed or replaced: %q", b)
	}
}

func TestStaleBreakLeavesNoHelperFile(t *testing.T) {
	dir := t.TempDir()
	plant(t, dir, "r.lock", time.Hour)
	release, err := Acquire(dir, "r.lock", fast)
	if err != nil {
		t.Fatal(err)
	}
	release()
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("files left behind: %d", len(entries))
	}
}

func TestAbandonedBreakHelperDoesNotBlockForever(t *testing.T) {
	dir := t.TempDir()
	plant(t, dir, "r.lock", time.Hour)
	plant(t, dir, "r.lock.break", time.Hour) // a breaker that crashed
	release, err := Acquire(dir, "r.lock", fast)
	if err != nil {
		t.Fatalf("Acquire = %v", err)
	}
	release()
}
