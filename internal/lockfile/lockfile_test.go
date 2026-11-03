package lockfile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/QuBiit0/gentle-vault/internal/perm"
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
