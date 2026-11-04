package keychain

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// clearOS removes this test id's main and staged entries from the shared
// mock keychain, before and after the test.
func clearOS(t *testing.T) {
	t.Helper()
	wipe := func() {
		_ = NewOS().Delete(testID)
		_ = NewOS().Delete(stagedID(testID))
	}
	wipe()
	t.Cleanup(wipe)
}

func TestStagePromoteOSMode(t *testing.T) {
	clearOS(t)
	home := t.TempDir()
	cur, _, err := Setup(home, testID, Options{getenv: env(nil)})
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{getenv: env(nil)}
	if has, err := HasStaged(home, testID, opts); err != nil || has {
		t.Fatalf("fresh: has=%v err=%v", has, err)
	}
	next := fixedKey(7)
	if err := Stage(home, testID, cur, next, opts); err != nil {
		t.Fatal(err)
	}
	if has, _ := HasStaged(home, testID, opts); !has {
		t.Fatal("staged key not visible")
	}
	got, err := Staged(home, testID, opts)
	if err != nil || revealStr(got) != revealStr(next) {
		t.Fatalf("Staged: %v", err)
	}
	// The main entry is untouched until Promote.
	if k, _, _ := Unlock(home, testID, opts); revealStr(k) != revealStr(cur) {
		t.Fatal("Stage changed the main key")
	}
	if err := Promote(home, testID, next, opts); err != nil {
		t.Fatal(err)
	}
	if k, _, _ := Unlock(home, testID, opts); revealStr(k) != revealStr(next) {
		t.Fatal("Promote did not replace the main key")
	}
	if has, _ := HasStaged(home, testID, opts); has {
		t.Fatal("staged key survived Promote")
	}
	// Promote again (a crash after the first step) is harmless.
	if err := Promote(home, testID, next, opts); err != nil {
		t.Fatalf("second Promote: %v", err)
	}
}

func TestUnstageOSMode(t *testing.T) {
	clearOS(t)
	home := t.TempDir()
	cur, _, err := Setup(home, testID, Options{getenv: env(nil)})
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{getenv: env(nil)}
	if err := Stage(home, testID, cur, fixedKey(8), opts); err != nil {
		t.Fatal(err)
	}
	if err := Unstage(home, testID, opts); err != nil {
		t.Fatal(err)
	}
	if has, _ := HasStaged(home, testID, opts); has {
		t.Fatal("Unstage left the key")
	}
	if err := Unstage(home, testID, opts); err != nil {
		t.Fatalf("Unstage twice: %v", err)
	}
	if _, err := Staged(home, testID, opts); !errors.Is(err, ErrNoKey) {
		t.Fatalf("Staged after Unstage: %v", err)
	}
}

func TestStagePassphraseModeVerifiesPassphrase(t *testing.T) {
	cheapKDF(t)
	noOS(t)
	home := t.TempDir()
	cur, _, err := Setup(home, testID, Options{getenv: env(nil), Passphrase: pass(fixturePass)})
	if err != nil {
		t.Fatal(err)
	}
	next := fixedKey(9)
	staged := filepath.Join(home, "key.next.enc")
	wrong := Options{getenv: env(nil), Passphrase: pass(fixtureOther)}
	if err := Stage(home, testID, cur, next, wrong); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	if _, err := os.Stat(staged); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a wrong passphrase still staged a key")
	}
	// A right passphrase for a key file that wraps another key is refused too.
	if err := Stage(home, testID, fixedKey(3), next, Options{getenv: env(nil), Passphrase: pass(fixturePass)}); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("current mismatch: %v", err)
	}
	var asked int
	opts := Options{getenv: env(nil), Passphrase: countingPass(fixturePass, &asked, nil)}
	if err := Stage(home, testID, cur, next, opts); err != nil {
		t.Fatal(err)
	}
	if asked != 1 {
		t.Fatalf("asked=%d", asked)
	}
	if has, _ := HasStaged(home, testID, Options{}); !has {
		t.Fatal("staged file missing")
	}
	got, err := Staged(home, testID, opts)
	if err != nil || revealStr(got) != revealStr(next) {
		t.Fatalf("Staged: %v", err)
	}
	if err := Promote(home, testID, next, opts); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(staged); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("staged file survived Promote")
	}
	k, mode, err := Unlock(home, testID, opts)
	if err != nil || mode != ModePassphrase || revealStr(k) != revealStr(next) {
		t.Fatalf("after Promote: mode=%s err=%v", mode, err)
	}
	// Promote with nothing staged and the key already in place is a no-op.
	if err := Promote(home, testID, next, opts); err != nil {
		t.Fatalf("second Promote: %v", err)
	}
}

func TestPromotePassphraseModeRefreshesCache(t *testing.T) {
	cheapKDF(t)
	noOS(t)
	home, run := t.TempDir(), t.TempDir()
	opts := cacheOpts(run)
	opts.Passphrase = pass(fixturePass)
	cur, _, err := Setup(home, testID, opts)
	if err != nil {
		t.Fatal(err)
	}
	next := fixedKey(4)
	if err := Stage(home, testID, cur, next, opts); err != nil {
		t.Fatal(err)
	}
	if err := Promote(home, testID, next, opts); err != nil {
		t.Fatal(err)
	}
	opts.Passphrase = nil // must come from the cache now
	k, _, err := Unlock(home, testID, opts)
	if err != nil || revealStr(k) != revealStr(next) {
		t.Fatalf("cache after Promote: %v", err)
	}
}

// W1: a promotion that fails after the cache was filled with the old key must
// not leave that stale key behind (Unlock would return it unchecked).
func TestPromoteDropsStaleCacheEvenWhenItFails(t *testing.T) {
	cheapKDF(t)
	noOS(t)
	home, run := t.TempDir(), t.TempDir()
	opts := cacheOpts(run)
	opts.Passphrase = pass(fixturePass)
	cur, _, err := Setup(home, testID, opts) // fills the cache with cur
	if err != nil {
		t.Fatal(err)
	}
	if err := Stage(home, testID, cur, fixedKey(5), opts); err != nil {
		t.Fatal(err)
	}
	// Make the rename fail: key.enc becomes a non-empty directory.
	if err := os.Remove(filepath.Join(home, "key.enc")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, "key.enc", "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := Promote(home, testID, fixedKey(5), opts); err == nil {
		t.Fatal("Promote succeeded over a directory")
	}
	if _, err := os.Stat(filepath.Join(run, "qbit-vault", testID+".key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the old key is still cached after a failed promotion")
	}
}
