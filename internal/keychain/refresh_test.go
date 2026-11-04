package keychain

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRefreshAsksEvenWithWarmCacheAndRecaches(t *testing.T) {
	cheapKDF(t)
	noOS(t)
	home, run := t.TempDir(), t.TempDir()
	opts := cacheOpts(run)
	opts.Passphrase = pass(fixturePass)
	key, _, err := Setup(home, testID, opts)
	if err != nil {
		t.Fatal(err)
	}
	var asked int
	at := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	opts.Passphrase = countingPass(fixturePass, &asked, nil)
	opts.now = func() time.Time { return at }
	got, mode, cached, exp, err := Refresh(home, testID, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Wipe()
	if asked != 1 {
		t.Fatalf("asked=%d, want 1: refresh must not trust the cache", asked)
	}
	if mode != ModePassphrase || !cached || !exp.Equal(at.Add(DefaultCacheTTL)) {
		t.Fatalf("mode=%s cached=%v exp=%v", mode, cached, exp)
	}
	if revealStr(got) != revealStr(key) {
		t.Fatal("refresh returned another key")
	}
	if _, err := os.Stat(filepath.Join(run, "qbit-vault", testID+".key")); err != nil {
		t.Fatal("cache missing after refresh")
	}
}

func TestRefreshWrongPassphraseKeepsCache(t *testing.T) {
	cheapKDF(t)
	noOS(t)
	home, run := t.TempDir(), t.TempDir()
	opts := cacheOpts(run)
	opts.Passphrase = pass(fixturePass)
	if _, _, err := Setup(home, testID, opts); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(run, "qbit-vault", testID+".key")
	before, err := os.ReadFile(cache)
	if err != nil {
		t.Fatal(err)
	}
	opts.Passphrase = pass(fixtureOther)
	if _, _, _, _, err := Refresh(home, testID, opts); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("err=%v, want ErrBadPassphrase", err)
	}
	after, err := os.ReadFile(cache)
	if err != nil || string(after) != string(before) {
		t.Fatal("a failed refresh changed the cache")
	}
}

func TestRefreshWithoutCacheDir(t *testing.T) {
	cheapKDF(t)
	noOS(t)
	home := t.TempDir()
	opts := Options{getenv: env(nil), Passphrase: pass(fixturePass)}
	if _, _, err := Setup(home, testID, opts); err != nil {
		t.Fatal(err)
	}
	k, mode, cached, exp, err := Refresh(home, testID, opts)
	if err != nil {
		t.Fatal(err)
	}
	k.Wipe()
	if mode != ModePassphrase || cached || !exp.IsZero() {
		t.Fatalf("mode=%s cached=%v exp=%v", mode, cached, exp)
	}
	opts.Passphrase = nil
	if _, _, _, _, err := Refresh(home, testID, opts); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("no passphrase source: err=%v", err)
	}
}

func TestRefreshKeychainModeReadsOS(t *testing.T) {
	home := t.TempDir()
	var asked int
	opts := Options{getenv: env(nil), Passphrase: countingPass(fixturePass, &asked, nil)}
	key, osMode, err := Setup(home, testID, opts)
	if err != nil {
		t.Fatal(err)
	}
	got, mode, cached, exp, err := Refresh(home, testID, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Wipe()
	if mode != osMode || cached || !exp.IsZero() || asked != 0 || revealStr(got) != revealStr(key) {
		t.Fatalf("mode=%s cached=%v exp=%v asked=%d", mode, cached, exp, asked)
	}
	if _, _, _, _, err := Refresh(home, "../evil", opts); err == nil {
		t.Fatal("Refresh accepted a path-like id")
	}
}

func TestModeOf(t *testing.T) {
	cheapKDF(t)
	home := t.TempDir()
	if m, err := ModeOf(home, Options{}); err != nil || m != Mode(NewOS().Name()) {
		t.Fatalf("no key file: mode=%s err=%v", m, err)
	}
	noOS(t)
	if _, _, err := Setup(home, testID, Options{getenv: env(nil), Passphrase: pass(fixturePass)}); err != nil {
		t.Fatal(err)
	}
	if m, err := ModeOf(home, Options{}); err != nil || m != ModePassphrase {
		t.Fatalf("key file: mode=%s err=%v", m, err)
	}
}
