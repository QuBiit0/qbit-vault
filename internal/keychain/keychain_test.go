package keychain

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/zalando/go-keyring"

	"github.com/qbitdevz/qbit-vault/internal/secret"
	"github.com/qbitdevz/qbit-vault/internal/vault"
)

const (
	fixturePass  = "TESTSECRET_passphrase_correct_horse"
	fixtureOther = "TESTSECRET_passphrase_other"
	testID       = "6f9619ff-8b86-4d11-b42d-00c04fc964ff"
)

func TestMain(m *testing.M) {
	keyring.MockInit()
	// Test directories are ordinary disk; the real check has its own test.
	memoryBacked = func(string) bool { return true }
	os.Exit(m.Run())
}

// cheapKDF swaps the Argon2 parameters for fast ones for the test's duration.
func cheapKDF(t *testing.T) {
	t.Helper()
	oldP, oldMin := argonParams, minMKiB
	argonParams = kdfParams{Alg: algArgon2id, T: 1, MKiB: 1024, P: 1}
	minMKiB = 1024
	t.Cleanup(func() { argonParams, minMKiB = oldP, oldMin })
}

func pass(s string) PassphraseFunc {
	return func(bool) (secret.Secret, error) { return secret.New("passphrase", []byte(s)), nil }
}

// countingPass counts how often the caller was asked and records confirm.
func countingPass(s string, n *int, confirms *[]bool) PassphraseFunc {
	return func(confirm bool) (secret.Secret, error) {
		*n++
		if confirms != nil {
			*confirms = append(*confirms, confirm)
		}
		return secret.New("passphrase", []byte(s)), nil
	}
}

func revealStr(s secret.Secret) string {
	b := s.Reveal()
	defer clear(b)
	return string(b)
}

func fixedKey(b byte) secret.Secret { return secret.New("master", bytes.Repeat([]byte{b}, keySize)) }

// noOS makes the OS keychain unreachable for the test.
func noOS(t *testing.T) {
	t.Helper()
	keyring.MockInitWithError(errors.New("no keychain"))
	t.Cleanup(keyring.MockInit)
}

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func mutateJSON(t *testing.T, data []byte, fn func(map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	fn(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func isPOSIX() bool { return runtime.GOOS != "windows" }

// ---- OS backend ----

func TestOSBackendRoundTrip(t *testing.T) {
	keyring.MockInit()
	b := NewOS()
	if !b.Available() {
		t.Fatal("mock keychain should be available")
	}
	if _, err := b.Get(testID); !errors.Is(err, ErrNoKey) {
		t.Fatalf("Get before Set: %v, want ErrNoKey", err)
	}
	key := fixedKey(7)
	if err := b.Set(testID, key); err != nil {
		t.Fatal(err)
	}
	got, err := b.Get(testID)
	if err != nil || revealStr(got) != revealStr(key) {
		t.Fatalf("Get: %v", err)
	}
	stored, err := keyring.Get("qbit-vault", "master:"+testID)
	if err != nil || stored != base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)) {
		t.Fatalf("stored under service/account unexpectedly: %v", err)
	}
	if err := b.Delete(testID); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Get(testID); !errors.Is(err, ErrNoKey) {
		t.Fatalf("Get after Delete: %v", err)
	}
	if err := b.Delete(testID); !errors.Is(err, ErrNoKey) {
		t.Fatalf("second Delete: %v, want ErrNoKey", err)
	}
}

func TestOSBackendName(t *testing.T) {
	switch NewOS().Name() {
	case "macos-keychain", "windows-credential-manager", "secret-service":
	default:
		t.Fatalf("Name = %q", NewOS().Name())
	}
}

func TestOSBackendRejectsMalformedStoredKey(t *testing.T) {
	keyring.MockInit()
	for name, stored := range map[string]string{
		"not base64": "!!!notbase64",
		"short key":  base64.StdEncoding.EncodeToString([]byte("short")),
	} {
		if err := keyring.Set("qbit-vault", "master:"+testID, stored); err != nil {
			t.Fatal(err)
		}
		if _, err := NewOS().Get(testID); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("%s: err = %v, want ErrCorrupt", name, err)
		}
	}
}

func TestOSBackendProbe(t *testing.T) {
	noOS(t)
	if NewOS().Available() {
		t.Fatal("erroring keychain reported available")
	}
	keyring.MockInit()
	if !NewOS().Available() {
		t.Fatal("expected available")
	}
	// The probe must not leave its throwaway account behind.
	if _, err := keyring.Get("qbit-vault", "master:"+testID); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatalf("unexpected entry: %v", err)
	}
}

func TestOSBackendGetPropagatesBackendFailureWithoutContent(t *testing.T) {
	noOS(t)
	_, err := NewOS().Get(testID)
	if err == nil || errors.Is(err, ErrNoKey) {
		t.Fatalf("err = %v, want a non-ErrNoKey failure", err)
	}
}

// ---- Setup / Unlock with the OS backend ----

func TestSetupUnlockOSMode(t *testing.T) {
	keyring.MockInit()
	home := t.TempDir()
	key, mode, err := Setup(home, testID, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if key.Len() != 32 || mode != Mode(NewOS().Name()) {
		t.Fatalf("len=%d mode=%s", key.Len(), mode)
	}
	if _, err := os.Stat(filepath.Join(home, "key.enc")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("OS mode must not write key.enc")
	}
	got, mode2, err := Unlock(home, testID, Options{})
	if err != nil || mode2 != mode || revealStr(got) != revealStr(key) {
		t.Fatalf("Unlock: %v", err)
	}
	if _, _, err := Setup(home, testID, Options{}); !errors.Is(err, ErrKeyExists) {
		t.Fatalf("second Setup: %v, want ErrKeyExists", err)
	}
	if _, _, err := Unlock(t.TempDir(), "11111111-1111-4111-8111-111111111111", Options{}); !errors.Is(err, ErrNoKey) {
		t.Fatalf("Unlock without key: %v, want ErrNoKey", err)
	}
}

func TestSetupFallsBackToPassphraseWhenKeychainUnavailable(t *testing.T) {
	cheapKDF(t)
	noOS(t)
	home := t.TempDir()
	var asked int
	var confirms []bool
	key, mode, err := Setup(home, testID, Options{Passphrase: countingPass(fixturePass, &asked, &confirms), getenv: env(nil)})
	if err != nil {
		t.Fatal(err)
	}
	if mode != ModePassphrase || key.Len() != 32 {
		t.Fatalf("mode=%s len=%d", mode, key.Len())
	}
	if asked != 1 || !confirms[0] {
		t.Fatalf("asked=%d confirms=%v, want one confirming ask", asked, confirms)
	}
	if _, err := os.Stat(filepath.Join(home, "key.enc")); err != nil {
		t.Fatal(err)
	}
	got, mode, err := Unlock(home, testID, Options{Passphrase: pass(fixturePass), getenv: env(nil)})
	if err != nil || mode != ModePassphrase || revealStr(got) != revealStr(key) {
		t.Fatalf("Unlock: %v", err)
	}
}

func TestSetupWithoutAnyBackendIsTypedError(t *testing.T) {
	noOS(t)
	if _, _, err := Setup(t.TempDir(), testID, Options{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
}

func TestSetupForcePassphraseSkipsKeychain(t *testing.T) {
	cheapKDF(t)
	keyring.MockInit()
	home := t.TempDir()
	opts := Options{ForcePassphrase: true, Passphrase: pass(fixturePass), getenv: env(nil)}
	_, mode, err := Setup(home, testID, opts)
	if err != nil || mode != ModePassphrase {
		t.Fatalf("mode=%s err=%v", mode, err)
	}
	if _, err := keyring.Get("qbit-vault", "master:"+testID); err == nil {
		t.Fatal("key leaked into the OS keychain in forced passphrase mode")
	}
	if _, _, err := Setup(home, testID, opts); !errors.Is(err, ErrKeyExists) {
		t.Fatalf("second Setup: %v, want ErrKeyExists", err)
	}
}

func TestSetupRefusesWhenKeyFileExists(t *testing.T) {
	cheapKDF(t)
	keyring.MockInit()
	home := t.TempDir()
	opts := Options{ForcePassphrase: true, Passphrase: pass(fixturePass), getenv: env(nil)}
	if _, _, err := Setup(home, testID, opts); err != nil {
		t.Fatal(err)
	}
	// key.enc exists, so an OS-mode Setup for the same id must refuse too.
	if _, _, err := Setup(home, testID, Options{}); !errors.Is(err, ErrKeyExists) {
		t.Fatalf("err = %v, want ErrKeyExists", err)
	}
}

func TestSetupRejectsBadVaultID(t *testing.T) {
	for _, id := range []string{"", "../x", "a/b", "NOT-HEX"} {
		if _, _, err := Setup(t.TempDir(), id, Options{}); err == nil {
			t.Fatalf("Setup accepted id %q", id)
		}
		if _, _, err := Unlock(t.TempDir(), id, Options{}); err == nil {
			t.Fatalf("Unlock accepted id %q", id)
		}
	}
}

// ---- Passphrase backend ----

func TestPassphraseRoundTripAndFileShape(t *testing.T) {
	cheapKDF(t)
	home := t.TempDir()
	key := fixedKey(3)
	if err := writeKeyFile(home, key, secret.New("p", []byte(fixturePass))); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(home, "key.enc"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"qbit-vault-key/1"`, `"argon2id"`, `"salt"`, `"t"`, `"m_kib"`, `"p"`, `"nonce"`, `"ct"`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("key.enc missing %s", want)
		}
	}
	got, err := readKeyFile(home, secret.New("p", []byte(fixturePass)))
	if err != nil || revealStr(got) != revealStr(key) {
		t.Fatalf("read: %v", err)
	}
	if isPOSIX() {
		fi, _ := os.Stat(filepath.Join(home, "key.enc"))
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("key.enc mode %v", fi.Mode().Perm())
		}
	}
	entries, _ := os.ReadDir(home)
	if len(entries) != 1 {
		t.Fatalf("leftover files after atomic write: %v", entries)
	}
}

func TestPassphraseFreshSaltAndNonce(t *testing.T) {
	cheapKDF(t)
	key := fixedKey(3)
	a, b := t.TempDir(), t.TempDir()
	for _, h := range []string{a, b} {
		if err := writeKeyFile(h, key, secret.New("p", []byte(fixturePass))); err != nil {
			t.Fatal(err)
		}
	}
	fa, _ := os.ReadFile(filepath.Join(a, "key.enc"))
	fb, _ := os.ReadFile(filepath.Join(b, "key.enc"))
	if bytes.Equal(fa, fb) {
		t.Fatal("two wraps of the same key are identical: salt/nonce reused")
	}
}

func TestWrongPassphrase(t *testing.T) {
	cheapKDF(t)
	home := t.TempDir()
	if err := writeKeyFile(home, fixedKey(3), secret.New("p", []byte(fixturePass))); err != nil {
		t.Fatal(err)
	}
	_, err := readKeyFile(home, secret.New("p", []byte(fixtureOther)))
	if !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("err = %v, want ErrBadPassphrase", err)
	}
	for _, s := range []string{fixtureOther, fixturePass} {
		if strings.Contains(err.Error(), s) {
			t.Fatal("error echoes a passphrase")
		}
	}
}

func TestEmptyPassphrase(t *testing.T) {
	cheapKDF(t)
	noOS(t)
	for _, p := range []string{"", "   ", "\t\n "} {
		home := t.TempDir()
		_, _, err := Setup(home, testID, Options{Passphrase: pass(p), getenv: env(nil)})
		if !errors.Is(err, ErrEmptyPassphrase) {
			t.Fatalf("Setup(%q): %v, want ErrEmptyPassphrase", p, err)
		}
		if _, statErr := os.Stat(filepath.Join(home, "key.enc")); statErr == nil {
			t.Fatal("key.enc written for an empty passphrase")
		}
	}
}

func TestPassphraseCallbackErrorPropagates(t *testing.T) {
	cheapKDF(t)
	noOS(t)
	boom := errors.New("user cancelled")
	_, _, err := Setup(t.TempDir(), testID, Options{Passphrase: func(bool) (secret.Secret, error) { return secret.Secret{}, boom }, getenv: env(nil)})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
}

func TestTamperedKeyFile(t *testing.T) {
	cheapKDF(t)
	home := t.TempDir()
	if err := writeKeyFile(home, fixedKey(3), secret.New("p", []byte(fixturePass))); err != nil {
		t.Fatal(err)
	}
	good, err := os.ReadFile(filepath.Join(home, "key.enc"))
	if err != nil {
		t.Fatal(err)
	}
	flip := func(target map[string]any, field string) {
		raw, _ := base64.StdEncoding.DecodeString(target[field].(string))
		raw[0] ^= 1
		target[field] = base64.StdEncoding.EncodeToString(raw)
	}
	kdf := func(m map[string]any) map[string]any { return m["kdf"].(map[string]any) }
	tests := []struct {
		name string
		fn   func(map[string]any)
		want error
	}{
		{"salt", func(m map[string]any) { flip(kdf(m), "salt") }, ErrBadPassphrase},
		{"nonce", func(m map[string]any) { flip(m, "nonce") }, ErrBadPassphrase},
		{"ct", func(m map[string]any) { flip(m, "ct") }, ErrBadPassphrase},
		{"t within bounds", func(m map[string]any) { kdf(m)["t"] = 2 }, ErrBadPassphrase},
		{"p within bounds", func(m map[string]any) { kdf(m)["p"] = 2 }, ErrBadPassphrase},
		{"m within bounds", func(m map[string]any) { kdf(m)["m_kib"] = 2048 }, ErrBadPassphrase},
		{"t too high", func(m map[string]any) { kdf(m)["t"] = 11 }, ErrCorrupt},
		{"t zero", func(m map[string]any) { kdf(m)["t"] = 0 }, ErrCorrupt},
		{"m too low", func(m map[string]any) { kdf(m)["m_kib"] = 8 }, ErrCorrupt},
		{"m too high", func(m map[string]any) { kdf(m)["m_kib"] = 4194304 }, ErrCorrupt},
		{"p too high", func(m map[string]any) { kdf(m)["p"] = 17 }, ErrCorrupt},
		{"p zero", func(m map[string]any) { kdf(m)["p"] = 0 }, ErrCorrupt},
		{"alg", func(m map[string]any) { kdf(m)["alg"] = "scrypt" }, ErrCorrupt},
		{"format", func(m map[string]any) { m["format"] = "qbit-vault-key/2" }, ErrCorrupt},
		{"short salt", func(m map[string]any) { kdf(m)["salt"] = base64.StdEncoding.EncodeToString([]byte("short")) }, ErrCorrupt},
		{"short nonce", func(m map[string]any) { m["nonce"] = base64.StdEncoding.EncodeToString([]byte("short")) }, ErrCorrupt},
		{"bad b64 ct", func(m map[string]any) { m["ct"] = "!!!" }, ErrCorrupt},
		{"unknown field", func(m map[string]any) { m["extra"] = 1 }, ErrCorrupt},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := t.TempDir()
			if err := os.WriteFile(filepath.Join(h, "key.enc"), mutateJSON(t, good, tt.fn), 0o600); err != nil {
				t.Fatal(err)
			}
			key, err := readKeyFile(h, secret.New("p", []byte(fixturePass)))
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if key.Len() != 0 {
				t.Fatal("key returned with error")
			}
		})
	}
	for name, content := range map[string][]byte{"not json": []byte("nope"), "empty": nil, "array": []byte("[]")} {
		h := t.TempDir()
		if err := os.WriteFile(filepath.Join(h, "key.enc"), content, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readKeyFile(h, secret.New("p", []byte(fixturePass))); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("%s: err = %v, want ErrCorrupt", name, err)
		}
	}
}

func TestOutOfBoundsParamsRejectedBeforeArgon2(t *testing.T) {
	// Production floor, and a 4 TiB memory request: must fail fast and cheap.
	home := t.TempDir()
	body := `{"format":"qbit-vault-key/1","kdf":{"alg":"argon2id","salt":"` +
		base64.StdEncoding.EncodeToString(make([]byte, 16)) + `","t":3,"m_kib":4000000000,"p":4},"nonce":"` +
		base64.StdEncoding.EncodeToString(make([]byte, 24)) + `","ct":"AAAA"}`
	if err := os.WriteFile(filepath.Join(home, "key.enc"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err := readKeyFile(home, secret.New("p", []byte(fixturePass)))
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err = %v, want ErrCorrupt", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("bounds check ran after Argon2")
	}
}

func TestProductionKDFParams(t *testing.T) {
	if testing.Short() {
		t.Skip("runs Argon2id with 64 MiB")
	}
	home := t.TempDir()
	key := fixedKey(5)
	if err := writeKeyFile(home, key, secret.New("p", []byte(fixturePass))); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(home, "key.enc"))
	var f struct {
		KDF kdfParams `json:"kdf"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.KDF.T != 3 || f.KDF.MKiB != 65536 || f.KDF.P != 4 || f.KDF.Alg != "argon2id" {
		t.Fatalf("params = %+v", f.KDF)
	}
	got, err := readKeyFile(home, secret.New("p", []byte(fixturePass)))
	if err != nil || revealStr(got) != revealStr(key) {
		t.Fatalf("read: %v", err)
	}
}

// ---- Unlock cache ----

func cacheOpts(dir string) Options {
	return Options{goos: "linux", getenv: env(map[string]string{"XDG_RUNTIME_DIR": dir})}
}

func TestCacheHitAvoidsPrompt(t *testing.T) {
	cheapKDF(t)
	noOS(t)
	home, run := t.TempDir(), t.TempDir()
	var asked int
	opts := cacheOpts(run)
	opts.Passphrase = countingPass(fixturePass, &asked, nil)
	key, _, err := Setup(home, testID, opts)
	if err != nil {
		t.Fatal(err)
	}
	asked = 0
	for i := 0; i < 3; i++ {
		got, mode, err := Unlock(home, testID, opts)
		if err != nil || mode != ModePassphrase || revealStr(got) != revealStr(key) {
			t.Fatalf("Unlock %d: %v", i, err)
		}
	}
	if asked != 0 {
		t.Fatalf("passphrase asked %d times despite a warm cache", asked)
	}
	fi, err := os.Stat(filepath.Join(run, "qbit-vault", testID+".key"))
	if err != nil {
		t.Fatal(err)
	}
	if isPOSIX() && fi.Mode().Perm() != 0o600 {
		t.Fatalf("cache mode %v", fi.Mode().Perm())
	}
}

func TestColdCachePromptsThenFills(t *testing.T) {
	cheapKDF(t)
	noOS(t)
	home, run := t.TempDir(), t.TempDir()
	if _, _, err := Setup(home, testID, Options{Passphrase: pass(fixturePass), getenv: env(nil)}); err != nil {
		t.Fatal(err)
	}
	var asked int
	var confirms []bool
	opts := cacheOpts(run)
	opts.Passphrase = countingPass(fixturePass, &asked, &confirms)
	if _, _, err := Unlock(home, testID, opts); err != nil {
		t.Fatal(err)
	}
	if asked != 1 || confirms[0] {
		t.Fatalf("asked=%d confirms=%v, want one non-confirm ask", asked, confirms)
	}
	if _, _, err := Unlock(home, testID, opts); err != nil || asked != 1 {
		t.Fatalf("second Unlock: err=%v asked=%d", err, asked)
	}
}

func TestExpiredCacheIgnoredAndDeleted(t *testing.T) {
	cheapKDF(t)
	noOS(t)
	home, run := t.TempDir(), t.TempDir()
	clock := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	var asked int
	opts := cacheOpts(run)
	opts.now = func() time.Time { return clock }
	opts.CacheTTL = time.Hour
	opts.Passphrase = countingPass(fixturePass, &asked, nil)
	if _, _, err := Setup(home, testID, opts); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(run, "qbit-vault", testID+".key")
	if _, err := os.Stat(cache); err != nil {
		t.Fatal(err)
	}
	asked = 0
	clock = clock.Add(time.Hour + time.Second)
	// Expired: ignored, so the prompt runs and the entry is replaced.
	if _, _, err := Unlock(home, testID, opts); err != nil || asked != 1 {
		t.Fatalf("err=%v asked=%d", err, asked)
	}
	raw, err := os.ReadFile(cache)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), clock.Add(time.Hour).Format(time.RFC3339)) {
		t.Fatal("expired entry was not replaced by a fresh expiry")
	}
	// Expired and the prompt then fails: the stale file must still be gone.
	clock = clock.Add(2 * time.Hour)
	opts.Passphrase = pass(fixtureOther)
	if _, _, err := Unlock(home, testID, opts); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(cache); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("expired cache file not deleted")
	}
}

func TestCorruptCacheIgnoredAndDeleted(t *testing.T) {
	cheapKDF(t)
	noOS(t)
	home, run := t.TempDir(), t.TempDir()
	if _, _, err := Setup(home, testID, Options{Passphrase: pass(fixturePass), getenv: env(nil)}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(run, "qbit-vault")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(dir, testID+".key")
	if err := os.WriteFile(cache, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	var asked int
	opts := cacheOpts(run)
	opts.Passphrase = countingPass(fixturePass, &asked, nil)
	if _, _, err := Unlock(home, testID, opts); err != nil || asked != 1 {
		t.Fatalf("err=%v asked=%d", err, asked)
	}
}

func TestNoRuntimeDirMeansNoCache(t *testing.T) {
	cheapKDF(t)
	noOS(t)
	home, tmp := t.TempDir(), t.TempDir()
	t.Setenv("TMPDIR", tmp)
	t.Setenv("TEMP", tmp)
	t.Setenv("TMP", tmp)
	var asked int
	opts := Options{getenv: env(nil), Passphrase: countingPass(fixturePass, &asked, nil)}
	if _, _, err := Setup(home, testID, opts); err != nil {
		t.Fatal(err)
	}
	asked = 0
	for i := 0; i < 2; i++ {
		if _, _, err := Unlock(home, testID, opts); err != nil {
			t.Fatal(err)
		}
	}
	if asked != 2 {
		t.Fatalf("asked=%d, want 2 (no cache)", asked)
	}
	// A set-but-missing runtime dir also disables the cache and is not created.
	missing := filepath.Join(tmp, "missing")
	opts.getenv = env(map[string]string{"XDG_RUNTIME_DIR": missing})
	if _, _, err := Unlock(home, testID, opts); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(missing); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("cache created a missing runtime directory")
	}
	for _, root := range []string{home, tmp} {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err == nil && (strings.HasSuffix(p, ".key") || strings.Contains(p, "qbit-vault")) {
				t.Errorf("unexpected cache artifact %s", filepath.Base(p))
			}
			return nil
		})
	}
}

func TestLockDeletesCache(t *testing.T) {
	cheapKDF(t)
	noOS(t)
	home, run := t.TempDir(), t.TempDir()
	opts := cacheOpts(run)
	opts.Passphrase = pass(fixturePass)
	if _, _, err := Setup(home, testID, opts); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(run, "qbit-vault", testID+".key")
	if _, err := os.Stat(cache); err != nil {
		t.Fatal(err)
	}
	if err := Lock(testID, opts); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cache); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("cache survived Lock")
	}
	if err := Lock(testID, opts); err != nil {
		t.Fatalf("Lock without cache: %v", err)
	}
	if err := Lock(testID, Options{getenv: env(nil)}); err != nil {
		t.Fatalf("Lock without runtime dir: %v", err)
	}
	if err := Lock("../evil", opts); err == nil {
		t.Fatal("Lock accepted a path-like id")
	}
}

// ---- Leaks ----

func TestPassphraseModeLeavesNoSecretOnDisk(t *testing.T) {
	cheapKDF(t)
	noOS(t)
	home := t.TempDir()
	key, _, err := Setup(home, testID, Options{Passphrase: pass(fixturePass), getenv: env(nil)})
	if err != nil {
		t.Fatal(err)
	}
	kb := key.Reveal()
	defer clear(kb)
	needles := map[string][]byte{}
	for name, v := range map[string][]byte{"passphrase": []byte(fixturePass), "master key": kb} {
		needles[name+" raw"] = v
		needles[name+" b64"] = []byte(base64.StdEncoding.EncodeToString(v))
		needles[name+" b64url"] = []byte(base64.RawURLEncoding.EncodeToString(v))
		needles[name+" hex"] = []byte(hex.EncodeToString(v))
	}
	files := 0
	err = filepath.WalkDir(home, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		files++
		data, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		for name, n := range needles {
			if bytes.Contains(data, n) {
				t.Errorf("%s found in %s", name, filepath.Base(p))
			}
		}
		return nil
	})
	if err != nil || files == 0 {
		t.Fatalf("walk: err=%v files=%d", err, files)
	}
}

func TestErrorsNeverContainPassphrase(t *testing.T) {
	cheapKDF(t)
	noOS(t)
	home := t.TempDir()
	if _, _, err := Setup(home, testID, Options{Passphrase: pass(fixturePass), getenv: env(nil)}); err != nil {
		t.Fatal(err)
	}
	_, _, err := Unlock(home, testID, Options{Passphrase: pass(fixtureOther), getenv: env(nil)})
	if err == nil {
		t.Fatal("expected error")
	}
	for _, s := range []string{fixturePass, fixtureOther} {
		if strings.Contains(err.Error(), s) {
			t.Fatal("error contains passphrase")
		}
	}
}

// ---- Integration with the vault ----

func TestSetupVaultInitUnlockOpenResolve(t *testing.T) {
	cheapKDF(t)
	for _, tc := range []struct {
		name string
		opts Options
	}{
		{"os keychain", Options{}},
		{"passphrase", Options{ForcePassphrase: true, Passphrase: pass(fixturePass), getenv: env(nil)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keyring.MockInit()
			home := filepath.Join(t.TempDir(), "home")
			id := vault.NewID()
			key, _, err := Setup(home, id, tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			v, err := vault.Init(home, id, key)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := vault.ReadID(home); err != nil || got != id {
				t.Fatalf("ReadID = %q, %v", got, err)
			}
			rec := vault.Record{Value: secret.New("TESTSECRET_NAME", []byte("TESTSECRET_value_integration"))}
			if err := v.Put(vault.Global(), "TESTSECRET_NAME", rec); err != nil {
				t.Fatal(err)
			}
			id2, err := vault.ReadID(home)
			if err != nil {
				t.Fatal(err)
			}
			key2, _, err := Unlock(home, id2, tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			v2, err := vault.Open(home, key2)
			if err != nil {
				t.Fatal(err)
			}
			got, _, err := v2.Resolve("TESTSECRET_NAME", home)
			if err != nil || revealStr(got.Value) != "TESTSECRET_value_integration" {
				t.Fatalf("Resolve: %v", err)
			}
		})
	}
}

// errBackend is a keychain that is reachable but fails every read.
type errBackend struct{ err error }

func (errBackend) Name() string                        { return "test-keychain" }
func (b errBackend) Get(string) (secret.Secret, error) { return secret.Secret{}, b.err }
func (errBackend) Set(string, secret.Secret) error     { return nil }
func (errBackend) Delete(string) error                 { return nil }

// B-F11: Setup in passphrase mode must not treat a keychain it could not read
// as "no key there": an entry may exist behind the failure.
func TestSetupPassphraseReportsKeychainReadError(t *testing.T) {
	cheapKDF(t)
	boom := errors.New("keychain locked")
	home := t.TempDir()
	opts := Options{ForcePassphrase: true, Passphrase: pass(fixturePass), getenv: env(nil), backend: errBackend{boom}}
	if _, _, err := Setup(home, testID, opts); !errors.Is(err, boom) {
		t.Fatalf("Setup = %v, want the keychain error", err)
	}
	if _, err := os.Stat(filepath.Join(home, "key.enc")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("key.enc was written despite the keychain error")
	}
}

func TestSetupPassphraseIgnoresMissingKeychainEntry(t *testing.T) {
	cheapKDF(t)
	home := t.TempDir()
	opts := Options{ForcePassphrase: true, Passphrase: pass(fixturePass), getenv: env(nil), backend: errBackend{ErrNoKey}}
	k, mode, err := Setup(home, testID, opts)
	if err != nil || mode != ModePassphrase {
		t.Fatalf("Setup = %v, %v", mode, err)
	}
	k.Wipe()
}
