package keychain

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/QuBiit0/gentle-vault/internal/perm"
	"github.com/QuBiit0/gentle-vault/internal/secret"
)

// The unlock cache lives only in a memory-backed runtime directory
// ($XDG_RUNTIME_DIR, tmpfs on Linux). Where none exists there is no cache and
// the passphrase is asked on every unlock (docs/STORAGE.md § Master key).

type cacheEntry struct {
	ExpiresAt string `json:"expires_at"`
	Key       string `json:"key"`
}

// cacheDir returns the cache directory, or "" when caching is off: not on
// Linux, or the variable is unset, relative, or not an existing directory.
func cacheDir(opts Options) string {
	// Only Linux's XDG_RUNTIME_DIR is known to be memory-backed (tmpfs).
	if opts.platform() != "linux" {
		return ""
	}
	run := opts.env("XDG_RUNTIME_DIR")
	// A relative value would resolve against cwd, which is ordinary disk.
	if run == "" || !filepath.IsAbs(run) {
		return ""
	}
	if fi, err := os.Stat(run); err != nil || !fi.IsDir() {
		return ""
	}
	return filepath.Join(run, "gentle-vault")
}

// cacheGet returns the cached key. An expired or unreadable entry is deleted
// and ignored.
func cacheGet(opts Options, vaultID string) (secret.Secret, bool) {
	dir := cacheDir(opts)
	if dir == "" {
		return secret.Secret{}, false
	}
	path := filepath.Join(dir, vaultID+".key")
	data, err := os.ReadFile(path)
	if err != nil {
		return secret.Secret{}, false
	}
	defer clear(data)
	var (
		e   cacheEntry
		exp time.Time
		raw []byte
	)
	err = json.Unmarshal(data, &e)
	if err == nil {
		exp, err = time.Parse(time.RFC3339, e.ExpiresAt)
	}
	if err == nil {
		raw, err = base64.StdEncoding.DecodeString(e.Key)
	}
	defer clear(raw)
	if err != nil || len(raw) != keySize || !opts.clock().Before(exp) {
		_ = os.Remove(path)
		return secret.Secret{}, false
	}
	return secret.New("master", raw), true
}

// cachePut stores key best-effort; failures are silent because the cache is
// only a convenience.
func cachePut(opts Options, vaultID string, key secret.Secret) {
	cachePutUntil(opts, vaultID, key, opts.clock().Add(opts.ttl()))
}

// cachePutUntil is cachePut with an explicit expiry.
func cachePutUntil(opts Options, vaultID string, key secret.Secret, exp time.Time) {
	dir := cacheDir(opts)
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	if err := perm.EnsureDir(dir); err != nil {
		return
	}
	raw := key.Reveal()
	defer clear(raw)
	enc := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
	defer clear(enc)
	base64.StdEncoding.Encode(enc, raw)
	body, err := json.Marshal(cacheEntry{
		ExpiresAt: exp.UTC().Format(time.RFC3339),
		Key:       string(enc),
	})
	if err != nil {
		return
	}
	defer clear(body)
	_ = writeAtomic(dir, vaultID+".key", body)
}

// cacheDelete removes the cache file; absent is fine.
func cacheDelete(opts Options, vaultID string) error {
	dir := cacheDir(opts)
	if dir == "" {
		return nil
	}
	err := os.Remove(filepath.Join(dir, vaultID+".key"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("keychain: delete unlock cache failed")
	}
	return nil
}
