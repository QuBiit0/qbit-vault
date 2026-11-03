package keychain

import (
	"os"
	"path/filepath"
	"testing"
)

// A relative XDG_RUNTIME_DIR is not trusted as memory-backed storage: no cache
// directory is used, so the key never lands on ordinary disk under cwd.
func TestCacheDirRejectsRelativeRuntimeDir(t *testing.T) {
	cwd := t.TempDir()
	if err := os.Mkdir(filepath.Join(cwd, "rel"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(cwd)
	if got := cacheDir(Options{getenv: env(map[string]string{"XDG_RUNTIME_DIR": "rel"})}); got != "" {
		t.Fatalf("relative XDG_RUNTIME_DIR accepted as cache dir")
	}
	abs := filepath.Join(cwd, "rel")
	if got := cacheDir(Options{getenv: env(map[string]string{"XDG_RUNTIME_DIR": abs})}); got != filepath.Join(abs, "gentle-vault") {
		t.Fatalf("absolute XDG_RUNTIME_DIR rejected")
	}
}
