package keychain

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/QuBiit0/qbit-vault/internal/secret"
)

// A relative XDG_RUNTIME_DIR is not trusted as memory-backed storage: no cache
// directory is used, so the key never lands on ordinary disk under cwd.
func TestCacheDirRejectsRelativeRuntimeDir(t *testing.T) {
	cwd := t.TempDir()
	if err := os.Mkdir(filepath.Join(cwd, "rel"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(cwd)
	if got := cacheDir(Options{goos: "linux", getenv: env(map[string]string{"XDG_RUNTIME_DIR": "rel"})}); got != "" {
		t.Fatalf("relative XDG_RUNTIME_DIR accepted as cache dir")
	}
	abs := filepath.Join(cwd, "rel")
	if got := cacheDir(Options{goos: "linux", getenv: env(map[string]string{"XDG_RUNTIME_DIR": abs})}); got != filepath.Join(abs, "qbit-vault") {
		t.Fatalf("absolute XDG_RUNTIME_DIR rejected")
	}
}

// The unlock cache exists only on Linux, whatever XDG_RUNTIME_DIR says:
// elsewhere a runtime dir is not known to be memory-backed.
func TestCacheDirOnlyOnLinux(t *testing.T) {
	abs := t.TempDir()
	for _, goos := range []string{"windows", "darwin", "freebsd"} {
		opts := Options{goos: goos, getenv: env(map[string]string{"XDG_RUNTIME_DIR": abs})}
		if got := cacheDir(opts); got != "" {
			t.Fatalf("cache enabled on %s", goos)
		}
	}
	opts := Options{goos: "linux", getenv: env(map[string]string{"XDG_RUNTIME_DIR": abs})}
	if got := cacheDir(opts); got == "" {
		t.Fatalf("cache disabled on linux")
	}
}

// B-F2: on Linux the cache is used only when XDG_RUNTIME_DIR is memory-backed;
// on a disk path there is no cache and nothing is written.
func TestCacheDirNeedsMemoryBackedStorage(t *testing.T) {
	abs := t.TempDir()
	old := memoryBacked
	t.Cleanup(func() { memoryBacked = old })

	memoryBacked = func(string) bool { return false }
	opts := Options{goos: "linux", getenv: env(map[string]string{"XDG_RUNTIME_DIR": abs})}
	if got := cacheDir(opts); got != "" {
		t.Fatalf("cache enabled on a disk-backed runtime dir")
	}
	cachePutUntil(opts, testID, secret.New("master", make([]byte, keySize)), time.Now().Add(time.Hour))
	if entries, err := os.ReadDir(abs); err != nil || len(entries) != 0 {
		t.Fatalf("something was written to a disk-backed runtime dir: %v %v", entries, err)
	}
	if _, ok := cacheGet(opts, testID); ok {
		t.Fatal("cache read on a disk-backed runtime dir")
	}

	memoryBacked = func(dir string) bool { return dir == abs }
	if got := cacheDir(opts); got != filepath.Join(abs, "qbit-vault") {
		t.Fatalf("cache disabled on a memory-backed runtime dir")
	}
}

// The real check recognizes tmpfs through statfs; other platforms keep
// today's behavior (the seam answers true, the cache is off anyway).
func TestMemoryBackedRealCheck(t *testing.T) {
	if runtime.GOOS != "linux" {
		if !onMemory(t.TempDir()) {
			t.Fatal("non-Linux check must stay true")
		}
		return
	}
	if onMemory(filepath.Join(t.TempDir(), "missing")) {
		t.Fatal("a missing directory is not memory-backed")
	}
	if fi, err := os.Stat("/dev/shm"); err == nil && fi.IsDir() && !onMemory("/dev/shm") {
		t.Fatal("/dev/shm is tmpfs")
	}
}
