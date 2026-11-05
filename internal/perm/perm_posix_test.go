//go:build !windows

package perm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mode(t *testing.T, p string) os.FileMode {
	t.Helper()
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

func TestPosixEnsureTightensWiderModes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "d")
	f := filepath.Join(dir, "f")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f, nil, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil { // umask may have narrowed it
		t.Fatal(err)
	}
	if err := os.Chmod(f, 0o644); err != nil {
		t.Fatal(err)
	}
	if ok, detail := Check(dir); ok || !strings.Contains(detail, "0755") || !strings.Contains(detail, "0700") {
		t.Fatalf("Check(dir) = %v, %q", ok, detail)
	}
	if ok, detail := Check(f); ok || !strings.Contains(detail, "0644") || !strings.Contains(detail, "0600") {
		t.Fatalf("Check(file) = %v, %q", ok, detail)
	}
	if err := EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := EnsureFile(f); err != nil {
		t.Fatal(err)
	}
	if m := mode(t, dir); m != 0o700 {
		t.Fatalf("dir mode %o, want 700", m)
	}
	if m := mode(t, f); m != 0o600 {
		t.Fatalf("file mode %o, want 600", m)
	}
}

func TestPosixStricterModesAreAccepted(t *testing.T) {
	f := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(f, nil, 0o400); err != nil {
		t.Fatal(err)
	}
	if ok, detail := Check(f); !ok {
		t.Fatalf("0400 reported wide: %s", detail)
	}
}
