package perm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckMissingPath(t *testing.T) {
	ok, detail := Check(filepath.Join(t.TempDir(), "nope"))
	if ok || detail == "" {
		t.Fatalf("Check(missing) = %v, %q", ok, detail)
	}
}

func TestEnsureThenCheck(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "home")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := EnsureDir(dir); err != nil {
		t.Fatalf("EnsureDir: %v", err)
	}
	if ok, detail := Check(dir); !ok {
		t.Fatalf("dir not private after EnsureDir: %s", detail)
	}
	f := filepath.Join(dir, "vault.enc")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := EnsureFile(f); err != nil {
		t.Fatalf("EnsureFile: %v", err)
	}
	if ok, detail := Check(f); !ok {
		t.Fatalf("file not private after EnsureFile: %s", detail)
	}
	// Idempotent, and the contents are untouched.
	if err := EnsureFile(f); err != nil {
		t.Fatalf("second EnsureFile: %v", err)
	}
	if b, _ := os.ReadFile(f); string(b) != "x" {
		t.Fatal("EnsureFile changed the contents")
	}
}

func TestEnsureErrorsOmitPath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "pathmarker")
	for name, err := range map[string]error{"dir": EnsureDir(missing), "file": EnsureFile(missing)} {
		if err == nil {
			t.Fatalf("%s: Ensure on a missing path succeeded", name)
		}
		if strings.Contains(err.Error(), "pathmarker") {
			t.Fatalf("%s: error contains the path", name)
		}
	}
}
