package filemerge

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func runtimeIsWindows() bool { return runtime.GOOS == "windows" }

func TestWriteAtomicCreatesFileAndParents(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a", "b", "c.json")
	if err := writeAtomic(p, []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, p); got != "{}\n" {
		t.Fatalf("content %q", got)
	}
}

func TestWriteAtomicKeepsMode(t *testing.T) {
	if runtimeIsWindows() {
		t.Skip("POSIX modes only")
	}
	p := filepath.Join(t.TempDir(), "c.json")
	writeFile(t, p, "old")
	if err := os.Chmod(p, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(p, []byte("new")); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(p)
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode %o, want 640", info.Mode().Perm())
	}
}

func TestWriteAtomicFailureLeavesOriginalAndNoTemp(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	writeFile(t, p, "original")
	boom := errors.New("simulated crash")
	prev := beforeRename
	beforeRename = func(string, string) error { return boom }
	defer func() { beforeRename = prev }()

	if err := writeAtomic(p, []byte("replacement")); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if got := readFile(t, p); got != "original" {
		t.Fatalf("original damaged: %q", got)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("leftover files: %v", entries)
	}
}

func TestWriteAtomicRenameFailureLeavesOriginal(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	writeFile(t, p, "original")
	prev := renameFile
	renameFile = func(string, string) error { return errors.New("denied") }
	defer func() { renameFile = prev }()
	if err := writeAtomic(p, []byte("x")); err == nil {
		t.Fatal("expected error")
	}
	if got := readFile(t, p); got != "original" {
		t.Fatalf("original damaged: %q", got)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("leftover files: %v", entries)
	}
}

func TestWriteAtomicRefusesSymlinkAndDirectory(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.json")
	writeFile(t, real, "keep")
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(real, link); err == nil {
		if err := writeAtomic(link, []byte("x")); !errors.Is(err, ErrSymlink) {
			t.Fatalf("symlink: %v", err)
		}
		if got := readFile(t, real); got != "keep" {
			t.Fatalf("symlink target modified: %q", got)
		}
		if fi, _ := os.Lstat(link); fi.Mode()&os.ModeSymlink == 0 {
			t.Fatal("symlink was replaced")
		}
	}
	sub := filepath.Join(dir, "d")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(sub, []byte("x")); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("dir: %v", err)
	}
}

func TestErrorsNeverCarryContents(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.json")
	writeFile(t, p, `{"TESTSECRET_leak": oops}`)
	_, err := MergeJSON([]byte(`{"TESTSECRET_leak": oops}`), []JSONEdit{{Path: []string{"a"}, Value: []byte(`1`)}})
	if err == nil || strings.Contains(err.Error(), "TESTSECRET_") {
		t.Fatalf("err = %v", err)
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
