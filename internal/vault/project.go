package vault

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ProjectRoot returns the canonical repository root of cwd: the nearest
// ancestor containing a .git entry (a directory, or the file of a linked
// worktree). The root is absolute, symlink-free and, on Windows and macOS,
// case-folded. ok is false when cwd is not inside a repository.
func ProjectRoot(cwd string) (root string, ok bool, err error) {
	root, _, ok, err = findRoot(cwd)
	return root, ok, err
}

// ProjectLayer returns the project layer for cwd, or ErrNoProject outside a
// repository.
func ProjectLayer(cwd string) (Layer, error) {
	root, label, ok, err := findRoot(cwd)
	if err != nil {
		return Layer{}, err
	}
	if !ok {
		return Layer{}, ErrNoProject
	}
	return Layer{Project: true, Root: root, Label: label}, nil
}

// walkStop is a test seam: when set, the upward search never inspects this
// directory or anything above it, so tests are isolated from checkouts that
// happen to contain the temp directory.
var walkStop string

func findRoot(cwd string) (root, label string, ok bool, err error) {
	abs, err := filepath.Abs(cwd)
	if err != nil {
		return "", "", false, errors.New("vault: cannot resolve working directory")
	}
	dir, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", "", false, errors.New("vault: cannot resolve working directory")
	}
	for {
		if walkStop != "" && foldCase(dir) == foldCase(walkStop) {
			return "", "", false, nil
		}
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return foldCase(dir), filepath.Base(dir), true, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", "", false, nil
		}
		dir = parent
	}
}

func foldCase(p string) string {
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		return strings.ToLower(p)
	}
	return p
}
