package vault

import (
	"os"
	"path/filepath"
)

// Relink repoints the project layer of oldRoot to newRoot, for a repository
// that was moved or re-cloned. It returns the number of secrets in the layer.
//
// Both paths are canonicalized like ProjectRoot (absolute, symlink-free,
// case-folded on Windows and macOS). oldRoot need not exist on disk, but it
// must be a project layer in the vault (ErrNotFound). newRoot must be an
// existing directory that itself contains .git (ErrNoProject otherwise) and
// must not already be a project layer (ErrExists). The move is one atomic
// vault write and the layer's label becomes the base name of newRoot.
func (v *Vault) Relink(oldRoot, newRoot string) (int, error) {
	n, _, err := v.RelinkWithGrants(oldRoot, newRoot, nil)
	return n, err
}

// repoRoot canonicalizes dir, which must be the root of a repository.
func repoRoot(dir string) (root, label string, err error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", "", ErrNoProject
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", "", ErrNoProject
	}
	if info, err := os.Stat(real); err != nil || !info.IsDir() {
		return "", "", ErrNoProject
	}
	if _, err := os.Lstat(filepath.Join(real, ".git")); err != nil {
		return "", "", ErrNoProject
	}
	return foldCase(real), filepath.Base(real), nil
}

// looseRoot canonicalizes a path that may no longer exist: symlinks are
// resolved when possible, otherwise the cleaned absolute path is used.
func looseRoot(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return foldCase(filepath.Clean(p))
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		abs = real
	}
	return foldCase(abs)
}
