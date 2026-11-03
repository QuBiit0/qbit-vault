// Package perm enforces owner-only access on the vault home and its files
// (docs/STORAGE.md § File permissions, R-VAULT-03): directories 0700 and
// files 0600 on POSIX, a protected DACL granting only the current user on
// Windows. Errors never contain the path.
package perm

// EnsureDir restricts the directory at path to the current user. On Windows
// the ACE is inheritable, so files created inside later start out private.
func EnsureDir(path string) error { return ensure(path, true) }

// EnsureFile restricts the file at path to the current user.
func EnsureFile(path string) error { return ensure(path, false) }

// Check reports whether path is already owner-only. When it is not, detail
// says why in fixed words (no path, no account names).
func Check(path string) (ok bool, detail string) { return check(path) }
