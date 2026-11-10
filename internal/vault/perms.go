package vault

import (
	"fmt"

	"github.com/qbitdevz/qbit-vault/internal/perm"
)

// secureDir and secureFile make a path owner-only (R-VAULT-03, docs/STORAGE.md
// § File permissions). They are called as each directory or file is created,
// before any secret-bearing bytes land in it or it replaces a live file, and
// they are cheap when the path is already private.
func secureDir(path, what string) error {
	if err := perm.EnsureDir(path); err != nil {
		return fmt.Errorf("vault: secure %s: %w", what, err)
	}
	return nil
}

func secureFile(path, what string) error {
	if err := perm.EnsureFile(path); err != nil {
		return fmt.Errorf("vault: secure %s: %w", what, err)
	}
	return nil
}
