package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/qbitdevz/qbit-vault/internal/secret"
)

// backupIDRE matches a snapshot directory name: the fixed-width UTC layout of
// backupTimeFormat plus the optional same-tick suffix.
var backupIDRE = regexp.MustCompile(`^\d{8}T\d{6}\.\d{9}Z(-\d{3})?$`)

// ErrBackupKey means no known key opens a snapshot: neither the current one
// nor a retired one. It satisfies errors.Is(err, ErrCorrupt).
var ErrBackupKey = fmt.Errorf("%w: backup cannot be opened with the current or a retired key", ErrCorrupt)

// ValidBackupID reports whether id names a snapshot directory. Only valid ids
// are ever joined into a path or shown in a message.
func ValidBackupID(id string) bool { return backupIDRE.MatchString(id) }

// Backup is one snapshot directory and the vault files it holds.
type Backup struct {
	ID    string
	Files []string // sorted
}

// ListBackups returns the vault snapshots under home/backups, newest first.
// Directories that are not snapshots are ignored; a home or backups
// directory that does not exist has none. It needs no key.
func ListBackups(home string) ([]Backup, error) {
	root := filepath.Join(home, "backups")
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("vault: list backups: %w", bare(err))
	}
	var out []Backup
	for _, e := range entries {
		if !e.IsDir() || !ValidBackupID(e.Name()) || !vaultBackup(filepath.Join(root, e.Name())) {
			continue
		}
		files, err := os.ReadDir(filepath.Join(root, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("vault: list backups: %w", bare(err))
		}
		b := Backup{ID: e.Name()}
		for _, f := range files {
			if f.Type().IsRegular() {
				b.Files = append(b.Files, f.Name())
			}
		}
		sort.Strings(b.Files)
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
}

// ReadBackupID returns the vault id recorded in a snapshot's state.json, for
// unlocking when the live state.json is unreadable.
func ReadBackupID(home, id string) (string, error) {
	if !ValidBackupID(id) {
		return "", ErrNotFound
	}
	st, err := loadState(filepath.Join(home, "backups", id))
	if err != nil {
		return "", err
	}
	return st.VaultID, nil
}

// Restore makes the vault equal to snapshot id: the snapshot's vault.enc is
// opened with key or a retired key and its body saved as the next write
// under key, so the rollback counter moves forward and the current pair is
// snapshotted first. It works on a corrupt or rolled-back live vault, and
// takes the snapshot's state.json when the live one is unreadable. A missing
// snapshot is ErrNotFound; one no known key opens is ErrCorrupt and changes
// nothing. Grants are untouched: they bind record ids, which restore keeps.
func Restore(home, id string, key secret.Secret) error {
	if err := checkKey(key); err != nil {
		return err
	}
	if !ValidBackupID(id) {
		return ErrNotFound
	}
	snap := filepath.Join(home, "backups", id)
	v := &Vault{st: &store{home: home, key: key}}
	return v.locked(false, func() error {
		data, err := os.ReadFile(filepath.Join(snap, vaultFile))
		if errors.Is(err, os.ErrNotExist) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("vault: read backup: %w", bare(err))
		}
		pt, aad, err := openWithAny(home, key, data)
		if err != nil {
			return err
		}
		defer clear(pt)
		if _, err := decodeBody(pt, ""); err != nil {
			return err
		}
		st, err := loadState(home)
		if err != nil {
			if st, err = loadState(snap); err != nil {
				return corrupt("no readable state file")
			}
		}
		floor, created := aad.Writes, aad.CreatedAt
		if live, rerr := os.ReadFile(filepath.Join(home, vaultFile)); rerr == nil {
			if lpt, laad, oerr := open(key, live); oerr == nil {
				clear(lpt)
				floor, created = max(floor, laad.Writes), laad.CreatedAt
			}
		}
		if created == "" {
			created = time.Now().UTC().Format(time.RFC3339)
		}
		return v.st.sealNext(st, created, floor, pt)
	})
}

// openWithAny opens a vault.enc envelope with key, then with each retired
// key. The caller wipes the plaintext.
func openWithAny(home string, key secret.Secret, data []byte) ([]byte, AAD, error) {
	if pt, aad, err := open(key, data); err == nil {
		return pt, aad, nil
	}
	retired, err := retiredKeys(home, key)
	if err != nil {
		if !errors.Is(err, ErrCorrupt) {
			return nil, AAD{}, err // a read error is not "no older key"
		}
		retired = nil // an undecryptable list only means no older key to try
	}
	defer func() {
		for _, k := range retired {
			k.Wipe()
		}
	}()
	for _, k := range retired {
		if pt, aad, err := open(k, data); err == nil {
			return pt, aad, nil
		}
	}
	return nil, AAD{}, ErrBackupKey
}
