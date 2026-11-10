package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/qbitdevz/qbit-vault/internal/envelope"
	"github.com/qbitdevz/qbit-vault/internal/secret"
)

// ErrRekeyNotStarted marks a Rekey refused before anything was re-sealed (the
// vault could not be opened with either key, or was rolled back). It wraps
// the cause, so errors.Is still matches ErrCorrupt or ErrRollback.
var ErrRekeyNotStarted = errors.New("vault: rekey refused before anything was re-sealed")

// Rekey re-seals the vault files from oldKey to newKey and adds oldKey to
// keys/retired.enc (docs/STORAGE.md § Master key). It is idempotent and
// resumable: every file is opened with newKey first and with oldKey only when
// that fails, so running it again after a crash finishes what is left. The
// order is vault.enc (snapshotted, so the old envelope stays as a backup),
// grants.enc, then retired.enc. The caller stores newKey durably (staged)
// before calling and promotes it after; see internal/keychain.
//
// A vault that neither key opens is ErrCorrupt; a rolled-back one is
// ErrRollback; neither is changed. Grants that cannot be trusted under either
// key are left as they are: they are reset on their next read anyway.
func Rekey(home string, oldKey, newKey secret.Secret) error {
	if err := checkKey(oldKey); err != nil {
		return err
	}
	if err := checkKey(newKey); err != nil {
		return err
	}
	v := &Vault{st: &store{home: home, key: newKey}}
	return v.locked(false, func() error {
		if err := rekeyVault(home, oldKey, newKey); err != nil {
			return err
		}
		if err := rekeyGrants(home, oldKey, newKey); err != nil {
			return err
		}
		return rekeyRetired(home, oldKey, newKey)
	})
}

func rekeyVault(home string, oldKey, newKey secret.Secret) error {
	notStarted := func(err error) error { return fmt.Errorf("%w: %w", ErrRekeyNotStarted, err) }
	if pt, _, err := (&store{home: home, key: newKey}).load(); err == nil {
		clear(pt)
		return nil // already re-sealed
	} else if errors.Is(err, ErrRollback) || !errors.Is(err, ErrCorrupt) {
		return notStarted(err)
	}
	old := &store{home: home, key: oldKey}
	pt, hdr, err := old.load()
	if err != nil {
		return notStarted(err)
	}
	defer clear(pt)
	st, err := loadState(home)
	if err != nil {
		return notStarted(err)
	}
	return (&store{home: home, key: newKey}).sealNext(st, hdr.CreatedAt, hdr.Writes, pt)
}

func rekeyGrants(home string, oldKey, newKey secret.Secret) error {
	data, err := os.ReadFile(filepath.Join(home, grantsFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if pt, _, err := envelope.Open(FormatGrants, newKey, data); err == nil {
		clear(pt)
		return nil
	}
	old := &store{home: home, key: oldKey}
	body, st, aad, reset, err := old.loadGrants()
	if err != nil {
		return err
	}
	defer clear(body)
	if reset || body == nil {
		return nil
	}
	return (&store{home: home, key: newKey}).saveGrants(st, aad, body)
}

func rekeyRetired(home string, oldKey, newKey secret.Secret) error {
	b, prev, _, err := loadRetired(home, newKey)
	if err != nil {
		if !errors.Is(err, ErrCorrupt) {
			return err // a read error: never overwrite a list we could not read
		}
		// Still sealed with the old key (a crash before this step), or
		// undecryptable: start from what the old key opens, else from nothing.
		if b, prev, _, err = loadRetired(home, oldKey); err != nil {
			if !errors.Is(err, ErrCorrupt) {
				return err
			}
			b, prev = retiredBody{}, AAD{}
		}
		defer b.wipe()
		if !sameKey(oldKey, newKey) {
			retire(&b, oldKey)
		}
		return saveRetired(home, newKey, prev, b)
	}
	defer b.wipe()
	if sameKey(oldKey, newKey) || !retire(&b, oldKey) {
		return nil
	}
	return saveRetired(home, newKey, prev, b)
}
