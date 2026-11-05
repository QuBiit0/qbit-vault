package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/QuBiit0/qbit-vault/internal/envelope"
	"github.com/QuBiit0/qbit-vault/internal/merge"
)

// The device roster of the schema 2 body (docs/REMOTE_SYNC.md § 1, § 7.3):
// labels, public keys and revocations, encrypted with the rest of the body.
// A roster entry carries no clock, so editing the roster stamps no record.

// Roster returns the device roster keyed by device id.
func (v *Vault) Roster() (map[string]merge.Device, error) {
	out := map[string]merge.Device{}
	err := v.read(func(b *body) error {
		for id, raw := range b.devices {
			var d merge.Device
			if err := json.Unmarshal(raw, &d); err != nil {
				return corrupt("unreadable device roster")
			}
			out[id] = d
		}
		return nil
	})
	return out, err
}

// EditRoster lets fn change the roster and saves the result.
func (v *Vault) EditRoster(fn func(map[string]merge.Device)) error {
	return v.mutate(func(b *body) error {
		roster := map[string]merge.Device{}
		for id, raw := range b.devices {
			var d merge.Device
			if err := json.Unmarshal(raw, &d); err != nil {
				return corrupt("unreadable device roster")
			}
			roster[id] = d
		}
		fn(roster)
		b.devices = map[string]json.RawMessage{}
		for id, d := range roster {
			raw, err := json.Marshal(d)
			if err != nil {
				return err
			}
			b.devices[id] = raw
		}
		return nil
	})
}

// ApplyBody is step 3 of a sync round (§ 7.2): under the vault lock it
// offers the local schema 2 body to fn and, when fn returns a merged body,
// writes it as the next vault write without stamping anything, so no change
// made by another process between the read and the write is lost. fn must
// not call back into the vault and must not touch the network. A nil result
// leaves the vault as it is. The slice fn gets is wiped on return.
func (v *Vault) ApplyBody(fn func(local []byte) (merged []byte, err error)) error {
	return v.locked(true, func() error {
		pt, _, err := v.st.load()
		if err != nil {
			return err
		}
		defer clear(pt)
		merged, err := fn(pt)
		if err != nil || merged == nil {
			return err
		}
		var probe struct {
			Schema int `json:"schema"`
		}
		if json.Unmarshal(merged, &probe) != nil || probe.Schema != schemaVersion {
			return corrupt("not a schema 2 body")
		}
		if _, err := decodeBody(merged, ""); err != nil {
			return err
		}
		return v.st.save(merged)
	})
}

// ConflictCount is the number of kept losing versions in the body (§ 7.4),
// read without writing anything.
func (v *Vault) ConflictCount() (int, error) {
	n := 0
	err := v.read(func(b *body) error { n = len(b.conflicts); return nil })
	return n, err
}

// DisableRemote turns sync off for the vault in home: remote/ and the remote
// object of state.json are removed under the vault lock; the vault, the key
// and the backups stay (a revoked device keeps its copy, REMOTE_SYNC § 4.5).
func DisableRemote(home string) error {
	v := &Vault{st: &store{home: home}}
	return v.locked(false, func() error {
		err := os.RemoveAll(filepath.Join(home, remoteDir))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("vault: remove remote files: %w", bare(err))
		}
		st, err := loadState(home)
		if err != nil {
			return err
		}
		delete(st.extra, remoteStateKey)
		delete(st.extra, anchorAtKey)
		return (&store{home: home}).saveState(st)
	})
}

// anchorAtKey is the key of state.json that holds the time of the last audit
// anchor this device uploaded (REMOTE_SYNC § 8). It sits beside "remote"
// because the Remote object has no field for it; DisableRemote and a zero
// WriteAnchorAt remove it.
const anchorAtKey = "remote_anchor_at"

// ReadAnchorAt returns when the last audit anchor was uploaded; ok is false
// when none was.
func ReadAnchorAt(home string) (at time.Time, ok bool, err error) {
	st, err := loadState(home)
	if err != nil {
		return time.Time{}, false, err
	}
	raw, found := st.extra[anchorAtKey]
	if !found {
		return time.Time{}, false, nil
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return time.Time{}, false, nil
	}
	at, perr := time.Parse(time.RFC3339, s)
	return at, perr == nil, nil
}

// WriteAnchorAt records the time of an anchor upload under the vault lock,
// keeping the rest of state.json. A zero time removes the record.
func WriteAnchorAt(home string, at time.Time) error {
	v := &Vault{st: &store{home: home}}
	return v.locked(false, func() error {
		st, err := loadState(home)
		if err != nil {
			return err
		}
		if at.IsZero() {
			delete(st.extra, anchorAtKey)
		} else {
			b, err := json.Marshal(at.UTC().Format(time.RFC3339))
			if err != nil {
				return err
			}
			st.extra[anchorAtKey] = b
		}
		return (&store{home: home}).saveState(st)
	})
}

// ResealRemoteFiles moves remote/device.enc and remote/base.enc to this
// vault's key. A file this key opens is left alone; one it does not open is
// opened with each retired key and sealed again. It is what finishes a key
// swap that died after the local files changed key and before these two did,
// and it is idempotent. A file no key opens is ErrCorrupt and is not touched;
// a missing file is skipped.
func (v *Vault) ResealRemoteFiles() error {
	retired, err := retiredKeys(v.st.home, v.st.key)
	if err != nil {
		retired = nil // an unreadable list only means no older key to try
	}
	defer func() {
		for _, k := range retired {
			k.Wipe()
		}
	}()
	for _, f := range []struct{ name, format string }{{deviceFile, formatDevice}, {baseFile, formatBase}} {
		err := v.locked(true, func() error {
			data, err := os.ReadFile(filepath.Join(v.st.home, remoteDir, f.name))
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			if err != nil {
				return fmt.Errorf("vault: read remote file: %w", bare(err))
			}
			if pt, _, err := envelope.Open(f.format, v.st.key, data); err == nil {
				clear(pt)
				return nil
			}
			for _, k := range retired {
				pt, aad, err := envelope.Open(f.format, k, data)
				if err != nil {
					continue
				}
				defer clear(pt)
				sealed, err := envelope.Seal(f.format, v.st.key, aad, pt)
				if err != nil {
					return err
				}
				return replaceFile(filepath.Join(v.st.home, remoteDir), f.name, sealed)
			}
			return corrupt("remote file cannot be opened with the current or a retired key")
		})
		if err != nil {
			return err
		}
	}
	return nil
}
