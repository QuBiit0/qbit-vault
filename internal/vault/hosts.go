package vault

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"regexp"

	"github.com/qbitdevz/qbit-vault/internal/filemerge"
)

// Host registrations on the vault side (docs/STORAGE.md § state.json): the
// `hosts` object of state.json maps a host name to what `init` registered
// there and the filemerge receipts that let `doctor` compare and `uninstall`
// revert. It holds paths and digests, never a config byte and never a secret.

const hostsStateKey = "hosts"

var hostNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// HostState is one host's record. Receipts are keyed by step name; every path
// in them is absolute.
type HostState struct {
	RegisteredAt string                       `json:"registered_at"`
	Registered   []string                     `json:"registered"`
	Receipts     map[string]filemerge.Receipt `json:"receipts"`
}

var errHostState = errors.New("vault: invalid host record")

func (h HostState) validate() error {
	for _, r := range h.Receipts {
		if !filepath.IsAbs(r.Path) || !filepath.IsAbs(r.Snapshot.Path) {
			return errHostState
		}
		if r.Snapshot.Backup != "" && !filepath.IsAbs(r.Snapshot.Backup) {
			return errHostState
		}
	}
	return nil
}

// ReadHosts returns the registered hosts by name; empty when none.
func ReadHosts(home string) (map[string]HostState, error) {
	st, err := loadState(home)
	if err != nil {
		return nil, err
	}
	raw, ok := st.extra[hostsStateKey]
	if !ok || string(raw) == "null" {
		return map[string]HostState{}, nil
	}
	var hs map[string]HostState
	if err := json.Unmarshal(raw, &hs); err != nil {
		return nil, corrupt("state has a malformed hosts object")
	}
	if hs == nil {
		hs = map[string]HostState{}
	}
	return hs, nil
}

// WriteHost replaces one host's record (nil removes it) under the vault
// lock, keeping the rest of state.json. A record with a relative path, or a
// host name outside [a-z0-9-], is refused before anything is written.
func WriteHost(home, name string, h *HostState) error {
	if !hostNameRE.MatchString(name) {
		return errors.New("vault: invalid host name")
	}
	if h != nil {
		if err := h.validate(); err != nil {
			return err
		}
	}
	v := &Vault{st: &store{home: home}}
	return v.locked(false, func() error {
		st, err := loadState(home)
		if err != nil {
			return err
		}
		hs := map[string]json.RawMessage{}
		if raw, ok := st.extra[hostsStateKey]; ok && string(raw) != "null" {
			if json.Unmarshal(raw, &hs) != nil {
				return corrupt("state has a malformed hosts object")
			}
		}
		if h == nil {
			delete(hs, name)
		} else {
			b, err := json.Marshal(h)
			if err != nil {
				return err
			}
			hs[name] = b
		}
		if len(hs) == 0 {
			delete(st.extra, hostsStateKey)
		} else {
			b, err := json.Marshal(hs)
			if err != nil {
				return err
			}
			st.extra[hostsStateKey] = b
		}
		return (&store{home: home}).saveState(st)
	})
}
