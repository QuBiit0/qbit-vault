package vault

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/QuBiit0/gentle-vault/internal/secret"
)

const (
	vaultFile   = "vault.enc"
	stateFile   = "state.json"
	formatState = "gentle-vault-state/1"
)

// state is the part of state.json this package owns. Unknown top-level keys
// are carried in extra and written back untouched.
type state struct {
	VaultID string
	Writes  uint64
	extra   map[string]json.RawMessage
}

func newVaultID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", errors.New("vault: random source failed")
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func (s *state) marshal() ([]byte, error) {
	m := make(map[string]json.RawMessage, len(s.extra)+3)
	for k, v := range s.extra {
		m[k] = v
	}
	var err error
	if m["format"], err = json.Marshal(formatState); err != nil {
		return nil, err
	}
	if m["vault_id"], err = json.Marshal(s.VaultID); err != nil {
		return nil, err
	}
	if m["writes"], err = json.Marshal(s.Writes); err != nil {
		return nil, err
	}
	return json.MarshalIndent(m, "", "  ")
}

// loadState reads state.json. A missing file wraps os.ErrNotExist.
func loadState(home string) (*state, error) {
	data, err := os.ReadFile(filepath.Join(home, stateFile))
	if err != nil {
		return nil, fmt.Errorf("vault: read state: %w", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, corrupt("unreadable state")
	}
	var format string
	if json.Unmarshal(m["format"], &format) != nil || format != formatState {
		return nil, corrupt("unsupported state format")
	}
	s := &state{extra: map[string]json.RawMessage{}}
	if json.Unmarshal(m["vault_id"], &s.VaultID) != nil || s.VaultID == "" {
		return nil, corrupt("state has no vault id")
	}
	if json.Unmarshal(m["writes"], &s.Writes) != nil {
		return nil, corrupt("state has no write counter")
	}
	for k, v := range m {
		switch k {
		case "format", "vault_id", "writes":
		default:
			s.extra[k] = v
		}
	}
	return s, nil
}

// store persists one encrypted vault body plus its state counter.
type store struct {
	home string
	key  secret.Secret
	keep int
}

// header is what load reports about the vault file besides its plaintext.
type header struct {
	CreatedAt string
	Writes    uint64
}

// load decrypts vault.enc and checks it against state.json. A vault file
// that is behind the counter is ErrRollback; one that is ahead (a crash
// between the two writes) is accepted and state.json is repaired. The caller
// must wipe the returned plaintext.
func (s *store) load() ([]byte, header, error) {
	data, err := os.ReadFile(filepath.Join(s.home, vaultFile))
	if err != nil {
		return nil, header{}, fmt.Errorf("vault: read vault: %w", err)
	}
	pt, aad, err := open(s.key, data)
	if err != nil {
		return nil, header{}, err
	}
	st, err := loadState(s.home)
	if err != nil {
		clear(pt)
		if errors.Is(err, os.ErrNotExist) {
			return nil, header{}, corrupt("state file missing")
		}
		return nil, header{}, err
	}
	switch {
	case aad.Writes < st.Writes:
		clear(pt)
		return nil, header{}, ErrRollback
	case aad.Writes > st.Writes:
		st.Writes = aad.Writes
		if err := s.saveState(st); err != nil {
			clear(pt)
			return nil, header{}, err
		}
	}
	return pt, header{CreatedAt: aad.CreatedAt, Writes: aad.Writes}, nil
}

func (s *store) saveState(st *state) error {
	b, err := st.marshal()
	if err != nil {
		return errors.New("vault: state encoding failed")
	}
	return writeAtomic(s.home, stateFile, b, s.keep)
}

// savePair snapshots the current vault.enc and state.json into one backup
// directory, writes both, then prunes: one snapshot per save, always a
// consistent pair that restore can swap back.
func (s *store) savePair(vaultBytes, stateBytes []byte) error {
	if err := os.MkdirAll(s.home, dirMode); err != nil {
		return fmt.Errorf("vault: create home: %w", err)
	}
	if err := snapshot(s.home, vaultFile, stateFile); err != nil {
		return err
	}
	if err := replaceFile(s.home, vaultFile, vaultBytes); err != nil {
		return err
	}
	if err := replaceFile(s.home, stateFile, stateBytes); err != nil {
		return err
	}
	return pruneBackups(filepath.Join(s.home, "backups"), s.keep)
}

// save encrypts plaintext as the next write: it bumps the counter, writes
// vault.enc, then state.json. The caller keeps ownership of plaintext.
func (s *store) save(plaintext []byte) error {
	st, err := loadState(s.home)
	switch {
	case errors.Is(err, os.ErrNotExist):
		id, idErr := newVaultID()
		if idErr != nil {
			return idErr
		}
		st = &state{VaultID: id, extra: map[string]json.RawMessage{}}
	case err != nil:
		return err
	}

	created := time.Now().UTC().Format(time.RFC3339)
	if data, rerr := os.ReadFile(filepath.Join(s.home, vaultFile)); rerr == nil {
		if pt, aad, oerr := open(s.key, data); oerr == nil {
			clear(pt)
			created = aad.CreatedAt
			st.Writes = max(st.Writes, aad.Writes)
		}
	}

	st.Writes++
	sealed, err := seal(s.key, AAD{Format: FormatVault, CreatedAt: created, Writes: st.Writes}, plaintext)
	if err != nil {
		return err
	}
	stateBytes, err := st.marshal()
	if err != nil {
		return errors.New("vault: state encoding failed")
	}
	return s.savePair(sealed, stateBytes)
}
