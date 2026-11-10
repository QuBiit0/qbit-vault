package vault

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/qbitdevz/qbit-vault/internal/secret"
)

const (
	vaultFile   = "vault.enc"
	stateFile   = "state.json"
	formatState = "qbit-vault-state/1"
)

// state is the part of state.json this package owns. Unknown top-level keys
// are carried in extra and written back untouched.
type state struct {
	VaultID  string
	Writes   uint64
	DeviceID string // this machine in project roots and the roster (schema 2)
	extra    map[string]json.RawMessage
}

var deviceIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// NewDeviceID returns 16 random bytes as hex.
func NewDeviceID() string { return newProjectID() }

// ReadDeviceID returns the device id recorded in state.json, "" when the
// vault predates it and has not been opened since.
func ReadDeviceID(home string) (string, error) {
	st, err := loadState(home)
	if err != nil {
		return "", err
	}
	return st.DeviceID, nil
}

var vaultIDRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// NewID returns a random UUID v4 to identify a new vault.
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("vault: random source failed")
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// ReadID returns the vault id recorded in state.json without needing the
// key. A missing file wraps os.ErrNotExist; a malformed one is ErrCorrupt.
func ReadID(home string) (string, error) {
	st, err := loadState(home)
	if err != nil {
		return "", err
	}
	return st.VaultID, nil
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
	if s.DeviceID != "" {
		if m["device_id"], err = json.Marshal(s.DeviceID); err != nil {
			return nil, err
		}
	}
	return json.MarshalIndent(m, "", "  ")
}

// loadState reads state.json. A missing file wraps os.ErrNotExist.
func loadState(home string) (*state, error) {
	data, err := os.ReadFile(filepath.Join(home, stateFile))
	if err != nil {
		return nil, fmt.Errorf("vault: read state: %w", bare(err))
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
	if json.Unmarshal(m["vault_id"], &s.VaultID) != nil || !vaultIDRE.MatchString(s.VaultID) {
		return nil, corrupt("state has no vault id")
	}
	if json.Unmarshal(m["writes"], &s.Writes) != nil {
		return nil, corrupt("state has no write counter")
	}
	if raw, ok := m["device_id"]; ok {
		if json.Unmarshal(raw, &s.DeviceID) != nil || !deviceIDRE.MatchString(s.DeviceID) {
			return nil, corrupt("state has a malformed device id")
		}
	}
	for k, v := range m {
		switch k {
		case "format", "vault_id", "writes", "device_id":
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
	id   string // vault id for a first save; empty means generate one
	// device is the device id a first save records (see deviceForNew).
	device string
}

// deviceForNew is the device id of a vault being created: the one in an
// existing state.json, else a fresh one the first save records.
func (s *store) deviceForNew() string {
	if st, err := loadState(s.home); err == nil && st.DeviceID != "" {
		return st.DeviceID
	}
	if s.device == "" {
		s.device = NewDeviceID()
	}
	return s.device
}

// header is what load reports about the vault file besides its plaintext.
type header struct {
	CreatedAt string
	Writes    uint64
	Device    string
}

// load decrypts vault.enc and checks it against state.json. A vault file
// that is behind the counter is ErrRollback; one that is ahead (a crash
// between the two writes) is accepted and state.json is repaired. The caller
// must wipe the returned plaintext.
func (s *store) load() ([]byte, header, error) {
	data, err := os.ReadFile(filepath.Join(s.home, vaultFile))
	if err != nil {
		return nil, header{}, fmt.Errorf("vault: read vault: %w", bare(err))
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
	repair := false
	switch {
	case aad.Writes < st.Writes:
		clear(pt)
		return nil, header{}, ErrRollback
	case aad.Writes > st.Writes:
		st.Writes, repair = aad.Writes, true
	}
	if st.DeviceID == "" {
		// A vault from before device ids: name this machine now.
		st.DeviceID, repair = NewDeviceID(), true
	}
	if repair {
		if err := s.saveState(st); err != nil {
			clear(pt)
			return nil, header{}, err
		}
	}
	return pt, header{CreatedAt: aad.CreatedAt, Writes: aad.Writes, Device: st.DeviceID}, nil
}

func (s *store) saveState(st *state) error {
	b, err := st.marshal()
	if err != nil {
		return errors.New("vault: state encoding failed")
	}
	// A repair restates a counter the vault file already proved; it is not a
	// user mutation, so it gets no snapshot and spends no backup slot.
	return replaceFile(s.home, stateFile, b)
}

// savePair snapshots the current vault.enc and state.json into one backup
// directory, writes both, then prunes: one snapshot per save, always a
// consistent pair that restore can swap back. A save that fails before it
// replaces anything removes the snapshot it made; once vault.enc has been
// replaced the snapshot is kept, because it is then the only copy of the
// previous consistent pair.
func (s *store) savePair(vaultBytes, stateBytes []byte) error {
	if err := os.MkdirAll(s.home, dirMode); err != nil {
		return fmt.Errorf("vault: create home: %w", bare(err))
	}
	dir, err := snapshot(s.home, vaultFile, stateFile)
	if err != nil {
		return err
	}
	if err := replaceFile(s.home, vaultFile, vaultBytes); err != nil {
		removeSnapshot(dir)
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
		id := s.id
		if id == "" {
			id = NewID()
		}
		dev := s.device
		if dev == "" {
			dev = NewDeviceID()
		}
		st = &state{VaultID: id, DeviceID: dev, extra: map[string]json.RawMessage{}}
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

	return s.sealNext(st, created, 0, plaintext)
}

// sealNext seals plaintext under s.key as write max(st.Writes, floor)+1 and
// saves it with st through savePair (snapshot first). The caller holds the
// vault lock and keeps ownership of plaintext.
func (s *store) sealNext(st *state, created string, floor uint64, plaintext []byte) error {
	st.Writes = max(st.Writes, floor) + 1
	sealed, err := seal(s.key, AAD{Format: FormatVault, Cipher: CipherName, CreatedAt: created, Writes: st.Writes}, plaintext)
	if err != nil {
		return err
	}
	stateBytes, err := st.marshal()
	if err != nil {
		return errors.New("vault: state encoding failed")
	}
	return s.savePair(sealed, stateBytes)
}
