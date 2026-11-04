package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/QuBiit0/gentle-vault/internal/envelope"
	"github.com/QuBiit0/gentle-vault/internal/secret"
)

// Remote sync state on the vault side (docs/REMOTE_SYNC.md § 11, STORAGE.md
// § Remote files): the `remote` object of state.json, and two files sealed
// with the master key: remote/device.enc (this device's secret) and
// remote/base.enc (the body of the last version this device agreed with).

const (
	remoteDir      = "remote"
	deviceFile     = "device.enc"
	baseFile       = "base.enc"
	formatDevice   = "gentle-vault-device/1"
	formatBase     = "gentle-vault-base/1"
	remoteStateKey = "remote"
)

// Remote is state.json's remote object; absent when the vault does not sync.
type Remote struct {
	Server              string `json:"server"`
	CAFile              string `json:"ca_file,omitempty"`
	AccountID           string `json:"account_id"`
	Generation          int    `json:"generation"`
	LastVersion         int64  `json:"last_version"`
	PendingPush         bool   `json:"pending_push"`
	LastPullAt          string `json:"last_pull_at,omitempty"`
	RecoveryUnconfirmed bool   `json:"recovery_unconfirmed,omitempty"`
}

// ReadRemote returns the remote state, nil when the vault does not sync.
func ReadRemote(home string) (*Remote, error) {
	st, err := loadState(home)
	if err != nil {
		return nil, err
	}
	raw, ok := st.extra[remoteStateKey]
	if !ok || string(raw) == "null" {
		return nil, nil
	}
	var r Remote
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, corrupt("state has a malformed remote object")
	}
	return &r, nil
}

// WriteRemote replaces the remote state (nil removes it) under the vault
// lock, keeping the rest of state.json.
func WriteRemote(home string, r *Remote) error {
	v := &Vault{st: &store{home: home}}
	return v.locked(false, func() error {
		st, err := loadState(home)
		if err != nil {
			return err
		}
		if r == nil {
			delete(st.extra, remoteStateKey)
		} else {
			b, err := json.Marshal(r)
			if err != nil {
				return err
			}
			st.extra[remoteStateKey] = b
		}
		return (&store{home: home}).saveState(st)
	})
}

func (v *Vault) sealFile(name, format string, pt []byte) error {
	sealed, err := envelope.Seal(format, v.st.key, AAD{CreatedAt: time.Now().UTC().Format(time.RFC3339), Writes: 1}, pt)
	if err != nil {
		return err
	}
	return v.locked(true, func() error {
		dir := filepath.Join(v.st.home, remoteDir)
		if err := os.MkdirAll(dir, dirMode); err != nil {
			return fmt.Errorf("vault: create remote dir: %w", bare(err))
		}
		return replaceFile(dir, name, sealed)
	})
}

func (v *Vault) openFile(name, format string) ([]byte, error) {
	var pt []byte
	err := v.locked(false, func() error {
		data, err := os.ReadFile(filepath.Join(v.st.home, remoteDir, name))
		if err != nil {
			return err
		}
		pt, _, err = envelope.Open(format, v.st.key, data)
		return err
	})
	return pt, err
}

// SaveDeviceSecret stores this device's secret DK, sealed.
func (v *Vault) SaveDeviceSecret(dk secret.Secret) error {
	raw := dk.Reveal()
	defer clear(raw)
	return v.sealFile(deviceFile, formatDevice, raw)
}

// DeviceSecret returns this device's secret DK; the caller wipes it.
func (v *Vault) DeviceSecret() (secret.Secret, error) {
	pt, err := v.openFile(deviceFile, formatDevice)
	if err != nil {
		return secret.Secret{}, err
	}
	defer clear(pt)
	if len(pt) != 32 {
		return secret.Secret{}, corrupt("device secret")
	}
	return secret.New("device", pt), nil
}

// SaveBase stores the merge base, sealed.
func (v *Vault) SaveBase(body []byte) error { return v.sealFile(baseFile, formatBase, body) }

// Base returns the merge base (wraps os.ErrNotExist when there is none).
// The caller wipes it.
func (v *Vault) Base() ([]byte, error) { return v.openFile(baseFile, formatBase) }

// ClearRemoteFiles removes remote/ (logout).
func (v *Vault) ClearRemoteFiles() error {
	return v.locked(false, func() error {
		err := os.RemoveAll(filepath.Join(v.st.home, remoteDir))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("vault: remove remote files: %w", bare(err))
		}
		return nil
	})
}

// Body returns the vault body as schema 2 JSON, the plaintext a remote
// version seals. A record without a clock yet (a vault migrated but not
// saved since) is stamped and saved first, so the body sent is the one on
// disk. The caller wipes it.
func (v *Vault) Body() ([]byte, error) {
	unstamped := false
	if err := v.read(func(b *body) error {
		for _, r := range b.Global {
			unstamped = unstamped || r.HLC == ""
		}
		for _, p := range b.allProjects() {
			unstamped = unstamped || p.HLC == ""
			for _, r := range p.Secrets {
				unstamped = unstamped || r.HLC == ""
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if unstamped {
		if err := v.mutate(func(*body) error { return nil }); err != nil {
			return nil, err
		}
	}
	var out []byte
	err := v.locked(false, func() error {
		pt, _, err := v.st.load()
		if err != nil {
			return err
		}
		out = pt
		return nil
	})
	return out, err
}

// ReplaceBody writes body (a merge result, schema 2) as the next vault write
// without stamping anything: its clocks are the merged ones. It is refused
// unless it decodes as a schema 2 body.
func (v *Vault) ReplaceBody(body []byte) error {
	var probe struct {
		Schema int `json:"schema"`
	}
	if json.Unmarshal(body, &probe) != nil || probe.Schema != schemaVersion {
		return corrupt("not a schema 2 body")
	}
	if _, err := decodeBody(body, ""); err != nil {
		return err
	}
	return v.locked(true, func() error { return v.st.save(body) })
}
