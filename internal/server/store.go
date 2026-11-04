package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// The store is files under the data directory (REMOTE_SYNC.md § 10): every
// write is atomic (temp file, fsync, rename), owner-only, and serialized per
// account by the server. One server instance per data directory.

const keepVersions = 10

type deviceRec struct {
	SignPub     string `json:"sign_pub"`
	BoxPub      string `json:"box_pub"`
	CreatedAt   string `json:"created_at"`
	LastSeen    string `json:"last_seen,omitempty"`
	KeyEnvelope string `json:"key_envelope,omitempty"`
	Generation  int    `json:"generation"`
}

type recoveryRec struct {
	LookupID string `json:"lookup_id"`
	AuthHash string `json:"auth_hash"`
	Envelope string `json:"envelope"`
}

type account struct {
	ID         string               `json:"id"`
	CreatedAt  string               `json:"created_at"`
	Version    int64                `json:"version"`
	Generation int                  `json:"generation"`
	Recovery   recoveryRec          `json:"recovery"`
	Devices    map[string]deviceRec `json:"devices"`
}

type store struct{ dir string }

func (s *store) path(parts ...string) string {
	return filepath.Join(append([]string{s.dir}, parts...)...)
}

func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	var r [4]byte
	_, _ = rand.Read(r[:])
	tmp := path + ".tmp." + hex.EncodeToString(r[:])
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if runtime.GOOS != "windows" {
		if d, derr := os.Open(filepath.Dir(path)); derr == nil {
			_ = d.Sync()
			_ = d.Close()
		}
	}
	return nil
}

func writeJSON(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return writeFile(path, b)
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func (s *store) loadAccount(id string) (*account, error) {
	var a account
	if err := readJSON(s.path("accounts", id, "account.json"), &a); err != nil {
		return nil, err
	}
	if a.Devices == nil {
		a.Devices = map[string]deviceRec{}
	}
	return &a, nil
}

func (s *store) saveAccount(a *account) error {
	return writeJSON(s.path("accounts", a.ID, "account.json"), a)
}

func (s *store) accountOfDevice(device string) (string, error) {
	b, err := os.ReadFile(s.path("devices", device))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func (s *store) indexDevice(device, accountID string) error {
	return writeFile(s.path("devices", device), []byte(accountID))
}

func (s *store) unindexDevice(device string) {
	_ = os.Remove(s.path("devices", device))
}

func (s *store) putVersion(id string, version int64, blob string) error {
	if err := writeFile(s.path("accounts", id, "vault", fmt.Sprintf("%020d.json", version)), []byte(blob)); err != nil {
		return err
	}
	vs, err := s.versions(id)
	if err != nil {
		return err
	}
	for len(vs) > keepVersions {
		_ = os.Remove(s.path("accounts", id, "vault", fmt.Sprintf("%020d.json", vs[len(vs)-1])))
		vs = vs[:len(vs)-1]
	}
	return nil
}

// versions lists the stored versions, newest first.
func (s *store) versions(id string) ([]int64, error) {
	entries, err := os.ReadDir(s.path("accounts", id, "vault"))
	if err != nil {
		return nil, err
	}
	var out []int64
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok {
			continue
		}
		if v, err := strconv.ParseInt(name, 10, 64); err == nil {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] > out[j] })
	return out, nil
}

func (s *store) getVersion(id string, version int64) (string, error) {
	b, err := os.ReadFile(s.path("accounts", id, "vault", fmt.Sprintf("%020d.json", version)))
	return string(b), err
}
