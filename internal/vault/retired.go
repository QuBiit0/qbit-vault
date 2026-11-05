package vault

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/QuBiit0/qbit-vault/internal/envelope"
	"github.com/QuBiit0/qbit-vault/internal/secret"
)

const (
	// FormatRetired identifies keys/retired.enc (docs/STORAGE.md § Retired keys).
	FormatRetired = "qbit-vault-retired/1"
	keysDir       = "keys"
	retiredFile   = "retired.enc"
	// maxRetired bounds the list; the oldest key is dropped first. Backups are
	// pruned to 20 saves by default, so older keys rarely open anything.
	maxRetired = 20
)

type retiredEntry struct {
	Generation string `json:"generation"`
	Key        string `json:"key"`
	RetiredAt  string `json:"retired_at"`
}

type retiredBody struct {
	Keys []retiredEntry `json:"keys"`
}

func retiredPath(home string) string { return filepath.Join(home, keysDir, retiredFile) }

// wipe clears the base64 key text the body holds.
func (b *retiredBody) wipe() {
	for i := range b.Keys {
		b.Keys[i].Key = ""
	}
}

// loadRetired opens keys/retired.enc with key. A missing file is an empty
// list (exists false); one key cannot open is ErrCorrupt.
func loadRetired(home string, key secret.Secret) (b retiredBody, prev AAD, exists bool, err error) {
	data, err := os.ReadFile(retiredPath(home))
	if errors.Is(err, os.ErrNotExist) {
		return retiredBody{}, AAD{}, false, nil
	}
	if err != nil {
		return retiredBody{}, AAD{}, false, fmt.Errorf("vault: read retired keys: %w", bare(err))
	}
	pt, aad, err := envelope.Open(FormatRetired, key, data)
	if err != nil {
		return retiredBody{}, AAD{}, true, err
	}
	defer clear(pt)
	if err := json.Unmarshal(pt, &b); err != nil {
		return retiredBody{}, AAD{}, true, corrupt("unreadable retired keys")
	}
	return b, aad, true, nil
}

// saveRetired seals b with key as the next write of keys/retired.enc. The
// caller holds the vault lock.
func saveRetired(home string, key secret.Secret, prev AAD, b retiredBody) error {
	pt, err := json.Marshal(b)
	if err != nil {
		return errors.New("vault: retired keys encoding failed")
	}
	defer clear(pt)
	created := prev.CreatedAt
	if created == "" {
		created = time.Now().UTC().Format(time.RFC3339)
	}
	sealed, err := envelope.Seal(FormatRetired, key, AAD{CreatedAt: created, Writes: prev.Writes + 1}, pt)
	if err != nil {
		return err
	}
	return replaceFile(filepath.Join(home, keysDir), retiredFile, sealed)
}

// retiredKeys returns the retired master keys, newest first. A missing file
// is none; a file key cannot open is ErrCorrupt. The caller wipes the keys.
func retiredKeys(home string, key secret.Secret) ([]secret.Secret, error) {
	b, _, _, err := loadRetired(home, key)
	if err != nil {
		return nil, err
	}
	defer b.wipe()
	out := make([]secret.Secret, 0, len(b.Keys))
	for _, e := range b.Keys {
		raw, err := base64.StdEncoding.DecodeString(e.Key)
		if err != nil || len(raw) != 32 {
			clear(raw)
			continue
		}
		out = append(out, secret.New("master", raw))
		clear(raw)
	}
	return out, nil
}

// retire adds old to the front of b unless it is already listed, keeping at
// most maxRetired entries. It reports whether b changed.
func retire(b *retiredBody, old secret.Secret) bool {
	raw := old.Reveal()
	defer clear(raw)
	enc := base64.StdEncoding.EncodeToString(raw)
	for _, e := range b.Keys {
		if e.Key == enc {
			return false
		}
	}
	entry := retiredEntry{Generation: "local", Key: enc, RetiredAt: stamp()}
	b.Keys = append([]retiredEntry{entry}, b.Keys...)
	if len(b.Keys) > maxRetired {
		b.Keys = b.Keys[:maxRetired]
	}
	return true
}

func sameKey(a, b secret.Secret) bool {
	x, y := a.Reveal(), b.Reveal()
	defer clear(x)
	defer clear(y)
	return bytes.Equal(x, y)
}
