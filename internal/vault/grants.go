package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/QuBiit0/gentle-vault/internal/envelope"
)

const (
	grantsFile        = "grants.enc"
	grantsCounterKey  = "grants_writes"
	layerKeyGlobal    = "global"
	layerKeyProjectPf = "project:"
)

// Key is the layer's stable text form, "global" or "project:<root>". It is
// what grants and audit records store.
func (l Layer) Key() string {
	if l.Project {
		return layerKeyProjectPf + l.Root
	}
	return layerKeyGlobal
}

// GrantsEditor rewrites the decoded grants body when a record changes. The
// vault never interprets the body: internal/grants does, behind this
// interface. A nil returned body means "unchanged" (no write); n counts the
// grants dropped or rewritten. body is nil when there are no grants.
type GrantsEditor interface {
	// DropRecord removes the grants of (name, layer).
	DropRecord(body []byte, name, layer string) (newBody []byte, n int, err error)
	// RelinkProject repoints the project grants of oldRoot to newRoot.
	RelinkProject(body []byte, oldRoot, newRoot string) (newBody []byte, n int, err error)
}

// GrantsResult reports what the grants side of an operation did.
type GrantsResult struct {
	Changed int  // grants dropped or rewritten
	Reset   bool // grants.enc was unreadable or rolled back and treated as empty
	// RecordID is the id of the record a ReplaceWithGrants stored.
	RecordID string
}

// grantsCounter reads grants_writes; a missing or malformed value is 0.
func (s *state) grantsCounter() uint64 {
	var n uint64
	if raw, ok := s.extra[grantsCounterKey]; !ok || json.Unmarshal(raw, &n) != nil {
		return 0
	}
	return n
}

func (s *state) setGrantsCounter(n uint64) {
	b, _ := json.Marshal(n)
	s.extra[grantsCounterKey] = b
}

// loadGrants decrypts grants.enc and checks it against the counter in
// state.json. A missing file is an empty store. A file that cannot be
// trusted (corrupt, wrong format or key, or behind the counter) is also an
// empty store but reported through reset, so a rollback can never revive a
// revoked grant (L3). A file ahead of the counter (a crash between the two
// writes, or a missing counter) is accepted and the counter repaired. The
// returned bytes are nil for an empty store.
func (s *store) loadGrants() (body []byte, st *state, aad AAD, reset bool, err error) {
	st, err = loadState(s.home)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, AAD{}, false, corrupt("state file missing")
		}
		return nil, nil, AAD{}, false, err
	}
	data, rerr := os.ReadFile(filepath.Join(s.home, grantsFile))
	if errors.Is(rerr, os.ErrNotExist) {
		return nil, st, AAD{}, false, nil
	}
	if rerr != nil {
		return nil, nil, AAD{}, false, fmt.Errorf("vault: read grants: %w", bare(rerr))
	}
	pt, aad, oerr := envelope.Open(FormatGrants, s.key, data)
	if oerr != nil {
		if errors.Is(oerr, ErrCorrupt) {
			return nil, st, AAD{}, true, nil
		}
		return nil, nil, AAD{}, false, oerr
	}
	switch counter := st.grantsCounter(); {
	case aad.Writes < counter:
		clear(pt)
		return nil, st, AAD{}, true, nil
	case aad.Writes > counter:
		st.setGrantsCounter(aad.Writes)
		if err := s.saveState(st); err != nil {
			clear(pt)
			return nil, nil, AAD{}, false, err
		}
	}
	return pt, st, aad, false, nil
}

// saveGrants seals plaintext as the next grants write: grants.enc first, then
// the counter in state.json. There is no snapshot: losing grants loses
// permissions, never secrets (docs/STORAGE.md § Grants).
func (s *store) saveGrants(st *state, prev AAD, plaintext []byte) error {
	created := time.Now().UTC().Format(time.RFC3339)
	if prev.CreatedAt != "" {
		created = prev.CreatedAt
	}
	next := max(st.grantsCounter(), prev.Writes) + 1
	sealed, err := envelope.Seal(FormatGrants, s.key, AAD{CreatedAt: created, Writes: next}, plaintext)
	if err != nil {
		return err
	}
	if err := replaceFile(s.home, grantsFile, sealed); err != nil {
		return err
	}
	st.setGrantsCounter(next)
	return s.saveState(st)
}

// ReadGrants gives fn the decrypted grants body (nil when there are none)
// under the vault lock. reset reports that grants.enc was unreadable or
// rolled back and was treated as empty.
func (v *Vault) ReadGrants(fn func(body []byte) error) (reset bool, err error) {
	err = v.locked(false, func() error {
		body, _, _, r, err := v.st.loadGrants()
		if err != nil {
			return err
		}
		defer clear(body)
		reset = r
		return fn(body)
	})
	return reset, err
}

// MutateGrants gives fn the decrypted grants body (nil when there are none,
// with reset true when the file was unreadable or rolled back) and persists
// the body it returns. A nil result or an error writes nothing.
func (v *Vault) MutateGrants(fn func(body []byte, reset bool) ([]byte, error)) (reset bool, err error) {
	err = v.locked(true, func() error {
		r, err := v.mutateGrantsLocked(fn)
		reset = r
		return err
	})
	return reset, err
}

func (v *Vault) mutateGrantsLocked(fn func(body []byte, reset bool) ([]byte, error)) (bool, error) {
	body, st, aad, reset, err := v.st.loadGrants()
	if err != nil {
		return false, err
	}
	defer clear(body)
	out, err := fn(body, reset)
	if err != nil || out == nil {
		return reset, err
	}
	return reset, v.st.saveGrants(st, aad, out)
}

// editGrantsLocked runs ed over the grants body inside an operation that
// already holds the lock and has committed its vault change.
func (v *Vault) editGrantsLocked(ed GrantsEditor, edit func(ed GrantsEditor, body []byte) ([]byte, int, error)) (GrantsResult, error) {
	var res GrantsResult
	if ed == nil {
		return res, nil
	}
	reset, err := v.mutateGrantsLocked(func(body []byte, _ bool) ([]byte, error) {
		out, n, err := edit(ed, body)
		res.Changed = n
		return out, err
	})
	res.Reset = reset
	return res, err
}

// RemoveWithGrants is Remove plus dropping the grants of the removed record
// in the same locked operation (vault first, then grants).
func (v *Vault) RemoveWithGrants(layer Layer, name string, ed GrantsEditor) (GrantsResult, error) {
	if err := checkName(name); err != nil {
		return GrantsResult{}, err
	}
	if err := checkLayer(layer); err != nil {
		return GrantsResult{}, err
	}
	var res GrantsResult
	err := v.locked(true, func() error {
		if err := v.mutateLocked(func(b *body) error {
			secrets := b.secrets(layer, false)
			if _, ok := secrets[name]; !ok {
				return withName(ErrNotFound, name)
			}
			delete(secrets, name)
			b.dropEmptyProject(layer)
			return nil
		}); err != nil {
			return err
		}
		var err error
		res, err = v.editGrantsLocked(ed, func(ed GrantsEditor, body []byte) ([]byte, int, error) {
			return ed.DropRecord(body, name, layer.Key())
		})
		return err
	})
	return res, err
}

// MoveWithGrants is Move plus dropping the grants of name in both layers: the
// moved record's grants no longer apply, and an overwritten target's grants
// belonged to a value that is gone (R-LAYER-05).
func (v *Vault) MoveWithGrants(name string, from, to Layer, overwrite bool, ed GrantsEditor) (GrantsResult, error) {
	if err := checkName(name); err != nil {
		return GrantsResult{}, err
	}
	if err := checkLayer(from); err != nil {
		return GrantsResult{}, err
	}
	if err := checkLayer(to); err != nil {
		return GrantsResult{}, err
	}
	var res GrantsResult
	err := v.locked(true, func() error {
		if err := v.mutateLocked(func(b *body) error { return moveIn(b, name, from, to, overwrite) }); err != nil {
			return err
		}
		if from.same(to) {
			return nil
		}
		var err error
		res, err = v.editGrantsLocked(ed, func(ed GrantsEditor, body []byte) ([]byte, int, error) {
			total := 0
			for _, l := range []Layer{from, to} {
				out, n, err := ed.DropRecord(body, name, l.Key())
				if err != nil {
					return nil, 0, err
				}
				if out != nil {
					body = out
				}
				total += n
			}
			if total == 0 {
				return nil, 0, nil
			}
			return body, total, nil
		})
		return err
	})
	return res, err
}

// ReplaceWithGrants is Put for a value replacement: when the record already
// existed its grants are dropped (L7, R-API-07). Creating a record consults
// no editor. Metadata-only edits use Put and keep their grants.
func (v *Vault) ReplaceWithGrants(layer Layer, name string, rec Record, ed GrantsEditor) (GrantsResult, error) {
	if err := checkName(name); err != nil {
		return GrantsResult{}, err
	}
	if err := checkLayer(layer); err != nil {
		return GrantsResult{}, err
	}
	var res GrantsResult
	id := ""
	err := v.locked(true, func() error {
		existed := false
		if err := v.mutateLocked(func(b *body) error {
			secrets := b.secrets(layer, true)
			_, existed = secrets[name]
			putIn(secrets, name, rec, false)
			id = secrets[name].ID
			return nil
		}); err != nil {
			return err
		}
		if !existed {
			return nil
		}
		var err error
		res, err = v.editGrantsLocked(ed, func(ed GrantsEditor, body []byte) ([]byte, int, error) {
			return ed.DropRecord(body, name, layer.Key())
		})
		return err
	})
	res.RecordID = id
	return res, err
}

// RelinkWithGrants is Relink plus repointing the project grants of the moved
// layer (layer `project:<old>` becomes `project:<new>`, project_root too).
func (v *Vault) RelinkWithGrants(oldRoot, newRoot string, ed GrantsEditor) (int, GrantsResult, error) {
	to, label, err := repoRoot(newRoot)
	if err != nil {
		return 0, GrantsResult{}, err
	}
	from := looseRoot(oldRoot)
	n := 0
	var res GrantsResult
	err = v.locked(true, func() error {
		if err := v.mutateLocked(func(b *body) error {
			p := b.Projects[from]
			if p == nil {
				return ErrNotFound
			}
			if _, taken := b.Projects[to]; taken {
				return ErrExists
			}
			b.Projects[to] = &projectBody{Label: label, Secrets: p.Secrets}
			delete(b.Projects, from)
			n = len(p.Secrets)
			return nil
		}); err != nil {
			return err
		}
		var err error
		res, err = v.editGrantsLocked(ed, func(ed GrantsEditor, body []byte) ([]byte, int, error) {
			return ed.RelinkProject(body, from, to)
		})
		return err
	})
	return n, res, err
}
