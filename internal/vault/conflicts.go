package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/qbitdevz/qbit-vault/internal/merge"
)

// Sync conflicts and restore (docs/REMOTE_SYNC.md § 7.4, § 7.6). A conflict
// is the losing side of a double edit, kept in the encrypted body. Nothing
// here returns a value: ConflictInfo is the metadata a row needs.

// Keep says which version survives a ResolveConflict.
type Keep string

const (
	// KeepCurrent discards every kept version of the record.
	KeepCurrent Keep = "current"
	// KeepConflict swaps the current record with the kept version.
	KeepConflict Keep = "conflict"
)

var (
	// ErrNoConflict means the layer holds no kept version under that name.
	ErrNoConflict = errors.New("vault: no sync conflict for that name")
	// ErrAmbiguousConflict means more than one version was kept for the name,
	// so "the" kept version is not defined.
	ErrAmbiguousConflict = errors.New("vault: more than one version was kept")
)

// ConflictInfo describes a kept version without its content.
type ConflictInfo struct {
	Name string
	// Layer is the layer of the record. A project that is not linked on this
	// device has an empty Root.
	Layer        Layer
	LostAt       string
	WinnerDevice string // device id of the winning side
	Deleted      bool   // the kept version is a deletion
}

// splitKey splits a merge key into the project id ("" for global) and name.
func splitKey(key string) (project, name string, ok bool) {
	if n, found := strings.CutPrefix(key, "global/"); found {
		return "", n, ValidName(n)
	}
	rest, found := strings.CutPrefix(key, "project/")
	if !found {
		return "", "", false
	}
	id, n, found := strings.Cut(rest, "/")
	return id, n, found && id != "" && ValidName(n)
}

// layerOfProject finds the layer of a project id in b.
func layerOfProject(b *body, id string) (Layer, bool) {
	for root, p := range b.Projects {
		if p.ID == id {
			return Layer{Project: true, Root: root, Label: p.Label}, true
		}
	}
	for _, p := range b.unlinked {
		if p.ID == id {
			return Layer{Project: true, Label: p.Label}, true
		}
	}
	return Layer{}, false
}

func (b *body) parsedConflicts() []merge.Conflict {
	out := make([]merge.Conflict, 0, len(b.conflicts))
	for _, raw := range b.conflicts {
		var c merge.Conflict
		if json.Unmarshal(raw, &c) == nil {
			out = append(out, c)
		}
	}
	return out
}

// Conflicts lists the kept versions, newest loss first. It reads only.
func (v *Vault) Conflicts() ([]ConflictInfo, error) {
	var out []ConflictInfo
	err := v.read(func(b *body) error {
		for _, c := range b.parsedConflicts() {
			pid, name, ok := splitKey(c.Key)
			if !ok {
				continue
			}
			layer := Layer{}
			if pid != "" {
				if layer, ok = layerOfProject(b, pid); !ok {
					layer = Layer{Project: true}
				}
			}
			out = append(out, ConflictInfo{Name: name, Layer: layer, LostAt: c.LostAt, WinnerDevice: c.WinnerDevice, Deleted: c.Deleted})
		}
		return nil
	})
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].LostAt != out[j].LostAt {
			return out[i].LostAt > out[j].LostAt
		}
		return out[i].Name < out[j].Name
	})
	return out, err
}

func conflictID(key, hlc string) string {
	sum := sha256.Sum256([]byte(key + "|" + hlc))
	return "c_" + hex.EncodeToString(sum[:8])
}

func toMergeRecord(r wireRecord) (merge.Record, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	var out merge.Record
	return out, json.Unmarshal(raw, &out)
}

func fromMergeRecord(r merge.Record) (wireRecord, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return wireRecord{}, err
	}
	var out wireRecord
	return out, json.Unmarshal(raw, &out)
}

// ResolveConflict settles the kept version of name in layer. KeepCurrent
// discards every kept version. KeepConflict swaps: the kept version becomes
// the record (with a fresh clock and record id, so it syncs like any edit
// and no grant of the replaced record applies to it) and the replaced record
// becomes the kept version. A kept deletion removes the record. More than
// one kept version makes KeepConflict ErrAmbiguousConflict.
func (v *Vault) ResolveConflict(layer Layer, name string, keep Keep) error {
	if keep != KeepCurrent && keep != KeepConflict {
		return errors.New("vault: unknown resolution")
	}
	return v.mutate(func(b *body) error {
		recs, key := b.Global, "global/"+name
		if layer.Project {
			p := b.Projects[layer.Root]
			if p == nil {
				return ErrNoConflict
			}
			recs, key = p.Secrets, "project/"+p.ID+"/"+name
		}
		var hit []int
		all := b.parsedConflicts()
		if len(all) != len(b.conflicts) {
			return corrupt("unreadable conflict list")
		}
		for i, c := range all {
			if c.Key == key {
				hit = append(hit, i)
			}
		}
		switch {
		case len(hit) == 0:
			return ErrNoConflict
		case keep == KeepConflict && len(hit) > 1:
			return ErrAmbiguousConflict
		}
		drop := map[int]bool{}
		for _, i := range hit {
			drop[i] = true
		}
		var kept []json.RawMessage
		for i, raw := range b.conflicts {
			if !drop[i] {
				kept = append(kept, raw)
			}
		}
		if keep == KeepConflict {
			c := all[hit[0]]
			cur, has := recs[name]
			if !c.Deleted || has {
				swapped := merge.Conflict{Key: key, LostAt: now().UTC().Format(time.RFC3339), WinnerDevice: b.device, Deleted: !has}
				hlc := ""
				if has {
					rec, err := toMergeRecord(cur)
					if err != nil {
						return err
					}
					swapped.Record, hlc = rec, cur.HLC
				} else {
					for _, t := range b.tombstones {
						if t.Key == key {
							hlc = t.HLC
						}
					}
				}
				swapped.ID = conflictID(key, hlc)
				raw, err := json.Marshal(swapped)
				if err != nil {
					return err
				}
				kept = append(kept, raw)
			}
			if c.Deleted {
				delete(recs, name)
			} else {
				rec, err := fromMergeRecord(c.Record)
				if err != nil {
					return corrupt("unreadable conflict record")
				}
				rec.ID, rec.HLC = newRecordID(), ""
				recs[name] = rec
			}
		}
		b.conflicts = kept
		return nil
	})
}

func sameContent(a, b wireRecord) bool {
	a.ID, a.HLC, b.ID, b.HLC = "", "", "", ""
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	same := string(x) == string(y)
	clear(x)
	clear(y)
	return same
}

// restoreRecords makes dst equal to src: a record that differs or is missing
// is written with a fresh clock and a fresh record id, one that src lacks is
// removed (the save leaves its tombstone). It returns the number of changes.
func restoreRecords(dst, src map[string]wireRecord) int {
	changed := 0
	for n, want := range src {
		if have, ok := dst[n]; ok && sameContent(have, want) {
			continue
		}
		want.ID, want.HLC = newRecordID(), ""
		dst[n] = want
		changed++
	}
	for n := range dst {
		if _, ok := src[n]; !ok {
			delete(dst, n)
			changed++
		}
	}
	return changed
}

// RestoreRecords makes the records of the vault equal to those of target, a
// schema 2 body (a version fetched from the server, § 7.6), by writing the
// difference through the normal save: every changed record gets a fresh
// hybrid clock, so it wins over the current ones when it syncs, and the
// replaced state is snapshotted like any write. The device roster, the kept
// conflicts and the grants are not touched (a revoked device stays revoked).
// It returns how many records changed.
func (v *Vault) RestoreRecords(target []byte) (int, error) {
	var probe struct {
		Schema int `json:"schema"`
	}
	if json.Unmarshal(target, &probe) != nil || probe.Schema != schemaVersion {
		return 0, corrupt("not a schema 2 body")
	}
	changed := 0
	err := v.mutate(func(b *body) error {
		tb, err := decodeBody(target, b.device)
		if err != nil {
			return err
		}
		changed += restoreRecords(b.Global, tb.Global)
		local := map[string]*projectBody{}
		for _, p := range b.allProjects() {
			local[p.ID] = p
		}
		seen := map[string]bool{}
		for _, tp := range tb.allProjects() {
			seen[tp.ID] = true
			if lp := local[tp.ID]; lp != nil {
				changed += restoreRecords(lp.Secrets, tp.Secrets)
				continue
			}
			np := &projectBody{Label: tp.Label, Origin: tp.Origin, ID: tp.ID, Roots: tp.Roots, Secrets: map[string]wireRecord{}}
			changed += restoreRecords(np.Secrets, tp.Secrets)
			if root := np.Roots[b.device]; root != "" && b.Projects[root] == nil {
				b.Projects[root] = np
			} else {
				b.unlinked = append(b.unlinked, np)
			}
		}
		for id, lp := range local {
			if !seen[id] {
				changed += restoreRecords(lp.Secrets, nil)
			}
		}
		return nil
	})
	return changed, err
}
