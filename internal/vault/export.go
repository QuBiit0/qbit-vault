package vault

import (
	"errors"
	"sort"
)

// NamedRecord is a record with its name, as an export carries it.
type NamedRecord struct {
	Name   string
	Record Record
}

// LayerRecords is one layer and its records in name order.
type LayerRecords struct {
	Layer   Layer
	Records []NamedRecord
}

// Replaced names a record an import overwrote.
type Replaced struct {
	Layer Layer
	Name  string
}

// ExportAll returns every record of every layer, values and metadata
// included: the global layer first, then the project layers by root. Empty
// layers are left out. Project layers synced from another device that have no
// root on this one cannot be addressed by root, so they are not returned;
// unlinked counts their records. The caller wipes the values.
func (v *Vault) ExportAll() (layers []LayerRecords, unlinked int, err error) {
	err = v.read(func(b *body) error {
		collect := func(l Layer, secrets map[string]wireRecord) {
			if len(secrets) == 0 {
				return
			}
			lr := LayerRecords{Layer: l}
			for n, w := range secrets {
				lr.Records = append(lr.Records, NamedRecord{Name: n, Record: fromWire(n, w)})
			}
			sort.Slice(lr.Records, func(i, j int) bool { return lr.Records[i].Name < lr.Records[j].Name })
			layers = append(layers, lr)
		}
		collect(Global(), b.Global)
		roots := make([]string, 0, len(b.Projects))
		for root := range b.Projects {
			roots = append(roots, root)
		}
		sort.Strings(roots)
		for _, root := range roots {
			p := b.Projects[root]
			collect(Layer{Project: true, Root: root, Label: p.Label}, p.Secrets)
		}
		for _, p := range b.unlinked {
			unlinked += len(p.Secrets)
		}
		return nil
	})
	return layers, unlinked, err
}

// checkImport validates what ImportAll and Clashes take: legal names, project
// layers bound to a root, no record listed twice.
func checkImport(layers []LayerRecords) error {
	seen := map[string]bool{}
	n := 0
	for _, lr := range layers {
		if err := checkLayer(lr.Layer); err != nil {
			return err
		}
		for _, nr := range lr.Records {
			if err := checkName(nr.Name); err != nil {
				return err
			}
			k := lr.Layer.Key() + "\x00" + nr.Name
			if seen[k] {
				return errors.New("vault: a record is listed twice")
			}
			seen[k] = true
			n++
		}
	}
	if n == 0 {
		return errors.New("vault: nothing to import")
	}
	return nil
}

// Clashes lists the records of layers that already exist in the vault, in
// layer then name order, without decoding any value.
func (v *Vault) Clashes(layers []LayerRecords) ([]Replaced, error) {
	if err := checkImport(layers); err != nil {
		return nil, err
	}
	var out []Replaced
	err := v.read(func(b *body) error {
		out = clashesIn(b, layers)
		return nil
	})
	return out, err
}

func clashesIn(b *body, layers []LayerRecords) []Replaced {
	var out []Replaced
	for _, lr := range layers {
		secrets := b.secrets(lr.Layer, false)
		for _, nr := range lr.Records {
			if _, ok := secrets[nr.Name]; ok {
				out = append(out, Replaced{Layer: lr.Layer, Name: nr.Name})
			}
		}
	}
	return out
}

// ImportAll merges layers into the vault in one locked write (one snapshot).
// A record whose name is not in the vault's layer is added; one whose name is
// already there is replaced whole (new id, nothing kept of the old record, its
// timestamps are the import's) and its grants are dropped in the same
// operation. Records of the vault that layers does not name are untouched,
// grants included. A project layer is matched by root, created when absent
// and keeps its label when present. Nothing is written when any name or layer
// is invalid. It returns what it replaced.
func (v *Vault) ImportAll(layers []LayerRecords, ed GrantsEditor) (GrantsResult, []Replaced, error) {
	if err := checkImport(layers); err != nil {
		return GrantsResult{}, nil, err
	}
	var (
		res      GrantsResult
		replaced []Replaced
	)
	err := v.locked(true, func() error {
		if err := v.mutateLocked(func(b *body) error {
			replaced = clashesIn(b, layers)
			for _, lr := range layers {
				if len(lr.Records) == 0 {
					continue
				}
				secrets := b.secrets(lr.Layer, true)
				for _, nr := range lr.Records {
					rec := nr.Record
					rec.ID = newRecordID()
					ts := stamp()
					if rec.CreatedAt == "" {
						rec.CreatedAt = ts
					}
					if rec.UpdatedAt == "" {
						rec.UpdatedAt = rec.CreatedAt
					}
					secrets[nr.Name] = toWire(rec)
				}
			}
			return nil
		}); err != nil {
			return err
		}
		if len(replaced) == 0 {
			return nil
		}
		var err error
		res, err = v.editGrantsLocked(ed, func(ed GrantsEditor, body []byte) ([]byte, int, error) {
			total := 0
			for _, r := range replaced {
				out, k, err := ed.DropRecord(body, r.Name, r.Layer.Key())
				if err != nil {
					return nil, 0, err
				}
				if out != nil {
					body = out
				}
				total += k
			}
			if total == 0 {
				return nil, 0, nil
			}
			return body, total, nil
		})
		return err
	})
	return res, replaced, err
}
