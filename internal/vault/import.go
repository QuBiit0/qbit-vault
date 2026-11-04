package vault

import "errors"

// PutManyWithGrants stores several values in layer in one locked write (one
// snapshot), for `import`. names gives the order and must list exactly the
// keys of recs. A replaced record keeps the metadata it had (description,
// sensitive, binaries, hosts) and gets a new id, and its grants are dropped
// in the same operation, as for a single `set`. It returns the names that
// replaced an existing record. Nothing is written when any name is invalid.
func (v *Vault) PutManyWithGrants(layer Layer, names []string, recs map[string]Record, ed GrantsEditor) (GrantsResult, []string, error) {
	if len(names) == 0 || len(names) != len(recs) {
		return GrantsResult{}, nil, errors.New("vault: names and records do not match")
	}
	for _, n := range names {
		if err := checkName(n); err != nil {
			return GrantsResult{}, nil, err
		}
		if _, ok := recs[n]; !ok {
			return GrantsResult{}, nil, errors.New("vault: names and records do not match")
		}
	}
	if err := checkLayer(layer); err != nil {
		return GrantsResult{}, nil, err
	}
	var (
		res      GrantsResult
		replaced []string
	)
	err := v.locked(true, func() error {
		if err := v.mutateLocked(func(b *body) error {
			replaced = replaced[:0]
			secrets := b.secrets(layer, true)
			for _, n := range names {
				rec := recs[n]
				if old, ok := secrets[n]; ok {
					replaced = append(replaced, n)
					rec.Description, rec.Sensitive = old.Description, old.Sensitive
					rec.Binaries, rec.Hosts = old.Binaries, old.Hosts
				}
				putIn(secrets, n, rec, false)
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
			for _, n := range replaced {
				out, k, err := ed.DropRecord(body, n, layer.Key())
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
