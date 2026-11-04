package vault

import (
	"encoding/json"

	"github.com/QuBiit0/gentle-vault/internal/merge"
)

// The device roster of the schema 2 body (docs/REMOTE_SYNC.md § 1, § 7.3):
// labels, public keys and revocations, encrypted with the rest of the body.
// A roster entry carries no clock, so editing the roster stamps no record.

// Roster returns the device roster keyed by device id.
func (v *Vault) Roster() (map[string]merge.Device, error) {
	out := map[string]merge.Device{}
	err := v.read(func(b *body) error {
		for id, raw := range b.devices {
			var d merge.Device
			if err := json.Unmarshal(raw, &d); err != nil {
				return corrupt("unreadable device roster")
			}
			out[id] = d
		}
		return nil
	})
	return out, err
}

// EditRoster lets fn change the roster and saves the result.
func (v *Vault) EditRoster(fn func(map[string]merge.Device)) error {
	return v.mutate(func(b *body) error {
		roster := map[string]merge.Device{}
		for id, raw := range b.devices {
			var d merge.Device
			if err := json.Unmarshal(raw, &d); err != nil {
				return corrupt("unreadable device roster")
			}
			roster[id] = d
		}
		fn(roster)
		b.devices = map[string]json.RawMessage{}
		for id, d := range roster {
			raw, err := json.Marshal(d)
			if err != nil {
				return err
			}
			b.devices[id] = raw
		}
		return nil
	})
}

// ApplyBody is step 3 of a sync round (§ 7.2): under the vault lock it
// offers the local schema 2 body to fn and, when fn returns a merged body,
// writes it as the next vault write without stamping anything, so no change
// made by another process between the read and the write is lost. fn must
// not call back into the vault and must not touch the network. A nil result
// leaves the vault as it is. The slice fn gets is wiped on return.
func (v *Vault) ApplyBody(fn func(local []byte) (merged []byte, err error)) error {
	return v.locked(true, func() error {
		pt, _, err := v.st.load()
		if err != nil {
			return err
		}
		defer clear(pt)
		merged, err := fn(pt)
		if err != nil || merged == nil {
			return err
		}
		var probe struct {
			Schema int `json:"schema"`
		}
		if json.Unmarshal(merged, &probe) != nil || probe.Schema != schemaVersion {
			return corrupt("not a schema 2 body")
		}
		if _, err := decodeBody(merged, ""); err != nil {
			return err
		}
		return v.st.save(merged)
	})
}

// ConflictCount is the number of kept losing versions in the body (§ 7.4),
// read without writing anything.
func (v *Vault) ConflictCount() (int, error) {
	n := 0
	err := v.read(func(b *body) error { n = len(b.conflicts); return nil })
	return n, err
}
