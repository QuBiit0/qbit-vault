package vault

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"

	"github.com/QuBiit0/gentle-vault/internal/secret"
)

// Record is one stored secret and its metadata (PRD R-VAULT-06).
type Record struct {
	// ID identifies this record instance. It is created with the record,
	// regenerated when the value is replaced, and kept by metadata edits,
	// mv and relink; grants bind to it so a grant can never authorize a
	// different record that reuses the name.
	ID    string
	Value secret.Secret
	// Kind is "secret" (masked at capture) or "text" (visible at capture);
	// empty means secret. Both are stored, injected and redacted alike.
	Kind        string
	Description string
	Sensitive   bool
	Binaries    []string
	Hosts       []string
	CreatedAt   string
	UpdatedAt   string
}

// Entry is a record together with where it lives, as returned by listings.
type Entry struct {
	Name            string
	Layer           Layer
	Record          Record
	OverridesGlobal bool
	// Unlinked marks a project layer synced from another device that has no
	// root on this one: Layer.Root is empty (STORAGE.md § Layers).
	Unlinked bool
}

// The plaintext body (docs/STORAGE.md § Plaintext body). It exists only
// inside one vault operation. The value is a Go string while encoded or
// decoded, which cannot be wiped; the byte buffers around it are.
type wireRecord struct {
	ID          string   `json:"id"`
	Value       string   `json:"value"`
	Kind        string   `json:"kind,omitempty"`
	Description string   `json:"description"`
	Sensitive   bool     `json:"sensitive"`
	Binaries    []string `json:"binaries"`
	Hosts       []string `json:"hosts"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
	// HLC is the hybrid logical clock of the record's last change (schema 2).
	HLC string `json:"hlc,omitempty"`
}

// projectBody is one project layer. ID is stable across devices; Roots maps
// each device to its checkout (schema 2).
type projectBody struct {
	Label   string
	Secrets map[string]wireRecord
	ID      string
	Origin  string
	Roots   map[string]string
	HLC     string
}

// body is the decoded vault body (see body2.go for the schema 2 codec).
// Projects holds the layers linked on this device, keyed by its root.
type body struct {
	Global     map[string]wireRecord
	Projects   map[string]*projectBody
	unlinked   []*projectBody
	tombstones []tombstone
	conflicts  []json.RawMessage
	devices    map[string]json.RawMessage
	device     string
	clock      *hlcClock
}

func newBody() *body {
	b := &body{Global: map[string]wireRecord{}, Projects: map[string]*projectBody{}}
	b.clock = &hlcClock{}
	return b
}

func toWire(r Record) wireRecord {
	v := r.Value.Reveal()
	defer clear(v)
	return wireRecord{
		ID:          r.ID,
		Value:       string(v),
		Kind:        r.Kind,
		Description: r.Description,
		Sensitive:   r.Sensitive,
		Binaries:    nonNil(r.Binaries),
		Hosts:       nonNil(r.Hosts),
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
}

func fromWire(name string, w wireRecord) Record {
	return Record{
		ID:          w.ID,
		Value:       secret.New(name, []byte(w.Value)),
		Kind:        w.Kind,
		Description: w.Description,
		Sensitive:   w.Sensitive,
		Binaries:    append([]string(nil), w.Binaries...),
		Hosts:       append([]string(nil), w.Hosts...),
		CreatedAt:   w.CreatedAt,
		UpdatedAt:   w.UpdatedAt,
	}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return append([]string{}, s...)
}

// secrets returns the map holding layer's secrets, or nil when the layer has
// no entry yet. With create set, a missing project entry is created.
func (b *body) secrets(l Layer, create bool) map[string]wireRecord {
	if !l.Project {
		return b.Global
	}
	p := b.Projects[l.Root]
	if p == nil {
		if !create {
			return nil
		}
		label := l.Label
		if label == "" {
			label = baseName(l.Root)
		}
		p = &projectBody{Label: label, Secrets: map[string]wireRecord{}, ID: newProjectID(),
			Origin: originOf(l.Root), Roots: map[string]string{}}
		b.Projects[l.Root] = p
	}
	return p.Secrets
}

// dropEmptyProject removes a project entry that no longer holds secrets, so
// forgotten roots do not linger in the vault.
func (b *body) dropEmptyProject(l Layer) {
	if l.Project {
		if p := b.Projects[l.Root]; p != nil && len(p.Secrets) == 0 {
			delete(b.Projects, l.Root)
		}
	}
}

// newRecordID returns 16 random bytes as hex.
func newRecordID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("vault: random source failed")
	}
	return hex.EncodeToString(b[:])
}
