package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/QuBiit0/gentle-vault/internal/secret"
)

// now is replaceable so tests can pin timestamps.
var now = time.Now

func baseName(root string) string { return filepath.Base(root) }

// Vault is an open, key-holding handle on one vault home. Every operation
// takes the cross-process lock (see acquireLock), then loads, mutates and
// persists the whole body; nothing is cached in memory, so reads see other
// processes' writes.
type Vault struct {
	mu sync.Mutex
	st *store
}

// Init creates an empty vault and its state file. It never overwrites an
// existing vault (ErrExists) and never reads the process environment. The
// caller supplies the vault id (see NewID) so the key can be stored under it
// before the vault exists.
func Init(home, vaultID string, key secret.Secret) (*Vault, error) {
	if err := checkKey(key); err != nil {
		return nil, err
	}
	if !vaultIDRE.MatchString(vaultID) {
		return nil, errors.New("vault: vault id must be a lowercase uuid v4")
	}
	v := &Vault{st: &store{home: home, key: key, id: vaultID}}
	err := v.locked(true, func() error {
		if _, err := os.Stat(filepath.Join(home, vaultFile)); err == nil {
			return ErrExists
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("vault: stat vault: %w", bare(err))
		}
		return v.mutateLocked(func(*body) error { return nil })
	})
	if err != nil {
		return nil, err
	}
	return v, nil
}

// Open opens an existing vault, verifying the key, the envelope and the
// rollback counter. A missing vault wraps os.ErrNotExist.
func Open(home string, key secret.Secret) (*Vault, error) {
	if err := checkKey(key); err != nil {
		return nil, err
	}
	v := &Vault{st: &store{home: home, key: key}}
	if err := v.read(func(*body) error { return nil }); err != nil {
		return nil, err
	}
	return v, nil
}

func (v *Vault) load() (*body, error) {
	pt, _, err := v.st.load()
	if err != nil {
		return nil, err
	}
	defer clear(pt)
	b := newBody()
	if err := json.Unmarshal(pt, b); err != nil {
		return nil, corrupt("unreadable body")
	}
	if b.Global == nil {
		b.Global = map[string]wireRecord{}
	}
	if b.Projects == nil {
		b.Projects = map[string]*projectBody{}
	}
	for root, p := range b.Projects {
		if p == nil {
			delete(b.Projects, root)
		} else if p.Secrets == nil {
			p.Secrets = map[string]wireRecord{}
		}
	}
	return b, nil
}

// locked runs fn holding the in-process mutex and the vault lock file. With
// create false a missing home is reported as not-exist instead of created.
func (v *Vault) locked(create bool, fn func() error) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if create {
		if err := os.MkdirAll(v.st.home, dirMode); err != nil {
			return fmt.Errorf("vault: create home: %w", bare(err))
		}
	}
	release, err := acquireLock(v.st.home)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("vault: read vault: %w", os.ErrNotExist)
		}
		return err
	}
	defer release()
	return fn()
}

func (v *Vault) read(fn func(*body) error) error {
	return v.locked(false, func() error {
		b, err := v.load()
		if err != nil {
			return err
		}
		return fn(b)
	})
}

func (v *Vault) mutate(fn func(*body) error) error {
	return v.locked(true, func() error { return v.mutateLocked(fn) })
}

// mutateLocked is mutate for a caller that already holds the lock.
func (v *Vault) mutateLocked(fn func(*body) error) error {
	b := newBody()
	if _, err := os.Stat(filepath.Join(v.st.home, vaultFile)); err == nil {
		if b, err = v.load(); err != nil {
			return err
		}
	}
	if err := fn(b); err != nil {
		return err
	}
	pt, err := json.Marshal(b)
	if err != nil {
		return errors.New("vault: body encoding failed")
	}
	defer clear(pt)
	return v.st.save(pt)
}

func stamp() string { return now().UTC().Format(time.RFC3339) }

// Put stores rec under name in layer, replacing any existing record while
// keeping its CreatedAt.
func (v *Vault) Put(layer Layer, name string, rec Record) error {
	if err := checkName(name); err != nil {
		return err
	}
	if err := checkLayer(layer); err != nil {
		return err
	}
	return v.mutate(func(b *body) error {
		secrets := b.secrets(layer, true)
		ts := stamp()
		rec.CreatedAt, rec.UpdatedAt = ts, ts
		if old, ok := secrets[name]; ok && old.CreatedAt != "" {
			rec.CreatedAt = old.CreatedAt
		}
		secrets[name] = toWire(rec)
		return nil
	})
}

// Remove deletes name from layer.
func (v *Vault) Remove(layer Layer, name string) error {
	if err := checkName(name); err != nil {
		return err
	}
	if err := checkLayer(layer); err != nil {
		return err
	}
	return v.mutate(func(b *body) error {
		secrets := b.secrets(layer, false)
		if _, ok := secrets[name]; !ok {
			return withName(ErrNotFound, name)
		}
		delete(secrets, name)
		b.dropEmptyProject(layer)
		return nil
	})
}

// Move relocates name between layers keeping value and metadata. If the
// target already holds the name, Move fails with ErrExists unless overwrite.
func (v *Vault) Move(name string, from, to Layer, overwrite bool) error {
	if err := checkName(name); err != nil {
		return err
	}
	if err := checkLayer(from); err != nil {
		return err
	}
	if err := checkLayer(to); err != nil {
		return err
	}
	return v.mutate(func(b *body) error {
		src := b.secrets(from, false)
		w, ok := src[name]
		if !ok {
			return withName(ErrNotFound, name)
		}
		if from.same(to) {
			return nil
		}
		dst := b.secrets(to, true)
		if _, exists := dst[name]; exists && !overwrite {
			b.dropEmptyProject(to)
			return withName(ErrExists, name)
		}
		dst[name] = w
		delete(src, name)
		b.dropEmptyProject(from)
		return nil
	})
}

// Resolve finds name for cwd: the project of cwd first, then global.
func (v *Vault) Resolve(name, cwd string) (Record, Layer, error) {
	if err := checkName(name); err != nil {
		return Record{}, Layer{}, err
	}
	layer, err := ProjectLayer(cwd)
	if err != nil && !errors.Is(err, ErrNoProject) {
		return Record{}, Layer{}, err
	}
	var (
		rec   Record
		found Layer
	)
	err2 := v.read(func(b *body) error {
		if layer.Project {
			if p := b.Projects[layer.Root]; p != nil {
				if w, ok := p.Secrets[name]; ok {
					rec, found = fromWire(name, w), Layer{Project: true, Root: layer.Root, Label: p.Label}
					return nil
				}
			}
		}
		if w, ok := b.Global[name]; ok {
			rec, found = fromWire(name, w), Global()
			return nil
		}
		return withName(ErrNotFound, name)
	})
	return rec, found, err2
}

// List returns what cwd can see: its project's secrets plus the global ones
// they do not override.
func (v *Vault) List(cwd string) ([]Entry, error) {
	layer, err := ProjectLayer(cwd)
	if err != nil && !errors.Is(err, ErrNoProject) {
		return nil, err
	}
	var out []Entry
	err = v.read(func(b *body) error {
		overridden := map[string]bool{}
		if layer.Project {
			if p := b.Projects[layer.Root]; p != nil {
				l := Layer{Project: true, Root: layer.Root, Label: p.Label}
				for n, w := range p.Secrets {
					_, over := b.Global[n]
					overridden[n] = true
					out = append(out, Entry{Name: n, Layer: l, Record: fromWire(n, w), OverridesGlobal: over})
				}
			}
		}
		for n, w := range b.Global {
			if !overridden[n] {
				out = append(out, Entry{Name: n, Layer: Global(), Record: fromWire(n, w)})
			}
		}
		return nil
	})
	sortEntries(out)
	return out, err
}

// ListAll returns every record in every layer.
func (v *Vault) ListAll() ([]Entry, error) {
	var out []Entry
	err := v.read(func(b *body) error {
		for n, w := range b.Global {
			out = append(out, Entry{Name: n, Layer: Global(), Record: fromWire(n, w)})
		}
		for root, p := range b.Projects {
			l := Layer{Project: true, Root: root, Label: p.Label}
			for n, w := range p.Secrets {
				_, over := b.Global[n]
				out = append(out, Entry{Name: n, Layer: l, Record: fromWire(n, w), OverridesGlobal: over})
			}
		}
		return nil
	})
	sortEntries(out)
	return out, err
}

func sortEntries(es []Entry) {
	sort.Slice(es, func(i, j int) bool {
		a, b := es[i], es[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Layer.Project != b.Layer.Project {
			return !a.Layer.Project
		}
		return strings.Compare(a.Layer.Root, b.Layer.Root) < 0
	})
}
