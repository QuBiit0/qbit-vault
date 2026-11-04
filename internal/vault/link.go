package vault

import (
	"errors"

	"github.com/QuBiit0/gentle-vault/internal/secret"
)

// ErrAmbiguous means several unlinked project layers share the label asked
// for.
var ErrAmbiguous = errors.New("vault: several unlinked project layers have that label")

// Link binds the unlinked project layer named label (one synced from another
// device) to the repository root of dir on this device (REMOTE_SYNC.md §
// 7.5). dir must be a repository root (ErrNoProject) without a layer of its
// own here (ErrExists). It returns the number of secrets in the layer. The
// user, not the vault, decides to call it: a matching origin is only a hint.
func (v *Vault) Link(label, dir string) (int, error) {
	root, _, err := repoRoot(dir)
	if err != nil {
		return 0, err
	}
	n := 0
	err = v.locked(true, func() error {
		return v.mutateLocked(func(b *body) error {
			if _, taken := b.Projects[root]; taken {
				return ErrExists
			}
			at := -1
			for i, p := range b.unlinked {
				if p.Label == label {
					if at >= 0 {
						return ErrAmbiguous
					}
					at = i
				}
			}
			if at < 0 {
				return ErrNotFound
			}
			p := b.unlinked[at]
			b.unlinked = append(b.unlinked[:at], b.unlinked[at+1:]...)
			b.Projects[root] = p // encodeBody records roots[this device]
			n = len(p.Secrets)
			return nil
		})
	})
	return n, err
}

// UnlinkedMatch reports the label of an unlinked project layer whose origin
// equals that of the repository of cwd, when that repository has no layer
// of its own here. It never links anything.
func (v *Vault) UnlinkedMatch(cwd string) (string, bool, error) {
	root, ok, err := ProjectRoot(cwd)
	if err != nil || !ok {
		return "", false, err
	}
	origin := originOf(root)
	if origin == "" {
		return "", false, nil
	}
	label, found := "", false
	err = v.read(func(b *body) error {
		if _, linked := b.Projects[root]; linked {
			return nil
		}
		for _, p := range b.unlinked {
			if p.Origin == origin {
				label, found = p.Label, true
				return nil
			}
		}
		return nil
	})
	return label, found, err
}

// AddUnlinkedForTesting stores a project layer linked only on another device,
// with one secret, so tests outside this package can exercise link and the
// unlinked listing. Production code must not call it.
func AddUnlinkedForTesting(home string, key secret.Secret, label, origin, name string, value secret.Secret) error {
	v, err := Open(home, key)
	if err != nil {
		return err
	}
	return v.mutate(func(b *body) error {
		w := toWire(Record{Value: value, ID: newRecordID(), CreatedAt: stamp(), UpdatedAt: stamp()})
		b.unlinked = append(b.unlinked, &projectBody{Label: label, Origin: origin, ID: newProjectID(),
			Roots: map[string]string{NewDeviceID(): "/elsewhere/" + label}, Secrets: map[string]wireRecord{name: w}})
		return nil
	})
}
