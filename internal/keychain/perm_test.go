package keychain

import (
	"path/filepath"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/perm"
)

// key.enc and the unlock cache are owner-only, independent of what the
// parent directory would let them inherit.
func TestKeyFileAndCacheAreOwnerOnly(t *testing.T) {
	home := t.TempDir()
	run := t.TempDir()
	opts := cacheOpts(run)
	opts.ForcePassphrase = true
	opts.Passphrase = pass(fixturePass)
	if _, _, err := Setup(home, testID, opts); err != nil {
		t.Fatalf("setup: %v", err)
	}
	paths := []string{
		filepath.Join(home, keyFileName),
		filepath.Join(run, "qbit-vault"),
		filepath.Join(run, "qbit-vault", testID+".key"),
	}
	for _, p := range paths {
		if ok, detail := perm.Check(p); !ok {
			t.Fatalf("%s not owner-only: %s", filepath.Base(p), detail)
		}
	}
}
