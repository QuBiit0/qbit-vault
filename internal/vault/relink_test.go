package vault

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// moveRepo renames a repository directory, as a user moving a checkout would.
func moveRepo(t *testing.T, from, to string) {
	t.Helper()
	if err := os.Rename(from, to); err != nil {
		t.Fatal(err)
	}
}

func TestRelinkMovesProjectLayer(t *testing.T) {
	v, _ := newVault(t)
	dir := t.TempDir()
	oldRepo := mkRepo(t, dir, "shop-api", false)
	oldRoot := canonical(t, oldRepo)
	mustPut(t, v, layerOf(t, oldRepo), "DB_URL", Record{Value: rec("v1").Value, Description: "db", Sensitive: true, Binaries: []string{"psql"}, Hosts: []string{"h"}})
	mustPut(t, v, layerOf(t, oldRepo), "API_KEY", rec("v2"))
	mustPut(t, v, Global(), "G", rec("g"))

	newRepo := filepath.Join(dir, "renamed")
	moveRepo(t, oldRepo, newRepo)
	n, err := v.Relink(oldRoot, newRepo)
	if err != nil || n != 2 {
		t.Fatalf("Relink = %d, %v", n, err)
	}
	r, l, err := v.Resolve("DB_URL", newRepo)
	if err != nil || !l.Project || l.Label != "renamed" || l.Root != canonical(t, newRepo) {
		t.Fatalf("Resolve from the new root: %+v %v", l, err)
	}
	if !sameValue(r, "v1") || r.Description != "db" || !r.Sensitive || len(r.Binaries) != 1 || len(r.Hosts) != 1 {
		t.Fatal("value or metadata changed")
	}
	all, _ := v.ListAll()
	for _, e := range all {
		if e.Layer.Project && e.Layer.Root == oldRoot {
			t.Fatal("old root still has a layer")
		}
	}
	if len(all) != 3 {
		t.Fatalf("want 3 records, got %d", len(all))
	}
}

func TestRelinkAcceptsNonCanonicalOldRoot(t *testing.T) {
	v, _ := newVault(t)
	dir := t.TempDir()
	oldRepo := mkRepo(t, dir, "a", false)
	mustPut(t, v, layerOf(t, oldRepo), "K", rec("x"))
	newRepo := mkRepo(t, dir, "b", false)
	// Trailing separator and a dot segment denote the same root.
	if _, err := v.Relink(oldRepo+string(filepath.Separator)+".", newRepo); err != nil {
		t.Fatalf("Relink: %v", err)
	}
}

func TestRelinkRefusals(t *testing.T) {
	setup := func(t *testing.T) (v *Vault, dir, oldRepo string) {
		v, _ = newVault(t)
		dir = t.TempDir()
		oldRepo = mkRepo(t, dir, "old", false)
		mustPut(t, v, layerOf(t, oldRepo), "K", rec("old-value"))
		return
	}
	snapshot := func(t *testing.T, v *Vault) string {
		all, err := v.ListAll()
		if err != nil {
			t.Fatal(err)
		}
		var b strings.Builder
		for _, e := range all {
			b.WriteString(e.Name + "|" + e.Layer.Root + "|" + e.Layer.Label + "|" + e.Record.UpdatedAt + "\n")
		}
		return b.String()
	}
	t.Run("old has no layer", func(t *testing.T) {
		v, dir, _ := setup(t)
		other := mkRepo(t, dir, "other", false)
		fresh := mkRepo(t, dir, "fresh", false)
		before := snapshot(t, v)
		if _, err := v.Relink(other, fresh); !errors.Is(err, ErrNotFound) {
			t.Fatalf("err = %v", err)
		}
		if snapshot(t, v) != before {
			t.Fatal("vault changed")
		}
	})
	t.Run("new already has a layer", func(t *testing.T) {
		v, dir, oldRepo := setup(t)
		taken := mkRepo(t, dir, "taken", false)
		mustPut(t, v, layerOf(t, taken), "T", rec("t"))
		before := snapshot(t, v)
		if _, err := v.Relink(oldRepo, taken); !errors.Is(err, ErrExists) {
			t.Fatalf("err = %v", err)
		}
		if snapshot(t, v) != before {
			t.Fatal("vault changed")
		}
	})
	t.Run("same root", func(t *testing.T) {
		v, _, oldRepo := setup(t)
		if _, err := v.Relink(oldRepo, oldRepo); !errors.Is(err, ErrExists) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("new is not a repository root", func(t *testing.T) {
		v, dir, oldRepo := setup(t)
		plain := mkDir(t, dir, "plain")
		sub := mkDir(t, oldRepo, "sub")
		missing := filepath.Join(dir, "missing")
		file := filepath.Join(dir, "file")
		if err := os.WriteFile(file, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		before := snapshot(t, v)
		for name, p := range map[string]string{"no .git": plain, "subdirectory": sub, "missing": missing, "file": file} {
			if _, err := v.Relink(oldRepo, p); !errors.Is(err, ErrNoProject) {
				t.Fatalf("%s: err = %v", name, err)
			}
		}
		if snapshot(t, v) != before {
			t.Fatal("vault changed")
		}
	})
}
