package vault

import (
	"path/filepath"
	"regexp"
	"testing"
)

var recordIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

func idOf(t *testing.T, v *Vault, name string) string {
	t.Helper()
	r, _, err := v.Resolve(name, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return r.ID
}

func TestRecordIDLifecycle(t *testing.T) {
	v, _ := newVault(t)
	mustPut(t, v, Global(), "A_KEY", rec("v1"))
	first := idOf(t, v, "A_KEY")
	if !recordIDRE.MatchString(first) {
		t.Fatalf("id = %q, want 32 hex chars", first)
	}
	if idOf(t, v, "A_KEY") != first {
		t.Fatal("a read changed the id")
	}

	// Edit-style Put (carries the current id) keeps it.
	r, _, _ := v.Resolve("A_KEY", t.TempDir())
	r.Description = "changed"
	if err := v.Put(Global(), "A_KEY", r); err != nil {
		t.Fatal(err)
	}
	if idOf(t, v, "A_KEY") != first {
		t.Fatal("edit changed the id")
	}

	// Remove then re-Put yields a new id.
	if err := v.Remove(Global(), "A_KEY"); err != nil {
		t.Fatal(err)
	}
	mustPut(t, v, Global(), "A_KEY", rec("v1"))
	second := idOf(t, v, "A_KEY")
	if second == first || !recordIDRE.MatchString(second) {
		t.Fatalf("re-created record reuses the id: %q", second)
	}

	// A value replacement (Put without the id, or ReplaceWithGrants) yields a new id.
	mustPut(t, v, Global(), "A_KEY", rec("v2"))
	third := idOf(t, v, "A_KEY")
	if third == second {
		t.Fatal("Put of a new value kept the id")
	}
	if _, err := v.ReplaceWithGrants(Global(), "A_KEY", rec("v3"), nil); err != nil {
		t.Fatal(err)
	}
	if idOf(t, v, "A_KEY") == third {
		t.Fatal("ReplaceWithGrants kept the id")
	}

	// A stale id on Put does not keep the id.
	r, _, _ = v.Resolve("A_KEY", t.TempDir())
	cur := r.ID
	r.ID = first
	mustPut(t, v, Global(), "A_KEY", r)
	if idOf(t, v, "A_KEY") == cur || idOf(t, v, "A_KEY") == first {
		t.Fatal("a stale id was honored")
	}
}

func TestRecordIDSurvivesMoveAndRelink(t *testing.T) {
	v, _ := newVault(t)
	dir := t.TempDir()
	oldRepo := mkRepo(t, dir, "shop", false)
	oldRoot := canonical(t, oldRepo)
	pl := layerOf(t, oldRepo)
	mustPut(t, v, Global(), "A_KEY", rec("g"))
	id := idOf(t, v, "A_KEY")
	if err := v.Move("A_KEY", Global(), pl, false); err != nil {
		t.Fatal(err)
	}
	r, _, err := v.Resolve("A_KEY", oldRepo)
	if err != nil || r.ID != id {
		t.Fatalf("move: id %q err %v, want %q", r.ID, err, id)
	}
	newRepo := filepath.Join(dir, "renamed")
	moveRepo(t, oldRepo, newRepo)
	if _, err := v.Relink(oldRoot, newRepo); err != nil {
		t.Fatal(err)
	}
	r, _, err = v.Resolve("A_KEY", newRepo)
	if err != nil || r.ID != id {
		t.Fatalf("relink: id %q err %v, want %q", r.ID, err, id)
	}
}
