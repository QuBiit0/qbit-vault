package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// S4.1: a rejoining device takes a new id and its project roots go with it.
func TestChangeDeviceIDMovesTheProjectRoots(t *testing.T) {
	v, home := newVault(t)
	repo := mkRepo(t, t.TempDir(), "shop-api", false)
	layer := layerOf(t, repo)
	mustPut(t, v, layer, "DB_URL", rec("TESTSECRET_project"))
	mustPut(t, v, Global(), "G_KEY", rec("TESTSECRET_global"))
	old, err := ReadDeviceID(home)
	if err != nil || old == "" {
		t.Fatalf("device id %q %v", old, err)
	}
	next := NewDeviceID()

	if err := v.ChangeDeviceID(next); err != nil {
		t.Fatal(err)
	}
	if got, _ := ReadDeviceID(home); got != next {
		t.Fatalf("device id = %q, want %q", got, next)
	}
	// Reopened, the project secret resolves in its repository and the global one too.
	v2, err := Open(home, testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	if r, l, err := v2.Resolve("DB_URL", repo); err != nil || !l.Project || !sameValue(r, "TESTSECRET_project") {
		t.Fatalf("project secret: %v %+v", err, l)
	}
	if r, _, err := v2.Resolve("G_KEY", t.TempDir()); err != nil || !sameValue(r, "TESTSECRET_global") {
		t.Fatalf("global secret: %v", err)
	}
	// The body records the root under the new id and keeps the old entry.
	body, err := v2.Body()
	if err != nil {
		t.Fatal(err)
	}
	if s := string(body); !strings.Contains(s, `"`+next+`":`) || !strings.Contains(s, `"`+old+`":`) {
		t.Fatalf("roots lack an id: %s", body)
	}
}

func TestChangeDeviceIDRefusals(t *testing.T) {
	v, home := newVault(t)
	repo := mkRepo(t, t.TempDir(), "shop-api", false)
	mustPut(t, v, layerOf(t, repo), "DB_URL", rec("TESTSECRET_project"))
	old, _ := ReadDeviceID(home)
	live, _ := os.ReadFile(filepath.Join(home, vaultFile))
	state, _ := os.ReadFile(filepath.Join(home, stateFile))

	for _, bad := range []string{"", "nothex", strings.Repeat("A", 32), strings.Repeat("a", 31)} {
		if err := v.ChangeDeviceID(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	// The same id is a no-op that writes nothing.
	if err := v.ChangeDeviceID(old); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(filepath.Join(home, vaultFile)); string(after) != string(live) {
		t.Fatal("vault.enc changed")
	}
	if after, _ := os.ReadFile(filepath.Join(home, stateFile)); string(after) != string(state) {
		t.Fatal("state.json changed")
	}
}
