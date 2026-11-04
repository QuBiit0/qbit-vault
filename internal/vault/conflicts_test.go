package vault

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/QuBiit0/gentle-vault/internal/merge"
)

// Kept versions and restore (docs/REMOTE_SYNC.md § 7.4, § 7.6), below the CLI.

// readBody parses the schema 2 body the vault syncs.
func readBody(t *testing.T, v *Vault) *merge.Body {
	t.Helper()
	raw, err := v.Body()
	if err != nil {
		t.Fatal(err)
	}
	var b merge.Body
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	return &b
}

// inject puts conflicts into the body, as a merge round would.
func inject(t *testing.T, v *Vault, cs ...merge.Conflict) {
	t.Helper()
	err := v.ApplyBody(func(local []byte) ([]byte, error) {
		var b merge.Body
		if err := json.Unmarshal(local, &b); err != nil {
			return nil, err
		}
		b.Conflicts = append(b.Conflicts, cs...)
		return json.Marshal(&b)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// keptRecord is a copy of rec with another value.
func keptRecord(rec merge.Record, value string) merge.Record {
	out := merge.Record{}
	for k, v := range rec {
		out[k] = v
	}
	raw, _ := json.Marshal(value)
	out["value"] = raw
	return out
}

func valueOf(t *testing.T, v *Vault, l Layer, name string) string {
	t.Helper()
	all, err := v.ListAll()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range all {
		if e.Name == name && e.Layer.same(l) {
			b := e.Record.Value.Reveal()
			defer clear(b)
			return string(b)
		}
	}
	t.Fatalf("%s not found", name)
	return ""
}

func TestResolveConflictSwapsOnAProjectLayer(t *testing.T) {
	v, _ := newVault(t)
	root := fakeRepo(t, "")
	l := Layer{Project: true, Root: root, Label: "shop-api"}
	mustPut(t, v, l, "P_KEY", rec("TESTSECRET_current"))
	b := readBody(t, v)
	var pid string
	for id := range b.Projects {
		pid = id
	}
	cur := b.Projects[pid].Secrets["P_KEY"]
	inject(t, v, merge.Conflict{ID: "c_1", Key: "project/" + pid + "/P_KEY", Record: keptRecord(cur, "TESTSECRET_kept"), LostAt: "2026-11-04T10:00:00Z", WinnerDevice: "dev1"})

	list, err := v.Conflicts()
	if err != nil || len(list) != 1 || list[0].Name != "P_KEY" || !list[0].Layer.Project || list[0].Layer.Root != root || list[0].Layer.Label != "shop-api" || list[0].WinnerDevice != "dev1" || list[0].Deleted {
		t.Fatalf("conflicts = %+v (%v)", list, err)
	}
	if n, _ := v.ConflictCount(); n != 1 {
		t.Fatalf("count = %d", n)
	}
	before := readBody(t, v).Projects[pid].Secrets["P_KEY"]
	if err := v.ResolveConflict(l, "P_KEY", KeepConflict); err != nil {
		t.Fatal(err)
	}
	if got := valueOf(t, v, l, "P_KEY"); got != "TESTSECRET_kept" {
		t.Fatal("the kept version did not become current")
	}
	after := readBody(t, v)
	now := after.Projects[pid].Secrets["P_KEY"]
	if now.HLC() <= before.HLC() || string(now["id"]) == string(before["id"]) {
		t.Fatalf("the swapped-in record needs a fresh clock and id: %s %s", before.HLC(), now.HLC())
	}
	if len(after.Conflicts) != 1 || after.Conflicts[0].Key != "project/"+pid+"/P_KEY" || string(after.Conflicts[0].Record["value"]) != `"TESTSECRET_current"` {
		t.Fatalf("the replaced record should be the kept one: %+v", after.Conflicts)
	}
	// Swapping again returns the first version; keeping current ends it.
	if err := v.ResolveConflict(l, "P_KEY", KeepConflict); err != nil || valueOf(t, v, l, "P_KEY") != "TESTSECRET_current" {
		t.Fatalf("swap back: %v", err)
	}
	if err := v.ResolveConflict(l, "P_KEY", KeepCurrent); err != nil {
		t.Fatal(err)
	}
	if n, _ := v.ConflictCount(); n != 0 || valueOf(t, v, l, "P_KEY") != "TESTSECRET_current" {
		t.Fatal("keep current must only drop the kept version")
	}
	if err := v.ResolveConflict(l, "P_KEY", KeepCurrent); !errors.Is(err, ErrNoConflict) {
		t.Fatalf("nothing left to resolve: %v", err)
	}
}

func TestResolveConflictRefusals(t *testing.T) {
	v, _ := newVault(t)
	mustPut(t, v, Global(), "G_KEY", rec("TESTSECRET_g"))
	cur := readBody(t, v).Global["G_KEY"]
	c := func(id, value string) merge.Conflict {
		return merge.Conflict{ID: id, Key: "global/G_KEY", Record: keptRecord(cur, value), LostAt: "2026-11-04T10:00:00Z"}
	}
	inject(t, v, c("c_1", "TESTSECRET_one"), c("c_2", "TESTSECRET_two"))
	before, _ := v.Body()
	if err := v.ResolveConflict(Global(), "G_KEY", KeepConflict); !errors.Is(err, ErrAmbiguousConflict) {
		t.Fatalf("two kept versions: %v", err)
	}
	if err := v.ResolveConflict(Global(), "OTHER", KeepCurrent); !errors.Is(err, ErrNoConflict) {
		t.Fatalf("unknown name: %v", err)
	}
	if err := v.ResolveConflict(Layer{Project: true, Root: "/nowhere"}, "G_KEY", KeepCurrent); !errors.Is(err, ErrNoConflict) {
		t.Fatalf("unknown project: %v", err)
	}
	if err := v.ResolveConflict(Global(), "G_KEY", Keep("both")); err == nil {
		t.Fatal("an unknown resolution was accepted")
	}
	if after, _ := v.Body(); string(after) != string(before) {
		t.Fatal("a refused resolution changed the body")
	}
	// Keeping the current version discards both.
	if err := v.ResolveConflict(Global(), "G_KEY", KeepCurrent); err != nil {
		t.Fatal(err)
	}
	if n, _ := v.ConflictCount(); n != 0 {
		t.Fatalf("%d conflicts left", n)
	}
}

func TestResolveConflictOnAKeptDeletion(t *testing.T) {
	v, _ := newVault(t)
	mustPut(t, v, Global(), "G_KEY", rec("TESTSECRET_g"))
	inject(t, v, merge.Conflict{ID: "c_d", Key: "global/G_KEY", Deleted: true, LostAt: "2026-11-04T10:00:00Z"})
	list, _ := v.Conflicts()
	if len(list) != 1 || !list[0].Deleted {
		t.Fatalf("conflicts = %+v", list)
	}
	if err := v.ResolveConflict(Global(), "G_KEY", KeepConflict); err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.Resolve("G_KEY", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the deletion should have been applied: %v", err)
	}
	b := readBody(t, v)
	if len(b.Tombstones) != 1 || b.Tombstones[0].Key != "global/G_KEY" {
		t.Fatalf("no tombstone: %+v", b.Tombstones)
	}
	if len(b.Conflicts) != 1 || b.Conflicts[0].Deleted || string(b.Conflicts[0].Record["value"]) != `"TESTSECRET_g"` {
		t.Fatalf("the deleted record should be the kept version: %+v", b.Conflicts)
	}
	// And back: the record returns with a fresh clock.
	if err := v.ResolveConflict(Global(), "G_KEY", KeepConflict); err != nil || valueOf(t, v, Global(), "G_KEY") != "TESTSECRET_g" {
		t.Fatalf("restore the record: %v", err)
	}
}

func TestConflictsIgnoreKeysThatAreNotNames(t *testing.T) {
	v, _ := newVault(t)
	inject(t, v,
		merge.Conflict{ID: "c_x", Key: "global/bad name\x1b[31m", LostAt: "2026-11-04T10:00:00Z", Deleted: true},
		merge.Conflict{ID: "c_y", Key: "nonsense", LostAt: "2026-11-04T10:00:00Z", Deleted: true},
		merge.Conflict{ID: "c_z", Key: "project/unknownid/P_KEY", LostAt: "2026-11-04T11:00:00Z", Deleted: true})
	list, err := v.Conflicts()
	if err != nil || len(list) != 1 || list[0].Name != "P_KEY" || !list[0].Layer.Project || list[0].Layer.Root != "" {
		t.Fatalf("conflicts = %+v (%v)", list, err)
	}
}

func TestRestoreRecordsWritesTheDifferenceAsNewChanges(t *testing.T) {
	v, _ := newVault(t)
	root := fakeRepo(t, "")
	pl := Layer{Project: true, Root: root, Label: "shop-api"}
	mustPut(t, v, Global(), "G_SAME", rec("TESTSECRET_same"))
	mustPut(t, v, Global(), "G_EDIT", rec("TESTSECRET_old"))
	mustPut(t, v, Global(), "G_GONE", rec("TESTSECRET_gone"))
	mustPut(t, v, pl, "P_KEY", rec("TESTSECRET_p_old"))
	target, err := v.Body()
	if err != nil {
		t.Fatal(err)
	}
	// Later state: an edit, a removal, a new record, a new project record,
	// and a device that was revoked meanwhile.
	mustPut(t, v, Global(), "G_EDIT", rec("TESTSECRET_new"))
	if err := v.Remove(Global(), "G_GONE"); err != nil {
		t.Fatal(err)
	}
	mustPut(t, v, Global(), "G_ADDED", rec("TESTSECRET_added"))
	mustPut(t, v, pl, "P_KEY", rec("TESTSECRET_p_new"))
	mustPut(t, v, pl, "P_ADDED", rec("TESTSECRET_p_added"))
	revoked := "2026-11-04T09:00:00Z"
	if err := v.EditRoster(func(r map[string]merge.Device) { r["dX"] = merge.Device{Label: "old", RevokedAt: &revoked} }); err != nil {
		t.Fatal(err)
	}
	before := readBody(t, v)
	var pid string
	for id := range before.Projects {
		pid = id
	}

	changed, err := v.RestoreRecords(target)
	if err != nil || changed != 5 {
		t.Fatalf("changed = %d err = %v", changed, err)
	}
	for name, want := range map[string]string{"G_SAME": "TESTSECRET_same", "G_EDIT": "TESTSECRET_old", "G_GONE": "TESTSECRET_gone"} {
		if got := valueOf(t, v, Global(), name); got != want {
			t.Fatalf("%s holds the wrong version", name)
		}
	}
	if valueOf(t, v, pl, "P_KEY") != "TESTSECRET_p_old" {
		t.Fatal("the project record was not restored")
	}
	all, _ := v.ListAll()
	for _, e := range all {
		if e.Name == "G_ADDED" || e.Name == "P_ADDED" {
			t.Fatalf("%s should be gone", e.Name)
		}
		e.Record.Value.Wipe()
	}
	after := readBody(t, v)
	// Unchanged records keep their clock and id; changed ones get fresh ones
	// that beat what was there, so they win when they sync.
	if after.Global["G_SAME"].HLC() != before.Global["G_SAME"].HLC() || string(after.Global["G_SAME"]["id"]) != string(before.Global["G_SAME"]["id"]) {
		t.Fatal("an unchanged record was rewritten")
	}
	for _, n := range []string{"G_EDIT"} {
		if after.Global[n].HLC() <= before.Global[n].HLC() || string(after.Global[n]["id"]) == string(before.Global[n]["id"]) {
			t.Fatalf("%s needs a fresh clock and id", n)
		}
	}
	if after.Global["G_GONE"].HLC() <= before.Global["G_EDIT"].HLC() {
		t.Fatal("a record brought back must beat the tombstone it replaces")
	}
	tombs := map[string]bool{}
	for _, tb := range after.Tombstones {
		tombs[tb.Key] = true
	}
	if !tombs["global/G_ADDED"] || !tombs["project/"+pid+"/P_ADDED"] || tombs["global/G_GONE"] {
		t.Fatalf("tombstones = %+v", after.Tombstones)
	}
	if d := after.Devices["dX"]; d.RevokedAt == nil {
		t.Fatal("a restore must not un-revoke a device")
	}
	// A second restore of the same target changes nothing.
	if n, err := v.RestoreRecords(target); err != nil || n != 0 {
		t.Fatalf("second restore = %d %v", n, err)
	}
	if _, err := v.RestoreRecords([]byte(`{"schema":1}`)); err == nil {
		t.Fatal("a body that is not schema 2 was applied")
	}
	if _, err := v.RestoreRecords([]byte(`not json`)); err == nil {
		t.Fatal("garbage was applied")
	}
}

func TestAnchorTimeLivesBesideTheRemoteState(t *testing.T) {
	v, home := newVault(t)
	_ = v
	if _, ok, err := ReadAnchorAt(home); ok || err != nil {
		t.Fatalf("fresh: %v %v", ok, err)
	}
	at := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	if err := WriteRemote(home, &Remote{Server: "http://127.0.0.1:1", AccountID: "a", Generation: 1}); err != nil {
		t.Fatal(err)
	}
	if err := WriteAnchorAt(home, at); err != nil {
		t.Fatal(err)
	}
	got, ok, err := ReadAnchorAt(home)
	if err != nil || !ok || !got.Equal(at) {
		t.Fatalf("read = %v %v %v", got, ok, err)
	}
	// Rewriting the remote object keeps it; a zero time and DisableRemote remove it.
	if err := WriteRemote(home, &Remote{Server: "http://127.0.0.1:1", AccountID: "a", Generation: 2}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := ReadAnchorAt(home); !ok {
		t.Fatal("writing the remote state dropped the anchor time")
	}
	if err := WriteAnchorAt(home, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := ReadAnchorAt(home); ok {
		t.Fatal("a zero time should remove it")
	}
	_ = WriteAnchorAt(home, at)
	if err := DisableRemote(home); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := ReadAnchorAt(home); ok || strings.Contains(string(mustRead(t, home)), anchorAtKey) {
		t.Fatal("DisableRemote left the anchor time")
	}
}

func mustRead(t *testing.T, home string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(home, stateFile))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
