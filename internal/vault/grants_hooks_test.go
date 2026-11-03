package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// fakeEditor stands in for internal/grants: the body is a JSON list of
// {"name","layer"} rows.
type fakeEditor struct {
	drops      [][2]string
	layerDrops []string
	broadDrops [][3]string
}

type fakeRow struct {
	Name  string `json:"name"`
	Layer string `json:"layer"`
	Scope string `json:"scope,omitempty"`
}

func fakeBody(rows ...fakeRow) []byte {
	b, _ := json.Marshal(rows)
	return b
}

func parseFake(t *testing.T, b []byte) []fakeRow {
	t.Helper()
	var rows []fakeRow
	if b != nil {
		if err := json.Unmarshal(b, &rows); err != nil {
			t.Fatal(err)
		}
	}
	return rows
}

func (f *fakeEditor) DropRecord(body []byte, name, layer string) ([]byte, int, error) {
	f.drops = append(f.drops, [2]string{name, layer})
	var rows, keep []fakeRow
	if body != nil {
		_ = json.Unmarshal(body, &rows)
	}
	for _, r := range rows {
		if r.Name != name || r.Layer != layer {
			keep = append(keep, r)
		}
	}
	if len(keep) == len(rows) {
		return nil, 0, nil
	}
	return fakeBody(keep...), len(rows) - len(keep), nil
}

func (f *fakeEditor) DropLayer(body []byte, layer string) ([]byte, int, error) {
	f.layerDrops = append(f.layerDrops, layer)
	var rows, keep []fakeRow
	if body != nil {
		_ = json.Unmarshal(body, &rows)
	}
	for _, r := range rows {
		if r.Layer != layer {
			keep = append(keep, r)
		}
	}
	if len(keep) == len(rows) {
		return nil, 0, nil
	}
	return fakeBody(keep...), len(rows) - len(keep), nil
}

func (f *fakeEditor) DropNonOnce(body []byte, name, layer, recordID string) ([]byte, int, error) {
	f.broadDrops = append(f.broadDrops, [3]string{name, layer, recordID})
	var rows, keep []fakeRow
	if body != nil {
		_ = json.Unmarshal(body, &rows)
	}
	for _, r := range rows {
		if r.Name == name && r.Layer == layer && r.Scope != "once" {
			continue
		}
		keep = append(keep, r)
	}
	if len(keep) == len(rows) {
		return nil, 0, nil
	}
	return fakeBody(keep...), len(rows) - len(keep), nil
}

func TestRemoveWithGrantsDropsOnlyThatRecord(t *testing.T) {
	v, _ := newVault(t)
	repo := mkRepo(t, t.TempDir(), "shop", false)
	pl := layerOf(t, repo)
	mustPut(t, v, Global(), "A_KEY", rec("g"))
	mustPut(t, v, pl, "A_KEY", rec("p"))
	setGrants(t, v, fakeBody(
		fakeRow{Name: "A_KEY", Layer: "global"}, fakeRow{Name: "A_KEY", Layer: pl.Key()}, fakeRow{Name: "A_KEY", Layer: pl.Key()}, fakeRow{Name: "OTHER", Layer: pl.Key()}))
	ed := &fakeEditor{}
	res, err := v.RemoveWithGrants(pl, "A_KEY", ed)
	if err != nil || res.Changed != 2 || res.Reset {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if len(ed.drops) != 1 || ed.drops[0] != [2]string{"A_KEY", "project:" + pl.Root} {
		t.Fatalf("drops = %v", ed.drops)
	}
	body, _ := getGrants(t, v)
	if got := parseFake(t, body); len(got) != 2 {
		t.Fatalf("rows = %v", got)
	}
}

func TestRemoveWithGrantsFailedRemoveTouchesNothing(t *testing.T) {
	v, home := newVault(t)
	setGrants(t, v, fakeBody(fakeRow{Name: "A_KEY", Layer: "global"}))
	before, _ := os.ReadFile(grantsPath(home))
	ed := &fakeEditor{}
	if _, err := v.RemoveWithGrants(Global(), "A_KEY", ed); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if len(ed.drops) != 0 {
		t.Fatal("editor ran for a failed remove")
	}
	if after, _ := os.ReadFile(grantsPath(home)); !bytes.Equal(before, after) {
		t.Fatal("grants changed")
	}
}

func TestPlainRemoveStillWorksWithoutEditor(t *testing.T) {
	v, _ := newVault(t)
	mustPut(t, v, Global(), "A_KEY", rec("g"))
	if err := v.Remove(Global(), "A_KEY"); err != nil {
		t.Fatal(err)
	}
}

func TestMoveWithGrantsDropsBothLayers(t *testing.T) {
	v, _ := newVault(t)
	repo := mkRepo(t, t.TempDir(), "shop", false)
	pl := layerOf(t, repo)
	mustPut(t, v, Global(), "A_KEY", rec("g"))
	setGrants(t, v, fakeBody(fakeRow{Name: "A_KEY", Layer: "global"}, fakeRow{Name: "A_KEY", Layer: pl.Key()}, fakeRow{Name: "B_KEY", Layer: "global"}))
	ed := &fakeEditor{}
	res, err := v.MoveWithGrants("A_KEY", Global(), pl, false, ed)
	if err != nil || res.Changed != 2 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	body, _ := getGrants(t, v)
	if got := parseFake(t, body); len(got) != 1 || got[0].Name != "B_KEY" {
		t.Fatalf("rows = %v", got)
	}
}

func TestMoveWithGrantsRefusedMoveKeepsGrants(t *testing.T) {
	v, _ := newVault(t)
	repo := mkRepo(t, t.TempDir(), "shop", false)
	pl := layerOf(t, repo)
	mustPut(t, v, Global(), "A_KEY", rec("g"))
	mustPut(t, v, pl, "A_KEY", rec("p"))
	setGrants(t, v, fakeBody(fakeRow{Name: "A_KEY", Layer: "global"}))
	ed := &fakeEditor{}
	if _, err := v.MoveWithGrants("A_KEY", Global(), pl, false, ed); !errors.Is(err, ErrExists) {
		t.Fatalf("err = %v", err)
	}
	if len(ed.drops) != 0 {
		t.Fatal("editor ran for a refused move")
	}
}

func TestReplaceWithGrants(t *testing.T) {
	v, _ := newVault(t)
	ed := &fakeEditor{}
	setGrants(t, v, fakeBody(fakeRow{Name: "A_KEY", Layer: "global"}))
	// First creation: nothing to drop, the editor is not consulted.
	if res, err := v.ReplaceWithGrants(Global(), "B_KEY", rec("x"), ed); err != nil || res.Changed != 0 || len(ed.drops) != 0 {
		t.Fatalf("create: res=%+v err=%v drops=%v", res, err, ed.drops)
	}
	mustPut(t, v, Global(), "A_KEY", rec("old"))
	res, err := v.ReplaceWithGrants(Global(), "A_KEY", rec("new"), ed)
	if err != nil || res.Changed != 1 {
		t.Fatalf("replace: res=%+v err=%v", res, err)
	}
	if body, _ := getGrants(t, v); len(parseFake(t, body)) != 0 {
		t.Fatal("grants survived a value replace")
	}
	r, _, _ := v.Resolve("A_KEY", t.TempDir())
	if !sameValue(r, "new") {
		t.Fatal("value not replaced")
	}
}

func TestRelinkWithGrantsDropsTheOldLayerAndCarriesNothing(t *testing.T) {
	v, _ := newVault(t)
	dir := t.TempDir()
	oldRepo := mkRepo(t, dir, "shop", false)
	oldRoot := canonical(t, oldRepo)
	mustPut(t, v, layerOf(t, oldRepo), "A_KEY", rec("v"))
	setGrants(t, v, fakeBody(fakeRow{Name: "A_KEY", Layer: "project:" + oldRoot}, fakeRow{Name: "B_KEY", Layer: "project:" + oldRoot}, fakeRow{Name: "A_KEY", Layer: "global"}))
	newRepo := filepath.Join(dir, "renamed")
	moveRepo(t, oldRepo, newRepo)
	ed := &fakeEditor{}
	n, res, err := v.RelinkWithGrants(oldRoot, newRepo, ed)
	if err != nil || n != 1 || res.Changed != 2 {
		t.Fatalf("n=%d res=%+v err=%v", n, res, err)
	}
	if len(ed.layerDrops) != 1 || ed.layerDrops[0] != "project:"+oldRoot {
		t.Fatalf("layer drops = %v", ed.layerDrops)
	}
	body, _ := getGrants(t, v)
	got := parseFake(t, body)
	if len(got) != 1 || got[0].Layer != "global" {
		t.Fatalf("rows = %v", got)
	}
}

func TestEditWithGrantsSensitiveDropsBroadGrantsKeepsID(t *testing.T) {
	v, _ := newVault(t)
	mustPut(t, v, Global(), "A_KEY", rec("v"))
	r, _, _ := v.Resolve("A_KEY", t.TempDir())
	id := r.ID
	setGrants(t, v, fakeBody(
		fakeRow{Name: "A_KEY", Layer: "global", Scope: "session"},
		fakeRow{Name: "A_KEY", Layer: "global", Scope: "once"},
		fakeRow{Name: "B_KEY", Layer: "global", Scope: "session"}))

	// Not sensitive: the editor is not consulted.
	ed := &fakeEditor{}
	r.Description = "d"
	if res, err := v.EditWithGrants(Global(), "A_KEY", r, ed); err != nil || res.Changed != 0 || len(ed.broadDrops) != 0 {
		t.Fatalf("plain edit: res=%+v err=%v drops=%v", res, err, ed.broadDrops)
	}
	r.Sensitive = true
	res, err := v.EditWithGrants(Global(), "A_KEY", r, ed)
	if err != nil || res.Changed != 1 {
		t.Fatalf("sensitive edit: res=%+v err=%v", res, err)
	}
	if len(ed.broadDrops) != 1 || ed.broadDrops[0] != [3]string{"A_KEY", "global", id} {
		t.Fatalf("broad drops = %v", ed.broadDrops)
	}
	body, _ := getGrants(t, v)
	if got := parseFake(t, body); len(got) != 2 {
		t.Fatalf("rows = %v", got)
	}
	after, _, _ := v.Resolve("A_KEY", t.TempDir())
	if after.ID != id || !after.Sensitive || after.Description != "d" {
		t.Fatalf("edit changed id or lost metadata: %+v", after)
	}
	// A failed vault edit leaves grants alone.
	ed = &fakeEditor{}
	if _, err := v.EditWithGrants(Global(), "NOPE_KEY", r, ed); !errors.Is(err, ErrNotFound) || len(ed.broadDrops) != 0 {
		t.Fatalf("err=%v drops=%v", err, ed.broadDrops)
	}
}

func TestRelinkWithGrantsRefusedKeepsGrants(t *testing.T) {
	v, _ := newVault(t)
	dir := t.TempDir()
	other := mkRepo(t, dir, "other", false)
	fresh := mkRepo(t, dir, "fresh", false)
	ed := &fakeEditor{}
	if _, _, err := v.RelinkWithGrants(other, fresh, ed); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if len(ed.layerDrops) != 0 {
		t.Fatal("editor ran for a refused relink")
	}
}

func TestEditorReportsReset(t *testing.T) {
	v, home := newVault(t)
	mustPut(t, v, Global(), "A_KEY", rec("g"))
	setGrants(t, v, fakeBody(fakeRow{Name: "A_KEY", Layer: "global"}))
	raw, _ := os.ReadFile(grantsPath(home))
	raw[len(raw)/2] ^= 0x01
	_ = os.WriteFile(grantsPath(home), raw, 0o600)
	res, err := v.RemoveWithGrants(Global(), "A_KEY", &fakeEditor{})
	if err != nil || !res.Reset || res.Changed != 0 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}
