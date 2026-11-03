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
	drops   [][2]string
	relinks [][2]string
}

type fakeRow struct {
	Name  string `json:"name"`
	Layer string `json:"layer"`
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

func (f *fakeEditor) RelinkProject(body []byte, oldRoot, newRoot string) ([]byte, int, error) {
	f.relinks = append(f.relinks, [2]string{oldRoot, newRoot})
	var rows []fakeRow
	if body != nil {
		_ = json.Unmarshal(body, &rows)
	}
	n := 0
	for i, r := range rows {
		if r.Layer == "project:"+oldRoot {
			rows[i].Layer = "project:" + newRoot
			n++
		}
	}
	if n == 0 {
		return nil, 0, nil
	}
	return fakeBody(rows...), n, nil
}

func TestRemoveWithGrantsDropsOnlyThatRecord(t *testing.T) {
	v, _ := newVault(t)
	repo := mkRepo(t, t.TempDir(), "shop", false)
	pl := layerOf(t, repo)
	mustPut(t, v, Global(), "A_KEY", rec("g"))
	mustPut(t, v, pl, "A_KEY", rec("p"))
	setGrants(t, v, fakeBody(
		fakeRow{"A_KEY", "global"}, fakeRow{"A_KEY", pl.Key()}, fakeRow{"A_KEY", pl.Key()}, fakeRow{"OTHER", pl.Key()}))
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
	setGrants(t, v, fakeBody(fakeRow{"A_KEY", "global"}))
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
	setGrants(t, v, fakeBody(fakeRow{"A_KEY", "global"}, fakeRow{"A_KEY", pl.Key()}, fakeRow{"B_KEY", "global"}))
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
	setGrants(t, v, fakeBody(fakeRow{"A_KEY", "global"}))
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
	setGrants(t, v, fakeBody(fakeRow{"A_KEY", "global"}))
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

func TestRelinkWithGrantsRewritesProjectGrants(t *testing.T) {
	v, _ := newVault(t)
	dir := t.TempDir()
	oldRepo := mkRepo(t, dir, "shop", false)
	oldRoot := canonical(t, oldRepo)
	mustPut(t, v, layerOf(t, oldRepo), "A_KEY", rec("v"))
	setGrants(t, v, fakeBody(fakeRow{"A_KEY", "project:" + oldRoot}, fakeRow{"A_KEY", "global"}))
	newRepo := filepath.Join(dir, "renamed")
	moveRepo(t, oldRepo, newRepo)
	ed := &fakeEditor{}
	n, res, err := v.RelinkWithGrants(oldRoot, newRepo, ed)
	newRoot := canonical(t, newRepo)
	if err != nil || n != 1 || res.Changed != 1 {
		t.Fatalf("n=%d res=%+v err=%v", n, res, err)
	}
	if len(ed.relinks) != 1 || ed.relinks[0] != [2]string{oldRoot, newRoot} {
		t.Fatalf("relinks = %v", ed.relinks)
	}
	body, _ := getGrants(t, v)
	got := parseFake(t, body)
	if len(got) != 2 || got[0].Layer != "project:"+newRoot || got[1].Layer != "global" {
		t.Fatalf("rows = %v", got)
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
	if len(ed.relinks) != 0 {
		t.Fatal("editor ran for a refused relink")
	}
}

func TestEditorReportsReset(t *testing.T) {
	v, home := newVault(t)
	mustPut(t, v, Global(), "A_KEY", rec("g"))
	setGrants(t, v, fakeBody(fakeRow{"A_KEY", "global"}))
	raw, _ := os.ReadFile(grantsPath(home))
	raw[len(raw)/2] ^= 0x01
	_ = os.WriteFile(grantsPath(home), raw, 0o600)
	res, err := v.RemoveWithGrants(Global(), "A_KEY", &fakeEditor{})
	if err != nil || !res.Reset || res.Changed != 0 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}
