package vault

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestExportAllListsEveryLayerWithValuesAndMetadata(t *testing.T) {
	v, _ := newVault(t)
	g := rec("TESTSECRET_g")
	g.Description, g.Sensitive, g.Binaries, g.Hosts, g.Kind = "d", true, []string{"gh"}, []string{"h"}, "text"
	mustPut(t, v, Global(), "G_KEY", g)
	mustPut(t, v, Global(), "A_KEY", rec("TESTSECRET_a"))
	mustPut(t, v, Layer{Project: true, Root: "/work/b", Label: "b"}, "P_KEY", rec("TESTSECRET_p"))
	mustPut(t, v, Layer{Project: true, Root: "/work/a", Label: "a"}, "P_KEY", rec("TESTSECRET_pa"))
	layers, unlinked, err := v.ExportAll()
	if err != nil || unlinked != 0 {
		t.Fatalf("err=%v unlinked=%d", err, unlinked)
	}
	if len(layers) != 3 || layers[0].Layer.Project || layers[1].Layer.Root != "/work/a" || layers[2].Layer.Root != "/work/b" || layers[2].Layer.Label != "b" {
		t.Fatalf("layers=%+v", layers)
	}
	if len(layers[0].Records) != 2 || layers[0].Records[0].Name != "A_KEY" || layers[0].Records[1].Name != "G_KEY" {
		t.Fatalf("global=%+v", layers[0].Records)
	}
	gr := layers[0].Records[1].Record
	if !sameValue(gr, "TESTSECRET_g") || gr.Description != "d" || !gr.Sensitive || gr.Kind != "text" || len(gr.Binaries) != 1 || len(gr.Hosts) != 1 || gr.CreatedAt == "" || gr.UpdatedAt == "" {
		t.Fatalf("record=%+v", gr)
	}
}

func TestImportAllMergesReplacesWholeAndKeepsTimestamps(t *testing.T) {
	v, home := newVault(t)
	old := rec("TESTSECRET_old")
	old.Description, old.Binaries, old.Hosts, old.Sensitive = "old", []string{"curl"}, []string{"old.host"}, true
	mustPut(t, v, Global(), "CLASH", old)
	mustPut(t, v, Global(), "ONLY_HERE", rec("TESTSECRET_mine"))
	oldRec, _, _ := v.Resolve("CLASH", t.TempDir())
	root := Layer{Project: true, Root: "/work/shop", Label: "shop"}
	in := []LayerRecords{
		{Layer: Global(), Records: []NamedRecord{{Name: "CLASH", Record: Record{
			Value: rec("TESTSECRET_new").Value, Description: "new", CreatedAt: "2025-01-02T03:04:05Z", UpdatedAt: "2025-06-07T08:09:10Z"}}}},
		{Layer: root, Records: []NamedRecord{{Name: "P_KEY", Record: rec("TESTSECRET_p")}}},
	}
	before := len(backupsOf(t, home))
	ed := &dropAll{}
	res, replaced, err := v.ImportAll(in, ed)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(backupsOf(t, home)) - before; got != 1 {
		t.Fatalf("%d snapshots for one import", got)
	}
	if len(replaced) != 1 || replaced[0].Name != "CLASH" || replaced[0].Layer.Project || res.Changed != 1 || len(ed.dropped) != 1 || ed.dropped[0] != "CLASH@global" {
		t.Fatalf("replaced=%+v res=%+v dropped=%v", replaced, res, ed.dropped)
	}
	got, _, err := v.Resolve("CLASH", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !sameValue(got, "TESTSECRET_new") || got.Description != "new" || got.Sensitive || len(got.Binaries) != 0 || len(got.Hosts) != 0 {
		t.Fatalf("CLASH kept something of the old record: %+v", got)
	}
	if got.CreatedAt != "2025-01-02T03:04:05Z" || got.UpdatedAt != "2025-06-07T08:09:10Z" {
		t.Fatalf("timestamps were not kept: %s %s", got.CreatedAt, got.UpdatedAt)
	}
	if got.ID == "" || got.ID == oldRec.ID {
		t.Fatal("a replaced record must get a new id")
	}
	mine, _, err := v.Resolve("ONLY_HERE", t.TempDir())
	if err != nil || !sameValue(mine, "TESTSECRET_mine") {
		t.Fatalf("a record the import does not name changed: %v", err)
	}
	all, _, _ := v.ExportAll()
	if len(all) != 2 || all[1].Layer.Root != "/work/shop" || all[1].Layer.Label != "shop" || len(all[1].Records) != 1 {
		t.Fatalf("project layer not created: %+v", all)
	}
	// A second import leaves the label alone and clashes with itself.
	again, err := v.Clashes(in)
	if err != nil || len(again) != 2 {
		t.Fatalf("clashes=%+v err=%v", again, err)
	}
}

func TestImportAllRejectsBadInputWithoutWriting(t *testing.T) {
	v, home := newVault(t)
	live, _ := os.ReadFile(filepath.Join(home, vaultFile))
	good := NamedRecord{Name: "A", Record: rec("x")}
	cases := map[string][]LayerRecords{
		"empty":          nil,
		"no records":     {{Layer: Global()}},
		"invalid name":   {{Layer: Global(), Records: []NamedRecord{good, {Name: "bad", Record: rec("y")}}}},
		"duplicate":      {{Layer: Global(), Records: []NamedRecord{good, good}}},
		"rootless layer": {{Layer: Layer{Project: true}, Records: []NamedRecord{good}}},
		"same twice":     {{Layer: Global(), Records: []NamedRecord{good}}, {Layer: Global(), Records: []NamedRecord{good}}},
	}
	for n, c := range cases {
		if _, _, err := v.ImportAll(c, nil); err == nil {
			t.Errorf("%s accepted", n)
		}
	}
	if _, _, err := v.ImportAll(cases["rootless layer"], nil); !errors.Is(err, ErrNoProject) {
		t.Fatalf("rootless layer: %v", err)
	}
	if now, _ := os.ReadFile(filepath.Join(home, vaultFile)); string(now) != string(live) {
		t.Fatal("rejected input changed the vault")
	}
}
