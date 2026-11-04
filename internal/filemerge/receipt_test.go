package filemerge

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

var jsonEdits = []JSONEdit{mcpEdit, hookEdit}

func TestMergeJSONFileCreatesSnapshotsAndReceipt(t *testing.T) {
	home := newHome(t)
	p := filepath.Join(t.TempDir(), ".claude", "settings.json")
	writeFile(t, p, "{\n  \"theme\": \"dark\"\n}\n")

	r, err := MergeJSONFile(home, p, jsonEdits, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Changed || r.Path != p || !r.Snapshot.Existed || r.Created || !r.Exact || r.SHA256 == "" {
		t.Fatalf("receipt: %+v", r)
	}
	if got := readFile(t, r.Snapshot.Backup); got != "{\n  \"theme\": \"dark\"\n}\n" {
		t.Fatalf("snapshot = %q", got)
	}
	// Second apply: no change, no new snapshot, receipt carried over.
	r2, err := MergeJSONFile(home, p, jsonEdits, &r)
	if err != nil {
		t.Fatal(err)
	}
	if r2.Changed || r2 != (Receipt{Path: r.Path, Snapshot: r.Snapshot, SHA256: r.SHA256, Created: r.Created, Exact: r.Exact}) {
		t.Fatalf("idempotent apply: %+v", r2)
	}
	entries, _ := os.ReadDir(filepath.Join(home, "backups"))
	if len(entries) != 1 {
		t.Fatalf("snapshots = %d, want 1", len(entries))
	}
}

func TestMergeFileInvalidInputTouchesNothing(t *testing.T) {
	home := newHome(t)
	p := filepath.Join(t.TempDir(), "settings.json")
	writeFile(t, p, "{ not json")
	if _, err := MergeJSONFile(home, p, jsonEdits, nil); !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("err = %v", err)
	}
	if got := readFile(t, p); got != "{ not json" {
		t.Fatalf("file modified: %q", got)
	}
	if _, err := os.Stat(filepath.Join(home, "backups")); !os.IsNotExist(err) {
		t.Fatalf("snapshot taken for a refused merge: %v", err)
	}

	tp := filepath.Join(t.TempDir(), "config.toml")
	dup := "[mcp_servers.qbit-vault]\na=1\n[mcp_servers.qbit-vault]\n"
	writeFile(t, tp, dup)
	if _, err := MergeTOMLFile(home, tp, tomlOwn, tomlBlock, nil); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("err = %v", err)
	}
	if got := readFile(t, tp); got != dup {
		t.Fatalf("file modified: %q", got)
	}
}

func TestMergeFileWriteFailureKeepsOriginal(t *testing.T) {
	home := newHome(t)
	p := filepath.Join(t.TempDir(), "settings.json")
	writeFile(t, p, "{}\n")
	prev := beforeRename
	beforeRename = func(string, string) error { return errors.New("crash") }
	defer func() { beforeRename = prev }()
	if _, err := MergeJSONFile(home, p, jsonEdits, nil); err == nil {
		t.Fatal("expected error")
	}
	if got := readFile(t, p); got != "{}\n" {
		t.Fatalf("original damaged: %q", got)
	}
}

func TestRevertCase1RestoresSnapshotByteForByte(t *testing.T) {
	home := newHome(t)
	p := filepath.Join(t.TempDir(), "settings.json")
	orig := "{\n    \"theme\" :  \"dark\" ,\n\n  \"x\":[1,\n2]}"
	writeFile(t, p, orig)
	r, err := MergeJSONFile(home, p, jsonEdits, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := RevertJSONFile(home, r, jsonEdits)
	if err != nil {
		t.Fatal(err)
	}
	if out != Restored || readFile(t, p) != orig {
		t.Fatalf("outcome %v, content %q", out, readFile(t, p))
	}
}

func TestRevertCase2KeepsUserEdits(t *testing.T) {
	home := newHome(t)
	p := filepath.Join(t.TempDir(), "settings.json")
	writeFile(t, p, "{\n  \"theme\": \"dark\"\n}\n")
	r, err := MergeJSONFile(home, p, jsonEdits, nil)
	if err != nil {
		t.Fatal(err)
	}
	merged := readFile(t, p)
	// The user adds a key after us.
	edited, err := MergeJSON([]byte(merged), []JSONEdit{{Path: []string{"model"}, Value: []byte(`"opus"`)}})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, p, string(edited))

	out, err := RevertJSONFile(home, r, jsonEdits)
	if err != nil {
		t.Fatal(err)
	}
	if out != Stripped {
		t.Fatalf("outcome %v", out)
	}
	got := readFile(t, p)
	for _, want := range []string{`"theme": "dark"`, `"model": "opus"`} {
		if !contains(got, want) {
			t.Fatalf("user key lost (%s): %q", want, got)
		}
	}
	for _, gone := range []string{"qbit-vault"} {
		if contains(got, gone) {
			t.Fatalf("our entry survived: %q", got)
		}
	}
}

func TestRevertCase3FileAbsentBefore(t *testing.T) {
	home := newHome(t)
	p := filepath.Join(t.TempDir(), ".claude", "settings.json")
	r, err := MergeJSONFile(home, p, jsonEdits, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Created || r.Snapshot.Existed {
		t.Fatalf("receipt: %+v", r)
	}

	// Untouched since: file is deleted.
	out, err := RevertJSONFile(home, r, jsonEdits)
	if err != nil || out != Deleted {
		t.Fatalf("outcome %v, err %v", out, err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("file still there: %v", err)
	}

	// Edited by the user since: only our keys go, the file stays.
	r, err = MergeJSONFile(home, p, jsonEdits, nil)
	if err != nil {
		t.Fatal(err)
	}
	edited, _ := MergeJSON([]byte(readFile(t, p)), []JSONEdit{{Path: []string{"model"}, Value: []byte(`"opus"`)}})
	writeFile(t, p, string(edited))
	out, err = RevertJSONFile(home, r, jsonEdits)
	if err != nil || out != Stripped {
		t.Fatalf("outcome %v, err %v", out, err)
	}
	got := readFile(t, p)
	if !contains(got, `"model": "opus"`) || contains(got, "qbit-vault") || contains(got, "mcpServers") || contains(got, "hooks") {
		t.Fatalf("after revert: %q", got)
	}

	// Edited, then everything the user added removed again: only our content remained, so delete.
	r, err = MergeJSONFile(home, p, jsonEdits, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = r
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	writeFile(t, p, `{"mcpServers":{"qbit-vault":{"command":"x"}}}`)
	r.Created = true
	r.Exact = false
	out, err = RevertJSONFile(home, r, jsonEdits)
	if err != nil || out != Deleted {
		t.Fatalf("outcome %v, err %v", out, err)
	}
}

func TestRevertAbsentFileAndMissingBackup(t *testing.T) {
	home := newHome(t)
	p := filepath.Join(t.TempDir(), "settings.json")
	writeFile(t, p, "{\"a\": 1}\n")
	r, err := MergeJSONFile(home, p, jsonEdits, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Backup pruned away: falls back to removing only our keys.
	if err := os.Remove(r.Snapshot.Backup); err != nil {
		t.Fatal(err)
	}
	out, err := RevertJSONFile(home, r, jsonEdits)
	if err != nil || out != Stripped {
		t.Fatalf("outcome %v, err %v", out, err)
	}
	if got := readFile(t, p); !contains(got, `"a": 1`) || contains(got, "qbit-vault") {
		t.Fatalf("after revert: %q", got)
	}
	// User deleted the file: nothing to do.
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	out, err = RevertJSONFile(home, r, jsonEdits)
	if err != nil || out != Absent {
		t.Fatalf("outcome %v, err %v", out, err)
	}
}

func TestRevertTwiceIsUnchanged(t *testing.T) {
	home := newHome(t)
	p := filepath.Join(t.TempDir(), "config.toml")
	writeFile(t, p, "model = \"o3\"\n")
	r, err := MergeTOMLFile(home, p, tomlOwn, tomlBlock, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := RevertTOMLFile(home, r, tomlOwn); err != nil || out != Restored {
		t.Fatalf("first: %v %v", out, err)
	}
	if out, err := RevertTOMLFile(home, r, tomlOwn); err != nil || out != Unchanged {
		t.Fatalf("second: %v %v", out, err)
	}
}

func TestRevertTOMLCases(t *testing.T) {
	home := newHome(t)
	p := filepath.Join(t.TempDir(), ".codex", "config.toml")

	// Absent before, untouched since: delete.
	r, err := MergeTOMLFile(home, p, tomlOwn, tomlBlock, nil)
	if err != nil || !r.Created {
		t.Fatalf("merge: %+v %v", r, err)
	}
	if got := readFile(t, p); got != tomlBlock {
		t.Fatalf("created file = %q", got)
	}
	if out, err := RevertTOMLFile(home, r, tomlOwn); err != nil || out != Deleted {
		t.Fatalf("delete: %v %v", out, err)
	}

	// Edited since: strip our table, keep the edit.
	r, err = MergeTOMLFile(home, p, tomlOwn, tomlBlock, nil)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, p, "# mine\nmodel = \"o3\"\n\n"+tomlBlock)
	if out, err := RevertTOMLFile(home, r, tomlOwn); err != nil || out != Stripped {
		t.Fatalf("strip: %v %v", out, err)
	}
	if got := readFile(t, p); got != "# mine\nmodel = \"o3\"\n" {
		t.Fatalf("after strip: %q", got)
	}

	// Refuses (and leaves the file) when the file became ambiguous.
	writeFile(t, p, tomlBlock+"\n"+tomlBlock)
	if _, err := RevertTOMLFile(home, r, tomlOwn); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("ambiguous: %v", err)
	}
	if got := readFile(t, p); got != tomlBlock+"\n"+tomlBlock {
		t.Fatalf("file modified: %q", got)
	}
}

func TestReapplyAfterUserEditIsNotExact(t *testing.T) {
	home := newHome(t)
	p := filepath.Join(t.TempDir(), "settings.json")
	writeFile(t, p, "{\"a\": 1}\n")
	r1, err := MergeJSONFile(home, p, jsonEdits, nil)
	if err != nil {
		t.Fatal(err)
	}
	// User edits, then sync re-applies a changed entry.
	edited, _ := MergeJSON([]byte(readFile(t, p)), []JSONEdit{{Path: []string{"model"}, Value: []byte(`"x"`)}})
	writeFile(t, p, string(edited))
	changed := []JSONEdit{{Path: []string{"mcpServers", "qbit-vault"}, Value: []byte(`{"command":"other"}`)}, hookEdit}
	r2, err := MergeJSONFile(home, p, changed, &r1)
	if err != nil {
		t.Fatal(err)
	}
	if !r2.Changed || r2.Exact || r2.Created {
		t.Fatalf("receipt: %+v", r2)
	}
	// Reverting must not roll the user's edit back to the first snapshot.
	out, err := RevertJSONFile(home, r2, jsonEdits)
	if err != nil || out != Stripped {
		t.Fatalf("outcome %v, err %v", out, err)
	}
	if got := readFile(t, p); !contains(got, `"model": "x"`) || contains(got, "qbit-vault") {
		t.Fatalf("after revert: %q", got)
	}
}

func TestRevertSnapshotsBeforeMutating(t *testing.T) {
	home := newHome(t)
	p := filepath.Join(t.TempDir(), "settings.json")
	writeFile(t, p, "{\"a\": 1}\n")
	r, err := MergeJSONFile(home, p, jsonEdits, nil)
	if err != nil {
		t.Fatal(err)
	}
	edited, _ := MergeJSON([]byte(readFile(t, p)), []JSONEdit{{Path: []string{"m"}, Value: []byte(`1`)}})
	writeFile(t, p, string(edited))
	before, _ := os.ReadDir(filepath.Join(home, "backups"))
	if _, err := RevertJSONFile(home, r, jsonEdits); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadDir(filepath.Join(home, "backups"))
	if len(after) != len(before)+1 {
		t.Fatalf("snapshots before=%d after=%d", len(before), len(after))
	}
}
