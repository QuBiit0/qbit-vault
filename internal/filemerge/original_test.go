package filemerge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Two steps sharing one file, like the Claude adapter's hooks and deny-list.
var (
	postEdit = JSONEdit{
		Path:   []string{"hooks", "PostToolUse"},
		Marker: "qbit-vault hook post",
		Value:  []byte(`{"hooks":[{"type":"command","command":"qbit-vault hook post"}]}`),
	}
	promptEdit = JSONEdit{
		Path:   []string{"hooks", "UserPromptSubmit"},
		Marker: "qbit-vault hook prompt",
		Value:  []byte(`{"hooks":[{"type":"command","command":"qbit-vault hook prompt"}]}`),
	}
	hooksStep = []JSONEdit{hookEdit, postEdit, promptEdit}
	denyStep  = []JSONEdit{denyEdit}
)

const userSettings = "{\n  \"hooks\": {\n    \"PreToolUse\": [\n      {\n        \"matcher\": \"Edit\",\n        \"hooks\": [{\"type\": \"command\", \"command\": \"mine\"}]\n      }\n    ]\n  },\n  \"theme\": \"dark\"\n}\n"

// driftHooks reapplies the repro: the user deletes our UserPromptSubmit block,
// then sync re-applies the hooks step with its previous receipt.
func driftAndReapply(t *testing.T, home, p string, rh Receipt) Receipt {
	t.Helper()
	cur := []byte(readFile(t, p))
	cut, err := UnmergeJSON(cur, []JSONEdit{promptEdit}, false)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, p, string(cut))
	rh2, err := MergeJSONFile(home, p, hooksStep, &rh)
	if err != nil {
		t.Fatal(err)
	}
	return rh2
}

func TestRevertSharedFileAfterDriftLeavesNoEmptyContainers(t *testing.T) {
	home := newHome(t)
	p := filepath.Join(t.TempDir(), "settings.json")
	writeFile(t, p, userSettings)

	rh, err := MergeJSONFile(home, p, hooksStep, nil)
	if err != nil {
		t.Fatal(err)
	}
	rd, err := MergeJSONFile(home, p, denyStep, nil)
	if err != nil {
		t.Fatal(err)
	}
	rh2 := driftAndReapply(t, home, p, rh)
	if rh2.Exact {
		t.Fatalf("re-apply must clear Exact: %+v", rh2)
	}

	if _, err := RevertJSONFile(home, rd, denyStep); err != nil {
		t.Fatal(err)
	}
	if _, err := RevertJSONFile(home, rh2, hooksStep); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, p); got != userSettings {
		t.Fatalf("not back to the original:\n%s", got)
	}
}

func TestOriginalSnapshotSurvivesReapplies(t *testing.T) {
	home := newHome(t)
	p := filepath.Join(t.TempDir(), "settings.json")
	writeFile(t, p, userSettings)
	r1, err := MergeJSONFile(home, p, hooksStep, nil)
	if err != nil {
		t.Fatal(err)
	}
	r2 := driftAndReapply(t, home, p, r1)
	r3 := driftAndReapply(t, home, p, r2)
	for i, r := range []Receipt{r2, r3} {
		orig, ok := r.original()
		if !ok || orig.Backup != r1.Snapshot.Backup {
			t.Fatalf("re-apply %d lost the original: %+v", i+1, r)
		}
		if got := readFile(t, orig.Backup); got != userSettings {
			t.Fatalf("original copy changed: %q", got)
		}
	}
	if r3.Snapshot.Backup == r1.Snapshot.Backup {
		t.Fatal("Snapshot must still be the latest pre-write copy")
	}
}

func TestRevertKeepsUserOwnedEmptyContainer(t *testing.T) {
	home := newHome(t)
	p := filepath.Join(t.TempDir(), "settings.json")
	orig := "{\n  \"hooks\": {\n    \"PostToolUse\": []\n  }\n}\n"
	writeFile(t, p, orig)
	r1, err := MergeJSONFile(home, p, hooksStep, nil)
	if err != nil {
		t.Fatal(err)
	}
	r2 := driftAndReapply(t, home, p, r1)
	if _, err := RevertJSONFile(home, r2, hooksStep); err != nil {
		t.Fatal(err)
	}
	got := readFile(t, p)
	if !contains(got, `"PostToolUse": []`) {
		t.Fatalf("user's empty array pruned: %q", got)
	}
	if contains(got, "UserPromptSubmit") || contains(got, "PreToolUse") || contains(got, "qbit-vault") {
		t.Fatalf("our leftovers: %q", got)
	}
}

func TestRevertAfterReapplyKeepsUserEditAndPrunesOurs(t *testing.T) {
	home := newHome(t)
	p := filepath.Join(t.TempDir(), "settings.json")
	writeFile(t, p, userSettings)
	r1, err := MergeJSONFile(home, p, hooksStep, nil)
	if err != nil {
		t.Fatal(err)
	}
	r2 := driftAndReapply(t, home, p, r1)
	edited, err := MergeJSON([]byte(readFile(t, p)), []JSONEdit{{Path: []string{"model"}, Value: []byte(`"opus"`)}})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, p, string(edited))

	out, err := RevertJSONFile(home, r2, hooksStep)
	if err != nil || out != Stripped {
		t.Fatalf("outcome %v, err %v", out, err)
	}
	got := readFile(t, p)
	if !contains(got, `"model": "opus"`) || !contains(got, `"theme": "dark"`) || !contains(got, `"mine"`) {
		t.Fatalf("user content lost: %q", got)
	}
	for _, gone := range []string{"qbit-vault", "PostToolUse", "UserPromptSubmit"} {
		if contains(got, gone) {
			t.Fatalf("%s left behind: %q", gone, got)
		}
	}
}

func TestRevertAfterUserEditOnFirstApplyPrunesOurs(t *testing.T) {
	// No re-apply: Exact stays true, the user edits afterwards, the snapshot is
	// the original and serves as the prune reference.
	home := newHome(t)
	p := filepath.Join(t.TempDir(), "settings.json")
	writeFile(t, p, userSettings)
	r1, err := MergeJSONFile(home, p, hooksStep, nil)
	if err != nil {
		t.Fatal(err)
	}
	edited, _ := MergeJSON([]byte(readFile(t, p)), []JSONEdit{{Path: []string{"model"}, Value: []byte(`"opus"`)}})
	writeFile(t, p, string(edited))
	if out, err := RevertJSONFile(home, r1, hooksStep); err != nil || out != Stripped {
		t.Fatalf("outcome %v, err %v", out, err)
	}
	got := readFile(t, p)
	if contains(got, "PostToolUse") || contains(got, "UserPromptSubmit") || !contains(got, `"model": "opus"`) {
		t.Fatalf("got %q", got)
	}
}

func TestRevertOldReceiptWithoutOriginalBehavesAsBefore(t *testing.T) {
	home := newHome(t)
	p := filepath.Join(t.TempDir(), "settings.json")
	writeFile(t, p, userSettings)
	r1, _ := MergeJSONFile(home, p, hooksStep, nil)
	r2 := driftAndReapply(t, home, p, r1)

	// An old state.json receipt: no "original" key at all.
	raw, err := json.Marshal(r2)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	delete(m, "original")
	raw, _ = json.Marshal(m)
	var old Receipt
	if err := json.Unmarshal(raw, &old); err != nil {
		t.Fatal(err)
	}
	if _, ok := old.original(); ok {
		t.Fatal("old receipt must have no original")
	}
	if out, err := RevertJSONFile(home, old, hooksStep); err != nil || out != Stripped {
		t.Fatalf("outcome %v, err %v", out, err)
	}
	got := readFile(t, p)
	if contains(got, "qbit-vault") || !contains(got, `"PostToolUse": []`) {
		t.Fatalf("old behaviour changed: %q", got)
	}
}

func TestReapplyOverOldExactReceiptAdoptsItsSnapshot(t *testing.T) {
	// An old receipt (Exact, no original) re-applied: its Snapshot is the
	// original and must be carried forward.
	home := newHome(t)
	p := filepath.Join(t.TempDir(), "settings.json")
	writeFile(t, p, userSettings)
	r1, _ := MergeJSONFile(home, p, hooksStep, nil)
	r2 := driftAndReapply(t, home, p, r1)
	if o, ok := r2.original(); !ok || o.Backup != r1.Snapshot.Backup {
		t.Fatalf("original = %+v", o)
	}
}

func TestRevertWithPrunedOriginalFallsBackToTodaysBehaviour(t *testing.T) {
	home := newHome(t)
	p := filepath.Join(t.TempDir(), "settings.json")
	writeFile(t, p, userSettings)
	r1, _ := MergeJSONFile(home, p, hooksStep, nil)
	r2 := driftAndReapply(t, home, p, r1)
	if err := os.Remove(r1.Snapshot.Backup); err != nil {
		t.Fatal(err)
	}
	out, err := RevertJSONFile(home, r2, hooksStep)
	if err != nil || out != Stripped {
		t.Fatalf("outcome %v, err %v", out, err)
	}
	got := readFile(t, p)
	if contains(got, "qbit-vault") || !contains(got, `"mine"`) || !contains(got, `"PostToolUse": []`) {
		t.Fatalf("got %q", got)
	}
}

func TestTOMLReapplyRevertLeavesNoParentHeader(t *testing.T) {
	home := newHome(t)
	p := filepath.Join(t.TempDir(), "config.toml")
	orig := "# mine\nmodel = \"o3\"\n"
	writeFile(t, p, orig)
	r1, err := MergeTOMLFile(home, p, tomlOwn, tomlBlock, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Drift: the user removes our table; the re-apply adds it back.
	writeFile(t, p, orig)
	r2, err := MergeTOMLFile(home, p, tomlOwn, tomlBlock, &r1)
	if err != nil {
		t.Fatal(err)
	}
	if o, ok := r2.original(); !ok || readFile(t, o.Backup) != orig {
		t.Fatalf("original = %+v", o)
	}
	if _, err := RevertTOMLFile(home, r2, tomlOwn); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, p); got != orig {
		t.Fatalf("got %q", got)
	}
}
