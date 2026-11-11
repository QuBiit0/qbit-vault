package codex_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/hosts"
	"github.com/qbitdevz/qbit-vault/internal/hosts/codex"
)

func (r *rig) hooksFile() string { return filepath.Join(r.env.UserHome, ".codex", "hooks.json") }

// hookCmd is one command hook of the written hooks.json.
type hookCmd struct{ event, matcher, command, status string }

func readHooks(t *testing.T, doc string) []hookCmd {
	t.Helper()
	var s struct {
		Hooks map[string][]struct {
			Matcher string `json:"matcher"`
			Hooks   []struct {
				Command       string `json:"command"`
				StatusMessage string `json:"statusMessage"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal([]byte(doc), &s); err != nil {
		t.Fatal(err)
	}
	var out []hookCmd
	for ev, list := range s.Hooks {
		for _, e := range list {
			for _, h := range e.Hooks {
				out = append(out, hookCmd{ev, e.Matcher, h.Command, h.StatusMessage})
			}
		}
	}
	return out
}

func ours(es []hookCmd) []hookCmd {
	var out []hookCmd
	for _, e := range es {
		if strings.Contains(e.status, "qbit-vault hook") {
			out = append(out, e)
		}
	}
	return out
}

func (r *rig) goldenHooks(name string) {
	r.t.Helper()
	got := strings.ReplaceAll(r.read(r.hooksFile()), r.env.UserHome, "{HOME}")
	if *update {
		if err := os.WriteFile(filepath.Join("testdata", name), []byte(got), 0o644); err != nil {
			r.t.Fatal(err)
		}
	}
	if got != lf(r.t, name) {
		r.t.Fatalf("hooks.json differs from %s:\n%s", name, got)
	}
}

// S5 of odd/tasks/output-guard.md: Bash output is redacted and apply_patch is
// guarded, with the Codex output protocol.
func TestRegistersTheCodexGuards(t *testing.T) {
	r := newRig(t)
	r.apply()
	want := []hookCmd{
		{"PostToolUse", "Bash", fakeExe + " hook post-bash --host codex", "qbit-vault hook post-bash"},
		{"PreToolUse", "apply_patch", fakeExe + " hook pre-write --host codex", "qbit-vault hook pre-write"},
	}
	es := readHooks(t, r.read(r.hooksFile()))
	if len(es) != len(want) {
		t.Fatalf("%d hooks: %+v", len(es), es)
	}
	for _, w := range want {
		found := false
		for _, e := range es {
			found = found || e == w
		}
		if !found {
			t.Fatalf("missing %+v in\n%s", w, r.read(r.hooksFile()))
		}
	}
	r.goldenHooks("absent.hooks.json.golden")
}

func TestHooksMergeIntoAnExistingFileWithoutTouchingOtherTools(t *testing.T) {
	r := newRig(t)
	orig := lf(t, "existing.hooks.json")
	r.write(r.hooksFile(), orig)
	before := r.backups()
	r.apply()
	r.goldenHooks("existing.hooks.json.golden")
	es := readHooks(t, r.read(r.hooksFile()))
	if len(es) != 6 || len(ours(es)) != 2 {
		t.Fatalf("hooks: %+v", es)
	}
	if r.backups() <= before {
		t.Fatal("no snapshot before the write")
	}
	if got, _ := os.ReadDir(filepath.Dir(r.hooksFile())); len(got) < 2 {
		t.Fatalf("dir: %v", got) // config.toml and hooks.json
	}
}

func TestHooksSecondApplyChangesNothing(t *testing.T) {
	r := newRig(t)
	r.write(r.hooksFile(), lf(t, "existing.hooks.json"))
	r.apply()
	a, nb := r.read(r.hooksFile()), r.backups()
	if res := r.apply(); res.Changed() {
		t.Fatalf("second apply wrote: %+v", res)
	}
	if r.read(r.hooksFile()) != a || r.backups() != nb {
		t.Fatal("second apply changed bytes or took a snapshot")
	}
}

func TestHooksRevertRemovesOnlyOurs(t *testing.T) {
	for _, existing := range []bool{true, false} {
		r := newRig(t)
		want := ""
		if existing {
			want = lf(t, "existing.hooks.json")
			r.write(r.hooksFile(), want)
		}
		r.apply()
		if err := hosts.Revert(r.env, r.host); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(r.hooksFile())
		switch {
		case existing && (err != nil || string(got) != want):
			t.Fatalf("not restored: %v\n%s", err, got)
		case !existing && err == nil:
			t.Fatalf("a file we created is still there:\n%s", got)
		}
	}
}

func TestHooksRevertKeepsAnEntryAddedAfterUs(t *testing.T) {
	r := newRig(t)
	r.write(r.hooksFile(), lf(t, "existing.hooks.json"))
	r.apply()
	r.write(r.hooksFile(), strings.Replace(r.read(r.hooksFile()), `"hooks": {`, `"hooks": {
    "SessionStart": [{"hooks": [{"type": "command", "command": "late"}]}],`, 1))
	if err := hosts.Revert(r.env, r.host); err != nil {
		t.Fatal(err)
	}
	es := readHooks(t, r.read(r.hooksFile()))
	if len(ours(es)) != 0 || len(es) != 5 {
		t.Fatalf("after revert: %+v", es)
	}
}

func TestCheckFindsMissingAndDriftedHooks(t *testing.T) {
	r := newRig(t)
	r.apply()
	if err := checks(r)["hooks"]; err != nil {
		t.Fatalf("fresh registration drifts: %v", err)
	}
	doc := r.read(r.hooksFile())
	for name, edited := range map[string]string{
		"flag removed":  strings.Replace(doc, " --host codex", "", 1),
		"matcher moved": strings.Replace(doc, `"apply_patch"`, `"Bash"`, 1),
		"file emptied":  "{}\n",
	} {
		r.write(r.hooksFile(), edited)
		if err := checks(r)["hooks"]; !errors.Is(err, hosts.ErrDrift) {
			t.Fatalf("%s: want drift, got %v", name, err)
		}
		if r.read(r.hooksFile()) != edited {
			t.Fatalf("%s: check wrote", name)
		}
		r.apply()
		if err := checks(r)["hooks"]; err != nil {
			t.Fatalf("%s: not repaired: %v", name, err)
		}
	}
}

func TestHookCommandQuoting(t *testing.T) {
	r := newRig(t)
	r.host = codex.NewWithExe("/opt/Q Bit/qbit-vault")
	r.apply()
	if es := ours(readHooks(t, r.read(r.hooksFile()))); len(es) != 2 || es[0].command == "" ||
		!strings.HasPrefix(es[0].command, `"/opt/Q Bit/qbit-vault" hook `) {
		t.Fatalf("hooks: %+v", es)
	}
	for _, bad := range []string{`/opt/a"b/qbit-vault`, "/opt/$HOME/qbit-vault", "/opt/`x`/qbit-vault", "/opt/%PATH%/qbit-vault"} {
		r2 := newRig(t)
		r2.host = codex.NewWithExe(bad)
		res := hosts.Apply(r2.env, []hosts.Adapter{r2.host})
		if res[0].Err() == nil {
			t.Fatalf("%q written", bad)
		}
		if _, err := os.Stat(r2.hooksFile()); err == nil {
			t.Fatalf("%q: hooks.json created", bad)
		}
	}
}
