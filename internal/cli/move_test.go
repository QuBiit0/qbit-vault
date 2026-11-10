package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/exitcode"
)

func TestMvGlobalToProjectAndBack(t *testing.T) {
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin", "--description", "desc", "--sensitive", "--binaries", "gh", "--hosts", "h.example")
	_, before, _ := w.run("", "--json", "describe", "A_KEY")
	w.inRepo()

	code, out, errs := w.run("", "--json", "mv", "A_KEY", "--to", "project")
	want := `{"ok":true,"name":"A_KEY","from":"global","to":"project","project":` + w.projectJSON() + `}` + "\n"
	if code != 0 || out != want || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	_, out, _ = w.run("", "--json", "describe", "A_KEY")
	wantAfter := strings.Replace(before, `"layer":"global","project":null`, `"layer":"project","project":`+w.projectJSON(), 1)
	if out != wantAfter {
		t.Fatalf("metadata changed:\n got %s\nwant %s", out, wantAfter)
	}
	if w.value("A_KEY") != fxVal {
		t.Fatal("value changed")
	}
	if _, out, _ = w.run("", "--json", "describe", "A_KEY", "--global"); !strings.Contains(out, `"unknown_secret"`) {
		t.Fatalf("global copy remains: %s", out)
	}

	code, out, errs = w.run("", "mv", "A_KEY", "--to", "global")
	if code != 0 || out != "moved A_KEY from project shop-api to global\n" || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	w.outRepo()
	if _, out, _ = w.run("", "--json", "describe", "A_KEY"); out != before {
		t.Fatalf("round trip changed the record:\n got %s\nwant %s", out, before)
	}
}

func TestMvOverwriteNeedsYes(t *testing.T) {
	w := newWorld(t)
	w.mustRun(fxVal+"g", "set", "A_KEY", "--global", "--stdin")
	w.inRepo()
	w.mustRun(fxVal+"p", "set", "A_KEY", "--project", "--stdin")
	before := w.snapshot()

	code, out, errs := w.run("", "mv", "A_KEY", "--to", "global")
	if code != exitcode.Usage || out != "" || errs != usageErr("A_KEY already exists in global; pass --yes to overwrite") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	code, out, errs = w.run("", "--json", "mv", "A_KEY", "--to", "global")
	if code != exitcode.Usage || errs != "" || out != `{"ok":false,"error":{"code":"usage","message":"A_KEY already exists in global; pass --yes to overwrite"}}`+"\n" {
		t.Fatalf("json: code=%d out=%q err=%q", code, out, errs)
	}
	if w.snapshot() != before {
		t.Fatal("refused move changed the vault")
	}

	w.mustRun("", "mv", "A_KEY", "--to", "global", "--yes")
	w.outRepo()
	if w.value("A_KEY") != fxVal+"p" {
		t.Fatal("global record was not overwritten by the project value")
	}
	w.inRepo()
	if _, out, _ = w.run("", "--json", "describe", "A_KEY", "--project"); !strings.Contains(out, `"unknown_secret"`) {
		t.Fatalf("project copy remains: %s", out)
	}
}

func TestMvErrors(t *testing.T) {
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	before := w.snapshot()
	tests := []struct {
		name string
		repo bool
		args []string
		code int
		err  string
	}{
		{"missing --to", false, []string{"mv", "A_KEY"}, exitcode.Usage, usageErr("choose --to global or --to project")},
		{"bad --to", false, []string{"mv", "A_KEY", "--to", "TESTSECRET_x"}, exitcode.Usage, usageErr("invalid --to: must be global or project")},
		{"extra arg", false, []string{"mv", "A_KEY", "TESTSECRET_x", "--to", "global"}, exitcode.Usage, usageErr("unexpected arguments")},
		{"to project outside repo", false, []string{"mv", "A_KEY", "--to", "project"}, exitcode.Refusal, "error: not inside a repository\n"},
		{"to global outside repo", false, []string{"mv", "A_KEY", "--to", "global"}, exitcode.Refusal, "error: not inside a repository\n"},
		{"unknown source", true, []string{"mv", "NOPE_KEY", "--to", "project"}, exitcode.Refusal, "error: NOPE_KEY is not stored\n"},
		{"invalid name", true, []string{"mv", "TESTSECRET_x", "--to", "project"}, exitcode.Refusal, "error: invalid secret name\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.repo {
				w.inRepo()
			} else {
				w.outRepo()
			}
			code, out, errs := w.run("", tt.args...)
			if code != tt.code || out != "" || errs != tt.err {
				t.Fatalf("code=%d out=%q err=%q", code, out, errs)
			}
			w.outRepo()
			if w.snapshot() != before {
				t.Fatal("vault changed")
			}
		})
	}
}

func TestRelink(t *testing.T) {
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	w.inRepo()
	w.mustRun(fxVal+"p", "set", "A_KEY", "--project", "--stdin")
	w.mustRun(fxVal+"q", "set", "B_KEY", "--project", "--stdin")
	w.outRepo()

	moved := filepath.Join(filepath.Dir(w.repo), "shop-api-v2")
	if err := os.MkdirAll(filepath.Join(moved, ".git"), 0o700); err != nil { // a fresh clone; t.Chdir keeps the old dir open, which blocks renames on Windows
		t.Fatal(err)
	}
	code, out, errs := w.run("", "--json", "relink", w.repo, moved)
	want := jsonOf(t, relinkBody{OK: true, From: w.repo, To: moved, Secrets: 2})
	if code != 0 || out != want || errs != "" {
		t.Fatalf("code=%d out=%q err=%q want=%q", code, out, errs, want)
	}
	t.Chdir(moved)
	_, out, _ = w.run("", "list")
	if !strings.Contains(out, "project:shop-api-v2") || strings.Count(out, "\n") != 3 {
		t.Fatalf("out=%q", out)
	}
	if w.value("A_KEY") != fxVal+"p" {
		t.Fatal("value changed by relink")
	}
}

func TestRelinkHuman(t *testing.T) {
	w := newWorld(t)
	w.inRepo()
	w.mustRun(fxVal, "set", "A_KEY", "--project", "--stdin")
	w.outRepo()
	moved := filepath.Join(filepath.Dir(w.repo), "elsewhere")
	if err := os.MkdirAll(filepath.Join(moved, ".git"), 0o700); err != nil { // a fresh clone; t.Chdir keeps the old dir open, which blocks renames on Windows
		t.Fatal(err)
	}
	code, out, errs := w.run("", "relink", w.repo, moved)
	if code != 0 || out != "relinked 1 secret from "+w.repo+" to "+moved+"\n" || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
}

func TestRelinkErrors(t *testing.T) {
	w := newWorld(t)
	w.inRepo()
	w.mustRun(fxVal, "set", "A_KEY", "--project", "--stdin")
	other := filepath.Join(filepath.Dir(w.repo), "other")
	if err := os.MkdirAll(filepath.Join(other, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(other)
	w.mustRun(fxVal, "set", "Z_KEY", "--project", "--stdin")
	w.outRepo()
	before := w.snapshot()
	plain := w.outside
	tests := []struct {
		name string
		args []string
		code int
		err  string
	}{
		{"old has no layer", []string{"relink", plain, filepath.Join(plain, "x")}, exitcode.Refusal, "error: not inside a repository\n"},
		{"new has a layer", []string{"relink", w.repo, other}, exitcode.Usage, usageErr("NEW_ROOT already has a project layer")},
		{"new is not a repository", []string{"relink", w.repo, plain}, exitcode.Refusal, "error: not inside a repository\n"},
		{"missing args", []string{"relink", w.repo}, exitcode.Usage, usageErr("usage: relink OLD_ROOT NEW_ROOT")},
		{"too many args", []string{"relink", "a", "b", "c"}, exitcode.Usage, usageErr("usage: relink OLD_ROOT NEW_ROOT")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out, errs := w.run("", tt.args...)
			if code != tt.code || out != "" || errs != tt.err {
				t.Fatalf("code=%d out=%q err=%q", code, out, errs)
			}
			if w.snapshot() != before {
				t.Fatal("vault changed")
			}
		})
	}
	// A real repository with no layer behind OLD_ROOT.
	fresh := filepath.Join(filepath.Dir(w.repo), "fresh")
	if err := os.MkdirAll(filepath.Join(fresh, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	spare := filepath.Join(filepath.Dir(w.repo), "spare")
	if err := os.MkdirAll(filepath.Join(spare, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	code, out, errs := w.run("", "relink", fresh, spare)
	if code != exitcode.Usage || out != "" || errs != usageErr("OLD_ROOT has no project layer") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if w.snapshot() != before {
		t.Fatal("vault changed")
	}
}
