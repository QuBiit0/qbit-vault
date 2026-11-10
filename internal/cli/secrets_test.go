package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/exitcode"
	"github.com/qbitdevz/qbit-vault/internal/refusal"
	"github.com/qbitdevz/qbit-vault/internal/vault"
)

const usageTail = "Run 'qbit-vault --help' for usage.\n"

var tsRE = regexp.MustCompile(`\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z`)

// norm replaces every timestamp with TS so output can be compared exactly.
func norm(s string) string { return tsRE.ReplaceAllString(s, "TS") }

// world is an initialized vault plus a fake repository and a directory
// outside any repository. The test starts outside the repository.
type world struct {
	*harness
	repo    string // canonical-ish path of the fake repository (has .git)
	root    string // its canonical project root as stored in the vault
	outside string
}

// newWorld is newBareWorld plus an initialized vault.
func newWorld(t *testing.T) *world {
	t.Helper()
	w := newBareWorld(t)
	w.mustRun("", "init")
	return w
}

func newBareWorld(t *testing.T) *world {
	t.Helper()
	h := newHarness(t)
	base := t.TempDir()
	repo := filepath.Join(base, "shop-api")
	outside := filepath.Join(base, "plain")
	for _, d := range []string{filepath.Join(repo, ".git"), outside} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	root, ok, err := vault.ProjectRoot(repo)
	if err != nil || !ok {
		t.Fatalf("fake repo not detected: %v", err)
	}
	w := &world{harness: h, repo: repo, root: root, outside: outside}
	t.Chdir(outside)
	return w
}

func (w *world) inRepo()  { w.t.Helper(); w.t.Chdir(w.repo) }
func (w *world) outRepo() { w.t.Helper(); w.t.Chdir(w.outside) }

// snapshot is the observable vault state: every layer, via the CLI.
func (w *world) snapshot() string {
	w.t.Helper()
	return w.mustRun("", "--json", "list", "--layer", "all")
}

// value reads a stored value through the vault API, for assertions only.
func (w *world) value(name string) string {
	w.t.Helper()
	g := &globals{getenv: envFrom(nil), home: w.home}
	s, err := g.openSession()
	if err != nil {
		w.t.Fatal(err)
	}
	defer s.close()
	cwd, _ := os.Getwd()
	rec, _, err := s.v.Resolve(name, cwd)
	if err != nil {
		w.t.Fatal(err)
	}
	b := rec.Value.Reveal()
	return string(b)
}

func (w *world) projectJSON() string {
	b, _ := json.Marshal(projectRef{Root: w.root, Label: "shop-api"})
	return string(b)
}

func usageErr(msg string) string { return "error: " + msg + "\n" + usageTail }

func TestSetStoresGlobalAndProject(t *testing.T) {
	w := newWorld(t)
	code, out, errs := w.run(fxVal+"\n", "set", "GITHUB_TOKEN", "--global", "--stdin")
	if code != 0 || out != "stored GITHUB_TOKEN (global)\n" || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if got := w.value("GITHUB_TOKEN"); got != fxVal {
		t.Fatal("stored value differs from input")
	}

	w.inRepo()
	code, out, errs = w.run("  "+fxVal+"_p \r\n\n", "set", "GITHUB_TOKEN", "--project", "--stdin")
	if code != 0 || out != "stored GITHUB_TOKEN (project shop-api)\n" || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if got := w.value("GITHUB_TOKEN"); got != fxVal+"_p" {
		t.Fatal("project value was not trimmed or does not override")
	}
	w.outRepo()
	if got := w.value("GITHUB_TOKEN"); got != fxVal {
		t.Fatal("global value changed")
	}
}

func TestSetJSONAndReplace(t *testing.T) {
	w := newWorld(t)
	code, out, errs := w.run(fxVal, "--json", "set", "A_KEY", "--stdin", "--description", "first", "--binaries", "gh,git", "--hosts", "api.github.com", "--sensitive")
	want := `{"ok":true,"name":"A_KEY","layer":"global","project":null,"replaced":false}` + "\n"
	if code != 0 || out != want || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	w.inRepo()
	code, out, _ = w.run(fxVal, "--json", "set", "A_KEY", "--project", "--stdin")
	want = `{"ok":true,"name":"A_KEY","layer":"project","project":` + w.projectJSON() + `,"replaced":false}` + "\n"
	if code != 0 || out != want {
		t.Fatalf("code=%d out=%q", code, out)
	}
	// Replace keeps metadata that was not given again.
	w.outRepo()
	_, out, _ = w.run(fxVal+"2", "--json", "set", "A_KEY", "--global", "--stdin")
	if !strings.HasSuffix(out, `"replaced":true}`+"\n") {
		t.Fatalf("out=%q", out)
	}
	_, out, _ = w.run("", "--json", "describe", "A_KEY")
	want = `{"ok":true,"name":"A_KEY","layer":"global","project":null,"overrides_global":false,"description":"first","sensitive":true,"binaries":["gh","git"],"hosts":["api.github.com"],"created_at":"TS","updated_at":"TS","grants":[]}` + "\n"
	if norm(out) != want {
		t.Fatalf("out=%q", out)
	}
	if w.value("A_KEY") != fxVal+"2" {
		t.Fatal("value not replaced")
	}
	// Given again, metadata is replaced.
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin", "--description", "second", "--sensitive=false", "--binaries", "", "--hosts", "")
	_, out, _ = w.run("", "--json", "describe", "A_KEY")
	want = `{"ok":true,"name":"A_KEY","layer":"global","project":null,"overrides_global":false,"description":"second","sensitive":false,"binaries":[],"hosts":[],"created_at":"TS","updated_at":"TS","grants":[]}` + "\n"
	if norm(out) != want {
		t.Fatalf("out=%q", out)
	}
}

func TestSetUsageErrorsLeaveVaultUnchanged(t *testing.T) {
	big := strings.Repeat("a", 64*1024+1)
	tests := []struct {
		name  string
		repo  bool
		stdin string
		args  []string
		msg   string
	}{
		{"no stdin flag", false, "", []string{"set", "A_KEY", "--global"}, "no controlling terminal available; use --stdin"},
		{"inside repo without layer", true, fxVal, []string{"set", "A_KEY", "--stdin"}, "choose --global or --project"},
		{"both layers", true, fxVal, []string{"set", "A_KEY", "--global", "--project", "--stdin"}, "choose only one of --global and --project"},
		{"extra arguments", false, fxVal, []string{"set", "A_KEY", "TESTSECRET_arg", "--stdin"}, "unexpected arguments"},
		{"missing name", false, fxVal, []string{"set", "--stdin"}, "missing NAME"},
		{"empty value", false, "", []string{"set", "A_KEY", "--stdin"}, "empty value"},
		{"whitespace value", false, " \t\r\n ", []string{"set", "A_KEY", "--global", "--stdin"}, "empty value"},
		{"too large", false, big, []string{"set", "A_KEY", "--stdin"}, "value too large"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newWorld(t)
			w.mustRun(fxVal, "set", "KEEP_ME", "--global", "--stdin")
			before := w.snapshot()
			if tt.repo {
				w.inRepo()
			}
			code, out, errs := w.run(tt.stdin, tt.args...)
			if code != exitcode.Usage || out != "" || errs != usageErr(tt.msg) {
				t.Fatalf("code=%d out=%q err=%q", code, out, errs)
			}
			w.outRepo()
			if w.snapshot() != before {
				t.Fatal("rejected input changed the vault")
			}
			// The same failure in JSON mode is one object on stdout.
			if tt.repo {
				w.inRepo()
			}
			args := append([]string{"--json"}, tt.args...)
			code, out, errs = w.run(tt.stdin, args...)
			wantJSON := `{"ok":false,"error":{"code":"usage","message":"` + tt.msg + `"}}` + "\n"
			if code != exitcode.Usage || out != wantJSON || errs != "" {
				t.Fatalf("json: code=%d out=%q err=%q", code, out, errs)
			}
		})
	}
}

func TestSetRefusals(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want refusal.Refusal
	}{
		{"project outside a repo", []string{"set", "A_KEY", "--project", "--stdin"}, refusal.New(refusal.NoProject, "")},
		{"invalid name", []string{"set", "TESTSECRET_lower", "--global", "--stdin"}, refusal.New(refusal.InvalidName, "")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newWorld(t)
			before := w.snapshot()
			code, out, errs := w.run(fxVal, append([]string{"--json"}, tt.args...)...)
			if code != exitcode.Refusal || out != jsonOf(t, tt.want.Envelope()) || errs != "" {
				t.Fatalf("code=%d out=%q err=%q", code, out, errs)
			}
			code, out, errs = w.run(fxVal, tt.args...)
			if code != exitcode.Refusal || out != "" || errs != "error: "+tt.want.Message+"\n" {
				t.Fatalf("human: code=%d out=%q err=%q", code, out, errs)
			}
			if strings.Contains(out+errs, "TESTSECRET_") || w.snapshot() != before {
				t.Fatal("input echoed or vault changed")
			}
		})
	}
}

func TestSetWithoutVault(t *testing.T) {
	h := newHarness(t)
	code, out, errs := h.run(fxVal, "set", "A_KEY", "--global", "--stdin")
	if code != exitcode.Failure || out != "" || errs != "error: no vault here; run 'qbit-vault init'\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
}

func TestListLayers(t *testing.T) {
	w := newWorld(t)
	w.mustRun(fxVal, "set", "GITHUB_TOKEN", "--global", "--stdin", "--description", "gh token")
	w.mustRun(fxVal, "set", "STRIPE_KEY", "--global", "--stdin")
	w.inRepo()
	w.mustRun(fxVal, "set", "STRIPE_KEY", "--project", "--stdin", "--description", "test key")
	w.mustRun(fxVal, "set", "DATABASE_URL", "--project", "--stdin")

	t.Run("here inside repo", func(t *testing.T) {
		code, out, errs := w.run("", "list")
		want := "NAME          LAYER             DESCRIPTION\n" +
			"DATABASE_URL  project:shop-api\n" +
			"GITHUB_TOKEN  global            gh token\n" +
			"STRIPE_KEY    project:shop-api  test key (overrides global)\n"
		if code != 0 || out != want || errs != "" {
			t.Fatalf("code=%d out=%q err=%q", code, out, errs)
		}
	})
	t.Run("here json", func(t *testing.T) {
		_, out, _ := w.run("", "--json", "list")
		want := `{"ok":true,"project":` + w.projectJSON() + `,"secrets":[` +
			`{"name":"DATABASE_URL","layer":"project","project_label":"shop-api","overrides_global":false,"description":"","sensitive":false,"binaries":[],"hosts":[],"created_at":"TS","updated_at":"TS"},` +
			`{"name":"GITHUB_TOKEN","layer":"global","overrides_global":false,"description":"gh token","sensitive":false,"binaries":[],"hosts":[],"created_at":"TS","updated_at":"TS"},` +
			`{"name":"STRIPE_KEY","layer":"project","project_label":"shop-api","overrides_global":true,"description":"test key","sensitive":false,"binaries":[],"hosts":[],"created_at":"TS","updated_at":"TS"}]}` + "\n"
		if norm(out) != want {
			t.Fatalf("out=%s", out)
		}
	})
	t.Run("here outside repo", func(t *testing.T) {
		w.outRepo()
		defer w.inRepo()
		_, out, _ := w.run("", "list")
		want := "NAME          LAYER   DESCRIPTION\n" +
			"GITHUB_TOKEN  global  gh token\n" +
			"STRIPE_KEY    global\n"
		if out != want {
			t.Fatalf("out=%q", out)
		}
		_, out, _ = w.run("", "--json", "list")
		if !strings.HasPrefix(out, `{"ok":true,"project":null,"secrets":[`) {
			t.Fatalf("out=%q", out)
		}
	})
	t.Run("global", func(t *testing.T) {
		_, out, _ := w.run("", "list", "--layer", "global")
		want := "NAME          LAYER   DESCRIPTION\n" +
			"GITHUB_TOKEN  global  gh token\n" +
			"STRIPE_KEY    global\n"
		if out != want {
			t.Fatalf("out=%q", out)
		}
	})
	t.Run("project", func(t *testing.T) {
		_, out, _ := w.run("", "list", "--layer", "project")
		want := "NAME          LAYER             DESCRIPTION\n" +
			"DATABASE_URL  project:shop-api\n" +
			"STRIPE_KEY    project:shop-api  test key (overrides global)\n"
		if out != want {
			t.Fatalf("out=%q", out)
		}
	})
	t.Run("all", func(t *testing.T) {
		_, out, _ := w.run("", "list", "--layer", "all")
		if n := strings.Count(out, "\n"); n != 5 {
			t.Fatalf("want header + 4 rows, out=%q", out)
		}
	})
	t.Run("project outside repo is a refusal", func(t *testing.T) {
		w.outRepo()
		defer w.inRepo()
		code, out, errs := w.run("", "--json", "list", "--layer", "project")
		if code != exitcode.Refusal || out != jsonOf(t, refusal.New(refusal.NoProject, "").Envelope()) || errs != "" {
			t.Fatalf("code=%d out=%q err=%q", code, out, errs)
		}
	})
	t.Run("bad layer", func(t *testing.T) {
		code, out, errs := w.run("", "list", "--layer", "TESTSECRET_x")
		if code != exitcode.Usage || out != "" || errs != usageErr("invalid --layer: must be here, global, project or all") {
			t.Fatalf("code=%d out=%q err=%q", code, out, errs)
		}
	})
}

func TestListEmpty(t *testing.T) {
	w := newWorld(t)
	code, out, errs := w.run("", "list")
	if code != 0 || out != "no secrets\n" || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	_, out, _ = w.run("", "--json", "list")
	if out != `{"ok":true,"project":null,"secrets":[]}`+"\n" {
		t.Fatalf("out=%q", out)
	}
}

func TestListNeverShowsValues(t *testing.T) {
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	for _, args := range [][]string{{"list"}, {"--json", "list"}, {"describe", "A_KEY"}, {"--json", "describe", "A_KEY"}} {
		_, out, errs := w.run("", args...)
		if strings.Contains(out+errs, "TESTSECRET_") {
			t.Fatalf("%v printed a value", args)
		}
	}
}

func TestDescribe(t *testing.T) {
	w := newWorld(t)
	w.mustRun(fxVal, "set", "STRIPE_KEY", "--global", "--stdin")
	w.inRepo()
	w.mustRun(fxVal, "set", "STRIPE_KEY", "--project", "--stdin", "--description", "test key", "--sensitive", "--binaries", "curl", "--hosts", "api.stripe.com")

	_, out, _ := w.run("", "--json", "describe", "STRIPE_KEY")
	want := `{"ok":true,"name":"STRIPE_KEY","layer":"project","project":` + w.projectJSON() + `,"overrides_global":true,"description":"test key","sensitive":true,"binaries":["curl"],"hosts":["api.stripe.com"],"created_at":"TS","updated_at":"TS","grants":[]}` + "\n"
	if norm(out) != want {
		t.Fatalf("out=%s", out)
	}
	_, out, _ = w.run("", "--json", "describe", "STRIPE_KEY", "--global")
	want = `{"ok":true,"name":"STRIPE_KEY","layer":"global","project":null,"overrides_global":false,"description":"","sensitive":false,"binaries":[],"hosts":[],"created_at":"TS","updated_at":"TS","grants":[]}` + "\n"
	if norm(out) != want {
		t.Fatalf("out=%s", out)
	}
	code, out, errs := w.run("", "describe", "STRIPE_KEY")
	wantHuman := "STRIPE_KEY (project shop-api)\n" +
		"  description: test key\n" +
		"  sensitive:   yes\n" +
		"  binaries:    curl\n" +
		"  hosts:       api.stripe.com\n" +
		"  overrides:   global STRIPE_KEY\n" +
		"  created:     TS\n" +
		"  updated:     TS\n" +
		"  grants:      none\n"
	if code != 0 || norm(out) != wantHuman || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
}

func TestDescribeRefusals(t *testing.T) {
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	tests := []struct {
		name string
		args []string
		want refusal.Refusal
	}{
		{"unknown", []string{"describe", "NOPE_KEY"}, refusal.New(refusal.UnknownSecret, "NOPE_KEY")},
		{"unknown in explicit layer", []string{"describe", "A_KEY", "--project"}, refusal.New(refusal.NoProject, "")},
		{"invalid name", []string{"describe", "TESTSECRET_x"}, refusal.New(refusal.InvalidName, "")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out, errs := w.run("", append([]string{"--json"}, tt.args...)...)
			if code != exitcode.Refusal || out != jsonOf(t, tt.want.Envelope()) || errs != "" {
				t.Fatalf("code=%d out=%q err=%q", code, out, errs)
			}
		})
	}
	w.inRepo()
	code, out, _ := w.run("", "--json", "describe", "A_KEY", "--project")
	if code != exitcode.Refusal || out != jsonOf(t, refusal.New(refusal.UnknownSecret, "A_KEY").Envelope()) {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

func TestEditChangesMetadataOnly(t *testing.T) {
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin", "--description", "old", "--binaries", "gh")
	code, out, errs := w.run("", "edit", "A_KEY", "--description", "new", "--sensitive", "--hosts", "a.example,b.example")
	if code != 0 || out != "updated A_KEY (global)\n" || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	_, out, _ = w.run("", "--json", "edit", "A_KEY", "--binaries", "")
	if out != `{"ok":true,"name":"A_KEY","layer":"global","project":null,"updated":true}`+"\n" {
		t.Fatalf("out=%q", out)
	}
	_, out, _ = w.run("", "--json", "describe", "A_KEY")
	want := `{"ok":true,"name":"A_KEY","layer":"global","project":null,"overrides_global":false,"description":"new","sensitive":true,"binaries":[],"hosts":["a.example","b.example"],"created_at":"TS","updated_at":"TS","grants":[]}` + "\n"
	if norm(out) != want {
		t.Fatalf("out=%s", out)
	}
	if w.value("A_KEY") != fxVal {
		t.Fatal("edit changed the value")
	}
	w.mustRun("", "edit", "A_KEY", "--sensitive=false")
	_, out, _ = w.run("", "--json", "describe", "A_KEY")
	if !strings.Contains(out, `"sensitive":false`) {
		t.Fatalf("out=%s", out)
	}
}

func TestEditTargetsResolvedLayer(t *testing.T) {
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	w.inRepo()
	w.mustRun(fxVal+"p", "set", "A_KEY", "--project", "--stdin")
	w.mustRun("", "edit", "A_KEY", "--description", "project one")
	_, out, _ := w.run("", "--json", "describe", "A_KEY", "--global")
	if !strings.Contains(out, `"description":""`) {
		t.Fatalf("edit reached the global record: %s", out)
	}
	w.mustRun("", "edit", "A_KEY", "--global", "--description", "global one")
	_, out, _ = w.run("", "--json", "describe", "A_KEY", "--project")
	if !strings.Contains(out, `"description":"project one"`) {
		t.Fatalf("explicit --global edit reached the project record: %s", out)
	}
	if w.value("A_KEY") != fxVal+"p" {
		t.Fatal("value changed")
	}
}

func TestEditErrors(t *testing.T) {
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	before := w.snapshot()
	code, out, errs := w.run("", "edit", "A_KEY")
	if code != exitcode.Usage || out != "" || errs != usageErr("nothing to change; pass --description, --sensitive, --binaries or --hosts") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	code, out, _ = w.run("", "--json", "edit", "NOPE_KEY", "--description", "x")
	if code != exitcode.Refusal || out != jsonOf(t, refusal.New(refusal.UnknownSecret, "NOPE_KEY").Envelope()) {
		t.Fatalf("code=%d out=%q", code, out)
	}
	if w.snapshot() != before {
		t.Fatal("failed edit changed the vault")
	}
}

func TestRm(t *testing.T) {
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	w.inRepo()
	w.mustRun(fxVal, "set", "A_KEY", "--project", "--stdin")
	before := w.snapshot()

	code, out, errs := w.run("", "rm", "A_KEY")
	if code != exitcode.Usage || out != "" || errs != usageErr("confirmation required; pass --yes") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if w.snapshot() != before {
		t.Fatal("unconfirmed rm changed the vault")
	}

	// Without a layer flag it removes the record NAME resolves to: the project one.
	code, out, errs = w.run("", "rm", "A_KEY", "--yes")
	if code != 0 || out != "removed A_KEY (project shop-api)\n" || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if w.value("A_KEY") != fxVal {
		t.Fatal("global record should now resolve")
	}
	code, out, _ = w.run("", "--json", "rm", "A_KEY", "--global", "--yes")
	if code != 0 || out != `{"ok":true,"name":"A_KEY","layer":"global","removed":true}`+"\n" {
		t.Fatalf("code=%d out=%q", code, out)
	}
	code, out, _ = w.run("", "--json", "rm", "A_KEY", "--yes")
	if code != exitcode.Refusal || out != jsonOf(t, refusal.New(refusal.UnknownSecret, "A_KEY").Envelope()) {
		t.Fatalf("code=%d out=%q", code, out)
	}
	_, out, _ = w.run("", "list", "--layer", "all")
	if out != "no secrets\n" {
		t.Fatalf("out=%q", out)
	}
}

func TestRmRejectsBadInputWithoutChange(t *testing.T) {
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	before := w.snapshot()
	tests := []struct {
		name string
		args []string
		code int
		err  string
	}{
		{"both layers", []string{"rm", "A_KEY", "--global", "--project", "--yes"}, exitcode.Usage, usageErr("choose only one of --global and --project")},
		{"extra arg", []string{"rm", "A_KEY", "TESTSECRET_x", "--yes"}, exitcode.Usage, usageErr("unexpected arguments")},
		{"project outside repo", []string{"rm", "A_KEY", "--project", "--yes"}, exitcode.Refusal, "error: not inside a repository\n"},
		{"invalid name", []string{"rm", "TESTSECRET_x", "--yes"}, exitcode.Refusal, "error: invalid secret name\n"},
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
}

// A description shown in list cannot move the cursor or reorder the line:
// C0, C1 and format characters (bidi overrides) become spaces.
func TestOneLineNeutralizesControlAndFormat(t *testing.T) {
	in := "a\x1b[31mb\u009bc\u202ed\u200be\nf"
	if got := oneLine(in); got != "a [31mb c d e f" {
		t.Fatalf("oneLine=%q", got)
	}
}
