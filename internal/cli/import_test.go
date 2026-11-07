package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/exitcode"
	"github.com/QuBiit0/qbit-vault/internal/prompt/prompttest"
)

// runEnv is run with a process environment.
func (h *harness) runEnv(env map[string]string, stdin string, args ...string) (int, string, string) {
	h.t.Helper()
	stdinOverride = strings.NewReader(stdin)
	h.t.Cleanup(func() { stdinOverride = nil })
	var out, errb bytes.Buffer
	code := execute(append([]string{"--home", h.home}, args...), &out, &errb, envFrom(env))
	return code, out.String(), errb.String()
}

var importEnv = map[string]string{
	"GH_TOKEN":  "TESTSECRET_gh_token_value",
	"NPM_TOKEN": "TESTSECRET_npm_token_value",
	"EMPTY_VAR": "",
}

const hintUnset = "hint: unset GH_TOKEN NPM_TOKEN in your shell; qbit-vault cannot change the environment of the shell that started it\n"

func TestImportFromEnv(t *testing.T) {
	w := newWorld(t)
	code, out, errs := w.runEnv(importEnv, "", "import", "--from-env", "GH_TOKEN,NPM_TOKEN", "--yes")
	if code != exitcode.OK || out != "imported 2 secrets into global: GH_TOKEN, NPM_TOKEN\n" || errs != hintUnset {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if w.value("GH_TOKEN") != "TESTSECRET_gh_token_value" || w.value("NPM_TOKEN") != "TESTSECRET_npm_token_value" {
		t.Fatal("values not stored")
	}
	if !w.auditHas(`"event":"capture"`) || !w.auditHas(`"reason":"import from env"`) || !w.auditHas(`"names":["GH_TOKEN","NPM_TOKEN"]`) {
		t.Fatalf("audit: %s", w.auditText())
	}
	noFixtures(t, "import output", out+errs+w.auditText())
}

func TestImportFromEnvJSONReplaces(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_old\n", "set", "NPM_TOKEN", "--stdin", "--description", "kept")
	code, out, errs := w.runEnv(importEnv, "", "--json", "import", "--from-env", "GH_TOKEN,NPM_TOKEN", "--yes")
	want := `{"ok":true,"layer":"global","project":null,"imported":[{"name":"GH_TOKEN","replaced":false},{"name":"NPM_TOKEN","replaced":true}],"skipped":0,"grants_dropped":0,"source_removed":false}` + "\n"
	if code != exitcode.OK || out != want || errs != hintUnset {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if !strings.Contains(w.mustRun("", "describe", "NPM_TOKEN"), "kept") {
		t.Fatal("replaced record lost its description")
	}
	code, out, _ = w.runEnv(importEnv, "", "import", "--from-env", "NPM_TOKEN", "--yes")
	if code != exitcode.OK || out != "imported 1 secret into global: NPM_TOKEN (replaced: NPM_TOKEN)\n" {
		t.Fatalf("human replace: %q", out)
	}
}

func TestImportUsageErrorsChangeNothing(t *testing.T) {
	w := newWorld(t)
	dotenv := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(dotenv, []byte("A=TESTSECRET_a\nB=\"TESTSECRET_open\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	only := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(only, []byte("lower=TESTSECRET_x\nEMPTY=\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(big, bytes.Repeat([]byte("#"), maxDotenvBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	before := w.snapshot()
	cases := []struct {
		args []string
		msg  string
	}{
		{[]string{"import", "--yes"}, "choose --from-env, --from-file or --from-export"},
		{[]string{"import", "--from-env", "GH_TOKEN", "--from-file", dotenv, "--yes"}, "choose --from-env, --from-file or --from-export"},
		{[]string{"import", "--from-env", "GH_TOKEN", "--names", "A", "--yes"}, "--names needs --from-file"},
		{[]string{"import", "--from-env", "GH_TOKEN", "--remove-source", "--yes"}, "--remove-source needs --from-file"},
		{[]string{"import", "--from-env", "MISSING_VAR", "--yes"}, "MISSING_VAR is not set or empty in the environment"},
		{[]string{"import", "--from-env", "EMPTY_VAR", "--yes"}, "EMPTY_VAR is not set or empty in the environment"},
		{[]string{"import", "--from-env", "GH_TOKEN,GH_TOKEN", "--yes"}, "GH_TOKEN is listed twice"},
		{[]string{"import", "--from-file", dotenv, "--yes"}, "the dotenv file has an error at line 2: unterminated quote"},
		{[]string{"import", "--from-file", only, "--yes"}, "nothing to import"},
		{[]string{"import", "--from-file", big, "--yes"}, "dotenv file too large"},
		{[]string{"import", "--from-file", filepath.Join(t.TempDir(), "missing"), "--yes"}, "cannot read the dotenv file"},
		{[]string{"import", "extra", "--yes"}, "unexpected arguments"},
	}
	for _, c := range cases {
		code, out, errs := w.runEnv(importEnv, "", c.args...)
		if code != exitcode.Usage || out != "" || errs != usageErr(c.msg) {
			t.Errorf("%v: code=%d out=%q err=%q", c.args[1:], code, out, errs)
		}
		noFixtures(t, "import error", errs)
	}
	code, _, errs := w.runEnv(importEnv, "", "import", "--from-env", "bad-name", "--yes")
	if code != exitcode.Refusal || errs != "error: invalid secret name\n" {
		t.Errorf("bad name: code=%d err=%q", code, errs)
	}
	if w.snapshot() != before {
		t.Fatal("a refused import changed the vault")
	}
}

func TestImportFromFileIntoProject(t *testing.T) {
	w := newWorld(t)
	dotenv := filepath.Join(t.TempDir(), ".env")
	body := "# app\nexport A=TESTSECRET_file_a\nB=\"TESTSECRET_file_b\"\nlower=ignored\nC=TESTSECRET_file_c\n"
	if err := os.WriteFile(dotenv, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	w.inRepo()
	code, out, errs := w.run("", "import", "--from-file", dotenv, "--names", "A,B", "--project", "--yes", "--remove-source")
	if code != exitcode.OK || out != "imported 2 secrets into project shop-api: A, B\n" || errs != "note: skipped 1 line (invalid name, no '=', or empty value)\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if _, err := os.Stat(dotenv); !os.IsNotExist(err) {
		t.Fatal("--remove-source left the file")
	}
	if w.value("A") != "TESTSECRET_file_a" || w.value("B") != "TESTSECRET_file_b" {
		t.Fatal("values not stored")
	}
	if strings.Contains(w.snapshot(), `"name":"C"`) {
		t.Fatal("--names imported an unlisted name")
	}
	if !w.auditHas(`"reason":"import from file"`) {
		t.Fatal("not audited")
	}
	// A listed name the file does not have.
	if err := os.WriteFile(dotenv, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs = w.run("", "import", "--from-file", dotenv, "--names", "A,ZZ", "--project", "--yes")
	if code != exitcode.Usage || out != "" || errs != usageErr("ZZ is not set in the file") {
		t.Fatalf("missing name: code=%d out=%q err=%q", code, out, errs)
	}
}

func TestImportConfirmationAndLayerQuestion(t *testing.T) {
	w := newWorld(t)
	dotenv := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(dotenv, []byte("A=TESTSECRET_a\nB=TESTSECRET_b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := w.snapshot()
	f := withBackend(t, answers(no()))
	code, out, errs := w.run("", "import", "--from-file", dotenv)
	if code != exitcode.Failure || out != "" || errs != msgCancelled {
		t.Fatalf("declined: code=%d out=%q err=%q", code, out, errs)
	}
	if len(f.Calls) != 1 || f.Calls[0].Q != "Import A, B from the dotenv file into all projects? Existing secrets with these names are replaced." {
		t.Fatalf("question: %+v", f.Calls)
	}
	if w.snapshot() != before {
		t.Fatal("a declined import changed the vault")
	}
	// Inside the repository: layer question, confirmation, delete question.
	w.inRepo()
	f = withBackend(t, answers(pick(1), yes(), yes()))
	code, out, errs = w.run("", "import", "--from-file", dotenv)
	if code != exitcode.OK || out != "imported 2 secrets into project shop-api: A, B\n" || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if f.Calls[0].Q != "Where should these secrets live?" || f.Calls[2].Q != "Delete the dotenv file now that its values are in the vault?" {
		t.Fatalf("calls: %+v", f.Calls)
	}
	if _, err := os.Stat(dotenv); !os.IsNotExist(err) {
		t.Fatal("the file was not deleted after yes")
	}
	// No prompt backend inside a repository without a layer flag.
	if err := os.WriteFile(dotenv, []byte("A=TESTSECRET_a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	withBackend(t, &prompttest.Fake{Unavailable: true})
	code, _, errs = w.run("", "import", "--from-file", dotenv, "--yes")
	if code != exitcode.Usage || errs != usageErr("choose --global or --project") {
		t.Fatalf("no backend in repo: code=%d err=%q", code, errs)
	}
	code, _, errs = w.run("", "import", "--from-file", dotenv, "--global")
	if code != exitcode.Usage || errs != usageErr("confirmation required; pass --yes") {
		t.Fatalf("no backend, no --yes: code=%d err=%q", code, errs)
	}
}
