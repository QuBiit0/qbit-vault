package cli

import (
	"strings"
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/keychain"
)

// TestEndToEndSecretLifecycle drives the whole secret-lifecycle surface through
// Execute against a temporary home and the mock keychain.
func TestEndToEndSecretLifecycle(t *testing.T) {
	w := newBareWorld(t)
	var all strings.Builder // every byte the lifecycle printed

	step := func(stdin, wantOut string, args ...string) {
		t.Helper()
		code, out, errs := w.run(stdin, args...)
		all.WriteString(out + errs)
		if code != 0 || norm(out) != wantOut || errs != "" {
			t.Fatalf("%v:\ncode=%d\nstdout=%q\nwant  =%q\nstderr=%q", args, code, out, wantOut, errs)
		}
	}

	step("", "vault initialized at "+w.home+" (keychain: "+keychain.NewOS().Name()+")\n", "init")
	step("", "vault already initialized at "+w.home+"\n", "init")

	// A global and a project secret with the same name.
	step(fxVal+"_global\n", "stored GITHUB_TOKEN (global)\n",
		"set", "GITHUB_TOKEN", "--global", "--stdin", "--description", "gh token")
	w.inRepo()
	step(fxVal+"_project\n", "stored GITHUB_TOKEN (project shop-api)\n",
		"set", "GITHUB_TOKEN", "--project", "--stdin", "--description", "shop token")

	// list from inside the repo shows the override, from outside the global one.
	step("", "NAME          LAYER             DESCRIPTION\n"+
		"GITHUB_TOKEN  project:shop-api  shop token (overrides global)\n", "list")
	w.outRepo()
	step("", "NAME          LAYER   DESCRIPTION\n"+
		"GITHUB_TOKEN  global  gh token\n", "list")
	if w.value("GITHUB_TOKEN") != fxVal+"_global" {
		t.Fatal("outside the repo the global value must resolve")
	}

	// describe: the project record by default inside the repo, the global one on request.
	w.inRepo()
	step("", "GITHUB_TOKEN (project shop-api)\n"+
		"  description: shop token\n"+
		"  sensitive:   no\n"+
		"  binaries:    -\n"+
		"  hosts:       -\n"+
		"  overrides:   global GITHUB_TOKEN\n"+
		"  created:     TS\n"+
		"  updated:     TS\n"+
		"  grants:      none\n", "describe", "GITHUB_TOKEN")
	step("", `{"ok":true,"name":"GITHUB_TOKEN","layer":"global","project":null,"overrides_global":false,"description":"gh token","sensitive":false,"binaries":[],"hosts":[],"created_at":"TS","updated_at":"TS","grants":[]}`+"\n",
		"--json", "describe", "GITHUB_TOKEN", "--global")

	// edit changes metadata only.
	step("", "updated GITHUB_TOKEN (project shop-api)\n",
		"edit", "GITHUB_TOKEN", "--binaries", "gh,git", "--sensitive")
	step("", `{"ok":true,"name":"GITHUB_TOKEN","layer":"project","project":`+w.projectJSON()+`,"overrides_global":true,"description":"shop token","sensitive":true,"binaries":["gh","git"],"hosts":[],"created_at":"TS","updated_at":"TS","grants":[]}`+"\n",
		"--json", "describe", "GITHUB_TOKEN")
	if w.value("GITHUB_TOKEN") != fxVal+"_project" {
		t.Fatal("edit changed the value")
	}

	// mv onto an existing global record needs --yes, then the project one moves with its metadata.
	code, out, errs := w.run("", "mv", "GITHUB_TOKEN", "--to", "global")
	if code != 2 || out != "" || errs != usageErr("GITHUB_TOKEN already exists in global; pass --yes to overwrite") {
		t.Fatalf("mv without --yes: code=%d out=%q err=%q", code, out, errs)
	}
	step("", "moved GITHUB_TOKEN from project shop-api to global\n", "mv", "GITHUB_TOKEN", "--to", "global", "--yes")
	step("", "NAME          LAYER   DESCRIPTION\n"+
		"GITHUB_TOKEN  global  shop token\n", "list")
	if w.value("GITHUB_TOKEN") != fxVal+"_project" {
		t.Fatal("mv lost the value")
	}

	// rm needs --yes and removes the resolved record.
	code, out, errs = w.run("", "rm", "GITHUB_TOKEN")
	if code != 2 || out != "" || errs != usageErr("confirmation required; pass --yes") {
		t.Fatalf("rm without --yes: code=%d out=%q err=%q", code, out, errs)
	}
	step("", "removed GITHUB_TOKEN (global)\n", "rm", "GITHUB_TOKEN", "--yes")
	step("", "no secrets\n", "list", "--layer", "all")

	// Nothing the lifecycle printed contained a value.
	if strings.Contains(all.String(), "TESTSECRET_") {
		t.Fatal("a value leaked into output")
	}
}
