package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/exitcode"
	"github.com/QuBiit0/qbit-vault/internal/keychain"
	"github.com/QuBiit0/qbit-vault/internal/prompt/prompttest"
	"github.com/QuBiit0/qbit-vault/internal/secret"
	"github.com/QuBiit0/qbit-vault/internal/vault"
)

const linkHint = "hint: project secrets \"shop-api\" from another device match this repository; run 'qbit-vault link shop-api'\n"

// syncedProject stores a "shop-api" layer from another device and gives the
// fake repository the same origin.
func (w *world) syncedProject() {
	w.t.Helper()
	id, _ := vault.ReadID(w.home)
	key, _, err := keychain.Unlock(w.home, id, keychain.Options{})
	if err != nil {
		w.t.Fatal(err)
	}
	defer key.Wipe()
	if err := vault.AddUnlinkedForTesting(w.home, key, "shop-api", "github.com/acme/shop-api", "DB", secret.New("DB", []byte("TESTSECRET_synced"))); err != nil {
		w.t.Fatal(err)
	}
	cfg := "[remote \"origin\"]\n\turl = git@github.com:acme/shop-api.git\n"
	if err := os.WriteFile(filepath.Join(w.repo, ".git", "config"), []byte(cfg), 0o600); err != nil {
		w.t.Fatal(err)
	}
}

func TestListShowsUnlinkedLayersAndHint(t *testing.T) {
	w := newWorld(t)
	w.syncedProject()
	out := w.mustRun("", "list", "--layer", "all")
	if out != "NAME  LAYER             DESCRIPTION\nDB    project:shop-api  (not linked on this device)\n" {
		t.Fatalf("list all=%q", out)
	}
	js := w.mustRun("", "--json", "list", "--layer", "all")
	if !strings.Contains(js, `"name":"DB","layer":"project","project_label":"shop-api"`) || !strings.Contains(js, `"unlinked":true`) {
		t.Fatalf("json=%s", js)
	}
	w.inRepo()
	code, out, errs := w.run("", "list")
	if code != exitcode.OK || out != "no secrets\n" || errs != linkHint {
		t.Fatalf("hint: code=%d out=%q err=%q", code, out, errs)
	}
	if _, _, errs := w.run("", "--json", "list"); errs != "" {
		t.Fatalf("json mode printed the hint: %q", errs)
	}
	_, m, _ := w.broker("list", envelope("list", w.repo, ""))
	if um, ok := m["unlinked_match"].(map[string]any); !ok || um["label"] != "shop-api" {
		t.Fatalf("broker unlinked_match=%v", m["unlinked_match"])
	}
	noFixtures(t, "list", out+js)
}

func TestLinkBindsTheLayerAfterConfirmation(t *testing.T) {
	w := newWorld(t)
	w.syncedProject()
	w.inRepo()
	f := withBackend(t, answers(yes()))
	code, out, errs := w.run("", "link", "shop-api")
	if code != exitcode.OK || errs != "" || out != "linked shop-api to "+w.root+" (1 secret)\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if f.Calls[0].Kind != "confirm" || f.Calls[0].Q != "Use the secrets of project shop-api in "+w.root+"?" {
		t.Fatalf("question=%+v", f.Calls)
	}
	if w.value("DB") != "TESTSECRET_synced" {
		t.Fatal("linked secret does not resolve")
	}
	if !w.auditHas(`"event":"link"`) {
		t.Fatal("link not audited")
	}
	if _, _, errs := w.run("", "list"); errs != "" {
		t.Fatalf("hint after link: %q", errs)
	}
}

func TestLinkRefusalsChangeNothing(t *testing.T) {
	w := newWorld(t)
	w.syncedProject()
	w.inRepo()
	before := w.snapshot() // in the repository: snapshot includes the cwd's project
	withBackend(t, &prompttest.Fake{Unavailable: true})
	code, _, errs := w.run("", "link", "shop-api")
	if code != exitcode.Refusal || errs != "error: this operation is not available to the model\n" {
		t.Fatalf("no prompt: code=%d err=%q", code, errs)
	}
	withBackend(t, answers(no()))
	if code, _, errs := w.run("", "link", "shop-api"); code != exitcode.Failure || errs != msgCancelled {
		t.Fatalf("declined: code=%d err=%q", code, errs)
	}
	withBackend(t, answers(yes()))
	cases := []struct {
		args []string
		code int
		errs string
	}{
		{[]string{"link", "TESTSECRET_nope"}, exitcode.Usage, usageErr("no unlinked project layer has that label")},
		{[]string{"link", "shop-api", w.outside}, exitcode.Refusal, "error: not inside a repository\n"},
		{[]string{"link"}, exitcode.Usage, usageErr("give the label of the project layer to link")},
	}
	for _, c := range cases {
		code, out, errs := w.run("", c.args...)
		if code != c.code || out != "" || errs != c.errs {
			t.Errorf("%v: code=%d out=%q err=%q", c.args, code, out, errs)
		}
	}
	if w.snapshot() != before {
		t.Fatal("a refused link changed the vault")
	}
	w.mustRun("TESTSECRET_local\n", "set", "LOCAL", "--stdin", "--project")
	withBackend(t, answers(yes()))
	if code, _, errs := w.run("", "link", "shop-api"); code != exitcode.Usage || errs != usageErr("this repository already has a project layer") {
		t.Fatalf("taken root: code=%d err=%q", code, errs)
	}
}
