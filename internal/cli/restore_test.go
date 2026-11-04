package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QuBiit0/gentle-vault/internal/exitcode"
	"github.com/QuBiit0/gentle-vault/internal/prompt/prompttest"
	"github.com/QuBiit0/gentle-vault/internal/vault"
)

// backupIDs returns the snapshot ids, newest first.
func (w *world) backupIDs() []string {
	w.t.Helper()
	bs, err := vault.ListBackups(w.home)
	if err != nil {
		w.t.Fatal(err)
	}
	ids := make([]string, len(bs))
	for i, b := range bs {
		ids[i] = b.ID
	}
	return ids
}

func (w *world) names() string {
	w.t.Helper()
	out := w.mustRun("", "list", "--layer", "all")
	var ns []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n")[1:] {
		ns = append(ns, strings.Fields(l)[0])
	}
	return strings.Join(ns, ",")
}

func TestRestoreUsage(t *testing.T) {
	w := newWorld(t)
	before := w.snapshot()
	cases := []struct {
		args []string
		msg  string
	}{
		{[]string{"restore"}, "choose --list or --from"},
		{[]string{"restore", "--list", "--from", "20261103T141500.123456789Z"}, "choose --list or --from"},
		{[]string{"restore", "--from", "TESTSECRET_not_an_id"}, "invalid backup id"},
		{[]string{"restore", "--from", "../../etc", "--yes"}, "invalid backup id"},
		{[]string{"restore", "--from", "20200101T000000.000000000Z", "--yes"}, "no backup 20200101T000000.000000000Z"},
		{[]string{"restore", "extra"}, "unexpected arguments"},
	}
	for _, c := range cases {
		code, out, errs := w.run("", c.args...)
		if code != exitcode.Usage || out != "" || errs != usageErr(c.msg) {
			t.Errorf("%v: code=%d out=%q err=%q", c.args, code, out, errs)
		}
	}
	if w.snapshot() != before {
		t.Fatal("a refused restore changed the vault")
	}
}

func TestRestoreList(t *testing.T) {
	w := newWorld(t)
	if out := w.mustRun("", "restore", "--list"); out != "no backups\n" {
		t.Fatalf("empty: %q", out)
	}
	if out := w.mustRun("", "--json", "restore", "--list"); out != `{"ok":true,"backups":[]}`+"\n" {
		t.Fatalf("empty json: %q", out)
	}
	w.mustRun("TESTSECRET_a\n", "set", "A", "--stdin")
	w.mustRun("TESTSECRET_b\n", "set", "B", "--stdin")
	ids := w.backupIDs()
	want := ids[0] + "  state.json, vault.enc\n" + ids[1] + "  state.json, vault.enc\n"
	if out := w.mustRun("", "restore", "--list"); out != want {
		t.Fatalf("list=%q want %q", out, want)
	}
	wantJSON := `{"ok":true,"backups":[{"id":"` + ids[0] + `","files":["state.json","vault.enc"]},{"id":"` + ids[1] + `","files":["state.json","vault.enc"]}]}` + "\n"
	if out := w.mustRun("", "--json", "restore", "--list"); out != wantJSON {
		t.Fatalf("json=%q", out)
	}
	h := newHarness(t)
	code, out, errs := h.run("", "restore", "--list")
	if code != exitcode.Failure || out != "" || errs != "error: no vault here; run 'gentle-vault init'\n" {
		t.Fatalf("no vault: code=%d out=%q err=%q", code, out, errs)
	}
}

func TestRestoreFromBackup(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_a\n", "set", "A", "--stdin")
	w.mustRun("TESTSECRET_b\n", "set", "B", "--stdin")
	id := w.backupIDs()[0] // the vault holding A only
	n := len(w.backupIDs())
	code, out, errs := w.run("", "restore", "--from", id, "--yes")
	if code != exitcode.OK || errs != "" || out != "restored the vault from "+id+" (the previous state was backed up first)\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if got := w.names(); got != "A" {
		t.Fatalf("names after restore = %q", got)
	}
	if w.value("A") != "TESTSECRET_a" {
		t.Fatal("restored value differs")
	}
	if len(w.backupIDs()) != n+1 {
		t.Fatal("the pre-restore state was not backed up")
	}
	if !w.auditHas(`"event":"restore"`) || !w.auditHas(`"detail":"`+id+`"`) {
		t.Fatal("restore not audited")
	}
	// JSON form, back to the newest snapshot (A and B).
	newest := w.backupIDs()[0]
	code, out, errs = w.run("", "--json", "restore", "--from", newest, "--yes")
	if code != exitcode.OK || errs != "" || out != `{"ok":true,"restored":"`+newest+`"}`+"\n" {
		t.Fatalf("json: code=%d out=%q err=%q", code, out, errs)
	}
	if got := w.names(); got != "A,B" {
		t.Fatalf("names = %q", got)
	}
	noFixtures(t, "restore output", out+errs+w.auditText())
}

func TestRestoreConfirmation(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_a\n", "set", "A", "--stdin")
	w.mustRun("TESTSECRET_b\n", "set", "B", "--stdin")
	id := w.backupIDs()[0]
	before := w.snapshot()

	withBackend(t, &prompttest.Fake{Unavailable: true})
	code, out, errs := w.run("", "restore", "--from", id)
	if code != exitcode.Usage || out != "" || errs != usageErr("confirmation required; pass --yes") {
		t.Fatalf("no terminal: code=%d out=%q err=%q", code, out, errs)
	}
	f := withBackend(t, answers(no()))
	code, out, errs = w.run("", "restore", "--from", id)
	if code != exitcode.Failure || out != "" || errs != msgCancelled {
		t.Fatalf("declined: code=%d out=%q err=%q", code, out, errs)
	}
	if len(f.Calls) != 1 || f.Calls[0].Q != "Restore the vault from "+id+"? The current vault is backed up first." {
		t.Fatalf("question = %+v", f.Calls)
	}
	if w.snapshot() != before {
		t.Fatal("a declined restore changed the vault")
	}
	withBackend(t, answers(yes()))
	if code, _, errs := w.run("", "restore", "--from", id); code != exitcode.OK || errs != "" {
		t.Fatalf("confirmed: code=%d err=%q", code, errs)
	}
	if w.names() != "A" {
		t.Fatal("confirmed restore did not apply")
	}
}

func TestRestoreRepairsCorruptVault(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_a\n", "set", "A", "--stdin")
	w.mustRun("TESTSECRET_b\n", "set", "B", "--stdin")
	id := w.backupIDs()[0]
	if err := os.WriteFile(filepath.Join(w.home, "vault.enc"), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errs := w.run("", "list")
	if code != exitcode.Corrupt || errs != "error: vault is corrupt; run 'gentle-vault restore'\n" {
		t.Fatalf("corrupt list: code=%d err=%q", code, errs)
	}
	w.mustRun("", "restore", "--from", id, "--yes")
	if w.names() != "A" {
		t.Fatal("restore did not repair the vault")
	}
}

func TestRestoreRefusesForeignBackup(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_a\n", "set", "A", "--stdin")
	w.mustRun("TESTSECRET_b\n", "set", "B", "--stdin")
	other := newWorld(t)
	other.mustRun("TESTSECRET_c\n", "set", "C", "--stdin")
	foreign, err := os.ReadFile(filepath.Join(other.home, "vault.enc"))
	if err != nil {
		t.Fatal(err)
	}
	id := w.backupIDs()[0]
	if err := os.WriteFile(filepath.Join(w.home, "backups", id, "vault.enc"), foreign, 0o600); err != nil {
		t.Fatal(err)
	}
	before := w.snapshot()
	code, out, errs := w.run("", "restore", "--from", id, "--yes")
	if code != exitcode.Corrupt || out != "" || errs != "error: backup cannot be opened with the current or a retired key\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if w.snapshot() != before {
		t.Fatal("a refused restore changed the vault")
	}
}
