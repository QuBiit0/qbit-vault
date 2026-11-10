package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/exitcode"
	"github.com/qbitdevz/qbit-vault/internal/grants"
)

// Replacing a value is one decision that also covers its permission: the
// user approves, picks how long the agent may use the new value, and types
// it. No second permission dialog follows (odd/tasks/prompt-ux.md U2).
func TestManageReplaceGrantsInTheSameDecision(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_old\n", "set", "A", "--stdin")
	f := withBackend(t, answers(pick(0), val("TESTSECRET_new")))
	code, m, out := w.broker("manage", manageReq(w.outside, `"action":"replace","name":"A","layer":"global"`))
	if code != exitcode.OK || out != `{"ok":true,"applied":true,"action":"replace","name":"A","layer":"global"}`+"\n" {
		t.Fatalf("code=%d m=%v out=%s", code, m, out)
	}
	if len(f.Calls) != 2 || f.Calls[0].Kind != "choose" || f.Calls[1].Kind != "secret" || !f.Calls[1].Request.Existing {
		t.Fatalf("dialogs = %+v", f.Calls)
	}
	q := f.Calls[0]
	if q.Q != "Pi wants to replace the value of A (all projects).\nWhy: "+manageReason || q.Default != 0 {
		t.Fatalf("question = %q default %d", q.Q, q.Default)
	}
	want := []string{"Replace, allow once", "Replace, but ask me before each use", "Don't replace"}
	if strings.Join(q.Options, "|") != strings.Join(want, "|") {
		t.Fatalf("options = %q", q.Options)
	}
	if w.value("A") != "TESTSECRET_new" {
		t.Fatal("not replaced")
	}
	if err := w.execCheck("A", brokerSession); err != nil {
		t.Fatalf("the new value needs another permission: %v", err)
	}
	if !w.auditHas(`"event":"manage"`) || !w.auditHas(`"event":"grant"`) {
		t.Fatalf("audit: %s", w.auditText())
	}
	noFixtures(t, "output", out+w.auditText())
}

// Replace only: the value changes and the next use asks again, as before.
func TestManageReplaceOnlyKeepsNoPermission(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_old\n", "set", "A", "--stdin")
	withBackend(t, answers(pick(1), val("TESTSECRET_new")))
	if code, m, _ := w.broker("manage", manageReq(w.outside, `"action":"replace","name":"A","layer":"global"`)); code != exitcode.OK {
		t.Fatalf("code=%d m=%v", code, m)
	}
	if w.value("A") != "TESTSECRET_new" {
		t.Fatal("not replaced")
	}
	if err := w.execCheck("A", brokerSession); !errors.Is(err, grants.ErrGrantRequired) {
		t.Fatalf("err = %v, want grant required", err)
	}
}

// Don't replace: nothing changes, the value is never asked, and the name
// cools down like any declined proposal.
func TestManageReplaceDeclined(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_old\n", "set", "A", "--stdin")
	before := w.snapshot()
	f := withBackend(t, answers(pick(2)))
	code, m, _ := w.broker("manage", manageReq(w.outside, `"action":"replace","name":"A","layer":"global"`))
	if code != exitcode.Refusal || refusalType(m) != "user_declined" || len(f.Calls) != 1 {
		t.Fatalf("code=%d m=%v calls=%d", code, m, len(f.Calls))
	}
	if w.snapshot() != before || w.value("A") != "TESTSECRET_old" {
		t.Fatal("a declined replace changed the vault")
	}
}

// A sensitive secret offers a one-time permission only.
func TestManageReplaceSensitiveOffersOnceOnly(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_old\n", "set", "A", "--stdin", "--sensitive")
	f := withBackend(t, answers(pick(0), val("TESTSECRET_new")))
	if code, m, _ := w.broker("manage", manageReq(w.outside, `"action":"replace","name":"A","layer":"global"`)); code != exitcode.OK {
		t.Fatalf("code=%d m=%v", code, m)
	}
	if o := f.Calls[0].Options; len(o) != 3 || o[0] != "Replace, allow once" || f.Calls[0].Default != 0 {
		t.Fatalf("options = %q default %d", o, f.Calls[0].Default)
	}
	if err := w.execCheck("A", brokerSession); err != nil {
		t.Fatalf("once grant missing: %v", err)
	}
}

// Inside a repository replace offers "always in this project" too, and the
// grant it makes covers a new agent session there, not another repository.
func TestManageReplaceInARepositoryCanGrantAlways(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_old\n", "set", "A", "--global", "--stdin")
	f := withBackend(t, answers(pick(1), val("TESTSECRET_new")))
	if code, m, _ := w.broker("manage", manageReq(w.repo, `"action":"replace","name":"A","layer":"global"`)); code != exitcode.OK {
		t.Fatalf("code=%d m=%v", code, m)
	}
	want := []string{"Replace, allow once", "Replace, always in this project", "Replace, but ask me before each use", "Don't replace"}
	if strings.Join(f.Calls[0].Options, "|") != strings.Join(want, "|") || f.Calls[0].Default != 0 {
		t.Fatalf("options=%q default=%d", f.Calls[0].Options, f.Calls[0].Default)
	}
	if err := w.checkIn("A", "mcp:restarted", w.repo); err != nil {
		t.Fatalf("after a restart: %v", err)
	}
	if err := w.checkIn("A", brokerSession, w.mkRepo("blog")); !errors.Is(err, grants.ErrGrantRequired) {
		t.Fatalf("another repository: err = %v", err)
	}
}
