package cli

import (
	"strings"
	"testing"

	"github.com/QuBiit0/gentle-vault/internal/exitcode"
	"github.com/QuBiit0/gentle-vault/internal/prompt/prompttest"
)

const manageReason = "this token belongs to shop-api only"

func manageReq(cwd, extra string) string {
	return envelope("manage", cwd, `"reason":"`+manageReason+`",`+extra)
}

func TestManageRemove(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_rm\n", "set", "A", "--stdin")
	f := withBackend(t, answers(yes()))
	code, _, out := w.broker("manage", manageReq(w.outside, `"action":"remove","name":"A","layer":"global"`))
	if code != exitcode.OK || out != `{"ok":true,"applied":true,"action":"remove","name":"A","layer":null}`+"\n" {
		t.Fatalf("code=%d out=%s", code, out)
	}
	q := f.Calls[0].Q
	if f.Calls[0].Kind != "confirm" || !strings.Contains(q, "remove A (global)") || !strings.Contains(q, manageReason) {
		t.Fatalf("question=%q", q)
	}
	if strings.Contains(w.snapshot(), `"name":"A"`) {
		t.Fatal("not removed")
	}
	if !w.auditHas(`"event":"manage"`) || !w.auditHas(`"by":"agent"`) {
		t.Fatalf("audit: %s", w.auditText())
	}
}

func TestManageDeclineChangesNothingAndCoolsDown(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_keep\n", "set", "A", "--stdin")
	before := w.snapshot()
	withBackend(t, answers(no()))
	req := manageReq(w.outside, `"action":"remove","name":"A","layer":"global"`)
	if code, m, _ := w.broker("manage", req); code != exitcode.Refusal || refusalType(m) != "user_declined" {
		t.Fatalf("decline: code=%d m=%v", code, m)
	}
	if w.snapshot() != before {
		t.Fatal("a declined manage changed the vault")
	}
	f := withBackend(t, answers())
	if code, m, _ := w.broker("manage", req); code != exitcode.Refusal || refusalType(m) != "rate_limited" || len(f.Calls) != 0 {
		t.Fatalf("cooldown: code=%d m=%v", code, m)
	}
}

func TestManageEditMarksWidening(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_edit\n", "set", "A", "--stdin", "--sensitive", "--binaries", "gh", "--description", "old")
	f := withBackend(t, answers(yes()))
	code, m, _ := w.broker("manage", manageReq(w.outside, `"action":"edit","name":"A","layer":"global","changes":{"sensitive":false,"binaries":[],"description":"new"}`))
	if code != exitcode.OK || m["layer"] != "global" {
		t.Fatalf("code=%d m=%v", code, m)
	}
	q := f.Calls[0].Q
	for _, want := range []string{"description: \"old\" -> \"new\"", "sensitive: true -> false (widening)", "binaries: gh -> any (widening)"} {
		if !strings.Contains(q, want) {
			t.Errorf("question lacks %q: %q", want, q)
		}
	}
	d := w.mustRun("", "--json", "describe", "A")
	if !strings.Contains(d, `"sensitive":false`) || !strings.Contains(d, `"description":"new"`) || !strings.Contains(d, `"binaries":[]`) {
		t.Fatalf("describe=%s", d)
	}
	if w.value("A") != "TESTSECRET_edit" {
		t.Fatal("edit touched the value")
	}
}

func TestManageMoveAndReplace(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_move\n", "set", "A", "--stdin")
	withBackend(t, answers(yes()))
	code, m, _ := w.broker("manage", manageReq(w.repo, `"action":"move","name":"A","layer":"global","to":"project"`))
	if code != exitcode.OK || m["layer"] != "project" {
		t.Fatalf("move: code=%d m=%v", code, m)
	}
	w.inRepo()
	if w.value("A") != "TESTSECRET_move" {
		t.Fatal("value lost in move")
	}
	f := withBackend(t, answers(yes(), val("TESTSECRET_replaced")))
	code, m, _ = w.broker("manage", manageReq(w.repo, `"action":"replace","name":"A","layer":"project"`))
	if code != exitcode.OK || m["action"] != "replace" {
		t.Fatalf("replace: code=%d m=%v", code, m)
	}
	if f.Calls[1].Kind != "secret" || f.Calls[1].Request.Existing != true {
		t.Fatalf("replace prompt=%+v", f.Calls)
	}
	if w.value("A") != "TESTSECRET_replaced" {
		t.Fatal("not replaced")
	}
}

func TestManageRefusals(t *testing.T) {
	w := newWorld(t)
	withBackend(t, answers())
	if code, m, _ := w.broker("manage", manageReq(w.outside, `"action":"remove","name":"NOPE","layer":"global"`)); code != exitcode.Refusal || refusalType(m) != "unknown_secret" {
		t.Fatalf("unknown: code=%d m=%v", code, m)
	}
	if code, m, _ := w.broker("manage", manageReq(w.outside, `"action":"move","name":"A","layer":"global","to":"project"`)); code != exitcode.Refusal || refusalType(m) != "no_project" && refusalType(m) != "unknown_secret" {
		t.Fatalf("move outside repo: code=%d m=%v", code, m)
	}
	w.mustRun("TESTSECRET_x\n", "set", "B", "--stdin")
	withBackend(t, &prompttest.Fake{Unavailable: true})
	if code, m, _ := w.broker("manage", manageReq(w.outside, `"action":"remove","name":"B","layer":"global"`)); code != exitcode.Refusal || refusalType(m) != "internal" {
		t.Fatalf("no prompt: code=%d m=%v", code, m)
	}
}

// B1: a blank allowlist entry empties the list once cleaned: the user must
// be told it widens.
func TestManageEditBlankEntriesAreWidening(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_b1\n", "set", "A", "--stdin", "--binaries", "gh")
	code, m, _ := w.broker("manage", manageReq(w.outside, `"action":"edit","name":"A","layer":"global","changes":{"binaries":[""]}`))
	if code != exitcode.Refusal || refusalType(m) != "internal" || m["refusal"].(map[string]any)["message"] != "invalid request: changes" {
		t.Fatalf("blank entry: code=%d m=%v", code, m)
	}
	f := withBackend(t, answers(yes()))
	w.broker("manage", manageReq(w.outside, `"action":"edit","name":"A","layer":"global","changes":{"binaries":[" gh "]}`))
	if q := f.Calls[0].Q; !strings.Contains(q, "binaries: gh -> gh;") && !strings.HasSuffix(strings.Split(q, ". Reason")[0], "binaries: gh -> gh") {
		t.Fatalf("question=%q", q)
	}
}
