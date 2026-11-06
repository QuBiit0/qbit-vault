package cli

import (
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/exitcode"
)

// A value pasted with its quotes, or with invisible characters copied from a
// web page, is the classic reason a service rejects a token that "looks
// right". Before saving, the user is told and can drop them; a clean value
// asks nothing more (odd/tasks/prompt-ux.md U3).

func TestValueIssues(t *testing.T) {
	tests := []struct {
		in, fixed, problem string
	}{
		{`"TESTSECRET_q"`, "TESTSECRET_q", "starts and ends with quotes"},
		{`'TESTSECRET_q'`, "TESTSECRET_q", "starts and ends with quotes"},
		{"`TESTSECRET_q`", "TESTSECRET_q", "starts and ends with quotes"},
		{"TESTSECRET_\u200bzw", "TESTSECRET_zw", "has invisible characters"},
		{"\ufeffTESTSECRET_bom", "TESTSECRET_bom", "has invisible characters"},
		{"TESTSECRET_\u00a0nb", "TESTSECRET_nb", "has invisible characters"},
		{"\"TESTSECRET_\u200bboth\"", "TESTSECRET_both", "starts and ends with quotes and has invisible characters"},
		{"TESTSECRET_clean-token_0123", "", ""},
		{`TESTSECRET_"inside"`, "", ""},   // quotes only inside: left alone
		{`"TESTSECRET_mismatch'`, "", ""}, // different quotes: not a pair
		{`"`, "", ""},                     // a lone quote is a value, not a pair
		{`""`, "", ""},                    // only a pair of quotes: nothing to keep inside
		{"TESTSECRET_é ñ", "", ""},        // visible non-ASCII and a normal space are fine
	}
	for _, tt := range tests {
		problem, fixed := valueIssues([]byte(tt.in))
		if problem != tt.problem || string(fixed) != tt.fixed {
			t.Errorf("valueIssues(%q) = %q, %q; want %q, %q", tt.in, problem, fixed, tt.problem, tt.fixed)
		}
	}
}

func TestRequestOffersToDropPastedQuotes(t *testing.T) {
	w := newWorld(t)
	f := withBackend(t, answers(val(`"TESTSECRET_quoted"`), pick(0), pick(1)))
	if code, m, _ := w.broker("request", reqFor(w.outside, "")); code != exitcode.OK {
		t.Fatalf("code=%d m=%v", code, m)
	}
	if len(f.Calls) != 3 || f.Calls[1].Kind != "choose" {
		t.Fatalf("calls=%+v", f.Calls)
	}
	q := f.Calls[1]
	if q.Q != "The value of A starts and ends with quotes. Keys and tokens usually don't, and a pasted extra breaks the login. Save it:" ||
		len(q.Options) != 3 || q.Options[0] != "Without them (recommended)" || q.Options[1] != "Exactly as typed" || q.Options[2] != "Cancel" || q.Default != 0 {
		t.Fatalf("question=%+v", q)
	}
	if w.value("A") != "TESTSECRET_quoted" {
		t.Fatalf("stored %q", w.value("A"))
	}
}

func TestRequestKeepsTheValueExactlyAsTypedWhenAsked(t *testing.T) {
	w := newWorld(t)
	withBackend(t, answers(val("'TESTSECRET_keep'"), pick(1), pick(1)))
	if code, m, _ := w.broker("request", reqFor(w.outside, "")); code != exitcode.OK {
		t.Fatalf("code=%d m=%v", code, m)
	}
	if w.value("A") != "'TESTSECRET_keep'" {
		t.Fatalf("stored %q", w.value("A"))
	}
}

func TestRequestCancelAtTheValueCheckSavesNothing(t *testing.T) {
	w := newWorld(t)
	before := w.snapshot()
	withBackend(t, answers(val("TESTSECRET_\u200bzw"), pick(2)))
	code, m, _ := w.broker("request", reqFor(w.outside, ""))
	if code != exitcode.Refusal || refusalType(m) != "user_declined" {
		t.Fatalf("code=%d m=%v", code, m)
	}
	if w.snapshot() != before {
		t.Fatal("a cancelled check changed the vault")
	}
}

func TestACleanValueAsksNothingMore(t *testing.T) {
	w := newWorld(t)
	f := withBackend(t, answers(val("TESTSECRET_clean"), pick(1)))
	if code, m, _ := w.broker("request", reqFor(w.outside, "")); code != exitcode.OK {
		t.Fatalf("code=%d m=%v", code, m)
	}
	if len(f.Calls) != 2 {
		t.Fatalf("calls=%+v", f.Calls)
	}
}

func TestSetInteractiveOffersToDropInvisibleCharacters(t *testing.T) {
	w := newWorld(t)
	f := withBackend(t, answers(val("TESTSECRET_\u200bset"), pick(0)))
	if code, out, errs := w.run("", "set", "A", "--global"); code != exitcode.OK {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if len(f.Calls) != 2 || f.Calls[1].Q != "The value of A has invisible characters. Keys and tokens usually don't, and a pasted extra breaks the login. Save it:" {
		t.Fatalf("calls=%+v", f.Calls)
	}
	if w.value("A") != "TESTSECRET_set" {
		t.Fatalf("stored %q", w.value("A"))
	}
}

func TestManageReplaceOffersToDropPastedQuotes(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_old\n", "set", "A", "--stdin")
	withBackend(t, answers(pick(1), val(`"TESTSECRET_new"`), pick(0)))
	if code, m, _ := w.broker("manage", manageReq(w.outside, `"action":"replace","name":"A","layer":"global"`)); code != exitcode.OK {
		t.Fatalf("code=%d m=%v", code, m)
	}
	if w.value("A") != "TESTSECRET_new" {
		t.Fatalf("stored %q", w.value("A"))
	}
}

// A value made only of invisible characters has nothing left without them:
// the check offers "as typed" or cancel, never a silent empty save.
func TestAllInvisibleValueOffersNoEmptyFix(t *testing.T) {
	w := newWorld(t)
	f := withBackend(t, answers(val("\u200b\u200b"), pick(0), pick(1)))
	if code, m, _ := w.broker("request", reqFor(w.outside, "")); code != exitcode.OK {
		t.Fatalf("code=%d m=%v", code, m)
	}
	if o := f.Calls[1].Options; len(o) != 2 || o[0] != "Exactly as typed" || o[1] != "Cancel" {
		t.Fatalf("options=%q", o)
	}
	if w.value("A") != "\u200b\u200b" {
		t.Fatalf("stored %q", w.value("A"))
	}
}
