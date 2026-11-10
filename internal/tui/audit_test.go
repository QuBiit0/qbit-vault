package tui_test

import (
	"strings"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/tui"
)

func auditPane(b *fakeBackend) tui.Model { return pressAll(newModel(b, false), digit('4')) }

func TestAuditListsTheNewestRecordsFirstWithoutAnyValue(t *testing.T) {
	m := auditPane(newReady())
	v := m.View()
	wantView(t, m, "audit", "TIME", "EVENT", "NAME", "BY", "10:31:07", "exec", "GITHUB_TOKEN", "agent",
		"09:14:02", "NPM_TOKEN", "user", "3 of 412 records")
	if strings.Index(v, "10:31:07") > strings.Index(v, "09:14:02") {
		t.Errorf("the log is not newest first:\n%s", v)
	}
}

func TestAuditDetailShowsTheSelectedRecordAndStatesNoValueIsStored(t *testing.T) {
	m := auditPane(newReady())
	wantView(t, m, "newest record", "exec", "2026-11-05 10:31", "GITHUB_TOKEN", "global", "agent", "No command text")
	m = pressAll(m, keyTab, keyDown, keyDown)
	wantView(t, m, "oldest record", "grant", "NPM_TOKEN", "user")
}

func TestAuditVerifyReportsAnIntactChain(t *testing.T) {
	b := newReady()
	m := pressAll(auditPane(b), runeKey('v'))
	if b.verifyCalls != 1 {
		t.Fatalf("VerifyAudit calls = %d", b.verifyCalls)
	}
	wantView(t, m, "verified", "audit log ok (412 records)")
}

func TestAuditVerifyNamesTheBrokenLineAndKeepsTheStateOnScreen(t *testing.T) {
	b := newReady()
	b.verdict = tui.AuditVerdict{Valid: false, Records: 310, Line: 311, Reason: "bad_hash"}
	m := pressAll(auditPane(b), runeKey('v'))
	wantView(t, m, "broken", "audit log broken at line 311", "bad_hash", "not trusted", "qbit-vault audit --verify")
	m = pressAll(m, keyTab, keyDown) // the notice clears with the next key; the verdict stays
	wantView(t, m, "broken, after moving", "line 311")
}

func TestAuditVerifyFailureShowsTheMessageNotAVerdict(t *testing.T) {
	b := newReady()
	b.verifyErr = errBoomText("audit: cannot read the log")
	m := pressAll(auditPane(b), runeKey('v'))
	wantView(t, m, "verify failed", "audit: cannot read the log")
	if strings.Contains(m.View(), "audit log ok") {
		t.Error("an unverified chain was reported ok")
	}
}

func TestAuditEmptyLogHasAnExplanation(t *testing.T) {
	b := newReady()
	b.audit = tui.AuditLog{}
	m := auditPane(b)
	wantView(t, m, "empty audit", "No audit records yet", "capture", "grant")
}

func TestAuditEntriesCannotRepaintTheScreen(t *testing.T) {
	b := newReady()
	b.audit.Entries[2].Names = []string{"EVIL\x1b[2J\x1b]0;x\x07"}
	m := auditPane(b)
	if v := m.View(); strings.ContainsRune(v, 0x1b) || strings.ContainsRune(v, 0x07) {
		t.Errorf("a control character reached the frame: %q", v)
	}
}

func TestAuditVerifyKeyOnlyActsInTheAuditSection(t *testing.T) {
	b := newReady()
	pressAll(newModel(b, false), runeKey('v'), digit('5'), runeKey('v'))
	if b.verifyCalls != 0 {
		t.Error("v verified outside the Audit section")
	}
}
