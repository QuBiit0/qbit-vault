package tui_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/tui"
)

var newer = tui.UpdateInfo{Current: "1.0.0", Latest: "v1.1.0", URL: "https://github.com/qbitdevz/qbit-vault/releases/tag/v1.1.0", Available: true}

func newModelWith(b tui.Backend, o tui.Options) tui.Model {
	suspended = 0
	o.Version, o.Exec = "1.0.0", fakeExec
	return tui.New(b, o)
}

// opened is the model after the open-time check ran: Init's command settled.
func opened(m tui.Model) tui.Model { return settle(m, m.Init()) }

func TestUpdateFirstFrameDoesNotWaitForTheCheck(t *testing.T) {
	b := newReady()
	b.update = newer
	m := pressAll(newModelWith(b, tui.Options{}), digit('7'))
	if b.updateCalls != 0 {
		t.Fatalf("the check ran inside New or a key (%d calls); it must be a command", b.updateCalls)
	}
	wantView(t, m, "update", "checking for updates")
	if strings.Contains(m.View(), "update available") {
		t.Error("the notice shows before the check finished")
	}
	if m.Init() == nil {
		t.Fatal("Init returned no command: nothing checks on open")
	}
	m = opened(m)
	if b.updateCalls != 1 {
		t.Errorf("CheckUpdate calls = %d, want 1", b.updateCalls)
	}
}

func TestUpdateNewerReleaseShowsHeaderNoticeAndSection(t *testing.T) {
	b := newReady()
	b.update = newer
	m := opened(newModelWith(b, tui.Options{}))
	wantView(t, m, "update available v1.1.0") // header, on any section
	m = pressAll(m, digit('7'))
	wantView(t, m, "current 1.0.0", "latest v1.1.0", "https://github.com/qbitdevz/qbit-vault/releases/tag/v1.1.0", "u", "update now")
	if strings.Contains(m.View(), "could not check") {
		t.Error("an available update reads as a failed check")
	}
}

func TestUpdateUpToDateHasNoHeaderNotice(t *testing.T) {
	b := newReady()
	b.update = tui.UpdateInfo{Current: "1.0.0", Latest: "v1.0.0"}
	m := pressAll(opened(newModelWith(b, tui.Options{})), digit('7'))
	if strings.Contains(m.View(), "update available") || strings.Contains(m.View(), "update now") {
		t.Errorf("up to date but offers an update:\n%s", m.View())
	}
	wantView(t, m, "current 1.0.0", "up to date")
}

func TestUpdateCheckFailureSaysSoQuietly(t *testing.T) {
	b := newReady()
	b.updateErr = errBoom
	m := opened(newModelWith(b, tui.Options{}))
	if strings.Contains(m.View(), "update available") || strings.Contains(m.View(), errBoom.Error()) {
		t.Errorf("a failed check changed the header or showed the error:\n%s", m.View())
	}
	m = pressAll(m, digit('7'))
	wantView(t, m, "could not check for updates")
	if strings.Contains(m.View(), "✗") || strings.Contains(m.View(), errBoom.Error()) {
		t.Errorf("a failed check shows an error notice:\n%s", m.View())
	}
}

func TestUpdateOptOutMakesNoCheckAndOffersCheckNow(t *testing.T) {
	b := newReady()
	b.update = newer
	m := newModelWith(b, tui.Options{NoUpdateCheck: true})
	if cmd := m.Init(); cmd != nil {
		settle(m, cmd)
	}
	m = pressAll(m, digit('7'))
	if b.updateCalls != 0 {
		t.Fatalf("CheckUpdate ran %d times with the check off", b.updateCalls)
	}
	wantView(t, m, "QBIT_VAULT_NO_UPDATE_CHECK", "c", "check now")
	m = pressAll(m, runeKey('c'))
	if b.updateCalls != 1 {
		t.Fatalf("c made %d checks, want 1", b.updateCalls)
	}
	wantView(t, m, "update available v1.1.0", "latest v1.1.0", "update now")
}

func TestUpdateKeyRunsTheActionSuspendedAndReportsDone(t *testing.T) {
	b := newReady()
	b.update = newer
	m := pressAll(opened(newModelWith(b, tui.Options{})), digit('7'), runeKey('u'))
	if suspended != 1 || len(b.ran) != 1 || b.ran[0] != "update" {
		t.Fatalf("suspended=%d ran=%v, want one suspended update", suspended, b.ran)
	}
	wantView(t, m, "updated to v1.1.0; restart qbit-vault and your agents")
	if strings.Contains(m.View(), "update now") || strings.Contains(m.View(), "update available") {
		t.Errorf("still offers the update after it ran:\n%s", m.View())
	}
}

func TestUpdateFailureShowsItsOneLine(t *testing.T) {
	b := newReady()
	b.update = newer
	b.updateRunErr = errors.New("cannot replace /usr/local/bin/qbit-vault: re-run the install command")
	m := pressAll(opened(newModelWith(b, tui.Options{})), digit('7'), runeKey('u'))
	wantView(t, m, "✗", "cannot replace /usr/local/bin/qbit-vault")
	if strings.Contains(m.View(), "updated to") {
		t.Error("a failed update says it updated")
	}
	wantView(t, m, "update now") // can try again
}

func TestUpdateKeyDoesNothingWithoutANewerRelease(t *testing.T) {
	b := newReady()
	b.update = tui.UpdateInfo{Current: "1.0.0", Latest: "v1.0.0"}
	m := pressAll(opened(newModelWith(b, tui.Options{})), digit('7'), runeKey('u'))
	if suspended != 0 || len(b.ran) != 0 {
		t.Error("u updated with nothing to update to")
	}
	_ = m
}

func TestUpdateNonReleaseBuildDoesNotCheckNorOfferU(t *testing.T) {
	b := newReady()
	b.update = newer
	m := newModelWith(b, tui.Options{NotRelease: true})
	m.Init()
	m = pressAll(m, digit('7'), runeKey('u'))
	if b.updateCalls != 0 || suspended != 0 {
		t.Errorf("non-release build checked (%d) or updated (%d)", b.updateCalls, suspended)
	}
	wantView(t, m, "this build is not a release")
	if strings.Contains(m.View(), "update now") {
		t.Error("a non-release build offers u")
	}
}

func TestUpdateNeverTouchesGrantsOrTheVault(t *testing.T) {
	b := newReady()
	b.update = newer
	before := len(b.grants)
	pressAll(opened(newModelWith(b, tui.Options{})), digit('7'), runeKey('u'))
	if len(b.grants) != before || b.revokedAll != 0 || len(b.revoked) != 0 || len(b.added) != 0 {
		t.Error("the update changed grants or secrets")
	}
}

func TestUpdateRecheckKeepsKnownReleaseUntilTheResultArrives(t *testing.T) {
	b := newReady()
	b.update = newer
	m := pressAll(opened(newModelWith(b, tui.Options{})), digit('7'))
	next, cmd := m.Update(runeKey('c')) // the check runs; its result is not delivered yet
	if cmd == nil {
		t.Fatal("c started no check")
	}
	wantView(t, next.(tui.Model), "update available v1.1.0", "latest v1.1.0", "update now")
}

func TestUpdateFailedRecheckKeepsKnownReleaseAndSaysSo(t *testing.T) {
	b := newReady()
	b.update = newer
	m := pressAll(opened(newModelWith(b, tui.Options{})), digit('7'))
	b.updateErr = errBoom
	m = pressAll(m, runeKey('c'))
	wantView(t, m, "update available v1.1.0", "latest v1.1.0", "update now", "could not re-check")
	if strings.Contains(m.View(), errBoom.Error()) {
		t.Errorf("a failed re-check shows the error:\n%s", m.View())
	}
}
