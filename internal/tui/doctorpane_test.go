package tui_test

import (
	"strings"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/tui"
)

func doctorPane(b *fakeBackend) tui.Model { return pressAll(newModel(b, false), digit('6')) }

func TestDoctorShowsEveryCheckWithItsStatusAndTheSummary(t *testing.T) {
	m := doctorPane(newReady())
	wantView(t, m, "doctor", "vault", "permissions", "audit", "ok", "warn", "fail", "2 problems")
	wantView(t, m, "first check detail", "unlocked (keychain: keychain)")
	m = pressAll(m, keyTab, keyDown, keyDown)
	wantView(t, m, "third check detail", "audit chain broken at line 3")
}

func TestDoctorStatusesUseTheirColors(t *testing.T) {
	m := pressAll(newModel(newReady(), true), digit('6'), keyTab, keyDown) // the selected row has its own style
	th := tui.NewTheme(tui.Profile{Color: true, TrueColor: true})
	v := m.View()
	for _, s := range []string{th.Green("ok"), th.Warn("warn"), th.Flare("fail")} {
		if !strings.Contains(v, s) {
			t.Errorf("the report lacks %q", s)
		}
	}
}

func TestDoctorHealthyReport(t *testing.T) {
	b := newReady()
	b.doctor = tui.DoctorReport{OK: true, Checks: []tui.DoctorCheck{{Name: "vault", Status: "ok", Detail: "unlocked"}}}
	wantView(t, doctorPane(b), "healthy", "healthy")
}

func TestDoctorRerunsOnR(t *testing.T) {
	b := newReady()
	m := doctorPane(b)
	before := b.doctorCalls
	b.doctor = tui.DoctorReport{OK: true, Checks: []tui.DoctorCheck{{Name: "vault", Status: "ok", Detail: "all good now"}}}
	m = pressAll(m, runeKey('r'))
	if b.doctorCalls != before+1 {
		t.Fatalf("Doctor calls = %d, want %d", b.doctorCalls, before+1)
	}
	wantView(t, m, "rerun", "all good now", "healthy", "r rerun")
}

func TestDoctorKeyOnlyActsInTheDoctorSection(t *testing.T) {
	b := newReady()
	m := pressAll(newModel(b, false), digit('5'))
	before := b.doctorCalls
	pressAll(m, runeKey('r'))
	if b.doctorCalls != before {
		t.Error("r reran the doctor outside its section")
	}
}

func TestDoctorEmptyReportIsExplained(t *testing.T) {
	b := newReady()
	b.doctor = tui.DoctorReport{}
	wantView(t, doctorPane(b), "empty report", "No checks ran", "r")
}
