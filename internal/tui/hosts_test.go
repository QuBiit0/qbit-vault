package tui_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/tui"
)

func hostsPane(b *fakeBackend) tui.Model { return pressAll(newModel(b, false), digit('3')) }

func TestHostsListShowsEachHostWithTheStatusOfItsSteps(t *testing.T) {
	m := hostsPane(newReady())
	wantView(t, m, "hosts", "HOST", "STATE", "STEPS",
		"claude-code", "drift", "✓ ! ✓",
		"codex", "registered", "pi", "detected")
	// The selected host's detail: its files and what drift means.
	wantView(t, m, "claude-code detail", "claude-code", "hooks", "settings.json",
		"drift", "Changed since registration")
}

func TestHostsDetailFollowsTheSelectionAndShowsItsConfigFile(t *testing.T) {
	m := pressAll(hostsPane(newReady()), keyTab, keyDown)
	wantView(t, m, "codex detail", "codex", "config.toml")
	if strings.Contains(m.View(), "changed since registration") {
		t.Error("a healthy host explains drift")
	}
	m = pressAll(m, keyDown)
	wantView(t, m, "pi detail", "pi", "not registered", "register")
}

func TestHostsRepairRunsTheSyncPathForTheSelectedHost(t *testing.T) {
	b := newReady()
	m := pressAll(hostsPane(b), runeKey('s'))
	if !reflect.DeepEqual(b.repaired, []string{"claude-code"}) {
		t.Fatalf("RepairHosts got %q, want the selected host", b.repaired)
	}
	wantView(t, m, "after repair", "repaired claude-code", "✓ ✓ ✓")
	if strings.Contains(m.View(), "✓ ! ✓") {
		t.Error("the drift is still shown after the repair")
	}
}

func TestHostsRepairAllUsesAnEmptyName(t *testing.T) {
	b := newReady()
	m := pressAll(hostsPane(b), runeKey('S'))
	if !reflect.DeepEqual(b.repaired, []string{""}) {
		t.Fatalf("RepairHosts got %q, want one call for every host", b.repaired)
	}
	wantView(t, m, "after repair all", "repaired every registered host")
}

func TestHostsRepairNeedsARegisteredHost(t *testing.T) {
	b := newReady()
	m := pressAll(hostsPane(b), keyTab, keyDown, keyDown, runeKey('s'))
	if len(b.repaired) != 0 {
		t.Fatalf("repaired %q a host that is not registered", b.repaired)
	}
	wantView(t, m, "repair of pi", "pi is not registered", "a")
}

func TestHostsUninstallAsksFirstStatingTheConsequence(t *testing.T) {
	b := newReady()
	m := pressAll(hostsPane(b), runeKey('x'))
	wantView(t, m, "uninstall question", "Uninstall claude-code?", "Reverts", "snapshot", "vault", "y", "confirm")
	if len(b.uninstalled) != 0 {
		t.Fatal("uninstalled before the confirmation")
	}
	cancelled := pressAll(m, runeKey('n'))
	if len(b.uninstalled) != 0 {
		t.Fatal("any other key must cancel")
	}
	if strings.Contains(cancelled.View(), "Uninstall claude-code?") {
		t.Error("the question stayed after cancelling")
	}
	m = pressAll(m, runeKey('y'))
	if !reflect.DeepEqual(b.uninstalled, []string{"claude-code"}) {
		t.Fatalf("UninstallHost got %q", b.uninstalled)
	}
	wantView(t, m, "after uninstall", "uninstalled claude-code", "detected")
}

func TestHostsUninstallOfAHostThatIsNotRegisteredDoesNothing(t *testing.T) {
	b := newReady()
	m := pressAll(hostsPane(b), keyTab, keyDown, keyDown, runeKey('x'))
	if strings.Contains(m.View(), "Uninstall") || len(b.uninstalled) != 0 {
		t.Fatal("asked to uninstall a host that is not registered")
	}
	wantView(t, m, "x on pi", "pi is not registered")
}

func TestHostsRegisterAddsADetectedHostThatIsNotRegistered(t *testing.T) {
	b := newReady()
	m := pressAll(hostsPane(b), keyTab, keyDown, keyDown, runeKey('a'))
	if !reflect.DeepEqual(b.registered, []string{"pi"}) {
		t.Fatalf("RegisterHost got %q", b.registered)
	}
	wantView(t, m, "after register", "registered pi")
	if suspended != 0 {
		t.Error("registering a host needs no prompt but suspended the TUI")
	}
}

func TestHostsRegisterRefusesAHostThatIsRegisteredOrNotInstalled(t *testing.T) {
	b := newReady()
	b.hosts[2].Detected = false
	m := pressAll(hostsPane(b), runeKey('a'))
	wantView(t, m, "a on a registered host", "claude-code is already registered")
	m = pressAll(m, keyTab, keyDown, keyDown, runeKey('a'))
	wantView(t, m, "a on a host not found", "pi was not found on this machine")
	if len(b.registered) != 0 {
		t.Fatalf("registered %q", b.registered)
	}
}

func TestHostsAHostThisBuildCannotManageIsOnlyListed(t *testing.T) {
	b := newReady()
	b.hosts = append(b.hosts, tui.HostInfo{Name: "old-host", Registered: true, NoAdapter: true})
	m := pressAll(hostsPane(b), keyTab, keyDown, keyDown, keyDown)
	wantView(t, m, "no adapter", "old-host", "no adapter")
	m = pressAll(m, runeKey('s'), runeKey('x'), runeKey('a'))
	if len(b.repaired)+len(b.uninstalled)+len(b.registered) != 0 || strings.Contains(m.View(), "Uninstall old-host") {
		t.Fatal("acted on a host this build cannot manage")
	}
}

func TestHostsOperationFailureShowsTheMessage(t *testing.T) {
	b := newReady()
	b.hostOpErr = errBoomText("host registration failed: claude-code (hooks)")
	m := pressAll(hostsPane(b), runeKey('s'))
	wantView(t, m, "failed repair", "host registration failed: claude-code (hooks)")
}

func TestHostsFooterNamesTheKeysAndTheyOnlyActInTheHostsSection(t *testing.T) {
	m := hostsPane(newReady())
	wantView(t, m, "hosts footer", "s repair", "S repair all", "x uninstall", "a register")
	b := newReady()
	pressAll(newModel(b, false), digit('4'), runeKey('s'), runeKey('S'), runeKey('x'), runeKey('y'), runeKey('a'))
	if len(b.repaired)+len(b.uninstalled)+len(b.registered) != 0 {
		t.Error("host keys acted outside the Hosts section")
	}
}

func TestHostsEmptyStateNamesTheNextAction(t *testing.T) {
	b := newReady()
	b.hosts = nil
	m := hostsPane(b)
	wantView(t, m, "no hosts", "No coding agents", "Claude Code", "Codex", "Pi")
}

func TestHostsRepairAllNeedsAtLeastOneRegisteredHost(t *testing.T) {
	b := newReady()
	for i := range b.hosts {
		b.hosts[i].Registered = false
	}
	pressAll(hostsPane(b), runeKey('S'))
	if len(b.repaired) != 0 {
		t.Fatalf("repair all ran with nothing registered: %q", b.repaired)
	}
}

func TestHostsNothingRegisteredYetPointsAtRegistering(t *testing.T) {
	b := newReady()
	for i := range b.hosts {
		b.hosts[i].Registered = false
	}
	m := hostsPane(b)
	wantView(t, m, "none registered", "No host is registered yet", "a")
}

// errBoomText is an error with fixed text for the messages the screens show.
type errBoomText string

func (e errBoomText) Error() string { return string(e) }

// ---- the states every new section shares ----

type sectionCase struct {
	name  string
	digit rune
	set   func(*fakeBackend, error)
	fail  string // what the error screen says
}

var sectionCases = []sectionCase{
	{"Hosts", '3', func(b *fakeBackend, e error) { b.hostsErr = e }, "Could not read the hosts."},
	{"Audit", '4', func(b *fakeBackend, e error) { b.auditErr = e }, "Could not read the audit log."},
	{"Sync", '5', func(b *fakeBackend, e error) { b.syncErr = e }, "Could not read the sync status."},
	{"Doctor", '6', func(b *fakeBackend, e error) { b.doctorErr = e }, "Could not read the doctor report."},
}

func TestSectionsShowAnErrorScreenWithANextActionNeverTheRawError(t *testing.T) {
	for _, c := range sectionCases {
		t.Run(c.name, func(t *testing.T) {
			b := newReady()
			c.set(b, errBoom)
			m := pressAll(newModel(b, false), digit(c.digit))
			wantView(t, m, c.name+" error", c.fail, "Nothing was changed", "enter", "retry", "qbit-vault doctor")
			if strings.Contains(m.View(), errBoom.Error()) {
				t.Error("the raw backend error reached the screen")
			}
			c.set(b, nil)
			m = pressAll(m, keyEnter)
			if strings.Contains(m.View(), c.fail) {
				t.Error("retry did not reload the section")
			}
		})
	}
}

func TestSectionsShowTheLockedStateAndUnlockThroughThePrompt(t *testing.T) {
	for _, c := range sectionCases {
		t.Run(c.name, func(t *testing.T) {
			b := newReady()
			b.status = locked
			after := ready
			b.afterUnlk = &after
			c.set(b, tui.ErrLocked)
			b.secretsErr, b.grantsErr = tui.ErrLocked, tui.ErrLocked
			m := pressAll(newModel(b, false), digit(c.digit))
			wantView(t, m, c.name+" locked", "vault is locked", "unlock")
			m = pressAll(m, runeKey('u'))
			if suspended != 1 || !reflect.DeepEqual(b.ran, []string{"unlock"}) {
				t.Fatalf("suspended=%d ran=%v: unlocking must use the suspended prompt", suspended, b.ran)
			}
			if strings.Contains(m.View(), "vault is locked") {
				t.Errorf("still locked after unlocking:\n%s", m.View())
			}
		})
	}
}
