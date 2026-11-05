package tui_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/QuBiit0/qbit-vault/internal/tui"
)

// wizard opens the setup wizard on a machine with claude-code and codex.
func wizard(t *testing.T) (tui.Model, *fakeBackend) {
	t.Helper()
	b := &fakeBackend{status: noVault, plan: setupPlan()}
	m := pressAll(newModel(b, false), keyEnter)
	if m.Screen() != tui.ScreenSetup {
		t.Fatalf("screen = %v, want setup", m.Screen())
	}
	return m, b
}

func wantView(t *testing.T, m tui.Model, what string, wants ...string) {
	t.Helper()
	v := m.View()
	for _, w := range wants {
		if !strings.Contains(v, w) {
			t.Errorf("%s lacks %q:\n%s", what, w, v)
		}
	}
}

func TestWizardStep1ShowsTheHomeThatWillBeCreated(t *testing.T) {
	m, b := wizard(t)
	wantView(t, m, "vault step",
		"Where will the vault live?", "~/.qbit-vault", "step 1 of 4", "nothing is written", "until Apply",
		"Vault", "Key storage", "Hosts", "Apply")
	if len(b.setups) != 0 {
		t.Error("the wizard wrote something before Apply")
	}
}

func TestWizardStep2OffersKeychainAndPassphraseWithTheirConsequences(t *testing.T) {
	m, _ := wizard(t)
	m = pressAll(m, keyEnter)
	wantView(t, m, "key storage step",
		"Where does the master key live?", "step 2 of 4",
		"OS keychain", "recommended", "Windows Credential Manager", "No passphrase to type",
		"Passphrase", "Argon2id", "no keychain",
		"never leaves this device", "starts empty")
	if !strings.Contains(m.View(), "▸ OS keychain") {
		t.Errorf("the keychain is not preselected:\n%s", m.View())
	}
	m = pressAll(m, keyDown)
	if !strings.Contains(m.View(), "▸ Passphrase") {
		t.Errorf("down did not select the passphrase:\n%s", m.View())
	}
	wantView(t, m, "passphrase selected", "asked in the terminal prompt", "never typed in this screen")
}

func TestWizardStep3ListsHostsWithDetectionAndToggles(t *testing.T) {
	m, _ := wizard(t)
	m = pressAll(m, keyEnter, keyEnter)
	wantView(t, m, "hosts step",
		"Register with your coding agents", "step 3 of 4",
		"[x] claude-code", "found", "[x] codex", "[ ] pi", "not found",
		"mcp", "hooks", "deny", "never asks for, reads or stores a secret")
	m = pressAll(m, keyDown, keyDown, keySpace)
	wantView(t, m, "pi toggled on", "[x] pi")
	m = pressAll(m, runeKey('n'))
	v := m.View()
	if strings.Contains(v, "[x]") {
		t.Errorf("n did not clear the selection:\n%s", v)
	}
	m = pressAll(m, runeKey('a'))
	if strings.Count(m.View(), "[x]") != 3 {
		t.Errorf("a did not select every host:\n%s", m.View())
	}
	m = pressAll(m, keyUp, keySpace)
	wantView(t, m, "codex toggled off", "[ ] codex")
}

func TestWizardReviewListsEveryChoiceAndEscKeepsThem(t *testing.T) {
	m, _ := wizard(t)
	m = pressAll(m, keyEnter, keyDown, keyEnter, keyDown, keyDown, keySpace, keyEnter) // passphrase, deselect nothing, add pi
	wantView(t, m, "review step",
		"step 4 of 4", "Review", "~/.qbit-vault", "passphrase", "claude-code", "codex", "pi",
		"Nothing is written until you press enter")
	m = pressAll(m, keyEsc)
	wantView(t, m, "hosts step after esc", "[x] pi", "[x] codex")
	m = pressAll(m, keyEsc)
	if !strings.Contains(m.View(), "▸ Passphrase") {
		t.Errorf("going back lost the key storage choice:\n%s", m.View())
	}
	m = pressAll(m, keyEsc)
	wantView(t, m, "vault step after esc", "Where will the vault live?")
	m = pressAll(m, keyEsc)
	if m.Screen() != tui.ScreenSplash {
		t.Errorf("esc on the first step landed on %v, want splash", m.Screen())
	}
}

func TestWizardApplyWithTheKeychainDoesNotSuspendTheTUI(t *testing.T) {
	m, b := wizard(t)
	b.afterSetup = &tui.Status{State: tui.StateUnlocked, Home: "~/.qbit-vault", KeyStore: "keychain", Hosts: 2}
	m = pressAll(m, keyEnter, keyEnter, keyEnter, keyEnter) // vault, key, hosts, review -> apply
	want := []tui.SetupRequest{{Passphrase: false, Hosts: []string{"claude-code", "codex"}}}
	if !reflect.DeepEqual(b.setups, want) {
		t.Fatalf("setup requests = %+v, want %+v", b.setups, want)
	}
	if !reflect.DeepEqual(b.ran, []string{"setup"}) {
		t.Fatalf("actions run = %v", b.ran)
	}
	if suspended != 0 {
		t.Error("the keychain setup suspended the TUI: it needs no prompt")
	}
	wantView(t, m, "done step", "Vault ready", "~/.qbit-vault", "keychain", "2 hosts", "add a secret")
}

func TestWizardApplyWithAPassphraseSuspendsTheTUIForThePrompt(t *testing.T) {
	m, b := wizard(t)
	b.afterSetup = &tui.Status{State: tui.StateUnlocked, Home: "~/.qbit-vault", KeyStore: "passphrase", Hosts: 2}
	m = pressAll(m, keyEnter, keyDown, keyEnter, keyEnter, keyEnter)
	want := []tui.SetupRequest{{Passphrase: true, Hosts: []string{"claude-code", "codex"}}}
	if !reflect.DeepEqual(b.setups, want) {
		t.Fatalf("setup requests = %+v, want %+v", b.setups, want)
	}
	if suspended != 1 {
		t.Errorf("the passphrase setup suspended the TUI %d times, want once", suspended)
	}
	wantView(t, m, "done step", "Vault ready", "passphrase")
}

func TestWizardNeverTakesTextInput(t *testing.T) {
	const typed = "TESTSECRET_typed_in_the_wizard"
	m, b := wizard(t)
	frames := []string{m.View()}
	for _, k := range []tea.KeyMsg{keyEnter, keyDown, keyEnter, keyEnter} {
		m = typeText(m, typed)
		frames = append(frames, m.View())
		m = pressAll(m, k)
		frames = append(frames, m.View())
	}
	for i, f := range frames {
		if strings.Contains(f, typed) {
			t.Fatalf("frame %d echoed typed text: a passphrase must never be typed in the TUI", i)
		}
	}
	if len(b.setups) > 1 {
		t.Errorf("stray typing triggered %d setups", len(b.setups))
	}
}

func TestWizardApplyFailureStaysOnReviewWithTheNextAction(t *testing.T) {
	m, b := wizard(t)
	b.setupErr = errors.New("host registration failed: claude-code (mcp)")
	m = pressAll(m, keyEnter, keyEnter, keyEnter, keyEnter)
	if m.Screen() != tui.ScreenSetup {
		t.Fatalf("screen = %v", m.Screen())
	}
	wantView(t, m, "failed review", "host registration failed: claude-code (mcp)", "Review", "enter", "retry", "esc", "back")
	if strings.Contains(m.View(), "Vault ready") {
		t.Error("a failed apply reported the vault ready")
	}
}

func TestWizardPartialFailureStillOffersTheVaultThatWasCreated(t *testing.T) {
	m, b := wizard(t)
	b.setupErr = errors.New("host registration failed: pi (mcp)")
	b.afterSetup = &tui.Status{State: tui.StateUnlocked, Home: "~/.qbit-vault", KeyStore: "keychain", Hosts: 1}
	m = pressAll(m, keyEnter, keyEnter, keyEnter, keyEnter)
	wantView(t, m, "partial done", "Vault ready", "host registration failed: pi (mcp)", "qbit-vault doctor")
}

func TestWizardSelectingNoHostsRegistersNone(t *testing.T) {
	m, b := wizard(t)
	m = pressAll(m, keyEnter, keyEnter, runeKey('n'), keyEnter, keyEnter)
	if len(b.setups) != 1 || len(b.setups[0].Hosts) != 0 {
		t.Fatalf("setup requests = %+v, want one with no hosts", b.setups)
	}
}

func TestWizardDoneOffersToAddASecret(t *testing.T) {
	newDone := func(t *testing.T) (tui.Model, *fakeBackend) {
		m, b := wizard(t)
		b.afterSetup = &tui.Status{State: tui.StateUnlocked, Home: "~/.qbit-vault", KeyStore: "keychain", Hosts: 2}
		return pressAll(m, keyEnter, keyEnter, keyEnter, keyEnter), b
	}
	t.Run("a opens the add form on the home screen", func(t *testing.T) {
		m, b := newDone(t)
		m = pressAll(m, runeKey('a'))
		if m.Screen() != tui.ScreenHome || m.Section() != "Secrets" {
			t.Fatalf("screen=%v section=%s", m.Screen(), m.Section())
		}
		wantView(t, m, "add form", "Add secret", "Name")
		if len(b.added) != 0 {
			t.Error("opening the form stored something")
		}
	})
	t.Run("enter goes home with the empty vault invitation", func(t *testing.T) {
		m, _ := newDone(t)
		m = pressAll(m, keyEnter)
		if m.Screen() != tui.ScreenHome {
			t.Fatalf("screen = %v", m.Screen())
		}
		wantView(t, m, "home", "No secrets yet", "a")
	})
}

func TestWizardPlanErrorIsAnErrorScreen(t *testing.T) {
	b := &fakeBackend{status: noVault, planErr: errBoom}
	m := pressAll(newModel(b, false), keyEnter)
	if m.Screen() != tui.ScreenError {
		t.Fatalf("screen = %v, want error", m.Screen())
	}
	if strings.Contains(m.View(), "backend failure") {
		t.Error("raw error text leaked")
	}
}
