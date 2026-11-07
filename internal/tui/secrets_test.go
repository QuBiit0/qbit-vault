package tui_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/QuBiit0/qbit-vault/internal/tui"
)

func TestSecretsListShowsNamesLayersAndMarksButNeverValues(t *testing.T) {
	m := newModel(newReady(), false)
	wantView(t, m, "secrets list",
		"NAME", "LAYER", "GITHUB_TOKEN", "NPM_TOKEN", "DATABASE_URL", "STRIPE_SECRET_KEY",
		"global", "shop-api", "◆", "4 secrets", "sensitive")
	if strings.Count(m.View(), "◆") < 2 { // the row mark and its legend
		t.Errorf("the sensitive secret is not marked:\n%s", m.View())
	}
}

func TestSecretsDetailFollowsTheSelectionAndStatesTheValueIsNeverShown(t *testing.T) {
	m := newModel(newReady(), false)
	wantView(t, m, "first secret detail",
		"GitHub PAT for gh and git", "never shown", "sensitive", "no", "gh, git", "api.github.com", "2026-11-03")
	m = pressAll(m, keyTab, keyDown, keyDown, keyDown)
	wantView(t, m, "fourth secret detail", "STRIPE_SECRET_KEY", "payments", "yes")
	if strings.Contains(m.View(), "gh, git") {
		t.Error("the detail kept the previous secret's binaries")
	}
	m = pressAll(m, keyDown, keyDown)
	wantView(t, m, "selection stops at the last row", "STRIPE_SECRET_KEY")
	m = pressAll(m, keyUp, keyUp, keyUp, keyUp, keyUp)
	wantView(t, m, "selection stops at the first row", "GitHub PAT for gh and git")
}

func TestSecretsListScrollsToKeepTheSelectionVisible(t *testing.T) {
	b := newReady()
	b.secrets.Items = nil
	for _, n := range []string{"A1", "B2", "C3", "D4", "E5", "F6", "G7", "H8", "I9", "J10", "K11", "L12", "M13", "N14"} {
		b.secrets.Items = append(b.secrets.Items, tui.Secret{Name: n, Layer: "global"})
	}
	m := newModel(b, false)
	m = pressAll(m, keyTab)
	for range 13 {
		m = pressAll(m, keyDown)
	}
	v := m.View()
	if !strings.Contains(v, "N14") {
		t.Errorf("the selected last row is not visible:\n%s", v)
	}
	if strings.Contains(v, "A1 ") {
		t.Errorf("the list did not scroll:\n%s", v)
	}
}

func TestEmptyVaultInvitesTheFirstSecret(t *testing.T) {
	b := &fakeBackend{status: ready, secrets: tui.SecretList{}}
	m := newModel(b, false)
	wantView(t, m, "empty vault", "No secrets yet", "Press a to add", "hidden prompt")
	m = pressAll(m, runeKey('a'))
	wantView(t, m, "add form from the empty state", "Add secret")
}

func TestLockedVaultExplainsHowToUnlockAndUnlocksThroughThePrompt(t *testing.T) {
	b := &fakeBackend{status: locked, secretsErr: tui.ErrLocked, grantsErr: tui.ErrLocked, secrets: sampleSecrets()}
	after := ready
	b.afterUnlk = &after
	m := newModel(b, false)
	wantView(t, m, "locked secrets", "vault is locked", "passphrase", "secure prompt", "u", "unlock")
	if strings.Contains(m.View(), "GITHUB_TOKEN") {
		t.Error("a locked vault listed names")
	}
	m = pressAll(m, runeKey('u'))
	if suspended != 1 || !reflect.DeepEqual(b.ran, []string{"unlock"}) {
		t.Fatalf("suspended=%d ran=%v: unlocking must go through the suspended prompt path", suspended, b.ran)
	}
	wantView(t, m, "unlocked secrets", "GITHUB_TOKEN", "unlocked")
}

func TestLockedGrantsPaneAlsoOffersUnlock(t *testing.T) {
	b := &fakeBackend{status: locked, grantsErr: tui.ErrLocked, secretsErr: tui.ErrLocked}
	m := pressAll(newModel(b, false), digit('2'))
	wantView(t, m, "locked grants", "vault is locked", "unlock")
}

func TestUnlockFailureIsShownWithoutLeavingTheLockedState(t *testing.T) {
	b := &fakeBackend{status: locked, secretsErr: tui.ErrLocked, unlockErr: errors.New("wrong passphrase")}
	m := pressAll(newModel(b, false), runeKey('u'))
	wantView(t, m, "unlock failed", "wrong passphrase", "vault is locked")
}

func fillAddForm(m tui.Model, name, desc string) tui.Model {
	m = pressAll(m, runeKey('a'))
	m = typeText(m, name)
	m = pressAll(m, keyTab, keyTab) // layer, description
	return typeText(m, desc)
}

func TestAddFormCollectsMetadataThenSuspendsForTheValue(t *testing.T) {
	b := newReady()
	m := newModel(b, false)
	m = pressAll(m, runeKey('a'))
	wantView(t, m, "add form", "Add secret", "Name", "Layer", "global", "Description", "Sensitive",
		"Saving does not grant anything", "enter", "save", "esc", "cancel")
	if strings.Contains(m.View(), "Value") {
		t.Errorf("the form has a value field: values are never typed in the TUI:\n%s", m.View())
	}
	m = typeText(m, "SENTRY_AUTH_TOKEN")
	m = pressAll(m, keyTab, keyRight) // layer -> project shop-api
	wantView(t, m, "layer toggled", "shop-api")
	m = pressAll(m, keyTab)
	m = typeText(m, "release uploads")
	m = pressAll(m, keyTab, keySpace) // sensitive on
	wantView(t, m, "sensitive toggled", "[x]")
	m = pressAll(m, keyEnter)

	want := []tui.NewSecret{{SecretRef: tui.SecretRef{Name: "SENTRY_AUTH_TOKEN", Project: true}, Description: "release uploads", Sensitive: true}}
	if !reflect.DeepEqual(b.added, want) {
		t.Fatalf("AddSecret got %+v, want %+v", b.added, want)
	}
	if suspended != 1 || !reflect.DeepEqual(b.ran, []string{"add"}) {
		t.Errorf("suspended=%d ran=%v: the value must be captured under tea.Exec", suspended, b.ran)
	}
	wantView(t, m, "after add", "SENTRY_AUTH_TOKEN", "stored")
	if strings.Contains(m.View(), "Add secret") {
		t.Error("the form is still open after saving")
	}
}

func TestAddFormRefusesAnEmptyNameAndKeepsTheOtherFields(t *testing.T) {
	b := newReady()
	m := fillAddForm(newModel(b, false), "", "keep this text")
	m = pressAll(m, keyEnter)
	wantView(t, m, "empty name", "Name cannot be empty", "keep this text", "Add secret")
	if len(b.added) != 0 || suspended != 0 {
		t.Error("an empty name reached the backend")
	}
}

func TestAddFormEscCancelsWithoutWriting(t *testing.T) {
	b := newReady()
	m := fillAddForm(newModel(b, false), "SOMETHING", "x")
	m = pressAll(m, keyEsc)
	if strings.Contains(m.View(), "Add secret") || len(b.added) != 0 || suspended != 0 {
		t.Errorf("esc did not cancel cleanly (added=%v suspended=%d)", b.added, suspended)
	}
}

func TestAddFormProjectLayerNeedsAProject(t *testing.T) {
	b := newReady()
	b.secrets.Project = ""
	m := pressAll(newModel(b, false), runeKey('a'))
	m = typeText(m, "X")
	m = pressAll(m, keyTab, keyRight)
	wantView(t, m, "no project", "Not inside a project")
	m = pressAll(m, keyEnter)
	if len(b.added) != 1 || b.added[0].Project {
		t.Errorf("added = %+v, want the global layer", b.added)
	}
}

func TestAddFailureIsShownAndNothingIsListed(t *testing.T) {
	b := newReady()
	b.addErr = errors.New("cancelled")
	m := fillAddForm(newModel(b, false), "NEWONE", "d")
	m = pressAll(m, keyEnter)
	wantView(t, m, "add failed", "cancelled")
	if strings.Contains(m.View(), "NEWONE") {
		t.Error("a failed add appears in the list")
	}
}

func TestAddWarnsWhenTheNameAlreadyExists(t *testing.T) {
	m := pressAll(newModel(newReady(), false), runeKey('a'))
	m = typeText(m, "NPM_TOKEN")
	wantView(t, m, "existing name", "already exists", "replaces its value")
}

func TestEditFormIsPrefilledAndCallsTheEditPath(t *testing.T) {
	b := newReady()
	m := pressAll(newModel(b, false), keyTab, runeKey('d'))
	wantView(t, m, "edit form", "Edit GITHUB_TOKEN", "GitHub PAT for gh and git", "enter", "save")
	if strings.Contains(m.View(), "Value") {
		t.Error("the edit form has a value field")
	}
	m = typeText(m, " updated") // the form opens on the description: the name is fixed
	m = pressAll(m, keyTab, keySpace, keyEnter)
	want := []tui.SecretEdit{{SecretRef: tui.SecretRef{Name: "GITHUB_TOKEN"}, Description: "GitHub PAT for gh and git updated", Sensitive: true}}
	if !reflect.DeepEqual(b.edited, want) {
		t.Fatalf("EditSecret got %+v, want %+v", b.edited, want)
	}
	if suspended != 0 {
		t.Error("editing metadata needs no prompt but suspended the TUI")
	}
	wantView(t, m, "after edit", "updated GITHUB_TOKEN")
}

func TestEditFailureShowsTheMessage(t *testing.T) {
	b := newReady()
	b.editErr = errors.New("secret not found")
	m := pressAll(newModel(b, false), runeKey('d'), keyEnter)
	wantView(t, m, "edit failed", "secret not found")
}

func TestRemoveAsksForConfirmationStatingTheConsequence(t *testing.T) {
	b := newReady()
	m := pressAll(newModel(b, false), runeKey('x'))
	wantView(t, m, "confirmation", "Remove GITHUB_TOKEN (global)?", "drops its grants", "backup", "y", "confirm")
	if len(b.removed) != 0 {
		t.Fatal("x removed without asking")
	}
	for _, k := range []tea.KeyMsg{keyEsc, runeKey('n'), keyEnter, keyDown} {
		m2 := pressAll(m, k)
		if len(b.removed) != 0 {
			t.Fatalf("%v confirmed the removal", k)
		}
		if strings.Contains(m2.View(), "Remove GITHUB_TOKEN") {
			t.Errorf("%v left the confirmation open", k)
		}
	}
}

func TestRemoveConfirmedCallsTheRemovePathAndRefreshes(t *testing.T) {
	b := newReady()
	m := pressAll(newModel(b, false), keyTab, keyDown, runeKey('x'), runeKey('y'))
	want := []tui.SecretRef{{Name: "NPM_TOKEN"}}
	if !reflect.DeepEqual(b.removed, want) {
		t.Fatalf("RemoveSecret got %+v, want %+v", b.removed, want)
	}
	v := m.View()
	if strings.Contains(v, "NPM_TOKEN  ") || !strings.Contains(v, "removed NPM_TOKEN") || !strings.Contains(v, "3 secrets") {
		t.Errorf("list not refreshed after removal:\n%s", v)
	}
}

func TestRemovingTheLastSecretShowsTheEmptyState(t *testing.T) {
	b := &fakeBackend{status: ready, secrets: tui.SecretList{Items: []tui.Secret{{Name: "ONLY", Layer: "global"}}}}
	m := pressAll(newModel(b, false), runeKey('x'), runeKey('y'))
	wantView(t, m, "empty after removal", "No secrets yet")
}

func TestRemoveFailureShowsTheMessageAndKeepsTheRow(t *testing.T) {
	b := newReady()
	b.removeErr = errors.New("secret not found")
	m := pressAll(newModel(b, false), runeKey('x'), runeKey('y'))
	wantView(t, m, "remove failed", "secret not found", "GITHUB_TOKEN")
}

func TestSecretKeysAreOnlyActiveInTheSecretsSection(t *testing.T) {
	b := newReady()
	m := pressAll(newModel(b, false), digit('3'))
	m = pressAll(m, runeKey('a'), runeKey('d'), runeKey('x'), runeKey('y'))
	if len(b.added) != 0 || len(b.edited) != 0 || len(b.removed) != 0 || suspended != 0 {
		t.Errorf("secret keys acted outside the Secrets section: %+v %+v %+v", b.added, b.edited, b.removed)
	}
}

func TestFooterNamesTheSecretKeysAndTheirConsequences(t *testing.T) {
	m := newModel(newReady(), false)
	lines := strings.Split(strings.TrimRight(m.View(), "\n"), "\n")
	f := lines[len(lines)-1]
	for _, want := range []string{"a add", "d edit info", "x remove"} {
		if !strings.Contains(f, want) {
			t.Errorf("secrets footer lacks %q: %q", want, f)
		}
	}
}

func TestSecretsErrorIsAScreenWithANextAction(t *testing.T) {
	b := newReady()
	b.secretsErr = errBoom
	m := newModel(b, false)
	v := m.View()
	if strings.Contains(v, "backend failure") || !strings.Contains(v, "Could not read the secrets") || !strings.Contains(v, "retry") {
		t.Errorf("secrets error state:\n%s", v)
	}
}

// The fixture never reaches a frame: the value is typed in a prompt the
// backend owns, so the model has nowhere to hold it.
func TestNoFixtureAppearsInAnyFrameOfTheAddAndListFlows(t *testing.T) {
	const fixture = "TESTSECRET_value_0123456789"
	b := newReady()
	m := newModel(b, true)
	frames := []string{m.View()}
	snap := func() { frames = append(frames, m.View()) }
	m = pressAll(m, runeKey('a'))
	snap()
	m = typeText(m, "SENTRY")
	snap()
	m = pressAll(m, keyEnter)
	snap()
	// Stray typing after the capture, as if the value had been typed here.
	m = typeText(m, fixture)
	snap()
	m = pressAll(m, keyTab, keyDown, keyDown)
	snap()
	m = pressAll(m, runeKey('d'))
	snap()
	for i, f := range frames {
		if strings.Contains(f, fixture) {
			t.Fatalf("frame %d holds the fixture", i)
		}
	}
}

// No exported type of the Backend contract has a field that could carry a
// secret value, a passphrase or a token.
func TestBackendTypesCannotCarryASecretValue(t *testing.T) {
	banned := []string{"value", "secret", "password", "passphrase", "token", "plaintext"}
	types := []reflect.Type{
		reflect.TypeOf(tui.Secret{}), reflect.TypeOf(tui.SecretList{}), reflect.TypeOf(tui.SecretRef{}),
		reflect.TypeOf(tui.NewSecret{}), reflect.TypeOf(tui.SecretEdit{}), reflect.TypeOf(tui.Grant{}),
		reflect.TypeOf(tui.GrantRef{}), reflect.TypeOf(tui.SetupRequest{}), reflect.TypeOf(tui.SetupPlan{}),
		reflect.TypeOf(tui.HostChoice{}), reflect.TypeOf(tui.Status{}),
	}
	for _, typ := range types {
		for i := range typ.NumField() {
			f := typ.Field(i)
			switch f.Type.Kind() {
			case reflect.String, reflect.Slice:
				// A string-ish field named like a secret could hold one.
			default:
				continue
			}
			if f.Type.Kind() == reflect.Slice && f.Type.Elem().Kind() != reflect.String && f.Type.Elem().Kind() != reflect.Uint8 {
				continue
			}
			name := strings.ToLower(f.Name)
			for _, b := range banned {
				if strings.Contains(name, b) {
					t.Errorf("%s.%s could carry a secret", typ.Name(), f.Name)
				}
			}
		}
	}
}
