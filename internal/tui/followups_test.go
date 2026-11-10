package tui_test

import (
	"reflect"
	"strings"
	"testing"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/qbitdevz/qbit-vault/internal/tui"
)

// F4: the edit form shows the description on one line, so saving it back
// unchanged would rewrite a multi-line description. An untouched field keeps
// the stored one.
func TestEditKeepsTheStoredDescriptionWhenTheFieldIsUntouched(t *testing.T) {
	b := newReady()
	m := pressAll(newModel(b, false), keyTab, runeKey('d'), keyTab, keySpace, keyEnter) // only the flag changes
	want := []tui.SecretEdit{{SecretRef: tui.SecretRef{Name: "GITHUB_TOKEN"}, KeepDescription: true, Sensitive: true}}
	if !reflect.DeepEqual(b.edited, want) {
		t.Fatalf("EditSecret got %+v, want %+v", b.edited, want)
	}
	wantView(t, m, "after edit", "updated GITHUB_TOKEN")
}

func TestEditSendsTheNewDescriptionOnlyWhenTheUserChangedIt(t *testing.T) {
	b := newReady()
	m := pressAll(newModel(b, false), keyTab, runeKey('d'))
	m = typeText(m, "!")
	pressAll(m, keyEnter)
	want := []tui.SecretEdit{{SecretRef: tui.SecretRef{Name: "GITHUB_TOKEN"}, Description: "GitHub PAT for gh and git!"}}
	if !reflect.DeepEqual(b.edited, want) {
		t.Fatalf("EditSecret got %+v, want %+v", b.edited, want)
	}
}

func TestEditTypedThenErasedBackToTheOriginalKeepsIt(t *testing.T) {
	b := newReady()
	m := pressAll(newModel(b, false), keyTab, runeKey('d'))
	m = typeText(m, "!")
	m = pressAll(m, tea.KeyMsg{Type: tea.KeyBackspace}, keyEnter)
	if len(b.edited) != 1 || !b.edited[0].KeepDescription {
		t.Fatalf("EditSecret got %+v, want the description kept", b.edited)
	}
}

func TestEditCanClearTheDescription(t *testing.T) {
	b := newReady()
	m := pressAll(newModel(b, false), keyTab, runeKey('d'))
	for range len("GitHub PAT for gh and git") {
		m = pressAll(m, tea.KeyMsg{Type: tea.KeyBackspace})
	}
	pressAll(m, keyEnter)
	if len(b.edited) != 1 || b.edited[0].KeepDescription || b.edited[0].Description != "" {
		t.Fatalf("EditSecret got %+v, want an explicit empty description", b.edited)
	}
}

// F5: users may paste a secret where a description goes.
func TestAddFormWarnsNotToPasteASecretIntoTheDescription(t *testing.T) {
	m := pressAll(newModel(newReady(), false), runeKey('a'))
	wantView(t, m, "add form", "The value is not typed here; do not paste a secret into the description.")
}

// ---- T3 S7: the leak test across every section ----

const leakFixture = "TESTSECRET_value_0123456789"

// A frame never holds the fixture, whatever section, focus or key: the
// backend metadata carries no value and the model has nowhere to keep one.
func TestNoFixtureAppearsInAnyFrameOfAnySectionOrScreen(t *testing.T) {
	var keys []tea.KeyMsg
	for r := rune(32); r < 127; r++ {
		if unicode.IsPrint(r) && r != 'q' {
			keys = append(keys, runeKey(r))
		}
	}
	keys = append(keys, keyEnter, keySpace, keyTab, keyShiftTab, keyEsc, keyLeft, keyRight, keyDown, keyUp)
	states := map[string]func() *fakeBackend{
		"ready": newReady,
		"empty": func() *fakeBackend {
			b := newReady()
			b.secrets, b.grants, b.hosts, b.audit = tui.SecretList{}, nil, nil, tui.AuditLog{}
			return b
		},
		"locked": func() *fakeBackend {
			b := newReady()
			b.status = locked
			b.secretsErr, b.grantsErr = tui.ErrLocked, tui.ErrLocked
			return b
		},
		"errors": func() *fakeBackend {
			b := newReady()
			b.secretsErr, b.grantsErr, b.hostsErr, b.auditErr, b.syncErr, b.doctorErr = errBoom, errBoom, errBoom, errBoom, errBoom, errBoom
			return b
		},
	}
	for name, mk := range states {
		for sec := '1'; sec <= '7'; sec++ {
			for focus := range 3 {
				m := newModel(mk(), true)
				frames := []string{m.View()}
				m = pressAll(m, digit(sec))
				for range focus {
					m = pressAll(m, keyTab)
				}
				frames = append(frames, m.View())
				m = typeText(m, leakFixture) // stray typing, as if a value were pasted
				frames = append(frames, m.View())
				for _, k := range keys {
					m = pressAll(m, k)
					frames = append(frames, m.View())
				}
				for i, f := range frames {
					if strings.Contains(f, leakFixture) || strings.Contains(f, "TESTSECRET_") {
						t.Fatalf("%s, section %c, focus %d: frame %d holds a fixture", name, sec, focus, i)
					}
				}
			}
		}
	}
}

func TestNoFixtureAppearsOnTheSplashWizardOrErrorScreens(t *testing.T) {
	b := &fakeBackend{status: noVault, plan: setupPlan()}
	m := newModel(b, true)
	frames := []string{m.View()}
	m = pressAll(m, keyEnter)
	for range 4 {
		m = typeText(m, leakFixture)
		frames = append(frames, m.View())
		m = pressAll(m, keyEnter)
	}
	frames = append(frames, m.View(), newModel(&fakeBackend{err: errBoom}, true).View())
	for i, f := range frames {
		if strings.Contains(f, "TESTSECRET_") {
			t.Fatalf("frame %d holds a fixture", i)
		}
	}
}

// Every type of the Backend contract: no field can carry a value, a code or a
// key. The section types added for hosts, audit, sync and doctor included.
func TestSectionTypesCannotCarryASecretCodeOrKey(t *testing.T) {
	banned := []string{"value", "secret", "password", "passphrase", "token", "plaintext", "code", "recovery", "pairing", "key"}
	for _, typ := range []reflect.Type{
		reflect.TypeOf(tui.HostInfo{}), reflect.TypeOf(tui.HostStep{}), reflect.TypeOf(tui.AuditEntry{}),
		reflect.TypeOf(tui.AuditLog{}), reflect.TypeOf(tui.AuditVerdict{}), reflect.TypeOf(tui.SyncStatus{}),
		reflect.TypeOf(tui.DoctorCheck{}), reflect.TypeOf(tui.DoctorReport{}),
	} {
		for i := range typ.NumField() {
			name := strings.ToLower(typ.Field(i).Name)
			for _, b := range banned {
				if strings.Contains(name, b) {
					t.Errorf("%s.%s could carry a secret, a code or a key", typ.Name(), typ.Field(i).Name)
				}
			}
		}
	}
}
