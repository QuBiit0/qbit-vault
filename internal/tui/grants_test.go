package tui_test

import (
	"errors"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/qbitdevz/qbit-vault/internal/tui"
)

func grantsPane(b *fakeBackend) tui.Model { return pressAll(newModel(b, false), digit('2')) }

func TestGrantsListShowsMetadataAndTheSelectedGrantDetail(t *testing.T) {
	m := grantsPane(newReady())
	wantView(t, m, "grants", "Active grants", "NAME", "LAYER", "SCOPE", "LEFT",
		"GITHUB_TOKEN", "global", "session", "11h 42m", "DATABASE_URL", "shop-api", "no expiry", "2 active grants",
		"claude-code:7f3a21")
	m = pressAll(m, keyTab, keyDown)
	wantView(t, m, "second grant", "DATABASE_URL", "project:shop-api", "scope", "project")
	if strings.Contains(m.View(), "claude-code:7f3a21") {
		t.Error("the detail kept the previous grant's session")
	}
}

func TestGrantsFooterAndDetailSayTheViewOnlyRevokes(t *testing.T) {
	m := grantsPane(newReady())
	wantView(t, m, "grants", "only revoke", "never grants", "approved in a native")
	lines := strings.Split(strings.TrimRight(m.View(), "\n"), "\n")
	f := lines[len(lines)-1]
	for _, want := range []string{"r revoke", "R revoke all"} {
		if !strings.Contains(f, want) {
			t.Errorf("grants footer lacks %q: %q", want, f)
		}
	}
}

func TestRevokeRevokesTheSelectedGrantThroughTheBackend(t *testing.T) {
	b := newReady()
	m := grantsPane(b)
	m = pressAll(m, keyTab, keyDown, runeKey('r'))
	want := []tui.GrantRef{{Name: "DATABASE_URL", Key: "project:/work/shop-api"}}
	if !reflect.DeepEqual(b.revoked, want) {
		t.Fatalf("RevokeGrant got %+v, want %+v", b.revoked, want)
	}
	v := m.View()
	if !strings.Contains(v, "revoked 1 grant (DATABASE_URL)") || strings.Contains(v, "no expiry") || !strings.Contains(v, "1 active grant") {
		t.Errorf("grants not refreshed after revoke:\n%s", v)
	}
	if suspended != 0 {
		t.Error("revoking needs no prompt but suspended the TUI")
	}
}

func TestRevokeAllAsksFirstAndCancelsOnAnythingButY(t *testing.T) {
	b := newReady()
	m := grantsPane(b)
	m = pressAll(m, runeKey('R'))
	wantView(t, m, "confirmation", "Revoke all 2 grants?", "next check", "y", "confirm")
	if b.revokedAll != 0 {
		t.Fatal("R revoked without asking")
	}
	for _, k := range []tea.KeyMsg{keyEsc, runeKey('n'), keyEnter, keyDown} {
		m2 := pressAll(m, k)
		if b.revokedAll != 0 || strings.Contains(m2.View(), "Revoke all 2 grants?") {
			t.Fatalf("%v did not cancel cleanly (revokedAll=%d)", k, b.revokedAll)
		}
	}
	m = pressAll(m, runeKey('y'))
	if b.revokedAll != 1 {
		t.Fatalf("revokedAll = %d, want 1", b.revokedAll)
	}
	wantView(t, m, "after revoke all", "revoked 2 grants", "No active grants")
}

func TestRevokeFailureShowsTheMessage(t *testing.T) {
	b := newReady()
	b.revokeErr = errors.New("grants store unreadable")
	m := pressAll(grantsPane(b), runeKey('r'))
	wantView(t, m, "revoke failed", "grants store unreadable", "GITHUB_TOKEN")
}

func TestNoGrantsShowsHowGrantsHappen(t *testing.T) {
	b := newReady()
	b.grants = nil
	m := grantsPane(b)
	wantView(t, m, "empty grants", "No active grants", "native", "dialog")
	m = pressAll(m, runeKey('r'), runeKey('R'), runeKey('y'))
	if len(b.revoked) != 0 || b.revokedAll != 0 {
		t.Error("revoke keys acted on an empty list")
	}
}

func TestGrantKeysAreOnlyActiveInTheGrantsSection(t *testing.T) {
	b := newReady()
	m := pressAll(newModel(b, false), digit('3'))
	pressAll(m, runeKey('r'), runeKey('R'), runeKey('y'))
	if len(b.revoked) != 0 || b.revokedAll != 0 {
		t.Error("revoke keys acted outside the Grants section")
	}
}

// Invariant 6 (AGENTS.md): every grant is an explicit user action in the
// prompt an agent's request triggers. The Backend therefore has no method that
// creates, approves or extends one.
func TestBackendHasNoMethodThatCreatesOrApprovesAGrant(t *testing.T) {
	typ := reflect.TypeOf((*tui.Backend)(nil)).Elem()
	// The only methods that may mention grants: read them, revoke them.
	allowed := map[string]bool{"Grants": true, "RevokeGrant": true, "RevokeAllGrants": true}
	suspicious := regexp.MustCompile(`(?i)grant|approve|allow|permit|authori|consent|token`)
	for i := range typ.NumMethod() {
		name := typ.Method(i).Name
		if suspicious.MatchString(name) && !allowed[name] {
			t.Errorf("Backend.%s looks like a grant-creating method", name)
		}
	}
	for name := range allowed {
		if _, ok := typ.MethodByName(name); !ok {
			t.Errorf("Backend.%s is missing", name)
		}
	}
	// And AddSecret must not be able to ask for a grant either.
	for _, ty := range []reflect.Type{reflect.TypeOf(tui.NewSecret{}), reflect.TypeOf(tui.SetupRequest{})} {
		for i := range ty.NumField() {
			if n := ty.Field(i).Name; strings.Contains(strings.ToLower(n), "grant") || strings.Contains(strings.ToLower(n), "scope") {
				t.Errorf("%s.%s could request a grant", ty.Name(), n)
			}
		}
	}
}

// Press every key a person could type in the grants pane: none of them
// reaches a backend method that stores, sets up or runs a prompt.
func TestNoKeyInTheGrantsPaneCreatesAGrantOrStartsACapture(t *testing.T) {
	var keys []tea.KeyMsg
	for r := rune(32); r < 127; r++ {
		if unicode.IsPrint(r) && r != 'q' && !(r >= '1' && r <= '9') && r != 'r' && r != 'R' && r != 'y' {
			keys = append(keys, runeKey(r))
		}
	}
	keys = append(keys, keyEnter, keySpace, keyTab, keyShiftTab, keyEsc, keyLeft, keyRight, keyDown, keyUp,
		tea.KeyMsg{Type: tea.KeyCtrlA}, tea.KeyMsg{Type: tea.KeyCtrlG}, tea.KeyMsg{Type: tea.KeyCtrlR}, tea.KeyMsg{Type: tea.KeyCtrlS})
	for _, focus := range []int{0, 1, 2} {
		b := newReady()
		m := grantsPane(b)
		for range focus {
			m = pressAll(m, keyTab)
		}
		for _, k := range keys {
			m = pressAll(m, k)
			if strings.Contains(m.View(), "Add secret") {
				t.Fatalf("key %q opened the add form in the grants pane", k.String())
			}
			if m.Screen() != tui.ScreenHome {
				t.Fatalf("key %q left the home screen", k.String())
			}
			m = pressAll(m, digit('2'))
		}
		if len(b.added) != 0 || len(b.setups) != 0 || len(b.ran) != 0 || len(b.edited) != 0 || len(b.removed) != 0 || suspended != 0 {
			t.Errorf("focus %d: a grants-pane key reached a mutating backend method: added=%v setups=%v ran=%v edited=%v removed=%v suspended=%d",
				focus, b.added, b.setups, b.ran, b.edited, b.removed, suspended)
		}
		if len(b.grants) != 2 {
			t.Errorf("focus %d: the grant list changed without a revoke", focus)
		}
	}
}
