package tui_test

import (
	"regexp"
	"strconv"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/QuBiit0/qbit-vault/internal/tui"
)

// suspended counts the actions the model handed to tea.Exec (the TUI
// suspended for a prompt) since the last newModel.
var suspended int

// fakeExec stands in for tea.Exec: it counts the suspension and runs the
// action when the command is executed, as the program would.
func fakeExec(a tui.Action, cb tea.ExecCallback) tea.Cmd {
	suspended++
	return func() tea.Msg { return cb(a.Run()) }
}

func newModel(b tui.Backend, color bool) tui.Model {
	suspended = 0
	return tui.New(b, tui.Options{Version: "9.9.9", Profile: tui.Profile{Color: color, TrueColor: color}, Exec: fakeExec})
}

// settle runs cmd and feeds every message it yields back to the model until
// no command is left, as the Bubble Tea runtime would.
func settle(m tui.Model, cmd tea.Cmd) tui.Model {
	for cmd != nil {
		msg := cmd()
		if msg == nil {
			break
		}
		if batch, ok := msg.(tea.BatchMsg); ok {
			for _, c := range batch {
				m = settle(m, c)
			}
			return m
		}
		if _, ok := msg.(tea.QuitMsg); ok {
			break
		}
		next, c := m.Update(msg)
		m, cmd = next.(tui.Model), c
	}
	return m
}

// pressAll presses the keys and settles every command they return.
func pressAll(m tui.Model, keys ...tea.KeyMsg) tui.Model {
	for _, k := range keys {
		next, c := m.Update(k)
		m = settle(next.(tui.Model), c)
	}
	return m
}

// typeText types s one rune at a time, as a terminal delivers it.
func typeText(m tui.Model, s string) tui.Model {
	for _, r := range s {
		m = pressAll(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
	return m
}

func runeKey(r rune) tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}} }

func press(m tui.Model, keys ...tea.KeyMsg) (tui.Model, tea.Cmd) {
	var cmd tea.Cmd
	for _, k := range keys {
		next, c := m.Update(k)
		m, cmd = next.(tui.Model), c
	}
	return m, cmd
}

var (
	keyEnter    = tea.KeyMsg{Type: tea.KeyEnter}
	keyEsc      = tea.KeyMsg{Type: tea.KeyEsc}
	keyDown     = tea.KeyMsg{Type: tea.KeyDown}
	keyUp       = tea.KeyMsg{Type: tea.KeyUp}
	keyTab      = tea.KeyMsg{Type: tea.KeyTab}
	keyShiftTab = tea.KeyMsg{Type: tea.KeyShiftTab}
	keyCtrlC    = tea.KeyMsg{Type: tea.KeyCtrlC}
	keyQ        = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}}
	keySpace    = tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}}
	keyLeft     = tea.KeyMsg{Type: tea.KeyLeft}
	keyRight    = tea.KeyMsg{Type: tea.KeyRight}
)

func digit(r rune) tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}} }

func isQuit(cmd tea.Cmd) bool {
	if cmd == nil {
		return false
	}
	_, ok := cmd().(tea.QuitMsg)
	return ok
}

func TestStartsOnSplashWhenThereIsNoVault(t *testing.T) {
	m := newModel(&fakeBackend{status: noVault}, false)
	if m.Screen() != tui.ScreenSplash {
		t.Fatalf("screen = %v, want splash", m.Screen())
	}
	v := m.View()
	for _, want := range []string{"qbit vault", "9.9.9", "by qbitdev", "Agents use your secrets.", "They never see them.", "enter", "start setup", "No vault yet"} {
		if !strings.Contains(v, want) {
			t.Errorf("splash view lacks %q:\n%s", want, v)
		}
	}
}

func TestSplashEnterOpensTheSetupWizardAndEscGoesBack(t *testing.T) {
	m, _ := press(newModel(&fakeBackend{status: noVault, plan: setupPlan()}, false), keyEnter)
	if m.Screen() != tui.ScreenSetup {
		t.Fatalf("screen = %v, want setup", m.Screen())
	}
	if !strings.Contains(m.View(), "Where will the vault live?") {
		t.Errorf("the wizard's first step is missing:\n%s", m.View())
	}
	m, _ = press(m, keyEsc)
	if m.Screen() != tui.ScreenSplash {
		t.Errorf("esc on setup landed on %v, want splash", m.Screen())
	}
}

func TestSplashQuits(t *testing.T) {
	_, cmd := press(newModel(&fakeBackend{status: noVault}, false), keyQ)
	if !isQuit(cmd) {
		t.Error("q on the splash did not quit")
	}
}

func TestStartsOnHomeWhenAVaultExists(t *testing.T) {
	m := newModel(&fakeBackend{status: ready}, false)
	if m.Screen() != tui.ScreenHome {
		t.Fatalf("screen = %v, want home", m.Screen())
	}
	if m.Section() != "Secrets" || m.Focus() != tui.PaneSections {
		t.Errorf("home opens on %s with focus %v, want Secrets with the sections pane", m.Section(), m.Focus())
	}
	v := m.View()
	for _, want := range []string{
		"1 Secrets", "2 Grants", "3 Hosts", "4 Audit", "5 Sync", "6 Doctor", "7 Update",
		"qbit-vault", "Detail", "No secrets yet",
		"~/.qbit-vault", "unlocked (keychain)", "3 hosts", "9.9.9",
	} {
		if !strings.Contains(v, want) {
			t.Errorf("home view lacks %q:\n%s", want, v)
		}
	}
	if strings.Count(v, "┌") != 3 {
		t.Errorf("home should draw three panes:\n%s", v)
	}
}

func TestHomeShowsLockedVaultWithoutAnUnknownCount(t *testing.T) {
	v := newModel(&fakeBackend{status: locked}, false).View()
	if !strings.Contains(v, "locked") || strings.Contains(v, "-1") {
		t.Errorf("locked home should say locked and hide the unknown count:\n%s", v)
	}
}

func TestSectionSwitching(t *testing.T) {
	tests := []struct {
		name    string
		keys    []tea.KeyMsg
		section string
		want    []string // text the section's panes show
	}{
		{"jump to Grants", []tea.KeyMsg{digit('2')}, "Grants", []string{"Active grants"}},
		{"jump to Hosts", []tea.KeyMsg{digit('3')}, "Hosts", []string{"HOST", "claude-code", "STEPS"}},
		{"jump to Update", []tea.KeyMsg{digit('7')}, "Update", []string{"Planned", "Update by hand"}},
		{"down twice", []tea.KeyMsg{keyDown, keyDown}, "Hosts", []string{"HOST"}},
		{"up stops at the first section", []tea.KeyMsg{keyUp}, "Secrets", []string{"GITHUB_TOKEN"}},
		{"down stops at the last section", []tea.KeyMsg{digit('7'), keyDown}, "Update", []string{"Planned"}},
		{"digit 8 is not a section", []tea.KeyMsg{digit('8')}, "Secrets", []string{"GITHUB_TOKEN"}},
		{"jump works from another pane", []tea.KeyMsg{keyTab, digit('5')}, "Sync", []string{"does not sync"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, cmd := press(newModel(newReady(), false), tt.keys...)
			if isQuit(cmd) || m.Screen() != tui.ScreenHome {
				t.Fatalf("left the home screen (%v)", m.Screen())
			}
			if m.Section() != tt.section {
				t.Fatalf("section = %s, want %s", m.Section(), tt.section)
			}
			v := m.View()
			for _, want := range tt.want {
				if !strings.Contains(v, want) {
					t.Errorf("view lacks %q:\n%s", want, v)
				}
			}
		})
	}
}

func TestSectionKeysDoNothingWhileAnotherPaneHasFocus(t *testing.T) {
	m, _ := press(newModel(&fakeBackend{status: ready}, false), keyTab, keyDown, keyDown)
	if m.Section() != "Secrets" {
		t.Errorf("down in the list pane changed the section to %s", m.Section())
	}
}

func TestFocusMovesBetweenPanes(t *testing.T) {
	m := newModel(&fakeBackend{status: ready}, false)
	steps := []struct {
		key  tea.KeyMsg
		want tui.Pane
	}{
		{keyTab, tui.PaneList},
		{keyTab, tui.PaneDetail},
		{keyTab, tui.PaneSections},
		{keyShiftTab, tui.PaneDetail},
		{keyShiftTab, tui.PaneList},
		{keyEsc, tui.PaneSections},
		{keyEsc, tui.PaneSections}, // nothing above the sections pane
	}
	for i, s := range steps {
		m, _ = press(m, s.key)
		if m.Focus() != s.want {
			t.Fatalf("step %d: focus = %v, want %v", i, m.Focus(), s.want)
		}
	}
	m, _ = press(m, keyTab, keyTab, keyEsc)
	if m.Focus() != tui.PaneList {
		t.Errorf("esc from the detail pane should go back one level, got %v", m.Focus())
	}
}

func TestFooterShowsTheKeysOfTheFocusedPane(t *testing.T) {
	m := newModel(&fakeBackend{status: ready}, false)
	footer := func(m tui.Model) string {
		lines := strings.Split(strings.TrimRight(m.View(), "\n"), "\n")
		return lines[len(lines)-1]
	}
	if f := footer(m); !strings.Contains(f, "↑↓ section") || !strings.Contains(f, "1-7 jump") || !strings.Contains(f, "tab next pane") || !strings.Contains(f, "q quit") {
		t.Errorf("sections footer = %q", f)
	}
	m, _ = press(m, keyTab)
	if f := footer(m); !strings.Contains(f, "shift+tab previous pane") || !strings.Contains(f, "esc back to sections") || strings.Contains(f, "↑↓ section") {
		t.Errorf("list footer = %q", f)
	}
	m, _ = press(m, keyTab)
	if f := footer(m); !strings.Contains(f, "esc back to list") {
		t.Errorf("detail footer = %q", f)
	}
}

func TestHomeQuitsOnQFromAnyPane(t *testing.T) {
	for _, keys := range [][]tea.KeyMsg{nil, {keyTab}, {keyTab, keyTab}} {
		if _, cmd := press(newModel(&fakeBackend{status: ready}, false), append(keys, keyQ)...); !isQuit(cmd) {
			t.Errorf("q after %d tabs did not quit", len(keys))
		}
	}
	t.Run("esc does not quit", func(t *testing.T) {
		m, cmd := press(newModel(&fakeBackend{status: ready}, false), keyEsc)
		if isQuit(cmd) || m.Screen() != tui.ScreenHome {
			t.Error("esc on the home screen must stay there")
		}
	})
}

func TestCtrlCQuitsFromEveryScreen(t *testing.T) {
	screens := map[string]func() tui.Model{
		"home":   func() tui.Model { return newModel(&fakeBackend{status: ready}, false) },
		"list":   func() tui.Model { m, _ := press(newModel(&fakeBackend{status: ready}, false), keyTab); return m },
		"splash": func() tui.Model { return newModel(&fakeBackend{status: noVault}, false) },
		"setup":  func() tui.Model { m, _ := press(newModel(&fakeBackend{status: noVault}, false), keyEnter); return m },
		"error":  func() tui.Model { return newModel(&fakeBackend{err: errBoom}, false) },
	}
	for name, mk := range screens {
		t.Run(name, func(t *testing.T) {
			if _, cmd := press(mk(), keyCtrlC); !isQuit(cmd) {
				t.Error("ctrl+c did not quit")
			}
		})
	}
}

func TestBackendErrorIsAScreenWithANextAction(t *testing.T) {
	b := &fakeBackend{err: errBoom}
	m := newModel(b, false)
	if m.Screen() != tui.ScreenError {
		t.Fatalf("screen = %v, want error", m.Screen())
	}
	v := m.View()
	if strings.Contains(v, "backend failure") {
		t.Errorf("raw backend error text leaked into the view:\n%s", v)
	}
	if !strings.Contains(v, "retry") || !strings.Contains(v, "quit") {
		t.Errorf("error screen offers no next action:\n%s", v)
	}
	b.err, b.status = nil, ready
	m, _ = press(m, keyEnter)
	if m.Screen() != tui.ScreenHome || b.calls != 2 {
		t.Errorf("retry: screen %v after %d status calls, want home after 2", m.Screen(), b.calls)
	}
}

var escRE = regexp.MustCompile(`\x1b`)

func TestNoColorViewsHaveNoEscapeSequences(t *testing.T) {
	views := map[string]tui.Model{
		"splash": newModel(&fakeBackend{status: noVault}, false),
		"home":   newModel(&fakeBackend{status: ready}, false),
		"locked": newModel(&fakeBackend{status: locked}, false),
		"error":  newModel(&fakeBackend{err: errBoom}, false),
	}
	views["setup"], _ = press(views["splash"], keyEnter)
	views["list focus"], _ = press(views["home"], keyTab)
	for name, m := range views {
		if escRE.MatchString(m.View()) {
			t.Errorf("%s view has ESC sequences without color:\n%q", name, m.View())
		}
	}
	if v := newModel(&fakeBackend{status: ready}, false).View(); !strings.Contains(v, "qbit vault") {
		t.Errorf("no-color header should degrade to the plain wordmark:\n%s", v)
	}
}

func TestColorViewUsesTheMarkTheGradientAndTheFocusBorder(t *testing.T) {
	m := newModel(&fakeBackend{status: ready}, true)
	v := m.View()
	if !strings.Contains(v, "▀") || !strings.Contains(v, "38;2;") {
		t.Errorf("color header lacks the truecolor mark:\n%q", v)
	}
	for _, c := range []struct {
		what    string
		sgr     string // 38 foreground, 48 background
		r, g, b int
	}{
		{"the start of the selected row gradient #1C6E9E", "48", 0x1C, 0x6E, 0x9E},
		{"the focused pane border #2E9BE0", "38", 0x2E, 0x9B, 0xE0},
		{"the unfocused pane border #16303D", "38", 0x16, 0x30, 0x3D},
	} {
		if !hasColor(v, c.sgr, c.r, c.g, c.b) {
			t.Errorf("view lacks %s:\n%q", c.what, v)
		}
	}
	if !strings.Contains(newModel(&fakeBackend{status: noVault}, true).View(), "▀") {
		t.Error("color splash lacks the mark")
	}
}

func TestViewKeepsPanesAlignedAtTheWindowWidth(t *testing.T) {
	m := newModel(&fakeBackend{status: ready}, false)
	next, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	for _, line := range strings.Split(next.View(), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "┌") || strings.HasPrefix(strings.TrimSpace(line), "│") || strings.HasPrefix(strings.TrimSpace(line), "└") {
			if n := len([]rune(line)); n != 120 {
				t.Fatalf("pane row is %d columns wide, want 120: %q", n, line)
			}
		}
	}
}

var truecolorRE = regexp.MustCompile(`(38|48);2;(\d+);(\d+);(\d+)`)

// hasColor reports whether v sets the truecolor (38 foreground, 48 background)
// within one unit per channel: the terminal library rounds hex colors.
func hasColor(v, sgr string, r, g, b int) bool {
	near := func(s string, want int) bool {
		n, _ := strconv.Atoi(s)
		return n >= want-1 && n <= want+1
	}
	for _, m := range truecolorRE.FindAllStringSubmatch(v, -1) {
		if m[1] == sgr && near(m[2], r) && near(m[3], g) && near(m[4], b) {
			return true
		}
	}
	return false
}
