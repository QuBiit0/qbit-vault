package tui_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/muesli/termenv"

	"github.com/qbitdevz/qbit-vault/internal/tui"
)

// F1 (odd/tasks/tui.md L6): without truecolor the selected row falls back to
// #1C6E9E in the 256-color palette, and nothing asks for 24-bit color.
func TestSelectedRowWithoutTruecolorUsesTheSolidFallbackColor(t *testing.T) {
	th := tui.NewTheme(tui.Profile{Color: true, TrueColor: false})
	got := th.Selected("Secrets", 12)
	idx := termenv.ANSI256.Convert(termenv.RGBColor("#1C6E9E"))
	n, ok := idx.(termenv.ANSI256Color)
	if !ok {
		t.Fatalf("#1C6E9E converts to %T, want an ANSI256 color", idx)
	}
	if want := "48;5;" + strconv.Itoa(int(n)); !strings.Contains(got, want) {
		t.Errorf("fallback selected row lacks the background %q (#1C6E9E): %q", want, got)
	}
	if strings.Contains(got, ";2;") {
		t.Errorf("fallback selected row asks for 24-bit color: %q", got)
	}
	if strings.Count(got, "48;") != 1 {
		t.Errorf("fallback selected row should be one solid color, not a gradient: %q", got)
	}
	if !strings.Contains(got, "Secrets") || !strings.Contains(got, "38;5;") {
		t.Errorf("fallback selected row lost its text or its white foreground: %q", got)
	}
}

func TestSelectedRowWithTruecolorRunsTheBlueToGreenGradient(t *testing.T) {
	got := tui.NewTheme(tui.Profile{Color: true, TrueColor: true}).Selected("Secrets", 12)
	if !hasColor(got, "48", 0x1C, 0x6E, 0x9E) || !hasColor(got, "48", 0x1F, 0x8A, 0x57) {
		t.Errorf("gradient lacks its endpoints #1C6E9E and #1F8A57: %q", got)
	}
}

func TestSelectedRowWithoutColorIsPlainText(t *testing.T) {
	got := tui.NewTheme(tui.Profile{}).Selected("Secrets", 12)
	if got != "Secrets     " {
		t.Errorf("no-color selected row = %q", got)
	}
}

func TestMarkWithoutTruecolorUses256ColorsOnly(t *testing.T) {
	got := tui.NewTheme(tui.Profile{Color: true, TrueColor: false}).Mark(16, false)
	if !strings.Contains(got, "▀") || !strings.Contains(got, "38;5;") || !strings.Contains(got, "48;5;") {
		t.Errorf("fallback mark lacks 256-color half blocks:\n%q", got)
	}
	if strings.Contains(got, ";2;") {
		t.Errorf("fallback mark uses 24-bit color:\n%q", got)
	}
}

func TestHomeWithoutTruecolorSelectsWithTheFallbackBackground(t *testing.T) {
	suspended = 0
	m := tui.New(newReady(), tui.Options{Version: "9.9.9", Profile: tui.Profile{Color: true, TrueColor: false}, Exec: fakeExec})
	v := m.View()
	n := termenv.ANSI256.Convert(termenv.RGBColor("#1C6E9E")).(termenv.ANSI256Color)
	if !strings.Contains(v, "48;5;"+strconv.Itoa(int(n))) {
		t.Errorf("the selected section row lacks the fallback background:\n%q", v)
	}
	if strings.Contains(v, ";2;") {
		t.Errorf("a non-truecolor home asks for 24-bit color:\n%q", v)
	}
}
