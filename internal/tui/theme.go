package tui

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// Palette tokens from design/system.md.
const (
	colBlueGlow  = "#7FD0EC"
	colGreen     = "#2FBF78"
	colGreenGlow = "#91ECC5"
	colFrost     = "#C7D9DE"
	colMist      = "#8FA7B2"
	colBlue      = "#2E9BE0"
	colLine      = "#16303D"
	colFlare     = "#F07A6A"
	colWarn      = "#E8B04A"
	colSelA      = "#1C6E9E" // on-light gradient, the terminal approximation of the selection
	colSelB      = "#1F8A57"
)

var selA, selB = fcolor{0x1C, 0x6E, 0x9E}, fcolor{0x1F, 0x8A, 0x57}

// Profile says what the terminal can show.
type Profile struct {
	Color     bool // false: no ESC sequences at all (--no-color, NO_COLOR)
	TrueColor bool // 24-bit color; false falls back to 256 colors
}

// Theme renders styled text for one Profile.
type Theme struct {
	p Profile
	r *lipgloss.Renderer
}

// NewTheme builds a theme whose output depends only on p, never on the
// environment, so the same input renders the same bytes everywhere.
func NewTheme(p Profile) Theme {
	r := lipgloss.NewRenderer(io.Discard)
	switch {
	case !p.Color:
		r.SetColorProfile(termenv.Ascii)
	case p.TrueColor:
		r.SetColorProfile(termenv.TrueColor)
	default:
		r.SetColorProfile(termenv.ANSI256)
	}
	return Theme{p: p, r: r}
}

func (t Theme) fg(color string) func(...string) string {
	return t.r.NewStyle().Foreground(lipgloss.Color(color)).Render
}

// Text styles. Without color they return the text unchanged.
func (t Theme) Frost(s string) string { return t.fg(colFrost)(s) }
func (t Theme) Mist(s string) string  { return t.fg(colMist)(s) }
func (t Theme) Glow(s string) string  { return t.fg(colBlueGlow)(s) }
func (t Theme) Blue(s string) string  { return t.fg(colBlue)(s) }
func (t Theme) Line(s string) string  { return t.fg(colLine)(s) }
func (t Theme) Green(s string) string { return t.fg(colGreen)(s) }
func (t Theme) Flare(s string) string { return t.fg(colFlare)(s) }
func (t Theme) Warn(s string) string  { return t.fg(colWarn)(s) }

// Heading is the current place in a crumb trail or a screen title.
func (t Theme) Heading(s string) string {
	return t.r.NewStyle().Foreground(lipgloss.Color(colFrost)).Bold(true).Render(s)
}

// Key renders a key name in the footer.
func (t Theme) Key(s string) string {
	return t.r.NewStyle().Foreground(lipgloss.Color(colBlueGlow)).Bold(true).Render(s)
}

// Wordmark is `qbit vault` with `vault` in green-glow.
func (t Theme) Wordmark() string {
	return t.Frost("qbit ") + t.fg(colGreenGlow)("vault")
}

// Selected renders a selected row padded to width: white text on the
// blue-to-green gradient, or on #1C6E9E without truecolor.
func (t Theme) Selected(s string, width int) string {
	if pad := width - lipgloss.Width(s); pad > 0 {
		s += strings.Repeat(" ", pad)
	}
	if !t.p.Color {
		return s
	}
	base := t.r.NewStyle().Foreground(lipgloss.Color("#FFFFFF")).Bold(true)
	if !t.p.TrueColor {
		return base.Background(lipgloss.Color(colSelA)).Render(s)
	}
	runes := []rune(s)
	var b strings.Builder
	for i, ch := range runes {
		frac := 0.0
		if len(runes) > 1 {
			frac = float64(i) / float64(len(runes)-1)
		}
		c := lerp(selA, selB, frac)
		hex := lipgloss.Color("#" + hex2(c))
		b.WriteString(base.Background(hex).Render(string(ch)))
	}
	return b.String()
}

func hex2(c fcolor) string {
	const digits = "0123456789ABCDEF"
	out := make([]byte, 0, 6)
	for _, v := range c {
		n := int(v + 0.5)
		out = append(out, digits[n>>4], digits[n&15])
	}
	return string(out)
}

// Mark renders the mark as half blocks (foreground = top pixel, background =
// bottom pixel), one line per terminal row. Without color it degrades to the
// plain wordmark `qbit vault`. Sizes used: 16 (no orbits) and 40 (orbits).
func (t Theme) Mark(size int, orbits bool) string {
	if !t.p.Color {
		return "qbit vault"
	}
	pix := RasterMark(size, orbits)
	lines := make([]string, 0, len(pix)/2)
	for j := 0; j+1 < len(pix); j += 2 {
		var b strings.Builder
		for i := range pix[j] {
			top, bot := pix[j][i], pix[j+1][i]
			if t.p.TrueColor {
				// Straight from the pixels, as term-mark.py prints them.
				fmt.Fprintf(&b, "\x1b[38;2;%d;%d;%dm\x1b[48;2;%d;%d;%dm\u2580", top[0], top[1], top[2], bot[0], bot[1], bot[2])
				continue
			}
			b.WriteString(t.r.NewStyle().
				Foreground(lipgloss.Color(rgbHex(top))).
				Background(lipgloss.Color(rgbHex(bot))).
				Render("\u2580"))
		}
		if t.p.TrueColor {
			b.WriteString("\x1b[0m")
		}
		lines = append(lines, b.String())
	}
	return strings.Join(lines, "\n")
}

func rgbHex(c rgb) string {
	return "#" + hex2(fcolor{float64(c[0]), float64(c[1]), float64(c[2])})
}

// Fit pads s with spaces to width w or truncates it there; s must be one line.
func (t Theme) Fit(s string, w int) string {
	return t.r.NewStyle().Inline(true).Width(w).MaxWidth(w).Render(s)
}
