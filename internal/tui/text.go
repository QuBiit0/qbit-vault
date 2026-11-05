package tui

import (
	"strings"
	"unicode"

	"github.com/charmbracelet/lipgloss"
)

// clean makes text from the vault safe to draw: a description synced from
// another device must not be able to move the cursor or recolor the screen.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			return ' '
		}
		return r
	}, s)
}

// trunc cuts s to w columns, marking the cut with an ellipsis.
func trunc(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= w {
		return s
	}
	r := []rune(s)
	for len(r) > 0 && lipgloss.Width(string(r))+1 > w {
		r = r[:len(r)-1]
	}
	return string(r) + "…"
}

// pad right-pads s with spaces to w columns (s is not truncated).
func pad(s string, w int) string {
	if n := w - lipgloss.Width(s); n > 0 {
		return s + strings.Repeat(" ", n)
	}
	return s
}

// wrap breaks s into lines of at most w columns at word boundaries; a word
// longer than w is cut.
func wrap(s string, w int) []string {
	if w < 4 {
		return []string{trunc(s, w)}
	}
	var lines []string
	cur := ""
	for _, word := range strings.Fields(s) {
		for lipgloss.Width(word) > w {
			r := []rune(word)
			n := len(r)
			for n > 1 && lipgloss.Width(string(r[:n])) > w {
				n--
			}
			if cur != "" {
				lines, cur = append(lines, cur), ""
			}
			lines, word = append(lines, string(r[:n])), string(r[n:])
		}
		switch {
		case cur == "":
			cur = word
		case lipgloss.Width(cur)+1+lipgloss.Width(word) <= w:
			cur += " " + word
		default:
			lines, cur = append(lines, cur), word
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

// plainTime shows an RFC 3339 stamp as "2006-01-02 15:04".
func plainTime(s string) string {
	s = clean(s)
	s = strings.Replace(s, "T", " ", 1)
	if len(s) > 16 {
		s = s[:16]
	}
	return s
}
