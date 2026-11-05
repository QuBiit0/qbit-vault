package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

const (
	indent    = "  "
	sectionsW = 16 // outer width of the sections pane
	paneRows  = 12 // content rows of every pane
)

// View implements tea.Model.
func (m Model) View() string {
	var body string
	switch m.screen {
	case ScreenSplash:
		body = m.splashView()
	case ScreenSetup:
		body = m.stack(m.header(), "", m.theme.Heading("Setup wizard: coming in T2"),
			m.theme.Mist("The guided setup is built in task T2 of odd/tasks/tui.md."), "",
			m.footer(kv("esc", "back"), kv("ctrl+c", "quit")))
	case ScreenHome:
		body = m.homeView()
	case ScreenError:
		body = m.stack(m.header(), "",
			m.theme.Flare("Could not read the vault status."),
			m.theme.Mist("Nothing was changed. Retry, or quit and run 'qbit-vault doctor'."), "",
			m.footer(kv("enter", "retry"), kv("q", "quit")))
	}
	return body + "\n"
}

func (m Model) stack(lines ...string) string {
	var b strings.Builder
	for i, l := range lines {
		if i > 0 {
			b.WriteByte('\n')
		}
		for j, ln := range strings.Split(l, "\n") {
			if j > 0 {
				b.WriteByte('\n')
			}
			if ln != "" {
				b.WriteString(indent + ln)
			}
		}
	}
	return b.String()
}

// header is the 16-column mark next to the wordmark, version and status line;
// without color it is the same text under the plain wordmark.
func (m Model) header() string {
	lines := []string{m.theme.Wordmark(), m.theme.Mist(m.opts.Version + "  by qbitdev")}
	if s := m.statusLine(); s != "" {
		lines = append(lines, s)
	}
	text := strings.Join(lines, "\n")
	if !m.opts.Profile.Color {
		return text
	}
	return lipgloss.JoinHorizontal(lipgloss.Center, m.theme.Mark(16, false), "    ", text)
}

func (m Model) statusLine() string {
	if m.screen != ScreenHome {
		return ""
	}
	st := m.status
	state := m.theme.Green("unlocked")
	if st.State == StateLocked {
		state = m.theme.Warn("locked")
	}
	if st.KeyStore != "" {
		state += m.theme.Mist(" (" + st.KeyStore + ")")
	}
	return m.theme.Mist(st.Home+"  ·  ") + state + m.theme.Mist("  ·  "+plural(st.Hosts, "host"))
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func (m Model) splashView() string {
	lines := []string{
		m.theme.Wordmark(),
		m.theme.Mist(m.opts.Version + "  by qbitdev"),
		"",
		m.theme.Mist("Agents use your secrets."),
		m.theme.Mist("They never see them."),
		"",
		m.theme.Key("enter") + " start setup",
		m.theme.Key("q") + "     quit",
	}
	text := strings.Join(lines, "\n")
	top := text
	if m.opts.Profile.Color {
		top = lipgloss.JoinHorizontal(lipgloss.Center, m.theme.Mark(40, true), "        ", text)
	}
	return m.stack(top, "", m.theme.Mist("No vault yet. Setup takes about a minute and never asks for a secret."))
}

func kv(key, label string) [2]string { return [2]string{key, label} }

func (m Model) footer(pairs ...[2]string) string {
	parts := make([]string, len(pairs))
	for i, p := range pairs {
		parts[i] = m.theme.Key(p[0]) + " " + m.theme.Mist(p[1])
	}
	return strings.Join(parts, "  ")
}

// homeView is the three panes of 01-panes: sections, list, detail, with the
// keys of the focused pane in the footer.
func (m Model) homeView() string {
	rest := m.width - len(indent) - sectionsW - 2
	listW := rest * 5 / 9
	detailW := rest - listW
	sec := sections[m.section]
	panes := lipgloss.JoinHorizontal(lipgloss.Top,
		m.box("qbit-vault", sectionsW, m.sectionRows(sectionsW-4), m.focus == PaneSections), " ",
		m.box(sec.title, listW, m.placeholder(sec, sec.title+" list"), m.focus == PaneList), " ",
		m.box("Detail", detailW, m.placeholder(sec, sec.title+" detail"), m.focus == PaneDetail))
	return m.stack(m.header(), "", panes, "", m.footer(m.focusKeys()...))
}

func (m Model) sectionRows(w int) []string {
	rows := make([]string, len(sections))
	for i, s := range sections {
		badge := ""
		switch {
		case s.title == "Secrets" && m.status.State == StateUnlocked && m.status.Secrets >= 0:
			badge = fmt.Sprint(m.status.Secrets)
		case s.title == "Hosts" && m.status.Hosts > 0:
			badge = fmt.Sprint(m.status.Hosts)
		}
		label := fmt.Sprintf("%d %s", i+1, s.title)
		if i == m.section {
			rows[i] = m.theme.Selected(fmt.Sprintf("%-*s%s", w-len(badge), label, badge), w)
			continue
		}
		pad := strings.Repeat(" ", max(w-len(label)-len(badge), 1))
		rows[i] = m.theme.Key(label[:1]) + m.theme.Frost(label[1:]) + pad + m.theme.Mist(badge)
	}
	return rows
}

// placeholder fills a pane until the task that builds it lands.
func (m Model) placeholder(s section, what string) []string {
	return []string{"", what + ": coming in " + s.task, m.theme.Mist("built in task " + s.task)}
}

// box draws a titled pane of outer width w and paneRows lines. The focused
// pane has the blue border.
func (m Model) box(title string, w int, body []string, focused bool) string {
	border, name := m.theme.Line, m.theme.Mist
	if focused {
		border, name = m.theme.Blue, m.theme.Heading
	}
	inner := w - 2
	fill := max(inner-lipgloss.Width(title)-3, 0)
	lines := []string{border("┌─ ") + name(title) + border(" "+strings.Repeat("─", fill)+"┐")}
	for i := 0; i < paneRows; i++ {
		row := ""
		if i < len(body) {
			row = body[i]
		}
		lines = append(lines, border("│")+m.theme.Fit(" "+row, inner)+border("│"))
	}
	return strings.Join(append(lines, border("└"+strings.Repeat("─", inner)+"┘")), "\n")
}

// focusKeys are the footer keys of the focused pane.
func (m Model) focusKeys() [][2]string {
	switch m.focus {
	case PaneList:
		return [][2]string{kv("tab", "next pane"), kv("shift+tab", "previous pane"), kv("1-7", "jump"), kv("esc", "back to sections"), kv("q", "quit")}
	case PaneDetail:
		return [][2]string{kv("tab", "next pane"), kv("shift+tab", "previous pane"), kv("1-7", "jump"), kv("esc", "back to list"), kv("q", "quit")}
	}
	return [][2]string{kv("↑↓", "section"), kv("1-7", "jump"), kv("tab", "next pane"), kv("q", "quit")}
}
