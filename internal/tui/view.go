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
		body = m.setupView()
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

// joinPanes puts boxes side by side.
func joinPanes(sep string, boxes ...string) string {
	parts := make([]string, 0, 2*len(boxes))
	for i, b := range boxes {
		if i > 0 {
			parts = append(parts, sep)
		}
		parts = append(parts, b)
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, parts...)
}

// paneWidths are the outer widths of the list and detail panes.
func (m Model) paneWidths() (list, detail int) {
	rest := m.width - len(indent) - sectionsW - 2
	list = rest * 5 / 9
	return list, rest - list
}

// homeView is the three panes of 01-panes: sections, list, detail, with the
// keys of the focused pane in the footer. An open form replaces the panes.
func (m Model) homeView() string {
	if m.form != nil {
		return m.formView()
	}
	listW, detailW := m.paneWidths()
	sec := sections[m.section]
	listTitle, detailTitle := sec.title, "Detail"
	var list, detail []string
	switch sec.title {
	case "Secrets":
		detailTitle, detail = m.secretDetail(detailW - 3)
		list = m.secretsBody(listW - 3)
	case "Grants":
		listTitle, list = "Active grants", m.grantsBody(listW-3)
		detailTitle, detail = m.grantDetail(detailW - 3)
	case "Hosts":
		list = m.hostsBody(listW - 3)
		detailTitle, detail = m.hostDetail(detailW - 3)
	case "Audit":
		listTitle, list = "Audit log · newest first", m.auditBody(listW-3)
		detailTitle, detail = m.auditDetail(detailW - 3)
	case "Sync":
		listTitle, list = "Sync status", m.syncBody(listW-3)
		detailTitle, detail = m.syncDetail(detailW - 3)
	case "Doctor":
		listTitle, list = "Doctor", m.doctorBody(listW-3)
		detailTitle, detail = m.doctorDetail(detailW - 3)
	case "Update":
		listTitle, list = "Update", m.updateBody(listW-3)
		detailTitle, detail = m.updateDetail(detailW - 3)
	}
	panes := joinPanes(" ",
		m.box("qbit-vault", sectionsW, m.sectionRows(sectionsW-4), m.focus == PaneSections),
		m.box(listTitle, listW, list, m.focus == PaneList),
		m.box(detailTitle, detailW, detail, m.focus == PaneDetail))
	lines := []string{m.header(), "", panes, ""}
	if sec.title == "Update" {
		lines = append(lines, m.theme.Mist("With Go:"), "  "+m.theme.Frost(updateCommand), "")
	}
	keys := m.focusKeys()
	switch {
	case m.ask != nil:
		lines = append(lines, m.theme.Warn(m.ask.question))
		lines = append(lines, wrapAll(m.theme.Mist, m.ask.consequence, m.width-2*len(indent))...)
		lines = append(lines, "")
		keys = [][2]string{kv("y", "confirm"), kv("any other key", "cancel")}
	case m.notice.text != "":
		if m.notice.bad {
			lines = append(lines, m.theme.Flare("✗ "+m.notice.text), "")
		} else {
			lines = append(lines, m.theme.Green("✓ ")+m.theme.Frost(m.notice.text), "")
		}
	}
	return m.stack(append(lines, m.footer(keys...))...)
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

// focusKeys are the footer keys of the focused pane, with the keys of the
// selected section ahead of the navigation ones.
func (m Model) focusKeys() [][2]string {
	var nav [][2]string
	switch m.focus {
	case PaneList:
		nav = [][2]string{kv("tab", "next pane"), kv("shift+tab", "previous pane"), kv("1-7", "jump"), kv("esc", "back to sections"), kv("q", "quit")}
	case PaneDetail:
		nav = [][2]string{kv("tab", "next pane"), kv("shift+tab", "previous pane"), kv("1-7", "jump"), kv("esc", "back to list"), kv("q", "quit")}
	default:
		nav = [][2]string{kv("1-7", "jump"), kv("tab", "next pane"), kv("q", "quit")}
	}
	move := kv("↑↓", "move")
	if m.focus == PaneSections {
		move = kv("↑↓", "section")
	}
	keys := [][2]string{move}
	keys = append(keys, m.sectionKeys()...)
	return append(keys, nav...)
}

// sectionKeys are the actions of the selected section; destructive ones name
// what they do in the confirmation they open.
func (m Model) sectionKeys() [][2]string {
	switch sections[m.section].title {
	case "Secrets":
		switch {
		case m.sec.locked:
			return [][2]string{kv("u", "unlock")}
		case m.sec.failed:
			return [][2]string{kv("enter", "retry")}
		case len(m.sec.list.Items) == 0:
			return [][2]string{kv("a", "add")}
		}
		return [][2]string{kv("a", "add"), kv("d", "edit info"), kv("x", "remove")}
	case "Grants":
		switch {
		case m.gr.locked:
			return [][2]string{kv("u", "unlock")}
		case m.gr.failed:
			return [][2]string{kv("enter", "retry")}
		case len(m.gr.items) == 0:
			return nil
		}
		return [][2]string{kv("r", "revoke"), kv("R", "revoke all")}
	case "Hosts":
		return m.stateKeysFor(m.hp.st, func() [][2]string {
			if len(m.hp.items) == 0 {
				return nil
			}
			return [][2]string{kv("s", "repair"), kv("S", "repair all"), kv("x", "uninstall"), kv("a", "register")}
		})
	case "Audit":
		return m.stateKeysFor(m.au.st, func() [][2]string { return [][2]string{kv("v", "verify chain")} })
	case "Sync":
		return m.stateKeysFor(m.sy.st, func() [][2]string { return nil })
	case "Doctor":
		return m.stateKeysFor(m.dr.st, func() [][2]string { return [][2]string{kv("r", "rerun")} })
	}
	return nil
}

// stateKeysFor is the footer of a section that can be locked or failed: those
// states offer unlock or retry, otherwise the section's own keys.
func (m Model) stateKeysFor(st loadState, ok func() [][2]string) [][2]string {
	switch st {
	case loadLocked:
		return [][2]string{kv("u", "unlock")}
	case loadFailed:
		return [][2]string{kv("enter", "retry")}
	}
	return ok()
}
