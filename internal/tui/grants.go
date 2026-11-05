package tui

import (
	"errors"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// grantsPane is the Grants section. It reads grants and revokes them; nothing
// here, in the Backend or in a key creates or approves one (AGENTS.md
// invariant 6): grants are approved in the prompt an agent's request triggers.
type grantsPane struct {
	items  []Grant
	cur    int
	locked bool
	failed bool
}

func (p grantsPane) selected() (Grant, bool) {
	if p.cur < 0 || p.cur >= len(p.items) {
		return Grant{}, false
	}
	return p.items[p.cur], true
}

func (m *Model) loadGrants() {
	p := grantsPane{cur: m.gr.cur}
	if m.status.State == StateLocked {
		p.locked = true
		m.gr = p
		return
	}
	items, err := m.b.Grants()
	switch {
	case errors.Is(err, ErrLocked):
		p.locked = true
	case err != nil:
		p.failed = true
	default:
		p.items = items
	}
	p.cur = max(min(p.cur, len(p.items)-1), 0)
	m.gr = p
}

// grantsKey handles the keys of the Grants section: move, revoke, revoke all
// (after a confirmation) and unlock. Nothing else.
func (m Model) grantsKey(key tea.KeyMsg) (Model, tea.Cmd, bool) {
	p := m.gr
	switch {
	case p.locked:
		if isRune(key, 'u') {
			next, cmd := m.unlock()
			return next, cmd, true
		}
	case p.failed:
		if key.Type == tea.KeyEnter {
			m.loadGrants()
			return m, nil, true
		}
	default:
		switch {
		case isRune(key, 'r'):
			if g, ok := p.selected(); ok {
				n, err := m.b.RevokeGrant(GrantRef{Name: g.Name, Key: g.Key})
				m.refreshAfter(err, fmt.Sprintf("revoked %s (%s)", plural(n, "grant"), clean(g.Name)))
			}
			return m, nil, true
		case isRune(key, 'R'):
			if len(p.items) > 0 {
				m.ask = &confirmation{kind: askRevokeAll,
					question:    fmt.Sprintf("Revoke all %s?", plural(len(p.items), "grant")),
					consequence: "Agents must ask again for every secret. Takes effect at the next check.",
				}
			}
			return m, nil, true
		case m.focus != PaneSections && isUp(key):
			m.gr.cur = max(p.cur-1, 0)
			return m, nil, true
		case m.focus != PaneSections && isDown(key):
			m.gr.cur = max(min(p.cur+1, len(p.items)-1), 0)
			return m, nil, true
		}
	}
	return m, nil, false
}

// grantsBody is the list pane of the Grants section; w is the row width.
func (m Model) grantsBody(w int) []string {
	t, p := m.theme, m.gr
	switch {
	case p.locked:
		return m.lockedBody(w)
	case p.failed:
		return append([]string{""}, m.failedBody("grants", w)...)
	case len(p.items) == 0:
		rows := []string{"", t.Frost("No active grants."), ""}
		return append(rows, wrapAll(t.Mist, "An agent that needs a secret asks for it; you approve in a native dialog and the grant shows up here.", w)...)
	}
	const layerW, scopeW, leftW = 8, 7, 9
	nameW := max(w-2-layerW-scopeW-leftW-3, 6)
	row := func(a, b, c, d string) string {
		return pad(trunc(a, nameW), nameW) + " " + pad(trunc(b, layerW), layerW) + " " + pad(trunc(c, scopeW), scopeW) + " " + d
	}
	rows := []string{t.Mist("  " + row("NAME", "LAYER", "SCOPE", "LEFT"))}
	start := min(max(p.cur-visibleRows+1, 0), max(len(p.items)-visibleRows, 0))
	for i := start; i < min(start+visibleRows, len(p.items)); i++ {
		g := p.items[i]
		text := row(clean(g.Name), shortLayer(clean(g.Layer)), clean(g.Scope), clean(g.Left))
		if i == p.cur {
			rows = append(rows, t.Selected("▸ "+text, w))
			continue
		}
		rows = append(rows, "  "+t.Frost(text))
	}
	return append(rows, "", t.Mist(plural(len(p.items), "active grant")))
}

// shortLayer is the layer as the list shows it: "global" or the project label.
func shortLayer(layer string) string { return strings.TrimPrefix(layer, "project:") }

// grantDetail is the detail pane of the selected grant.
func (m Model) grantDetail(w int) (string, []string) {
	t, p := m.theme, m.gr
	g, ok := p.selected()
	if p.locked || p.failed || !ok {
		rows := []string{""}
		if !p.locked && !p.failed {
			rows = append(rows, wrapAll(t.Mist, "Revoking needs little: it only narrows access.", w)...)
		}
		return "Nothing selected", rows
	}
	rows := []string{t.Heading(trunc(clean(g.Name), w-len(g.Layer)-3)) + "  " + t.Mist(clean(g.Layer)),
		detailLine(t, "scope", clean(g.Scope), w)}
	if g.Session != "" {
		rows = append(rows, detailLine(t, "session", clean(g.Session), w))
	}
	rows = append(rows, detailLine(t, "left", clean(g.Left), w), "",
		t.Key("r")+t.Mist(" revoke this secret's grants"), t.Key("R")+t.Mist(" revoke all"), "")
	rows = append(rows, wrapAll(t.Mist, "Grants are approved in a native dialog when an agent asks.", w)...)
	rows = append(rows, wrapAll(t.Mist, "This view can only revoke; it never grants.", w)...)
	return clean(g.Name), rows
}
