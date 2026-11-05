package tui

import (
	"errors"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// loadState is what a section's last read came to: data, a locked vault
// (offer unlock) or a failure (offer a retry). The raw error is never kept.
type loadState int

const (
	loadOK loadState = iota
	loadLocked
	loadFailed
)

func classify(err error) loadState {
	switch {
	case err == nil:
		return loadOK
	case errors.Is(err, ErrLocked):
		return loadLocked
	}
	return loadFailed
}

// stateKeys handles the keys the locked and failed states share: u unlocks,
// enter retries. ok reports whether the key was one of them.
func (m Model) stateKeys(st loadState, key tea.KeyMsg, retry func(*Model)) (Model, tea.Cmd, bool) {
	switch {
	case st == loadLocked && isRune(key, 'u'):
		next, cmd := m.unlock()
		return next, cmd, true
	case st == loadFailed && key.Type == tea.KeyEnter:
		retry(&m)
		return m, nil, true
	}
	return m, nil, false
}

// stateBody is the list pane of a locked or failed section; nil when the
// section has data.
func (m Model) stateBody(st loadState, what string, w int) []string {
	switch st {
	case loadLocked:
		return m.lockedBody(w)
	case loadFailed:
		return append([]string{""}, m.failedBody(what, w)...)
	}
	return nil
}

// ---- Hosts ----

// hostsPane is the Hosts section: the coding agents and the status of each
// registration step, from the data `doctor` uses.
type hostsPane struct {
	items []HostInfo
	cur   int
	st    loadState
}

func (p hostsPane) selected() (HostInfo, bool) {
	if p.cur < 0 || p.cur >= len(p.items) {
		return HostInfo{}, false
	}
	return p.items[p.cur], true
}

func (m *Model) loadHosts() {
	p := hostsPane{cur: m.hp.cur}
	items, err := m.b.Hosts()
	p.st = classify(err)
	if p.st == loadOK {
		p.items = items
	}
	p.cur = max(min(p.cur, len(p.items)-1), 0)
	m.hp = p
}

// hostState words a host's state and says how loud to be about it:
// 0 healthy, 1 needs attention, 2 neutral.
func hostState(h HostInfo) (string, int) {
	switch {
	case h.NoAdapter:
		return "no adapter", 2
	case !h.Registered && h.Detected:
		return "detected", 2
	case !h.Registered:
		return "not found", 2
	}
	for _, s := range h.Steps {
		if s.Status != StepOK {
			return "drift", 1
		}
	}
	return "registered", 0
}

func stepGlyph(h HostInfo, s HostStep) string {
	switch {
	case !h.Registered:
		return "·"
	case s.Status == StepOK:
		return "✓"
	case s.Status == StepUnreadable:
		return "?"
	}
	return "!"
}

// hostSteps is one glyph per step (✓ ok, ! drift or missing, ? unreadable, ·
// not registered); the detail pane names them.
func hostSteps(h HostInfo) string {
	parts := make([]string, len(h.Steps))
	for i, s := range h.Steps {
		parts[i] = stepGlyph(h, s)
	}
	return strings.Join(parts, " ")
}

func (m Model) hostsKey(key tea.KeyMsg) (Model, tea.Cmd, bool) {
	p := m.hp
	if next, cmd, ok := m.stateKeys(p.st, key, (*Model).loadHosts); ok {
		return next, cmd, true
	}
	if p.st != loadOK {
		return m, nil, false
	}
	h, ok := p.selected()
	switch {
	case m.focus != PaneSections && isUp(key):
		m.hp.cur = max(p.cur-1, 0)
	case m.focus != PaneSections && isDown(key):
		m.hp.cur = max(min(p.cur+1, len(p.items)-1), 0)
	case isRune(key, 'S'):
		if anyRegistered(p.items) {
			s, err := m.b.RepairHosts("")
			m.refreshAfter(err, s)
		}
	case isRune(key, 's'), isRune(key, 'x'), isRune(key, 'a'):
		if !ok {
			break
		}
		m = m.hostAction(key.Runes[0], h)
	default:
		return m, nil, false
	}
	return m, nil, true
}

func anyRegistered(items []HostInfo) bool {
	for _, h := range items {
		if h.Registered && !h.NoAdapter {
			return true
		}
	}
	return false
}

// hostAction runs s (repair), x (uninstall, after a confirmation) or a
// (register) on h, refusing what makes no sense with a message that names the
// next step.
func (m Model) hostAction(k rune, h HostInfo) Model {
	name := clean(h.Name)
	say := func(text string) Model { m.notice = notice{text: text, bad: true}; return m }
	switch {
	case h.NoAdapter:
		return say(name + ": this build has no adapter for it, so it is left as it is.")
	case k == 'a':
		switch {
		case h.Registered:
			return say(name + " is already registered.")
		case !h.Detected:
			return say(name + " was not found on this machine.")
		}
		s, err := m.b.RegisterHost(h.Name)
		m.refreshAfter(err, s)
	case !h.Registered:
		return say(name + " is not registered. Press a to register it.")
	case k == 's':
		s, err := m.b.RepairHosts(h.Name)
		m.refreshAfter(err, s)
	case k == 'x':
		m.ask = &confirmation{kind: askUninstall, ref: SecretRef{Name: h.Name},
			question:    fmt.Sprintf("Uninstall %s?", name),
			consequence: "Reverts the qbit-vault entries in its config files; a snapshot of each file is kept. The agent can no longer use your secrets through qbit-vault. The vault and its secrets stay.",
		}
	}
	return m
}

// hostsBody is the list pane of the Hosts section; w is the row width.
func (m Model) hostsBody(w int) []string {
	t, p := m.theme, m.hp
	if rows := m.stateBody(p.st, "hosts", w); rows != nil {
		return rows
	}
	if len(p.items) == 0 {
		rows := []string{"", t.Frost("No coding agents found.")}
		return append(rows, wrapAll(t.Mist, "Install Claude Code, Codex or Pi, then open this screen again to register it.", w)...)
	}
	const hostW, stateW = 12, 10
	stepsW := max(w-2-hostW-stateW-2, 6)
	rows := []string{t.Mist("  " + pad("HOST", hostW) + " " + pad("STATE", stateW) + " STEPS")}
	start := min(max(p.cur-visibleRows+1, 0), max(len(p.items)-visibleRows, 0))
	registered, drift := 0, 0
	for _, h := range p.items {
		_, level := hostState(h)
		if h.Registered {
			registered++
		}
		if level == 1 {
			drift++
		}
	}
	for i := start; i < min(start+visibleRows, len(p.items)); i++ {
		h := p.items[i]
		state, level := hostState(h)
		name, steps := pad(trunc(clean(h.Name), hostW), hostW), trunc(hostSteps(h), stepsW)
		if i == p.cur {
			rows = append(rows, t.Selected("▸ "+name+" "+pad(state, stateW)+" "+steps, w))
			continue
		}
		style := []func(string) string{t.Green, t.Warn, t.Mist}[level]
		rows = append(rows, "  "+t.Frost(name)+" "+style(pad(state, stateW))+" "+t.Mist(steps))
	}
	summary := fmt.Sprintf("%d registered", registered)
	if drift > 0 {
		summary += fmt.Sprintf(" · %d with drift", drift)
	}
	rows = append(rows, "", t.Mist(summary), t.Mist("steps: ✓ ok  ! drift  · not registered"))
	if registered == 0 {
		rows = append(rows, wrapAll(t.Frost, "No host is registered yet. Select a detected host and press a to register it.", w)...)
	}
	return rows
}

// hostDetail is the detail pane of the selected host: its steps, the config
// files they edit and, when something drifted, what that means.
func (m Model) hostDetail(w int) (string, []string) {
	t, p := m.theme, m.hp
	h, ok := p.selected()
	if p.st != loadOK || !ok {
		return "Detail", append([]string{""}, wrapAll(t.Mist, "Nothing selected.", w)...)
	}
	state, level := hostState(h)
	style := []func(string) string{t.Green, t.Warn, t.Mist}[level]
	rows := []string{t.Heading(trunc(clean(h.Name), w-len(state)-3)) + "  " + style(state)}
	var files []string
	seen := map[string]bool{}
	drifted, missing := false, false
	for _, s := range h.Steps {
		label := s.Status
		if !h.Registered {
			label = "not registered"
		}
		rows = append(rows, t.Mist(pad(clean(s.Name), 11))+hostStepStyle(t, s.Status, h.Registered)(label))
		drifted = drifted || s.Status == StepDrift
		missing = missing || (h.Registered && s.Status == StepMissing)
		if s.File != "" && !seen[s.File] {
			seen[s.File] = true
			files = append(files, s.File)
		}
	}
	for _, f := range files {
		rows = append(rows, t.Mist(truncLeft(clean(f), w)))
	}
	switch {
	case drifted:
		rows = append(rows, "", t.Warn("Changed since registration:"))
		rows = append(rows, wrapAll(t.Mist, "The config no longer holds our entries. Press s to re-apply them.", w)...)
	case missing:
		rows = append(rows, "", t.Warn("A step is not recorded:"))
		rows = append(rows, wrapAll(t.Mist, "Press s to register it again.", w)...)
	}
	rows = append(rows, "")
	switch {
	case h.NoAdapter:
		rows = append(rows, wrapAll(t.Mist, "This build has no adapter for this host; it is only listed.", w)...)
	case h.Registered:
		rows = append(rows, t.Key("s")+t.Mist(" repair   ")+t.Key("x")+t.Mist(" uninstall"))
	case h.Detected:
		rows = append(rows, t.Key("a")+t.Mist(" register"))
		rows = append(rows, wrapAll(t.Mist, "Each config file is snapshotted first. Registering never reads or stores a secret.", w)...)
	default:
		rows = append(rows, wrapAll(t.Mist, "Not found on this machine.", w)...)
	}
	return clean(h.Name), rows
}

func hostStepStyle(t Theme, status string, registered bool) func(string) string {
	switch {
	case !registered:
		return t.Mist
	case status == StepOK:
		return t.Green
	}
	return t.Warn
}
