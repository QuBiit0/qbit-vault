package tui

import (
	"errors"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

// secretsPane is the Secrets section: names and metadata, never a value.
type secretsPane struct {
	list   SecretList
	cur    int
	locked bool // the vault cannot be opened without a prompt
	failed bool // the backend could not read the secrets
}

const visibleRows = 8 // list rows between the header and the summary

func (p secretsPane) selected() (Secret, bool) {
	if p.cur < 0 || p.cur >= len(p.list.Items) {
		return Secret{}, false
	}
	return p.list.Items[p.cur], true
}

func (m *Model) loadSecrets() {
	p := secretsPane{cur: m.sec.cur}
	if m.status.State == StateLocked {
		p.locked = true
		m.sec = p
		return
	}
	list, err := m.b.Secrets()
	switch {
	case errors.Is(err, ErrLocked):
		p.locked = true
	case err != nil:
		p.failed = true
	default:
		p.list = list
	}
	p.cur = max(min(p.cur, len(p.list.Items)-1), 0)
	m.sec = p
}

// secretsKey handles the keys of the Secrets section; ok reports whether the
// key was one of them.
func (m Model) secretsKey(key tea.KeyMsg) (Model, tea.Cmd, bool) {
	p := m.sec
	switch {
	case p.locked:
		if isRune(key, 'u') {
			next, cmd := m.unlock()
			return next, cmd, true
		}
	case p.failed:
		if key.Type == tea.KeyEnter {
			m.loadSecrets()
			return m, nil, true
		}
	default:
		switch {
		case isRune(key, 'a'):
			m.openAddForm()
			return m, nil, true
		case isRune(key, 'd'):
			if s, ok := p.selected(); ok {
				m.form = newForm(true, s, p.list.Project)
			}
			return m, nil, true
		case isRune(key, 'x'):
			if s, ok := p.selected(); ok {
				m.ask = &confirmation{kind: askRemove, ref: SecretRef{Name: s.Name, Project: s.Project},
					question:    fmt.Sprintf("Remove %s (%s)?", clean(s.Name), clean(s.Layer)),
					consequence: "Deletes the value and drops its grants. A backup of the vault is kept first (qbit-vault restore).",
				}
			}
			return m, nil, true
		case m.focus != PaneSections && isUp(key):
			m.sec.cur = max(p.cur-1, 0)
			return m, nil, true
		case m.focus != PaneSections && isDown(key):
			m.sec.cur = max(min(p.cur+1, len(p.list.Items)-1), 0)
			return m, nil, true
		}
	}
	return m, nil, false
}

// unlock asks the passphrase through the prompt backend, with the TUI suspended.
func (m Model) unlock() (Model, tea.Cmd) {
	act := m.b.Unlock()
	return m, m.exec(act, func(err error) tea.Msg { return actionDoneMsg{kind: actUnlock, err: err} })
}

func (m *Model) openAddForm() {
	m.form = newForm(false, Secret{}, m.sec.list.Project)
}

// secretsBody is the list pane of the Secrets section; w is the row width.
func (m Model) secretsBody(w int) []string {
	t, p := m.theme, m.sec
	switch {
	case p.locked:
		return m.lockedBody(w)
	case p.failed:
		return append([]string{""}, m.failedBody("secrets", w)...)
	case len(p.list.Items) == 0:
		lines := []string{"", t.Frost("No secrets yet."), "", t.Frost("Press ") + t.Key("a") + t.Frost(" to add your first one.")}
		lines = append(lines, "")
		for _, l := range wrap("The value is typed in a masked prompt, never in this screen.", w) {
			lines = append(lines, t.Mist(l))
		}
		return lines
	}
	nameW := max(w-14, 6)
	rows := []string{t.Mist("  " + pad("NAME", nameW) + " " + pad("LAYER", 9))}
	start := min(max(p.cur-visibleRows+1, 0), max(len(p.list.Items)-visibleRows, 0))
	end := min(start+visibleRows, len(p.list.Items))
	sensitive := false
	for i := start; i < end; i++ {
		s := p.list.Items[i]
		mark := " "
		if s.Sensitive {
			mark, sensitive = "◆", true
		}
		layer := trunc(clean(s.Layer), 9)
		if i == p.cur {
			rows = append(rows, t.Selected("▸ "+pad(trunc(clean(s.Name), nameW), nameW)+" "+pad(layer, 9)+" "+mark, w))
			continue
		}
		rows = append(rows, "  "+t.Frost(pad(trunc(clean(s.Name), nameW), nameW))+" "+t.Mist(pad(layer, 9))+" "+t.Warn(mark))
	}
	rows = append(rows, "", t.Mist(m.secretSummary()))
	for _, s := range p.list.Items {
		if s.Sensitive && !sensitive {
			sensitive = true
		}
	}
	if sensitive {
		rows = append(rows, t.Warn("◆")+t.Mist(" sensitive: granted once at a time"))
	}
	return rows
}

// secretSummary is "4 secrets · 2 global · 2 shop-api".
func (m Model) secretSummary() string {
	items := m.sec.list.Items
	counts := map[string]int{}
	var order []string
	for _, s := range items {
		if counts[s.Layer] == 0 {
			order = append(order, s.Layer)
		}
		counts[s.Layer]++
	}
	parts := []string{plural(len(items), "secret")}
	for _, l := range order {
		parts = append(parts, fmt.Sprintf("%d %s", counts[l], clean(l)))
	}
	return strings.Join(parts, " · ")
}

// secretDetail is the detail pane of the selected secret; w is the row width.
func (m Model) secretDetail(w int) (string, []string) {
	t, p := m.theme, m.sec
	s, ok := p.selected()
	if p.locked || p.failed || !ok {
		return "Detail", append([]string{""}, wrapAll(t.Mist, "Nothing selected.", w)...)
	}
	rows := []string{t.Heading(trunc(clean(s.Name), w-len(s.Layer)-3)) + "  " + t.Mist(clean(s.Layer))}
	for _, l := range wrap(clean(s.Description), w) {
		rows = append(rows, t.Frost(l))
	}
	sens := "no"
	if s.Sensitive {
		sens = "yes, granted once at a time"
	}
	rows = append(rows, "",
		detailLine(t, "value", "••••••••  never shown", w),
		detailLine(t, "sensitive", sens, w),
		detailLine(t, "binaries", orDash(clean(strings.Join(s.Binaries, ", "))), w),
		detailLine(t, "hosts", orDash(clean(strings.Join(s.Hosts, ", "))), w))
	if s.Overrides {
		rows = append(rows, detailLine(t, "overrides", "a global secret", w))
	}
	if s.Unlinked {
		rows = append(rows, detailLine(t, "linked", "not on this device", w))
	}
	if s.UpdatedAt != "" {
		rows = append(rows, detailLine(t, "updated", plainTime(s.UpdatedAt), w))
	}
	rows = append(rows, "", t.Key("d")+t.Mist(" edit info    ")+t.Key("x")+t.Mist(" remove"))
	return clean(s.Name), rows
}

func detailLine(t Theme, label, value string, w int) string {
	return t.Mist(pad(label, 10)) + t.Frost(trunc(value, max(w-10, 4)))
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func wrapAll(style func(string) string, s string, w int) []string {
	var out []string
	for _, l := range wrap(s, w) {
		out = append(out, style(l))
	}
	return out
}

func (m Model) lockedBody(w int) []string {
	t := m.theme
	rows := []string{"", t.Warn("The vault is locked.")}
	rows = append(rows, wrapAll(t.Mist, "The master key is not cached (passphrase mode).", w)...)
	rows = append(rows, "")
	rows = append(rows, wrapAll(t.Frost, "Press u to unlock. Your passphrase is asked in the terminal prompt, never in this screen.", w)...)
	return rows
}

func (m Model) failedBody(what string, w int) []string {
	t := m.theme
	rows := []string{t.Flare("Could not read the " + what + ".")}
	rows = append(rows, wrapAll(t.Mist, "Nothing was changed. Press enter to retry, or run 'qbit-vault doctor'.", w)...)
	return rows
}

// ---- the add and edit forms ----

type formField int

const (
	fName formField = iota
	fLayer
	fDesc
	fSens
)

// form collects the metadata of a secret. It has no value field: the value is
// typed later in the prompt backend, with the TUI suspended.
type form struct {
	edit      bool
	ref       SecretRef
	label     string // the layer shown for an edit
	project   bool
	sensitive bool
	name      textinput.Model
	desc      textinput.Model
	fields    []formField
	at        int
	err       string
	projLabel string // label of the current repository, "" outside one
	prefill   string // the description the edit form opened with, as shown
}

func newInput(v string) textinput.Model {
	ti := textinput.New()
	ti.Prompt = ""
	ti.CharLimit = 200
	ti.SetValue(v)
	return ti
}

func newForm(edit bool, s Secret, projLabel string) *form {
	f := &form{edit: edit, projLabel: projLabel, name: newInput(""), desc: newInput("")}
	f.fields = []formField{fName, fLayer, fDesc, fSens}
	if edit {
		f.ref, f.label, f.project, f.sensitive = SecretRef{Name: s.Name, Project: s.Project}, s.Layer, s.Project, s.Sensitive
		f.desc = newInput(s.Description)
		f.prefill = f.desc.Value()
		f.fields = []formField{fDesc, fSens}
	}
	f.focusCurrent()
	return f
}

func (f *form) field() formField { return f.fields[f.at] }

func (f *form) focusCurrent() {
	f.name.Blur()
	f.desc.Blur()
	switch f.field() {
	case fName:
		f.name.Focus()
	case fDesc:
		f.desc.Focus()
	}
}

func (f *form) move(d int) {
	f.at = (f.at + d + len(f.fields)) % len(f.fields)
	f.focusCurrent()
}

func (m Model) updateForm(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	cp := *m.form
	f := &cp
	m.form = f
	switch {
	case key.Type == tea.KeyEsc:
		m.form = nil
	case key.Type == tea.KeyEnter:
		return m.submitForm()
	case key.Type == tea.KeyTab || key.Type == tea.KeyDown:
		f.move(1)
	case key.Type == tea.KeyShiftTab || key.Type == tea.KeyUp:
		f.move(-1)
	default:
		switch f.field() {
		case fName:
			f.name, _ = f.name.Update(key)
			f.err = ""
		case fDesc:
			f.desc, _ = f.desc.Update(key)
		case fLayer:
			if key.Type == tea.KeyLeft || key.Type == tea.KeyRight || key.Type == tea.KeySpace {
				if !f.project && f.projLabel == "" {
					f.err = "Not inside a project: run the TUI from a repository to use the project layer."
					break
				}
				f.project, f.err = !f.project, ""
			}
		case fSens:
			if key.Type == tea.KeyLeft || key.Type == tea.KeyRight || key.Type == tea.KeySpace {
				f.sensitive = !f.sensitive
			}
		}
	}
	return m, nil
}

func (m Model) submitForm() (tea.Model, tea.Cmd) {
	f := m.form
	desc := strings.TrimSpace(f.desc.Value())
	if f.edit {
		// An untouched field keeps the stored description: the form shows it
		// on one line, so writing it back could rewrite it.
		edit := SecretEdit{SecretRef: f.ref, Sensitive: f.sensitive}
		if f.desc.Value() == f.prefill {
			edit.KeepDescription = true
		} else {
			edit.Description = desc
		}
		err := m.b.EditSecret(edit)
		m.form = nil
		m.refreshAfter(err, "updated "+clean(f.ref.Name))
		return m, nil
	}
	name := strings.TrimSpace(f.name.Value())
	if name == "" {
		f.err = "Name cannot be empty."
		return m, nil
	}
	act := m.b.AddSecret(NewSecret{SecretRef: SecretRef{Name: name, Project: f.project}, Description: desc, Sensitive: f.sensitive})
	m.form, m.notice = nil, notice{}
	return m, m.exec(act, func(err error) tea.Msg { return actionDoneMsg{kind: actAdd, err: err, name: name} })
}

// exists reports whether the add form names a secret that is already stored
// in the chosen layer, so saving would replace its value.
func (f *form) exists(items []Secret) bool {
	name := strings.TrimSpace(f.name.Value())
	for _, s := range items {
		if s.Name == name && s.Project == f.project {
			return true
		}
	}
	return false
}

func (m Model) formView() string {
	f, t := m.form, m.theme
	field := func(label string, which formField, body string) string {
		cursor := "  "
		if f.field() == which {
			cursor = t.Glow("▸") + " "
		}
		return " " + cursor + t.Mist(pad(label, 13)) + body
	}
	input := func(ti textinput.Model, focused bool) string {
		v := []rune(ti.Value())
		pos := min(ti.Position(), len(v))
		if !focused {
			return t.Frost(clean(string(v)))
		}
		return t.Frost(clean(string(v[:pos]))) + t.Glow("▏") + t.Frost(clean(string(v[pos:])))
	}
	box := func(on bool) string {
		if on {
			return "[x]"
		}
		return "[ ]"
	}
	title := "Add secret"
	var rows []string
	if f.edit {
		title = "Edit " + clean(f.ref.Name)
		rows = []string{"", field("Name", -1, t.Frost(clean(f.ref.Name))), field("Layer", -1, t.Mist(clean(f.label)))}
	} else {
		layer := "(•) global    ( ) project " + clean(orDefault(f.projLabel, "(none)"))
		if f.project {
			layer = "( ) global    (•) project " + clean(f.projLabel)
		}
		rows = []string{"", field("Name", fName, input(f.name, f.field() == fName)), field("Layer", fLayer, t.Frost(layer))}
	}
	rows = append(rows,
		field("Description", fDesc, input(f.desc, f.field() == fDesc)),
		field("Sensitive", fSens, t.Frost(box(f.sensitive))+t.Mist(" grant once at a time")), "")
	switch {
	case f.err != "":
		rows = append(rows, " "+t.Flare(f.err))
	case !f.edit && f.exists(m.sec.list.Items):
		rows = append(rows, " "+t.Warn("Name already exists in this layer: saving replaces its value."))
	default:
		rows = append(rows, "")
	}
	if f.edit {
		rows = append(rows, " "+t.Mist("Changes metadata only. The value is not touched."))
	} else {
		rows = append(rows, " "+t.Warn("The value is not typed here; do not paste a secret into the description."),
			" "+t.Mist("The value is asked next, in a masked prompt."), " "+t.Mist("Saving does not grant anything: agents still have to ask."))
	}
	keys := [][2]string{kv("enter", "save"), kv("tab", "next field"), kv("esc", "cancel")}
	w := m.width - len(indent) - 2
	return m.stack(m.header(), "", m.box(title, w, rows, true), "", m.footer(keys...))
}

// ---- inline confirmations ----

type askKind int

const (
	askRemove askKind = iota
	askRevokeAll
	askUninstall
)

// confirmation is a destructive key waiting for a "y": it states the
// consequence first. Any other key cancels.
type confirmation struct {
	kind        askKind
	ref         SecretRef
	question    string
	consequence string
}

func (m Model) updateAsk(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	c := *m.ask
	m.ask = nil
	if !isRune(key, 'y') {
		return m, nil
	}
	switch c.kind {
	case askRemove:
		err := m.b.RemoveSecret(c.ref)
		m.refreshAfter(err, "removed "+clean(c.ref.Name))
	case askRevokeAll:
		n, err := m.b.RevokeAllGrants()
		m.refreshAfter(err, "revoked "+plural(n, "grant"))
	case askUninstall:
		s, err := m.b.UninstallHost(c.ref.Name)
		m.refreshAfter(err, s)
	}
	return m, nil
}

// notice is the one-line result of the last action.
type notice struct {
	text string
	bad  bool
}

// refreshAfter reloads what the screens show and reports the outcome.
func (m *Model) refreshAfter(err error, done string) {
	if st, serr := m.b.Status(); serr == nil {
		m.status = st
	}
	m.loadSecrets()
	m.loadGrants()
	m.loadHosts()
	switch sections[m.section].title {
	case "Audit", "Sync", "Doctor":
		m.enterSection() // an unlock may have opened what was locked
	}
	if err != nil {
		m.notice = notice{text: errText(err), bad: true}
		return
	}
	m.notice = notice{text: done}
}

// errText is an error as one short line. Backend errors are curated for
// display: they name a secret, never a value.
func errText(err error) string {
	if err == nil {
		return ""
	}
	return trunc(clean(err.Error()), 90)
}
