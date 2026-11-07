package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// ---- Audit ----

// auditPane is the Audit section: the newest records, newest first, and the
// last verification of the hash chain. It shows when, what, names, layer and
// who; the record has no value to show.
type auditPane struct {
	log     AuditLog
	cur     int
	st      loadState
	verdict *AuditVerdict
}

func (p auditPane) selected() (AuditEntry, bool) {
	if p.cur < 0 || p.cur >= len(p.log.Entries) {
		return AuditEntry{}, false
	}
	return p.log.Entries[p.cur], true
}

func (m *Model) loadAudit() {
	p := auditPane{cur: m.au.cur, verdict: m.au.verdict}
	log, err := m.b.Audit()
	p.st = classify(err)
	if p.st == loadOK {
		// The backend reads oldest first; the screen shows the newest on top.
		for i := len(log.Entries) - 1; i >= 0; i-- {
			p.log.Entries = append(p.log.Entries, log.Entries[i])
		}
		p.log.Total = log.Total
	}
	p.cur = max(min(p.cur, len(p.log.Entries)-1), 0)
	m.au = p
}

func (m Model) auditKey(key tea.KeyMsg) (Model, tea.Cmd, bool) {
	p := m.au
	if next, cmd, ok := m.stateKeys(p.st, key, (*Model).loadAudit); ok {
		return next, cmd, true
	}
	if p.st != loadOK {
		return m, nil, false
	}
	switch {
	case isRune(key, 'v'):
		v, err := m.b.VerifyAudit()
		switch {
		case err != nil:
			m.notice = notice{text: errText(err), bad: true}
		case v.Valid:
			m.au.verdict = &v
			m.notice = notice{text: fmt.Sprintf("audit log ok (%s)", plural(v.Records, "record"))}
		default:
			m.au.verdict = &v
			m.notice = notice{text: fmt.Sprintf("audit log broken at line %d (%s). Records after it are not trusted.", v.Line, clean(v.Reason)), bad: true}
		}
	case m.focus != PaneSections && isUp(key):
		m.au.cur = max(p.cur-1, 0)
	case m.focus != PaneSections && isDown(key):
		m.au.cur = max(min(p.cur+1, len(p.log.Entries)-1), 0)
	default:
		return m, nil, false
	}
	return m, nil, true
}

func clock24(ts string) string {
	s := plainTime(ts)
	if len(s) >= 16 {
		return s[11:16] + ":" + seconds(ts)
	}
	return s
}

// seconds is the ss of an RFC 3339 stamp, "00" when it has none.
func seconds(ts string) string {
	if len(ts) >= 19 && ts[16] == ':' {
		return clean(ts[17:19])
	}
	return "00"
}

func entryNames(e AuditEntry) string {
	return orDash(clean(strings.Join(e.Names, ",")))
}

// auditBody is the list pane of the Audit section; w is the row width.
func (m Model) auditBody(w int) []string {
	t, p := m.theme, m.au
	if rows := m.stateBody(p.st, "audit log", w); rows != nil {
		return rows
	}
	if len(p.log.Entries) == 0 {
		rows := []string{"", t.Frost("No audit records yet.")}
		return append(rows, wrapAll(t.Mist, "Every capture, grant, exec and refusal is recorded here, names only.", w)...)
	}
	const timeW, eventW, byW = 8, 8, 5
	nameW := max(w-3-timeW-eventW-byW-3, 6)
	row := func(a, b, c, d string) string {
		return pad(trunc(a, timeW), timeW) + " " + pad(trunc(b, eventW), eventW) + " " + pad(trunc(c, nameW), nameW) + " " + trunc(d, byW)
	}
	rows := []string{t.Mist("  " + row("TIME", "EVENT", "NAME", "BY"))}
	start := min(max(p.cur-visibleRows+1, 0), max(len(p.log.Entries)-visibleRows, 0))
	for i := start; i < min(start+visibleRows, len(p.log.Entries)); i++ {
		e := p.log.Entries[i]
		text := row(clock24(e.Time), clean(e.Event), entryNames(e), orDash(clean(e.By)))
		if i == p.cur {
			rows = append(rows, t.Selected("▸ "+text, w))
			continue
		}
		rows = append(rows, "  "+t.Frost(text))
	}
	return append(rows, "", t.Mist(fmt.Sprintf("%d of %d records", len(p.log.Entries), max(p.log.Total, len(p.log.Entries)))))
}

// auditDetail is the detail pane: the selected record and the verdict of the
// last verification.
func (m Model) auditDetail(w int) (string, []string) {
	t, p := m.theme, m.au
	e, ok := p.selected()
	if p.st != loadOK || !ok {
		return "Record", append([]string{""}, wrapAll(t.Mist, "Nothing selected.", w)...)
	}
	rows := []string{t.Heading(clean(e.Event)),
		detailLine(t, "time", plainTime(e.Time), w),
		detailLine(t, "names", entryNames(e), w),
		detailLine(t, "layer", orDash(clean(e.Layer)), w),
		detailLine(t, "by", orDash(clean(e.By)), w), ""}
	rows = append(rows, wrapAll(t.Mist, "No command text, reason or value is shown here.", w)...)
	if v := p.verdict; v != nil {
		rows = append(rows, "")
		if v.Valid {
			rows = append(rows, t.Green("chain verified ("+plural(v.Records, "record")+")"))
		} else {
			rows = append(rows, t.Flare(fmt.Sprintf("Chain broken at line %d", v.Line)), t.Mist("Records after it are not trusted."), t.Frost("qbit-vault audit --verify"))
		}
	}
	rows = append(rows, "", t.Key("v")+t.Mist(" verify the chain"))
	return "Record", rows
}

// ---- Sync ----

// syncPane is the Sync section: remote status only. Linking, pairing and
// resolving happen in the CLI; no code or key is ever read or shown here.
type syncPane struct {
	s  SyncStatus
	st loadState
}

func (m *Model) loadSync() {
	s, err := m.b.SyncStatus()
	m.sy = syncPane{st: classify(err)}
	if m.sy.st == loadOK {
		m.sy.s = s
	}
}

func (m Model) syncKey(key tea.KeyMsg) (Model, tea.Cmd, bool) {
	return m.stateKeys(m.sy.st, key, (*Model).loadSync)
}

func (m Model) syncBody(w int) []string {
	t, p := m.theme, m.sy
	if rows := m.stateBody(p.st, "sync status", w); rows != nil {
		return rows
	}
	s := p.s
	if !s.Linked {
		rows := []string{"", t.Frost("This vault does not sync."), ""}
		return append(rows, wrapAll(t.Mist, "It lives on this machine only. Link it to a qbit-vault-server to share it between your devices.", w)...)
	}
	last := "no round yet"
	if s.LastRound != "" {
		last = plainTime(s.LastRound)
	}
	conflicts := t.Frost("no conflicts")
	switch {
	case s.Conflicts < 0:
		conflicts = t.Mist("conflicts unknown")
	case s.Conflicts > 0:
		conflicts = t.Warn(plural(s.Conflicts, "conflict"))
	}
	field := func(label, value string) string {
		return t.Mist(pad(label, 11)) + t.Frost(trunc(value, max(w-11, 4)))
	}
	rows := []string{"",
		field("server", orDash(clean(s.Server))),
		field("device", orDash(clean(s.Device))),
		field("last round", last),
		t.Mist(pad("conflicts", 11)) + conflicts}
	if s.Cached && s.Conflicts >= 0 {
		rows = append(rows, t.Mist(pad("", 11)+"from the last round"))
	}
	if s.Conflicts < 0 {
		rows = append(rows, wrapAll(t.Mist, "Run 'qbit-vault unlock' to count them.", w)...)
	}
	if s.PendingPush {
		rows = append(rows, t.Warn(pad("pending", 11)+"push pending"))
	}
	if s.Offline {
		rows = append(rows, "", t.Warn("offline"))
		rows = append(rows, wrapAll(t.Mist, "Remote calls are off (QBIT_VAULT_NO_REMOTE=1).", w)...)
	}
	return rows
}

// syncDetail names the CLI commands for what this screen does not do.
func (m Model) syncDetail(w int) (string, []string) {
	t, p := m.theme, m.sy
	if p.st != loadOK {
		return "Actions", append([]string{""}, wrapAll(t.Mist, "Nothing to show.", w)...)
	}
	cmd := func(c, _ string) []string { return []string{t.Frost(c)} }
	rows := []string{""}
	if !p.s.Linked {
		rows = append(rows, t.Mist("Link or pair from your shell:"))
		rows = append(rows, cmd("qbit-vault remote register", "new account")...)
		rows = append(rows, cmd("qbit-vault remote join", "pair this device")...)
	} else {
		rows = append(rows, t.Mist("From your shell:"))
		rows = append(rows, cmd("qbit-vault remote sync", "run a round")...)
		rows = append(rows, cmd("qbit-vault remote conflicts", "list conflicts")...)
		rows = append(rows, cmd("qbit-vault remote resolve", "pick a version")...)
		rows = append(rows, cmd("qbit-vault remote approve", "pair a new device")...)
	}
	rows = append(rows, "")
	rows = append(rows, wrapAll(t.Mist, "Pairing codes and recovery keys are entered in a native dialog, never here.", w)...)
	return "Actions", rows
}

// ---- Doctor ----

// doctorPane is the Doctor section: the report of `qbit-vault doctor`.
type doctorPane struct {
	r   DoctorReport
	cur int
	st  loadState
}

func (m *Model) loadDoctor() {
	p := doctorPane{cur: m.dr.cur}
	r, err := m.b.Doctor()
	p.st = classify(err)
	if p.st == loadOK {
		p.r = r
	}
	p.cur = max(min(p.cur, len(p.r.Checks)-1), 0)
	m.dr = p
}

func (m Model) doctorKey(key tea.KeyMsg) (Model, tea.Cmd, bool) {
	p := m.dr
	if next, cmd, ok := m.stateKeys(p.st, key, (*Model).loadDoctor); ok {
		return next, cmd, true
	}
	switch {
	case isRune(key, 'r'):
		m.loadDoctor()
	case p.st == loadOK && m.focus != PaneSections && isUp(key):
		m.dr.cur = max(p.cur-1, 0)
	case p.st == loadOK && m.focus != PaneSections && isDown(key):
		m.dr.cur = max(min(p.cur+1, len(p.r.Checks)-1), 0)
	default:
		return m, nil, false
	}
	return m, nil, true
}

// checkStyle colors a doctor status: ok green, warn amber, fail flare.
func (m Model) checkStyle(status string) func(string) string {
	switch status {
	case "ok":
		return m.theme.Green
	case "warn":
		return m.theme.Warn
	}
	return m.theme.Flare
}

func problems(r DoctorReport) int {
	n := 0
	for _, c := range r.Checks {
		if c.Status != "ok" {
			n++
		}
	}
	return n
}

func (m Model) doctorBody(w int) []string {
	t, p := m.theme, m.dr
	if rows := m.stateBody(p.st, "doctor report", w); rows != nil {
		return rows
	}
	if len(p.r.Checks) == 0 {
		rows := []string{"", t.Frost("No checks ran.")}
		return append(rows, wrapAll(t.Mist, "Press r to run the report again.", w)...)
	}
	nameW := max(w-2-4-2, 6)
	rows := []string{t.Mist("  " + pad("", 4) + "  CHECK")}
	start := min(max(p.cur-visibleRows+1, 0), max(len(p.r.Checks)-visibleRows, 0))
	for i := start; i < min(start+visibleRows, len(p.r.Checks)); i++ {
		c := p.r.Checks[i]
		status := trunc(clean(c.Status), 4)
		name := trunc(clean(c.Name), nameW)
		if i == p.cur {
			rows = append(rows, t.Selected("▸ "+pad(status, 4)+"  "+name, w))
			continue
		}
		rows = append(rows, "  "+m.checkStyle(c.Status)(status)+strings.Repeat(" ", 4-lenRunes(status))+"  "+t.Frost(name))
	}
	summary := t.Green("healthy")
	if n := problems(p.r); n > 0 {
		summary = t.Warn(plural(n, "problem"))
	}
	return append(rows, "", summary)
}

func lenRunes(s string) int { return len([]rune(s)) }

func (m Model) doctorDetail(w int) (string, []string) {
	t, p := m.theme, m.dr
	if p.st != loadOK || p.cur >= len(p.r.Checks) {
		return "Detail", append([]string{""}, wrapAll(t.Mist, "Nothing selected.", w)...)
	}
	c := p.r.Checks[p.cur]
	rows := []string{t.Heading(trunc(clean(c.Name), w-6)) + "  " + m.checkStyle(c.Status)(clean(c.Status)), ""}
	rows = append(rows, wrapAll(t.Frost, clean(c.Detail), w)...)
	rows = append(rows, "", t.Key("r")+t.Mist(" run again"))
	return clean(c.Name), rows
}

// ---- Update ----

// updateCommand is the Go way to upgrade; the screen only shows it.
const updateCommand = "go install github.com/QuBiit0/qbit-vault/cmd/qbit-vault@latest"

func (m Model) updateBody(w int) []string {
	t := m.theme
	rows := []string{"", t.Frost("Re-run the install command to upgrade.")}
	rows = append(rows, wrapAll(t.Mist, "The installer replaces the binary in place and re-applies your agent registrations.", w)...)
	return rows
}

func (m Model) updateDetail(w int) (string, []string) {
	t := m.theme
	rows := []string{""}
	rows = append(rows, wrapAll(t.Frost, "Run the one-line installer from the README again, or use the Go command below.", w)...)
	rows = append(rows, "")
	rows = append(rows, wrapAll(t.Mist, "No network call is made here.", w)...)
	return "Install command", rows
}
