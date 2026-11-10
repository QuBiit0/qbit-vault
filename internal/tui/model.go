package tui

import (
	"io"

	tea "github.com/charmbracelet/bubbletea"
)

// Screen is a place the router can show.
type Screen int

const (
	ScreenSplash Screen = iota // first run, no vault yet
	ScreenSetup                // setup wizard
	ScreenHome                 // the three panes: sections, list, detail
	ScreenError                // the backend failed: a message and a next action
)

func (s Screen) String() string {
	switch s {
	case ScreenSplash:
		return "splash"
	case ScreenSetup:
		return "setup"
	case ScreenHome:
		return "home"
	case ScreenError:
		return "error"
	}
	return "unknown"
}

// Pane is one of the three panes of the home screen.
type Pane int

const (
	PaneSections Pane = iota
	PaneList
	PaneDetail
	paneCount
)

func (p Pane) String() string {
	switch p {
	case PaneSections:
		return "sections"
	case PaneList:
		return "list"
	case PaneDetail:
		return "detail"
	}
	return "unknown"
}

// section is one entry of the sections pane.
type section struct{ title string }

var sections = []section{
	{"Secrets"}, {"Grants"}, {"Hosts"}, {"Audit"}, {"Sync"}, {"Doctor"}, {"Update"},
}

// Options configure the app.
type Options struct {
	Version string
	Profile Profile
	// Exec runs an Action with the TUI suspended; nil means tea.Exec. Tests
	// replace it, since a program is needed to suspend anything.
	Exec func(Action, tea.ExecCallback) tea.Cmd
	// NoUpdateCheck turns the open-time release check off
	// (QBIT_VAULT_NO_UPDATE_CHECK=1); the Update section offers "c check now".
	NoUpdateCheck bool
	// NotRelease marks a build that cannot update itself (dev, a pseudo-version):
	// no check runs and u is not offered.
	NotRelease bool
}

const defaultWidth = 100

// Model is the root Bubble Tea model: it owns the status and routes between
// screens. It is a value type; Update returns the next Model.
type Model struct {
	b       Backend
	opts    Options
	theme   Theme
	status  Status
	screen  Screen
	section int
	focus   Pane
	width   int

	wiz    wizard
	sec    secretsPane
	gr     grantsPane
	hp     hostsPane
	au     auditPane
	sy     syncPane
	dr     doctorPane
	up     updatePane
	form   *form         // the add or edit form, while open
	ask    *confirmation // a destructive key waiting for "y"
	notice notice        // the result of the last action
}

// New builds the root model and reads the vault status once. A vault that does
// not exist starts on the splash; any other state starts on the home screen.
func New(b Backend, o Options) Model {
	m := Model{b: b, opts: o, theme: NewTheme(o.Profile), width: defaultWidth}
	m.load()
	if m.autoCheck() {
		m.up.st = upChecking
	}
	if m.screen == ScreenHome {
		m.enterSection()
	}
	return m
}

// Screen reports the screen being shown.
func (m Model) Screen() Screen { return m.screen }

// Section reports the title of the section selected on the home screen.
func (m Model) Section() string { return sections[m.section].title }

// Focus reports the focused pane of the home screen.
func (m Model) Focus() Pane { return m.focus }

func (m *Model) load() {
	st, err := m.b.Status()
	switch {
	case err != nil:
		m.screen = ScreenError
	case st.State == StateNone:
		m.status, m.screen = st, ScreenSplash
	default:
		m.status, m.screen = st, ScreenHome
	}
}

// Init implements tea.Model.
func (m Model) Init() tea.Cmd {
	if m.autoCheck() {
		return m.checkCmd()
	}
	return nil
}

// Update implements tea.Model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = max(msg.Width, 80)
	case tea.KeyMsg:
		return m.updateKey(msg)
	case actionDoneMsg:
		return m.actionDone(msg), nil
	case updateCheckedMsg:
		return m.updateChecked(msg), nil
	}
	return m, nil
}

// actionKind says which Action finished.
type actionKind int

const (
	actSetup actionKind = iota
	actAdd
	actUnlock
	actUpdate
)

// actionDoneMsg reports that an Action (a suspended prompt, or the setup)
// returned.
type actionDoneMsg struct {
	kind actionKind
	err  error
	name string // the secret an add was for
}

func (m Model) actionDone(msg actionDoneMsg) Model {
	switch msg.kind {
	case actSetup:
		return m.setupDone(msg.err)
	case actAdd:
		m.refreshAfter(msg.err, "stored "+clean(msg.name))
		for i, s := range m.sec.list.Items {
			if s.Name == msg.name && msg.err == nil {
				m.sec.cur = i
			}
		}
	case actUnlock:
		m.refreshAfter(msg.err, "unlocked")
	case actUpdate:
		m.updateDone(msg.err)
	}
	return m
}

// exec runs an Action with the TUI suspended, so a prompt can use the terminal.
func (m Model) exec(a Action, cb tea.ExecCallback) tea.Cmd {
	if m.opts.Exec != nil {
		return m.opts.Exec(a, cb)
	}
	return tea.Exec(a, cb)
}

// enterSection loads what the selected section shows.
func (m *Model) enterSection() {
	switch sections[m.section].title {
	case "Secrets":
		m.loadSecrets()
	case "Grants":
		m.loadGrants()
	case "Hosts":
		m.loadHosts()
	case "Audit":
		m.loadAudit()
	case "Sync":
		m.loadSync()
	case "Doctor":
		m.loadDoctor()
	}
}

func (m Model) updateKey(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if key.Type == tea.KeyCtrlC {
		return m, tea.Quit
	}
	switch m.screen {
	case ScreenSplash:
		switch {
		case key.Type == tea.KeyEnter:
			m.startWizard()
		case isRune(key, 'q'):
			return m, tea.Quit
		}
	case ScreenSetup:
		return m.updateSetup(key)
	case ScreenHome:
		return m.updateHome(key)
	case ScreenError:
		switch {
		case key.Type == tea.KeyEnter:
			m.load()
		case isRune(key, 'q'):
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m Model) updateHome(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case m.form != nil:
		return m.updateForm(key)
	case m.ask != nil:
		return m.updateAsk(key)
	}
	m.notice = notice{}
	var (
		next Model
		cmd  tea.Cmd
		ok   bool
	)
	switch sections[m.section].title {
	case "Secrets":
		next, cmd, ok = m.secretsKey(key)
	case "Grants":
		next, cmd, ok = m.grantsKey(key)
	case "Hosts":
		next, cmd, ok = m.hostsKey(key)
	case "Audit":
		next, cmd, ok = m.auditKey(key)
	case "Sync":
		next, cmd, ok = m.syncKey(key)
	case "Doctor":
		next, cmd, ok = m.doctorKey(key)
	case "Update":
		next, cmd, ok = m.updateSectionKey(key)
	}
	if ok {
		return next, cmd
	}
	n := len(sections)
	before := m.section
	switch {
	case isRune(key, 'q'):
		return m, tea.Quit
	case key.Type == tea.KeyTab:
		m.focus = (m.focus + 1) % paneCount
	case key.Type == tea.KeyShiftTab:
		m.focus = (m.focus + paneCount - 1) % paneCount
	case key.Type == tea.KeyEsc:
		if m.focus > PaneSections {
			m.focus--
		}
	case key.Type == tea.KeyRunes && len(key.Runes) == 1 && key.Runes[0] >= '1' && int(key.Runes[0]-'1') < n:
		m.section = int(key.Runes[0] - '1')
	case m.focus == PaneSections && (key.Type == tea.KeyUp || isRune(key, 'k')):
		m.section = max(m.section-1, 0)
	case m.focus == PaneSections && (key.Type == tea.KeyDown || isRune(key, 'j')):
		m.section = min(m.section+1, n-1)
	}
	if m.section != before {
		m.enterSection()
	}
	return m, nil
}

func isRune(k tea.KeyMsg, r rune) bool {
	return k.Type == tea.KeyRunes && len(k.Runes) == 1 && k.Runes[0] == r
}

// Run shows the TUI on the given terminal until the user quits.
func Run(b Backend, o Options, in io.Reader, out io.Writer) error {
	_, err := tea.NewProgram(New(b, o), tea.WithInput(in), tea.WithOutput(out), tea.WithAltScreen()).Run()
	return err
}
