package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// wizStep is a step of the first-run wizard (02-launcher): vault, key
// storage, hosts, review; then applying and done.
type wizStep int

const (
	stepVault wizStep = iota
	stepKey
	stepHosts
	stepReview
	stepApplying
	stepDone
)

const (
	wizSteps = 4  // the steps listed in the left pane; review is part of Apply
	wizLeftW = 24 // outer width of the left pane
)

// wizard is the state of the setup wizard. Nothing is written until Apply.
type wizard struct {
	step       wizStep
	plan       SetupPlan
	passphrase bool
	cursor     int    // the highlighted host
	picked     []bool // aligned with plan.Hosts
	err        string // the last apply failure or warning
}

func (m *Model) startWizard() {
	plan, err := m.b.SetupPlan()
	if err != nil {
		m.screen = ScreenError
		return
	}
	w := wizard{plan: plan, picked: make([]bool, len(plan.Hosts))}
	for i, h := range plan.Hosts {
		w.picked[i] = h.Detected
	}
	m.wiz, m.screen = w, ScreenSetup
}

func (w wizard) hostNames() []string {
	names := []string{}
	for i, h := range w.plan.Hosts {
		if w.picked[i] {
			names = append(names, h.Name)
		}
	}
	return names
}

func (m Model) updateSetup(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	w := &m.wiz
	switch w.step {
	case stepVault:
		switch {
		case key.Type == tea.KeyEnter:
			w.step = stepKey
		case key.Type == tea.KeyEsc:
			m.screen = ScreenSplash
		}
	case stepKey:
		switch {
		case isUp(key), isDown(key):
			w.passphrase = !w.passphrase
		case key.Type == tea.KeyEnter:
			w.step = stepHosts
		case key.Type == tea.KeyEsc:
			w.step = stepVault
		}
	case stepHosts:
		n := len(w.plan.Hosts)
		switch {
		case isUp(key):
			w.cursor = max(w.cursor-1, 0)
		case isDown(key):
			w.cursor = min(w.cursor+1, max(n-1, 0))
		case key.Type == tea.KeySpace && n > 0:
			w.picked[w.cursor] = !w.picked[w.cursor]
		case isRune(key, 'a'):
			for i := range w.picked {
				w.picked[i] = true
			}
		case isRune(key, 'n'):
			for i := range w.picked {
				w.picked[i] = false
			}
		case key.Type == tea.KeyEnter:
			w.step = stepReview
		case key.Type == tea.KeyEsc:
			w.step = stepKey
		}
	case stepReview:
		switch {
		case key.Type == tea.KeyEnter:
			return m.apply()
		case key.Type == tea.KeyEsc:
			w.err = ""
			w.step = stepHosts
		}
	case stepDone:
		switch {
		case isRune(key, 'a'):
			m.leaveWizard()
			m.openAddForm()
		case key.Type == tea.KeyEnter:
			m.leaveWizard()
		}
	}
	return m, nil
}

// leaveWizard lands on the Secrets section of the home screen.
func (m *Model) leaveWizard() {
	m.screen, m.section, m.focus = ScreenHome, 0, PaneSections
	m.enterSection()
}

// apply runs the setup. A passphrase is asked by the prompt backend, so that
// run suspends the TUI; the keychain needs no prompt and runs off the loop.
func (m Model) apply() (tea.Model, tea.Cmd) {
	req := SetupRequest{Passphrase: m.wiz.passphrase, Hosts: m.wiz.hostNames()}
	act := m.b.Setup(req)
	m.wiz.step, m.wiz.err = stepApplying, ""
	done := func(err error) tea.Msg { return actionDoneMsg{kind: actSetup, err: err} }
	if req.Passphrase {
		return m, m.exec(act, done)
	}
	return m, func() tea.Msg { return done(act.Run()) }
}

// setupDone moves on once the apply finished. A vault that exists is done even
// when a host failed: the failure is shown with the next action.
func (m Model) setupDone(err error) Model {
	st, serr := m.b.Status()
	if serr == nil && st.State != StateNone {
		m.status = st
		m.wiz.step, m.wiz.err = stepDone, errText(err)
		return m
	}
	m.wiz.step, m.wiz.err = stepReview, errText(err)
	if m.wiz.err == "" {
		m.wiz.err = "The vault was not created."
	}
	return m
}

func (m Model) setupView() string {
	w := m.wiz
	cur := min(int(w.step), wizSteps-1)
	left := []string{""}
	for i, name := range [wizSteps]string{"Vault", "Key storage", "Hosts", "Apply"} {
		mark, label := m.theme.Mist("○"), m.theme.Mist(name)
		switch {
		case w.step == stepDone || i < cur:
			mark, label = m.theme.Green("✓"), m.theme.Frost(name)
		case i == cur:
			mark, label = m.theme.Glow("▸"), m.theme.Heading(name)
		}
		left = append(left, " "+mark+"  "+label)
	}
	left = append(left, "", " "+m.theme.Mist(fmt.Sprintf("step %d of %d", cur+1, wizSteps)))
	switch w.step {
	case stepApplying:
		left = append(left, " "+m.theme.Mist("writing…"))
	case stepDone:
		left = append(left, " "+m.theme.Mist("all written"))
	default:
		left = append(left, " "+m.theme.Mist("nothing is written"), " "+m.theme.Mist("until Apply"))
	}

	rightW := m.width - len(indent) - wizLeftW - 1
	title, body, keys := m.setupStep()
	panes := joinPanes(" ", m.box("Setup", wizLeftW, left, false), m.box(title, rightW, body, true))
	return m.stack(m.header(), "", panes, "", m.footer(keys...))
}

// setupStep is the title, body and footer keys of the current step.
func (m Model) setupStep() (string, []string, [][2]string) {
	wz, t := m.wiz, m.theme
	switch wz.step {
	case stepVault:
		return "Where will the vault live?", []string{
			"",
			"  " + t.Frost(clean(wz.plan.Home)),
			"",
			"  " + t.Mist("An empty, encrypted vault is created here."),
			"  " + t.Mist("Nothing is read from your environment."),
			"",
			"  " + t.Mist("Nothing is written until you reach Apply."),
		}, [][2]string{kv("enter", "next"), kv("esc", "back"), kv("ctrl+c", "quit")}
	case stepKey:
		kc, pp := "  ", "  "
		if wz.passphrase {
			pp = t.Glow("▸") + " "
		} else {
			kc = t.Glow("▸") + " "
		}
		body := []string{
			"",
			" " + kc + "OS keychain  " + t.Green("recommended") + t.Mist(": "+clean(orDefault(wz.plan.Keychain, "the OS keychain"))),
			"     " + t.Mist("Unlocked by your login. No passphrase to type."),
			"",
			" " + pp + "Passphrase  " + t.Mist("Argon2id, asked once and cached until `qbit-vault lock`"),
			"     " + t.Mist("Use it where there is no keychain (servers, containers)."),
		}
		if wz.passphrase {
			body = append(body, "     "+t.Warn("It is asked in a secure prompt when you apply:"), "     "+t.Warn("never typed in this screen."))
		} else {
			body = append(body, "", "")
		}
		body = append(body, "", " "+t.Mist("The key never leaves this device. vault.enc is useless without it."), " "+t.Mist("The vault starts empty: no secret is read or imported."))
		return "Where does the master key live?", body, [][2]string{kv("↑↓", "choose"), kv("enter", "next"), kv("esc", "back"), kv("ctrl+c", "quit")}
	case stepHosts:
		body := []string{""}
		for i, h := range wz.plan.Hosts {
			box, at := "[ ]", "  "
			if wz.picked[i] {
				box = "[x]"
			}
			if i == wz.cursor {
				at = t.Glow("▸") + " "
			}
			found := t.Mist("not found")
			if h.Detected {
				found = t.Green("found")
			}
			body = append(body, " "+at+box+" "+pad(clean(h.Name), 12)+" "+pad(found, 10)+t.Mist(" steps "+clean(strings.Join(h.Steps, " "))))
		}
		body = append(body, "", " "+t.Mist("Every config file is snapshotted before it changes"), " "+t.Mist("and written atomically."), " "+t.Mist("Registering never asks for, reads or stores a secret."))
		return "Register with your coding agents", body, [][2]string{kv("↑↓", "move"), kv("space", "toggle"), kv("a", "all"), kv("n", "none"), kv("enter", "next"), kv("esc", "back")}
	case stepReview:
		store := "OS keychain"
		if wz.passphrase {
			store = "passphrase (asked in a secure prompt)"
		}
		hosts := "none"
		if names := wz.hostNames(); len(names) > 0 {
			hosts = strings.Join(names, ", ")
		}
		body := []string{
			"",
			" " + t.Mist("vault        ") + clean(wz.plan.Home) + t.Mist(" (empty)"),
			" " + t.Mist("key storage  ") + store,
			" " + t.Mist("hosts        ") + clean(hosts),
			"",
			" " + t.Mist("Nothing is written until you press enter."),
		}
		keys := [][2]string{kv("enter", "apply"), kv("esc", "back"), kv("ctrl+c", "quit")}
		if wz.err != "" {
			body = append(body, "", " "+t.Flare(wz.err), " "+t.Mist("Fix it, or press enter to retry."))
			keys = [][2]string{kv("enter", "retry"), kv("esc", "back"), kv("ctrl+c", "quit")}
		}
		return "Review", body, keys
	case stepApplying:
		return "Applying", []string{"", " " + t.Mist("Applying… this takes a few seconds."), " " + t.Mist("ctrl+c is safe: every step is atomic.")},
			[][2]string{kv("ctrl+c", "quit")}
	}
	st := m.status
	body := []string{
		"",
		" " + t.Green("✓") + " " + t.Heading("Vault ready"),
		" " + t.Mist(clean(st.Home)+"  ·  key in "+orDefault(st.KeyStore, "keychain")+"  ·  "+plural(st.Hosts, "host")),
	}
	if wz.err != "" {
		body = append(body, "", " "+t.Warn(wz.err), " "+t.Mist("Run 'qbit-vault doctor' to see what is left to fix."))
	}
	body = append(body, "", " "+t.Frost("Next: add a secret."), " "+t.Mist("The value is typed in a hidden prompt, never here."))
	return "Done", body, [][2]string{kv("a", "add a secret"), kv("enter", "go to the vault"), kv("ctrl+c", "quit")}
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func isUp(k tea.KeyMsg) bool   { return k.Type == tea.KeyUp || isRune(k, 'k') }
func isDown(k tea.KeyMsg) bool { return k.Type == tea.KeyDown || isRune(k, 'j') }
