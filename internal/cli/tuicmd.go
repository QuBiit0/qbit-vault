package cli

import (
	"errors"
	"os"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/QuBiit0/qbit-vault/internal/exitcode"
	"github.com/QuBiit0/qbit-vault/internal/keychain"
	"github.com/QuBiit0/qbit-vault/internal/tui"
	"github.com/QuBiit0/qbit-vault/internal/vault"
)

const envNoTUI = "QBIT_VAULT_NO_TUI"

// isInteractive reports whether the process has a terminal on both stdin and
// stdout. It looks at the real file descriptors, not at the writers Execute was
// given; tests replace it.
var isInteractive = func() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

// runTUI shows the TUI on the process terminal; tests replace it.
var runTUI = func(b tui.Backend, o tui.Options) error {
	return tui.Run(b, o, os.Stdin, os.Stdout)
}

func newTUI(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "tui",
		Short: "Open the interactive terminal UI",
		Long: `Open the interactive terminal UI: first-run setup, then three panes (sections,
list, detail) to manage secrets, grants, hosts, the audit log and sync.

It needs a terminal on both stdin and stdout. The UI never shows a secret value:
it lists names, layers and status, and a value is only ever typed in the same
masked prompt the 'set' command uses.

Running 'qbit-vault' with no arguments opens it too, but only in a terminal and
not with --json or ` + envNoTUI + `=1; otherwise that prints the help.

--home picks the vault directory; --no-color (or NO_COLOR) drops all colors and
shows the plain wordmark instead of the mark.`,
		Args: noArgs,
		RunE: func(*cobra.Command, []string) error {
			if g.JSON {
				return usageError{"the TUI does not support --json"}
			}
			return g.startTUI(true)
		},
	}
}

// startTUI runs the TUI. explicit is false for the no-args shortcut, which has
// already checked for a terminal.
func (g *globals) startTUI(explicit bool) error {
	if explicit && !isInteractive() {
		return usageError{"the TUI needs an interactive terminal (stdin and stdout must be terminals)"}
	}
	opts := tui.Options{
		Version: Version,
		Profile: tui.Profile{Color: !g.NoColorEnabled(), TrueColor: g.trueColor()},
	}
	if err := runTUI(&tuiBackend{g: g}, opts); err != nil {
		// The runner's error text is not shown: nothing in it is worth a leak risk.
		return codedError{"internal", "the TUI stopped unexpectedly", exitcode.Failure}
	}
	return nil
}

// wantTUI is the no-args rule: open the TUI only for a person at a terminal.
func (g *globals) wantTUI() bool {
	return !g.JSON && g.getenv(envNoTUI) != "1" && isInteractive()
}

// trueColor guesses 24-bit color support: Windows terminals have it, elsewhere
// COLORTERM says so.
func (g *globals) trueColor() bool {
	ct := strings.ToLower(g.getenv("COLORTERM"))
	return runtime.GOOS == "windows" || ct == "truecolor" || ct == "24bit"
}

// tuiBackend gives the TUI the vault status. It carries counts and names of
// states only: no secret value ever leaves the session it opens here.
type tuiBackend struct{ g *globals }

func (b *tuiBackend) Status() (tui.Status, error) {
	home := b.g.Home()
	st := tui.Status{Home: home}
	if _, err := vault.ReadID(home); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return st, nil // no vault yet: StateNone
		}
		return tui.Status{}, err
	}
	if hs, err := vault.ReadHosts(home); err == nil {
		st.Hosts = len(hs)
	}
	s, err := b.g.openSessionQuiet()
	switch {
	case errors.Is(err, errSessionLocked):
		st.State, st.Secrets = tui.StateLocked, -1
		return st, nil
	case err != nil:
		return tui.Status{}, err
	}
	defer s.close()
	entries, err := s.v.ListAll()
	if err != nil {
		return tui.Status{}, err
	}
	st.Secrets = len(entries)
	wipeEntries(entries)
	st.State, st.KeyStore = tui.StateUnlocked, "keychain"
	if s.mode == keychain.ModePassphrase {
		st.KeyStore = "passphrase"
	}
	return st, nil
}
