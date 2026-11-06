package cli

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/exitcode"
	"github.com/QuBiit0/qbit-vault/internal/tui"
)

// rootHelpBeforeTUI is `qbit-vault --help` as captured before the tui command
// existed. The no-args behavior outside a terminal must stay byte-identical to
// it, except for the one new line in "Available Commands".
const rootHelpBeforeTUI = `Local secrets broker for coding agents

Usage:
  qbit-vault [flags]
  qbit-vault [command]

Available Commands:
  audit       Read the audit log or verify its hash chain
  describe    Show a secret's metadata (never its value)
  doctor      Read-only health report
  edit        Change a secret's metadata (never its value)
  exec        Run a command with granted secrets injected into that child only
  export      Write an encrypted, portable copy of the whole vault to FILE
  grant       Allow a secret to be injected (asks you to confirm)
  grants      List active grants
  help        Help about any command
  hook        Host hooks: read an event on stdin, answer on stdout (host plumbing)
  import      Import secrets from the environment, a dotenv file or an export
  init        Create an empty vault and register the coding-agent hosts
  link        Bind a project layer synced from another device to this repository
  list        List secret names and metadata (never values)
  lock        Passphrase mode: drop the cached master key
  mcp         Serve the four secret tools over stdio MCP (host plumbing)
  mv          Move a secret between the global layer and the current project
  prompt      Ask the user to allow a secret and print a prompt token (host plumbing)
  rekey       Rotate the master key
  relink      Repoint a project layer after moving or re-cloning a repository
  remote      Sync the vault between machines through qbit-vault-server
  restore     List encrypted backups or restore the vault from one
  revoke      Revoke grants
  rm          Delete a secret
  set         Store or replace a secret value (masked prompt, or --stdin)
  sync        Re-apply the recorded host registrations (not vault sync: see 'remote')
  uninstall   Revert the host registrations; with --purge also delete the vault
  unlock      Passphrase mode: ask the passphrase and refresh the cached master key
  version     Print version information

Flags:
  -h, --help             help for qbit-vault
      --home string      vault directory (default $QBIT_VAULT_HOME or ~/.qbit-vault)
      --json             machine output: exactly one JSON object on stdout
      --no-color         disable colored output (also honors NO_COLOR)
      --quiet            suppress non-essential output
      --session string   host session id (default $QBIT_VAULT_SESSION)

Use "qbit-vault [command] --help" for more information about a command.
`

const tuiHelpLine = "  tui         Open the interactive terminal UI\n"

// helpWithTUI inserts the tui line where cobra sorts it: after sync.
func helpWithTUI(t *testing.T) string {
	t.Helper()
	const after = "  sync        Re-apply the recorded host registrations (not vault sync: see 'remote')\n"
	if strings.Count(rootHelpBeforeTUI, after) != 1 {
		t.Fatal("baseline help changed shape")
	}
	return strings.Replace(rootHelpBeforeTUI, after, after+tuiHelpLine, 1)
}

// tuiProbe replaces the terminal check and the TUI runner for one test.
type tuiProbe struct {
	calls   int
	opts    tui.Options
	backend tui.Backend
	err     error
}

func probeTUI(t *testing.T, interactive bool) *tuiProbe {
	t.Helper()
	p := &tuiProbe{}
	oldTTY, oldRun := isInteractive, runTUI
	isInteractive = func() bool { return interactive }
	runTUI = func(b tui.Backend, o tui.Options) error {
		p.calls++
		p.backend, p.opts = b, o
		return p.err
	}
	t.Cleanup(func() { isInteractive, runTUI = oldTTY, oldRun })
	return p
}

func TestRootNoArgsOutsideATerminalPrintsTheUnchangedHelp(t *testing.T) {
	p := probeTUI(t, false)
	code, out, errs := run(t, nil)
	if code != exitcode.OK || errs != "" || out != helpWithTUI(t) {
		t.Fatalf("code=%d err=%q\nhelp differs from the baseline plus the tui line:\n%s", code, errs, out)
	}
	if p.calls != 0 {
		t.Error("the TUI started without a terminal")
	}
}

func TestRootHelpDiffersFromTheBaselineByExactlyTheTUILine(t *testing.T) {
	probeTUI(t, false)
	_, out, _ := run(t, nil, "--help")
	got, want := strings.Split(out, "\n"), strings.Split(rootHelpBeforeTUI, "\n")
	if len(got) != len(want)+1 {
		t.Fatalf("help has %d lines, baseline %d: exactly one line may be added", len(got), len(want))
	}
	extra := 0
	for i, j := 0, 0; i < len(got); i++ {
		if j < len(want) && got[i] == want[j] {
			j++
			continue
		}
		extra++
		if got[i]+"\n" != tuiHelpLine {
			t.Errorf("unexpected help line %q", got[i])
		}
	}
	if extra != 1 {
		t.Errorf("%d lines differ from the baseline, want 1", extra)
	}
}

func TestRootNoArgsJSONStaysAUsageErrorEvenInATerminal(t *testing.T) {
	p := probeTUI(t, true)
	code, out, errs := run(t, nil, "--json")
	wantCode, wantOut, wantErr := func() (int, string, string) {
		probeTUI(t, false)
		return run(t, nil, "--json")
	}()
	if code != exitcode.Usage || out != wantOut || errs != wantErr || !strings.Contains(out, `"message":"no command given"`) {
		t.Fatalf("code=%d (want %d) out=%q err=%q", code, wantCode, out, errs)
	}
	if p.calls != 0 {
		t.Error("--json must never open the TUI")
	}
}

func TestRootNoArgsHonorsNoTUIEnv(t *testing.T) {
	p := probeTUI(t, true)
	code, out, _ := run(t, map[string]string{"QBIT_VAULT_NO_TUI": "1"})
	if code != exitcode.OK || out != helpWithTUI(t) || p.calls != 0 {
		t.Fatalf("code=%d calls=%d: QBIT_VAULT_NO_TUI=1 must keep the help", code, p.calls)
	}
}

func TestRootNoArgsInATerminalOpensTheTUI(t *testing.T) {
	p := probeTUI(t, true)
	home := t.TempDir()
	code, out, errs := run(t, nil, "--home", home)
	if code != exitcode.OK || out != "" || errs != "" || p.calls != 1 {
		t.Fatalf("code=%d calls=%d out=%q err=%q", code, p.calls, out, errs)
	}
	if !p.opts.Profile.Color || p.opts.Version != Version {
		t.Errorf("options = %+v, want color on and version %q", p.opts, Version)
	}
	st, err := p.backend.Status()
	if err != nil || st.State != tui.StateNone || st.Home != home {
		t.Errorf("status = %+v, %v: --home was not honored", st, err)
	}
}

func TestTUICommandDropsColorOnRequest(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		args []string
	}{
		{"flag", nil, []string{"tui", "--no-color"}},
		{"NO_COLOR", map[string]string{"NO_COLOR": "1"}, []string{"tui"}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			p := probeTUI(t, true)
			if code, _, errs := run(t, tt.env, tt.args...); code != exitcode.OK || p.calls != 1 {
				t.Fatalf("code=%d calls=%d err=%q", code, p.calls, errs)
			}
			if p.opts.Profile.Color {
				t.Error("color is still on")
			}
		})
	}
}

func TestTUICommandRunsEvenWithNoTUIEnv(t *testing.T) {
	p := probeTUI(t, true)
	if code, _, _ := run(t, map[string]string{"QBIT_VAULT_NO_TUI": "1"}, "tui"); code != exitcode.OK || p.calls != 1 {
		t.Fatalf("code=%d calls=%d: the explicit command is not the no-args shortcut", code, p.calls)
	}
}

func TestTUICommandWithoutATerminalFailsInsteadOfHanging(t *testing.T) {
	p := probeTUI(t, false)
	code, out, errs := run(t, nil, "tui")
	if code != exitcode.Usage || out != "" || p.calls != 0 {
		t.Fatalf("code=%d calls=%d out=%q", code, p.calls, out)
	}
	if !strings.Contains(errs, "error: the TUI needs an interactive terminal") || !strings.HasSuffix(errs, helpHint) {
		t.Errorf("stderr = %q", errs)
	}
	code, out, errs = run(t, nil, "tui", "--json")
	if code != exitcode.Usage || errs != "" || !strings.Contains(out, `"code":"usage"`) || p.calls != 0 {
		t.Errorf("--json: code=%d out=%q err=%q", code, out, errs)
	}
}

func TestTUICommandRejectsArguments(t *testing.T) {
	p := probeTUI(t, true)
	if code, _, _ := run(t, nil, "tui", "extra"); code != exitcode.Usage || p.calls != 0 {
		t.Fatalf("code=%d calls=%d", code, p.calls)
	}
}

func TestTUIRunnerFailureIsReportedWithoutItsText(t *testing.T) {
	p := probeTUI(t, true)
	p.err = errors.New("terminal exploded: " + fixture)
	code, _, errs := run(t, nil, "tui")
	if code != exitcode.Failure || strings.Contains(errs, fixture) || !strings.Contains(errs, "the TUI stopped unexpectedly") {
		t.Fatalf("code=%d err=%q", code, errs)
	}
}

func TestTUIHelpDescribesTheCommand(t *testing.T) {
	probeTUI(t, false)
	_, out, _ := run(t, nil, "tui", "--help")
	for _, want := range []string{"Open the interactive terminal UI", "QBIT_VAULT_NO_TUI", "never shows a secret value", "--home"} {
		if !strings.Contains(out, want) {
			t.Errorf("tui help lacks %q:\n%s", want, out)
		}
	}
}

func TestTUIStatusBackend(t *testing.T) {
	t.Run("no vault", func(t *testing.T) {
		home := filepath.Join(t.TempDir(), "none")
		st, err := (&tuiBackend{g: &globals{getenv: envFrom(nil), home: home}}).Status()
		if err != nil || st.State != tui.StateNone || st.Home != home || st.Secrets != 0 || st.Hosts != 0 {
			t.Fatalf("status = %+v, err = %v", st, err)
		}
	})
}
