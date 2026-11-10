// Package cli implements the qbit-vault command line (docs/CLI.md).
package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/qbitdevz/qbit-vault/internal/exitcode"
	"github.com/qbitdevz/qbit-vault/internal/refusal"
)

// Set by ldflags at release time.
var (
	Version = "dev"
	Commit  = "unknown"
)

const (
	envHome    = "QBIT_VAULT_HOME"
	envSession = "QBIT_VAULT_SESSION"
	envNoColor = "NO_COLOR"
)

var sessionRE = regexp.MustCompile(`^[a-z0-9-]+:[A-Za-z0-9._-]{4,128}$`)

// globals holds the persistent flags shared by every command.
type globals struct {
	getenv func(string) string
	stderr io.Writer // for test prompt backends that play the terminal
	// execStdin, when set, is the stdin of an exec child instead of ours.
	execStdin io.Reader
	// cwd is the working directory of a broker call (its envelope's cwd);
	// empty means the process's own, except in a broker call (broker).
	cwd     string
	broker  bool
	home    string
	JSON    bool
	Session string
	Quiet   bool
	NoColor bool
}

// Home returns the vault directory: --home, else $QBIT_VAULT_HOME, else
// ~/.qbit-vault. It is resolved lazily so commands that do not need it
// never touch the user's home directory.
func (g *globals) Home() string {
	if g.home != "" {
		return g.home
	}
	if h := g.getenv(envHome); h != "" {
		return h
	}
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".qbit-vault")
	}
	return ".qbit-vault"
}

// NoColorEnabled reports whether colored output must be suppressed.
func (g *globals) NoColorEnabled() bool {
	return g.NoColor || g.getenv(envNoColor) != ""
}

// Usage errors are fixed strings: they never include user-supplied text, so
// a secret pasted by mistake as a command, flag or argument is not echoed.
type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

// Execute runs the CLI and returns the process exit code.
func Execute(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	return execute(args, stdout, stderr, getenv)
}

// execute is Execute plus extra commands, which tests use to inject probes.
func execute(args []string, stdout, stderr io.Writer, getenv func(string) string, extra ...func(*globals) *cobra.Command) (code int) {
	g := &globals{getenv: getenv, stderr: stderr}

	defer func() {
		// Never print the panic value: it could hold a secret.
		if recover() != nil {
			code = report(stdout, stderr, g.JSON || jsonRequested(args), "internal", "internal error", exitcode.Failure)
		}
	}()

	entered := false
	root := newRoot(g, &entered)
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	for _, mk := range extra {
		root.AddCommand(mk(g))
	}

	err := root.Execute()
	if err == nil {
		return exitcode.OK
	}
	asJSON := g.JSON || jsonRequested(args)
	var (
		ue usageError
		rf refusal.Refusal
		ce codedError
		xe exitError
	)
	switch {
	case errors.As(err, &xe):
		return xe.code
	case errors.As(err, &ue):
		return report(stdout, stderr, asJSON, "usage", ue.msg, exitcode.Usage)
	case errors.As(err, &rf):
		code = reportRefusal(stdout, stderr, asJSON, rf)
		g.recordRefusal(stderr, rf)
		return code
	case errors.As(err, &ce):
		return report(stdout, stderr, asJSON, ce.code, ce.msg, ce.exit)
	case !entered:
		// Any other failure before the command ran is cobra's parse error.
		// Its text can embed the user's input, so it is never shown.
		return report(stdout, stderr, asJSON, "usage", "invalid usage", exitcode.Usage)
	default:
		return report(stdout, stderr, asJSON, "internal", err.Error(), exitcode.Failure)
	}
}

// jsonRequested covers failures that happen before --json has been parsed.
func jsonRequested(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if a == "--json" || a == "--json=true" {
			return true
		}
	}
	return false
}

func report(stdout, stderr io.Writer, asJSON bool, code, msg string, exit int) int {
	if asJSON {
		_ = writeJSON(stdout, errorBody{OK: false, Error: errorDetail{Code: code, Message: msg}})
		return exit
	}
	fmt.Fprintf(stderr, "error: %s\n", msg)
	if code == "usage" {
		fmt.Fprintln(stderr, "Run 'qbit-vault --help' for usage.")
	}
	return exit
}

type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type errorBody struct {
	OK    bool        `json:"ok"`
	Error errorDetail `json:"error"`
}

type versionBody struct {
	OK      bool   `json:"ok"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Go      string `json:"go"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

func writeJSON(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

func newRoot(g *globals, entered *bool) *cobra.Command {
	root := &cobra.Command{
		Use:           "qbit-vault",
		Short:         "Local secrets broker for coding agents",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(*cobra.Command, []string) error {
			if g.Session != "" && !sessionRE.MatchString(g.Session) {
				return usageError{"invalid --session: must match " + sessionRE.String()}
			}
			*entered = true
			return nil
		},
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				return usageError{"unknown command"}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if g.JSON {
				return usageError{"no command given"}
			}
			if g.wantTUI() {
				return g.startTUI(false)
			}
			return cmd.Help()
		},
	}
	root.CompletionOptions.DisableDefaultCmd = true
	root.SetFlagErrorFunc(flagUsageError)

	f := root.PersistentFlags()
	f.StringVar(&g.home, "home", "", "vault directory (default $"+envHome+" or ~/.qbit-vault)")
	f.BoolVar(&g.JSON, "json", false, "machine output: exactly one JSON object on stdout")
	f.StringVar(&g.Session, "session", g.getenv(envSession), "host session id (default $"+envSession+")")
	f.BoolVar(&g.Quiet, "quiet", false, "suppress non-essential output")
	f.BoolVar(&g.NoColor, "no-color", false, "disable colored output (also honors "+envNoColor+")")

	root.AddCommand(newVersion(g))
	root.AddCommand(newInit(g), newSync(g), newUninstall(g), newDoctor(g))
	root.AddCommand(newSet(g), newRm(g), newDescribe(g), newEdit(g), newList(g), newMv(g), newRelink(g))
	root.AddCommand(newGrant(g), newRevoke(g), newGrantsList(g))
	root.AddCommand(newAudit(g))
	root.AddCommand(newExec(g))
	root.AddCommand(newPromptCmd(g))
	root.AddCommand(newLock(g), newUnlock(g), newRestore(g), newRekey(g), newImport(g), newExport(g))
	root.AddCommand(newBrokerCmd(g), newMCPCmd(g), newHookCmd(g), newLink(g))
	root.AddCommand(newRemote(g))
	root.AddCommand(newTUI(g))
	return root
}

var (
	invalidArgRE = regexp.MustCompile(`for "(?:-[A-Za-z0-9], )?--([A-Za-z0-9][A-Za-z0-9-]*)" flag: `)
	needsArgRE   = regexp.MustCompile(`^flag needs an argument: --([A-Za-z0-9][A-Za-z0-9-]*)$`)
)

// flagUsageError maps pflag's parse errors, which quote the offending input,
// to fixed messages. A flag name is shown only when it is a defined flag.
func flagUsageError(cmd *cobra.Command, err error) error {
	msg := err.Error()
	help := "; see '" + cmd.CommandPath() + " --help'"
	switch {
	case strings.HasPrefix(msg, "unknown flag"), strings.HasPrefix(msg, "unknown shorthand flag"):
		return usageError{"unknown flag" + help}
	case strings.HasPrefix(msg, "invalid argument "):
		if m := invalidArgRE.FindAllStringSubmatch(msg, -1); len(m) > 0 {
			if name := m[len(m)-1][1]; cmd.Flag(name) != nil {
				return usageError{"invalid value for --" + name + help}
			}
		}
	case strings.HasPrefix(msg, "flag needs an argument"):
		if m := needsArgRE.FindStringSubmatch(msg); m != nil && cmd.Flag(m[1]) != nil {
			return usageError{"invalid value for --" + m[1] + help}
		}
	}
	return usageError{"invalid flag usage" + help}
}

func noArgs(_ *cobra.Command, args []string) error {
	if len(args) > 0 {
		return usageError{"unexpected arguments"}
	}
	return nil
}

func newVersion(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			if g.JSON {
				return writeJSON(out, versionBody{
					OK: true, Version: Version, Commit: Commit,
					Go: runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH,
				})
			}
			_, err := fmt.Fprintf(out, "qbit-vault %s (%s, %s/%s)\n", Version, Commit, runtime.GOOS, runtime.GOARCH)
			return err
		},
	}
}
