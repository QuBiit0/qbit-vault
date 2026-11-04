package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/QuBiit0/gentle-vault/internal/audit"
	"github.com/QuBiit0/gentle-vault/internal/dumpguard"
	"github.com/QuBiit0/gentle-vault/internal/grants"
	"github.com/QuBiit0/gentle-vault/internal/redact"
	"github.com/QuBiit0/gentle-vault/internal/refusal"
	"github.com/QuBiit0/gentle-vault/internal/runner"
	"github.com/QuBiit0/gentle-vault/internal/secret"
	"github.com/QuBiit0/gentle-vault/internal/vault"
)

const (
	maxExecSecrets  = 16
	maxCommandBytes = 16 << 10
	minExecTimeout  = time.Second
	maxExecTimeout  = time.Hour
	// auditCommandLimit bounds the command text kept in an audit record so a
	// line always fits the 64 KiB window the audit writer reads back, even
	// when every byte is JSON-escaped.
	auditCommandLimit = 2048
	// exitInterrupted is the exit code after SIGINT or SIGTERM (128+2).
	exitInterrupted = 130
)

const (
	outcomeStarted  = "started"
	outcomeFinished = "finished"
	outcomeError    = "error"
)

// builtins are shell builtins that start no process of their own; they do not
// count against a binaries allowlist (L3).
var builtins = map[string]bool{
	"cd": true, "pushd": true, "popd": true, "true": true, "false": true, ":": true, "exit": true,
	"test": true, "[": true, "[[": true, "export": true, "unset": true, "shift": true,
}

// execSecret maps a vault secret to the variable the child sees.
type execSecret struct{ env, name string }

// parseSecretFlag reads NAME or ENV=NAME (docs/CLI.md § Exec).
func parseSecretFlag(v string) (execSecret, bool) {
	env, name, found := strings.Cut(v, "=")
	if !found {
		env, name = v, v
	}
	if !vault.ValidName(env) || !vault.ValidName(name) {
		return execSecret{}, false
	}
	return execSecret{env: env, name: name}, true
}

type execFlags struct {
	secrets []string
	timeout time.Duration
	shell   string
	cwd     string
	stream  bool
}

// execPlan is a validated invocation.
type execPlan struct {
	secrets []execSecret
	names   []string // distinct vault names, in the order given
	command string
	timeout time.Duration
	shell   runner.Shell
	dir     string // canonical working directory
}

func newExec(g *globals) *cobra.Command {
	var f execFlags
	cmd := &cobra.Command{
		Use:   "exec --session S --secret [ENV=]NAME ... [--timeout 10m] [--shell auto|sh|bash|cmd|pwsh] [--cwd DIR] [--stream] -- <command...>",
		Short: "Run a command with granted secrets injected into that child only",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			plan, err := g.planExec(cmd, args, f)
			if err != nil {
				return err
			}
			return g.runExec(cmd, plan, f.stream)
		},
	}
	fl := cmd.Flags()
	fl.StringArrayVar(&f.secrets, "secret", nil, "secret to inject, NAME or ENV=NAME (repeatable, at most 16)")
	fl.DurationVar(&f.timeout, "timeout", 10*time.Minute, "wall-clock limit, 1s to 1h")
	fl.StringVar(&f.shell, "shell", "auto", "auto, sh, bash, cmd or pwsh")
	fl.StringVar(&f.cwd, "cwd", "", "working directory (default: the current one)")
	fl.BoolVar(&f.stream, "stream", false, "with --json, print NDJSON chunks as the output arrives")
	return cmd
}

// planExec validates everything that needs no vault.
func (g *globals) planExec(cmd *cobra.Command, args []string, f execFlags) (execPlan, error) {
	var p execPlan
	if g.Session == "" {
		return p, usageError{"--session is required"}
	}
	switch n := len(f.secrets); {
	case n == 0:
		return p, usageError{"at least one --secret is required"}
	case n > maxExecSecrets:
		return p, usageError{"at most 16 --secret flags"}
	}
	seenEnv, seenName := map[string]bool{}, map[string]bool{}
	for _, raw := range f.secrets {
		s, ok := parseSecretFlag(raw)
		if !ok {
			return p, usageError{"invalid --secret: use NAME or ENV=NAME with valid names"}
		}
		if seenEnv[s.env] {
			return p, usageError{"duplicate environment variable in --secret"}
		}
		seenEnv[s.env] = true
		p.secrets = append(p.secrets, s)
		if !seenName[s.name] {
			seenName[s.name] = true
			p.names = append(p.names, s.name)
		}
	}
	if f.timeout < minExecTimeout || f.timeout > maxExecTimeout {
		return p, usageError{"invalid --timeout: must be between 1s and 1h"}
	}
	p.timeout = f.timeout
	switch sh := runner.Shell(f.shell); sh {
	case runner.ShellAuto, runner.ShellSh, runner.ShellBash, runner.ShellCmd, runner.ShellPwsh:
		if err := runner.CheckShell(sh); err != nil {
			return p, usageError{"shell not available on this system"}
		}
		p.shell = sh
	default:
		return p, usageError{"invalid --shell: must be auto, sh, bash, cmd or pwsh"}
	}
	dash := cmd.ArgsLenAtDash()
	switch {
	case dash < 0:
		return p, usageError{"missing command: put it after --"}
	case dash > 0:
		return p, usageError{"unexpected arguments"}
	}
	// The words after -- are joined with single spaces and handed to the
	// shell as one command; they are not re-quoted.
	p.command = strings.Join(args, " ")
	if strings.TrimSpace(p.command) == "" || len(p.command) > maxCommandBytes {
		return p, usageError{"command must be 1 to 16384 bytes"}
	}
	dir := f.cwd
	if dir == "" {
		var err error
		if dir, err = getwd(); err != nil {
			return p, err
		}
	}
	abs, err := filepath.Abs(dir)
	if err == nil {
		abs, err = filepath.EvalSymlinks(abs)
	}
	if err != nil {
		return p, usageError{"invalid --cwd: not a directory"}
	}
	if fi, err := os.Stat(abs); err != nil || !fi.IsDir() {
		return p, usageError{"invalid --cwd: not a directory"}
	}
	p.dir = abs
	return p, nil
}

// foldPath mirrors the vault's root canonicalization for a directory that is
// not inside a repository.
func foldPath(p string) string {
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		return strings.ToLower(p)
	}
	return p
}

// auditExec appends an exec record. Exec records carry no `by`: the actor is
// the host's session, not the user at a keyboard.
func (g *globals) auditExec(r audit.Record) error {
	if r.Session == "" {
		r.Session = g.Session
	}
	if r.Session == "" {
		r.Session = cliSession
	}
	return audit.Append(g.Home(), r)
}

// grantGate evaluates the grants of every injected record (STORAGE.md §
// Grants evaluation) and refuses with the first missing one. With a nil
// started it only looks: nothing is consumed or written. With a started
// record it consumes the once grants and appends that record inside the
// grants lock (L2, L7), so a failed append consumes nothing and nothing runs.
func (g *globals) grantGate(stderr io.Writer, s *session, recs []vault.Entry, cwd string, started *audit.Record) error {
	return g.mutateGrants(stderr, s, func(st *grants.Store) (bool, error) {
		work := &grants.Store{
			Grants: append([]grants.Grant(nil), st.Grants...),
			Tokens: append([]grants.Token(nil), st.Tokens...),
		}
		now, mutated := clock(), false
		for _, e := range recs {
			d, m := grants.Check(work, e.Name, e.Layer.Key(), e.Record.ID, e.Record.Sensitive, g.Session, cwd, now)
			mutated = mutated || m
			if !d.Allowed {
				return false, refusal.New(refusal.GrantRequired, e.Name)
			}
		}
		if started == nil {
			return false, nil
		}
		if err := g.auditExec(*started); err != nil {
			return false, refusal.New(refusal.Internal, "")
		}
		st.Grants, st.Tokens = work.Grants, work.Tokens
		return mutated, nil
	})
}

// truncateUTF8 cuts s to at most n bytes on a character boundary.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "...[truncated]"
}

func (g *globals) runExec(cmd *cobra.Command, p execPlan, stream bool) error {
	stdout, stderr := cmd.OutOrStdout(), cmd.ErrOrStderr()
	s, err := g.openSession()
	if err != nil {
		return err
	}
	defer s.close()

	// 1. Resolve every secret from the working directory (S6).
	byName := map[string]vault.Entry{}
	var recs []vault.Entry
	defer func() { wipeEntries(recs) }()
	for _, name := range p.names {
		e, err := findEntry(s, name, layerFlags{}, p.dir)
		if err != nil {
			return err
		}
		recs = append(recs, e)
		byName[name] = e
	}
	root, ok, err := vault.ProjectRoot(p.dir)
	if err != nil {
		return mapErr(err, "")
	}
	grantCwd := foldPath(p.dir)
	if ok {
		grantCwd = root
	}

	// 2. Grants, without consuming anything yet.
	if err := g.grantGate(stderr, s, recs, grantCwd, nil); err != nil {
		return err
	}

	// 3. Dump guard, over the names the child will see.
	guard, err := dumpguard.Load(g.Home())
	if err != nil {
		var pe *dumpguard.ParseError
		if errors.As(err, &pe) && pe.Line > 0 {
			return refusal.New(refusal.Internal, "").WithMessage(fmt.Sprintf("dumpguard.yaml is invalid at line %d", pe.Line))
		}
		return refusal.New(refusal.Internal, "").WithMessage("dumpguard.yaml cannot be read")
	}
	injected := make([]string, len(p.secrets))
	for i, sc := range p.secrets {
		injected[i] = sc.env
	}
	// cmd and pwsh quote and separate differently from POSIX, which is what
	// Segments models: the raw text is tested as well (F1).
	eff := runner.Resolve(p.shell)
	foreign := eff == runner.ShellCmd || eff == runner.ShellPwsh
	if guard.Match(p.command, injected) || (foreign && guard.MatchRaw(p.command, injected)) {
		return refusal.New(refusal.DumpCommand, "")
	}

	// 4. Binary allowlist: every program the shell may start (L3).
	programs := dumpguard.Binaries(p.command)
	if foreign {
		// Fail closed: the segments above follow POSIX grammar, so under cmd
		// or pwsh an allowlist only admits one simple command (F1).
		prog, simple := dumpguard.SimpleProgram(string(eff), p.command)
		programs = []string{prog}
		for _, e := range recs {
			if len(e.Record.Binaries) > 0 && !simple {
				return refusal.New(refusal.ScopeBinary, e.Name)
			}
		}
	}
	for _, e := range recs {
		if len(e.Record.Binaries) == 0 {
			continue
		}
		allowed := map[string]bool{}
		for _, b := range e.Record.Binaries {
			allowed[dumpguard.ProgramName(b)] = true
		}
		for _, prog := range programs {
			if prog == dumpguard.Ambiguous || (!builtins[prog] && !allowed[prog]) {
				return refusal.New(refusal.ScopeBinary, e.Name)
			}
		}
	}

	// 5. Hosts are advisory (R-EXEC-08): the audit notes it, the run goes on.
	hostsWarning := false
	for _, e := range recs {
		hostsWarning = hostsWarning || hostsOutside(p.command, e.Record.Hosts)
	}

	// 6. Redactor over every injected value.
	values := make([]secret.Secret, len(recs))
	for i, e := range recs {
		values[i] = e.Record.Value
	}
	red, err := redact.New(values)
	if err != nil {
		return refusal.New(refusal.Internal, "")
	}
	defer red.Wipe()
	for _, n := range red.Warnings() {
		g.record(stderr, audit.Record{Event: audit.EventWarning, Names: []string{n}, Detail: "short value"})
	}
	shown, _ := red.Bytes([]byte(p.command))
	if shown == nil {
		return refusal.New(refusal.Internal, "")
	}

	// 7. Consume once grants and append the started record, fail-closed (L2).
	rec := audit.Record{
		Event: audit.EventExec, Names: p.names, Layer: sharedLayer(recs), Cwd: p.dir,
		Command: truncateUTF8(string(shown), auditCommandLimit), Outcome: outcomeStarted,
	}
	if hostsWarning {
		rec.Detail = "hosts warning"
	}
	if err := g.grantGate(stderr, s, recs, grantCwd, &rec); err != nil {
		return err
	}

	// 8. Run.
	spec := runner.Spec{
		Command: p.command, Shell: p.shell, Dir: p.dir, Timeout: p.timeout, Redactor: red,
		Env: map[string]secret.Secret{},
	}
	for _, sc := range p.secrets {
		spec.Env[sc.env] = byName[sc.name].Record.Value
	}
	spec.ScrubNames, err = g.vaultNames(s)
	if err != nil {
		return err
	}
	if stdinOverride != nil {
		spec.Stdin = stdinOverride
	}
	if g.execStdin != nil {
		// The broker's own stdin is the request (or the MCP stream): the
		// child never inherits it.
		spec.Stdin = g.execStdin
	}
	captured := g.JSON && !stream
	switch {
	case !g.JSON:
		spec.Stdout, spec.Stderr = stdout, stderr
	case stream:
		w := newChunkWriters(stdout)
		spec.Stdout, spec.Stderr = w.stdout, w.stderr
	}
	ctx, stop := signal.NotifyContext(commandContext(cmd), os.Interrupt, syscall.SIGTERM)
	defer stop()
	res, runErr := runner.Run(ctx, spec)

	// 9. The finished record is best effort.
	fin := audit.Record{
		Event: audit.EventExec, Names: p.names, Layer: rec.Layer, Outcome: outcomeFinished,
		ExitCode: &res.ExitCode, Redactions: res.Redactions,
	}
	ms := res.Duration.Milliseconds()
	fin.DurationMS = &ms
	switch {
	case res.TimedOut:
		fin.Detail = "timeout"
	case runErr != nil && errors.Is(runErr, context.Canceled):
		fin.Detail = "interrupted"
	case runErr != nil:
		fin.Outcome = outcomeError
	}
	if err := g.auditExec(fin); err != nil {
		_, _ = io.WriteString(stderr, auditWriteWarning)
	}

	// 10. Report.
	switch {
	case errors.Is(runErr, context.Canceled):
		return exitError{exitInterrupted}
	case runErr != nil:
		return refusal.New(refusal.Internal, "")
	case res.TimedOut:
		rf := refusal.New(refusal.Timeout, "")
		if captured {
			rf = rf.WithPartial(res.Stdout, res.Stderr)
		}
		return rf
	}
	switch {
	case captured:
		err = writeJSON(stdout, execBody{
			OK: true, ExitCode: res.ExitCode, Stdout: res.Stdout, Stderr: res.Stderr,
			DurationMS: ms, Redactions: res.Redactions, Truncated: res.Truncated,
		})
	case g.JSON:
		err = writeJSON(stdout, execFinal{ExitCode: res.ExitCode, DurationMS: ms, Redactions: res.Redactions})
	}
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return exitError{res.ExitCode}
	}
	return nil
}

// sharedLayer is the layer every record lives in, or "" when they differ.
func sharedLayer(recs []vault.Entry) string {
	layer := ""
	for i, e := range recs {
		k := auditLayer(e.Layer)
		if i > 0 && k != layer {
			return ""
		}
		layer = k
	}
	return layer
}

// vaultNames lists every secret name in the vault: all of them are removed
// from the child's inherited environment (R-EXEC-01).
func (g *globals) vaultNames(s *session) ([]string, error) {
	all, err := s.v.ListAll()
	if err != nil {
		return nil, mapErr(err, "")
	}
	defer wipeEntries(all)
	seen := map[string]bool{}
	var names []string
	for _, e := range all {
		if !seen[e.Name] {
			seen[e.Name] = true
			names = append(names, e.Name)
		}
	}
	return names, nil
}

func commandContext(cmd *cobra.Command) context.Context {
	if ctx := cmd.Context(); ctx != nil {
		return ctx
	}
	return context.Background()
}
