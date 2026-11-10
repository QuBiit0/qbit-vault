package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/qbitdevz/qbit-vault/internal/audit"
	"github.com/qbitdevz/qbit-vault/internal/broker"
	"github.com/qbitdevz/qbit-vault/internal/grants"
	"github.com/qbitdevz/qbit-vault/internal/keychain"
	"github.com/qbitdevz/qbit-vault/internal/refusal"
	"github.com/qbitdevz/qbit-vault/internal/runner"
	"github.com/qbitdevz/qbit-vault/internal/vault"
)

// newBrokerCmd is the raw contract call of docs/CLI.md § Host plumbing: one
// envelope on stdin, one JSON object on stdout. It is the host transport,
// used by the Pi extension; `grant` still needs a prompt token there.
func newBrokerCmd(g *globals) *cobra.Command {
	var op string
	cmd := &cobra.Command{
		Use:    "broker --op OP",
		Short:  "Raw contract call: envelope on stdin, one JSON object on stdout (host plumbing)",
		Args:   noArgs,
		Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			raw, err := io.ReadAll(io.LimitReader(stdinOf(cmd), broker.MaxRequestBytes+1))
			var out []byte
			switch {
			case err != nil:
				out = refusalLine(refusal.New(refusal.Internal, "").WithMessage("invalid request: unreadable"))
			case broker.Op(raw) != op:
				out = refusalLine(refusal.New(refusal.Internal, "").WithMessage("invalid request: op"))
			default:
				out = broker.Handle(commandContext(cmd), raw, &cliBackend{g: g}, broker.TransportHost)
			}
			if _, err := cmd.OutOrStdout().Write(out); err != nil {
				return err
			}
			return exitError{responseExit(out)}
		},
	}
	cmd.Flags().StringVar(&op, "op", "", "the envelope's op")
	return cmd
}

func refusalLine(r refusal.Refusal) []byte {
	b, _ := json.Marshal(r.Envelope())
	return append(b, '\n')
}

// responseExit is 0 for a success and the refusal's exit code otherwise.
func responseExit(out []byte) int {
	var r refusal.Envelope
	var ok struct {
		OK bool `json:"ok"`
	}
	if json.Unmarshal(out, &ok) == nil && ok.OK {
		return 0
	}
	if json.Unmarshal(out, &r) != nil {
		return refusal.New(refusal.Internal, "").ExitCode()
	}
	return r.Refusal.ExitCode()
}

// cliBackend implements broker.Backend with the command code. Each call gets
// its own globals bound to the envelope's session; layers and grants are
// resolved from the envelope's cwd, never the process one.
type cliBackend struct{ g *globals }

// Refused audits a refusal answered over the broker or MCP exactly like a CLI
// refusal (cli.go): event `refusal`, the reason code, the secret name when
// the refusal carries a valid one, and the envelope's session. The actor is
// the agent's host, not the user at a keyboard. Never the command, the
// reason or any value; an audit failure changes nothing (best effort).
func (b *cliBackend) Refused(e broker.Envelope, rf refusal.Refusal) {
	r := audit.Record{Event: audit.EventRefusal, Session: e.Session, By: "agent", Refusal: string(rf.Type)}
	if rf.Name != nil {
		r.Names = []string{*rf.Name}
	}
	_ = audit.Append(b.g.Home(), r)
}

// bound is hot plus a pull first: it is what the operations that read for
// the agent (list, request) start with, so the answer reflects the other
// devices (REMOTE_SYNC § 7.1). exec, grant, revoke and manage use hot.
func (b *cliBackend) bound(e broker.Envelope) *globals {
	c := b.hot(e)
	c.pullFirst(context.Background())
	return c
}

func (b *cliBackend) hot(e broker.Envelope) *globals {
	c := *b.g
	c.Session, c.JSON, c.cwd, c.broker = e.Session, true, e.Cwd, true
	c.execStdin = bytes.NewReader(nil)
	return &c
}

// asRefusal maps what the command code returns to a contract refusal.
func asRefusal(err error) error {
	var (
		rf refusal.Refusal
		ue usageError
		ce codedError
	)
	switch {
	case err == nil:
		return nil
	case errors.As(err, &rf):
		return rf
	case errors.As(err, &ue):
		return refusal.New(refusal.Internal, "").WithMessage(ue.msg)
	case errors.As(err, &ce):
		if ce.code == "cancelled" {
			return refusal.New(refusal.UserDeclined, "")
		}
		return refusal.New(refusal.Internal, "").WithMessage(ce.msg)
	default:
		return refusal.New(refusal.Internal, "")
	}
}

func quiet() *cobra.Command {
	c := &cobra.Command{}
	c.SetOut(io.Discard)
	c.SetErr(io.Discard)
	return c
}

var contractBackends = map[string]bool{"pi-ui": true, "osascript": true, "powershell": true, "zenity": true, "kdialog": true, "tty": true}

func (b *cliBackend) Info() broker.Info {
	info := broker.Info{Streaming: true, PromptBackends: []string{}}
	if mode, err := keychain.ModeOf(b.g.Home(), keychain.Options{}); err == nil {
		info.Keychain = string(mode)
	}
	// Only names the contract knows (capabilities.prompt_backends enum).
	if p, err := b.g.backend(); err == nil && contractBackends[p.Name()] {
		info.PromptBackends = []string{p.Name()}
	}
	return info
}

func (b *cliBackend) List(_ context.Context, e broker.Envelope) (broker.ListResult, error) {
	g := b.bound(e)
	g.unlock.never = true // list never opens a dialog
	s, err := g.openSession()
	if err != nil {
		return broker.ListResult{}, asRefusal(lockedHint(err))
	}
	defer s.close()
	entries, err := s.v.List(e.Cwd)
	if err != nil {
		return broker.ListResult{}, asRefusal(mapErr(err, ""))
	}
	defer wipeEntries(entries)
	var st *grants.Store
	if _, err := s.v.ReadGrants(func(body []byte) error {
		var derr error
		st, derr = grants.Decode(body)
		return derr
	}); err != nil {
		return broker.ListResult{}, asRefusal(mapErr(err, ""))
	}
	res := broker.ListResult{Secrets: []broker.SecretMeta{}, Cooldowns: []broker.Cooldown{}}
	if proj, perr := vault.ProjectLayer(e.Cwd); perr == nil {
		res.Project = &broker.Project{Root: proj.Root, Label: proj.Label}
	}
	if label, ok, merr := s.v.UnlinkedMatch(e.Cwd); merr == nil && ok {
		res.Unlinked = &broker.UnlinkedMatch{Label: label}
	}
	now := clock()
	listCwd, _ := grantCwdOf(e.Cwd)
	for _, c := range grants.Cooldowns(st, e.Session, now) {
		res.Cooldowns = append(res.Cooldowns, broker.Cooldown{Name: c.Name, Until: c.Until.UTC().Format(time.RFC3339)})
	}
	for _, en := range entries {
		meta := broker.SecretMeta{
			Name: en.Name, Layer: layerName(en.Layer), OverridesGlobal: en.OverridesGlobal, Kind: kindOf(en.Record),
			Description: en.Record.Description, Sensitive: en.Record.Sensitive,
			Binaries: nonNil(en.Record.Binaries), Hosts: nonNil(en.Record.Hosts),
			CreatedAt: en.Record.CreatedAt, UpdatedAt: en.Record.UpdatedAt,
		}
		meta.Grant, meta.GrantNote = listedGrant(st, en, e.Session, listCwd, now)
		res.Secrets = append(res.Secrets, meta)
	}
	return res, nil
}

// listedGrant is the grant exec would accept for this record from here
// (grants.Lookup: the predicate of grants.Check, without consuming), and, when
// a grant exists but does not apply, a note the agent can act on (issue #42).
func listedGrant(st *grants.Store, en vault.Entry, session, cwd string, now time.Time) (*broker.GrantInfo, string) {
	gr, why := grants.Lookup(st, en.Name, en.Layer.Key(), en.Record.ID, en.Record.Sensitive, session, cwd, now)
	if gr != nil {
		return &broker.GrantInfo{Scope: string(gr.Scope), ExpiresAt: expiryText(gr.ExpiresAt)}, ""
	}
	switch why {
	case grants.WhyOtherDirectory:
		return nil, broker.NoteOtherDirectory
	case grants.WhyOtherRecord:
		return nil, broker.NoteOtherRecord
	}
	return nil, ""
}

func (b *cliBackend) Exec(ctx context.Context, e broker.Envelope, r broker.ExecRequest) (broker.ExecResponse, error) {
	g := b.hot(e)
	g.unlock.never = true // exec never opens a dialog: the user already said yes
	p := execPlan{command: r.Command, timeout: time.Duration(r.TimeoutMS) * time.Millisecond, shell: runner.Shell(r.Shell)}
	seen := map[string]bool{}
	for _, sc := range r.Secrets {
		p.secrets = append(p.secrets, execSecret{env: sc.Name, name: sc.From})
		if !seen[sc.From] {
			seen[sc.From] = true
			p.names = append(p.names, sc.From)
		}
	}
	if err := runner.CheckShell(p.shell); err != nil {
		return broker.ExecResponse{}, refusal.New(refusal.Internal, "").WithMessage("shell not available on this system")
	}
	dir, err := filepath.EvalSymlinks(e.Cwd)
	if err == nil {
		var fi os.FileInfo
		if fi, err = os.Stat(dir); err == nil && !fi.IsDir() {
			err = errors.New("not a directory")
		}
	}
	if err != nil {
		return broker.ExecResponse{}, refusal.New(refusal.Internal, "").WithMessage("invalid request: cwd")
	}
	p.dir = dir
	var out bytes.Buffer
	cmd := quiet()
	cmd.SetOut(&out)
	cmd.SetContext(ctx)
	if err := g.runExec(cmd, p, false); err != nil {
		var xe exitError
		if !errors.As(err, &xe) {
			return broker.ExecResponse{}, asRefusal(lockedHint(err))
		}
	}
	var res broker.ExecResponse
	if err := json.Unmarshal(out.Bytes(), &res); err != nil || !res.OK {
		return broker.ExecResponse{}, refusal.New(refusal.Internal, "")
	}
	return res, nil
}

func (b *cliBackend) Grant(ctx context.Context, e broker.Envelope, r broker.GrantRequest) (broker.GrantResponse, error) {
	g := b.hot(e)
	g.ctx = ctx
	g.unlock = agentUnlock{names: []string{r.Name}, layer: r.Layer}
	s, err := g.openSession()
	if err != nil {
		return broker.GrantResponse{}, asRefusal(err)
	}
	defer s.close()
	lf := layerFlags{global: r.Layer == "global", project: r.Layer == "project"}
	en, err := findEntry(s, r.Name, lf, e.Cwd)
	if err != nil {
		return broker.GrantResponse{}, asRefusal(err)
	}
	en.Record.Value.Wipe()
	scope, _ := grants.ParseScope(r.Scope)
	req := grants.Request{Name: r.Name, Layer: en.Layer.Key(), RecordID: en.Record.ID, Scope: scope,
		TTL: time.Duration(r.TTLMS) * time.Millisecond, Sensitive: en.Record.Sensitive}
	if scope != grants.ScopeProject {
		req.Session = e.Session
	}
	if err := grants.Validate(req); err != nil {
		return broker.GrantResponse{}, asRefusal(grantErr(err, r.Name))
	}
	cmd := quiet()
	hash, err := g.confirm(cmd, s, req, en.Layer, r.PromptToken, true)
	if err != nil {
		return broker.GrantResponse{}, asRefusal(err)
	}
	gr, err := g.create(cmd, s, req, hash)
	if err != nil {
		return broker.GrantResponse{}, asRefusal(err)
	}
	return broker.GrantResponse{OK: true, Grant: broker.GrantInfo{Scope: string(gr.Scope), ExpiresAt: expiryText(gr.ExpiresAt)}}, nil
}

func (b *cliBackend) Revoke(ctx context.Context, e broker.Envelope, r broker.RevokeRequest) (broker.RevokeResponse, error) {
	g := b.hot(e)
	g.ctx = ctx
	if r.Name != "" {
		g.unlock.names = []string{r.Name}
	}
	s, err := g.openSession()
	if err != nil {
		return broker.RevokeResponse{}, asRefusal(err)
	}
	defer s.close()
	n, err := g.revokeGrants(io.Discard, s, r.Name, "", r.All, r.SessionOnly)
	if err != nil {
		return broker.RevokeResponse{}, asRefusal(err)
	}
	return broker.RevokeResponse{OK: true, Revoked: n}, nil
}

// kindOf is a record's field kind; records stored before kinds are secret.
func kindOf(r vault.Record) string {
	if r.Kind == "" {
		return "secret"
	}
	return r.Kind
}
