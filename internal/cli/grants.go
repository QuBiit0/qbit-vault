package cli

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/QuBiit0/gentle-vault/internal/audit"
	"github.com/QuBiit0/gentle-vault/internal/grants"
	"github.com/QuBiit0/gentle-vault/internal/prompt"
	"github.com/QuBiit0/gentle-vault/internal/refusal"
	"github.com/QuBiit0/gentle-vault/internal/vault"
)

// clock is the time source of everything with a TTL; tests pin it.
var clock = time.Now

const grantsResetWarning = "warning: grants were reset (store unreadable or rolled back)\n"

// noteGrantsReset tells the user, and the audit log, that grants.enc could
// not be trusted and was treated as empty (L3).
func (g *globals) noteGrantsReset(stderr io.Writer, reset bool) {
	if !reset {
		return
	}
	_, _ = io.WriteString(stderr, grantsResetWarning)
	g.record(stderr, audit.Record{Event: audit.EventWarning, Detail: "grants reset"})
}

// newGrantsEditor builds the editor the record operations use; tests replace
// it to simulate a failed drop.
var newGrantsEditor = func() vault.GrantsEditor { return grantsEditor{} }

// grantsEditor drops and rewrites grants for the vault operations that
// change a record (rm, mv, set replace, edit --sensitive, relink). It adapts internal/grants to
// vault.GrantsEditor.
type grantsEditor struct{}

func (grantsEditor) DropRecord(body []byte, name, layer string) ([]byte, int, error) {
	return edit(body, func(st *grants.Store) int { return grants.DropRecord(st, name, layer) })
}

func (grantsEditor) DropNonOnce(body []byte, name, layer, recordID string) ([]byte, int, error) {
	return edit(body, func(st *grants.Store) int { return grants.DropNonOnce(st, name, layer, recordID) })
}

func (grantsEditor) DropLayer(body []byte, layer string) ([]byte, int, error) {
	return edit(body, func(st *grants.Store) int { return grants.DropLayer(st, layer) })
}

func edit(body []byte, fn func(*grants.Store) int) ([]byte, int, error) {
	st, err := grants.Decode(body)
	if err != nil {
		return nil, 0, err
	}
	n := fn(st)
	if n == 0 {
		return nil, 0, nil
	}
	out, err := grants.Encode(st)
	return out, n, err
}

// mutateGrants decodes the grants store, runs fn and persists the store when
// fn reports a change (or when an unreadable store has to be replaced). An
// error from fn is returned after its change was persisted, which is how a
// burnt prompt token stays burnt.
func (g *globals) mutateGrants(stderr io.Writer, s *session, fn func(*grants.Store) (changed bool, err error)) error {
	var fnErr error
	reset, err := s.v.MutateGrants(func(body []byte, reset bool) ([]byte, error) {
		st, err := grants.Decode(body)
		if err != nil {
			return nil, err
		}
		changed, ferr := fn(st)
		fnErr = ferr
		if !changed && !reset {
			return nil, nil
		}
		return grants.Encode(st)
	})
	g.noteGrantsReset(stderr, reset)
	if err != nil {
		return mapErr(err, "")
	}
	return fnErr
}

// recordStrict appends r to the audit log and fails when it cannot (L4).
func (g *globals) recordStrict(r audit.Record) error {
	if r.Session == "" {
		r.Session = g.Session
	}
	if r.Session == "" {
		r.Session = cliSession
	}
	r.By = "user"
	if err := audit.Append(g.Home(), r); err != nil {
		return refusal.New(refusal.Internal, "")
	}
	return nil
}

// grantErr maps a grants package failure to what the user sees.
func grantErr(err error, name string) error {
	switch {
	case errors.Is(err, grants.ErrNeedsProject):
		return refusal.New(refusal.ScopeNotAllowed, name).WithMessage("project scope needs a project secret")
	case errors.Is(err, grants.ErrScopeNotAllowed):
		return refusal.New(refusal.ScopeNotAllowed, name)
	case errors.Is(err, grants.ErrBadToken):
		return refusal.New(refusal.NotModelCallable, name)
	case errors.Is(err, grants.ErrInvalidTTL):
		return usageError{ttlHelp}
	case errors.Is(err, grants.ErrInvalidRequest):
		return usageError{"invalid grant request"}
	default:
		return err
	}
}

const ttlHelp = "invalid --ttl: must be between 1m and 24h"

// grantFlags are --scope, --ttl and --from-prompt-token (grant and set).
type grantFlags struct {
	scope string
	ttl   time.Duration
	token string
}

// parse validates the flags that need no vault. scope is already the parsed
// scope. session is the host session (--session), required except for the
// project scope.
func (gf grantFlags) parse(cmd *cobra.Command, scope, session string) (grants.Scope, time.Duration, error) {
	sc, ok := grants.ParseScope(scope)
	if !ok {
		return "", 0, usageError{"invalid scope: must be once, session or project"}
	}
	f := cmd.Flags()
	var ttl time.Duration
	if f.Lookup("ttl") != nil && f.Changed("ttl") {
		if sc != grants.ScopeSession {
			return "", 0, usageError{"--ttl applies to the session scope only"}
		}
		ttl = gf.ttl
		if ttl < grants.MinTTL || ttl > grants.MaxTTL {
			return "", 0, usageError{ttlHelp}
		}
	}
	if sc != grants.ScopeProject && session == "" {
		return "", 0, usageError{"--session is required for the once and session scopes"}
	}
	return sc, ttl, nil
}

// confirm obtains the explicit user action behind a grant (R-GRANT-03, L5):
// a valid prompt token, or a yes on the prompt backend (the controlling
// terminal, never stdin). Anything else is
// not_model_callable. It returns the hash of the token used, if any.
func (g *globals) confirm(cmd *cobra.Command, s *session, req grants.Request, layer vault.Layer, token string, tokenGiven bool) (string, error) {
	stderr := cmd.ErrOrStderr()
	if tokenGiven {
		var (
			hash string
			cerr error
		)
		err := g.mutateGrants(stderr, s, func(st *grants.Store) (bool, error) {
			before := len(st.Tokens)
			hash, cerr = grants.ConsumeToken(st, token, req.Name, req.Layer, req.RecordID, req.Scope, req.Session, req.TTL, clock())
			return len(st.Tokens) != before, nil
		})
		if err != nil {
			return "", err
		}
		if cerr != nil {
			return "", grantErr(cerr, req.Name)
		}
		return hash, nil
	}
	b, err := g.backend()
	if err != nil {
		if errors.Is(err, prompt.ErrUnavailable) {
			return "", refusal.New(refusal.NotModelCallable, req.Name)
		}
		return "", mapErr(err, "")
	}
	who := "this project"
	if req.Scope != grants.ScopeProject {
		who = req.Session
	}
	ok, err := b.Confirm(fmt.Sprintf("Grant %s (%s) to %s, scope %s?", req.Name, layerText(layer), who, req.Scope))
	switch {
	case errors.Is(err, prompt.ErrUnavailable):
		return "", refusal.New(refusal.NotModelCallable, req.Name)
	case err != nil && !errors.Is(err, prompt.ErrCancelled):
		return "", mapErr(err, "")
	case err != nil || !ok:
		return "", refusal.New(refusal.UserDeclined, req.Name)
	}
	return "", nil
}

// promptToken is the confirmation of a grant the user just asked for in an
// interactive prompt (set --grant): the choice itself is the explicit action.
// It issues a token and redeems it in the same step, so the grant is audited
// as a prompt-token grant like every other one the broker's own prompt makes.
func (g *globals) promptToken(cmd *cobra.Command, s *session, req grants.Request) (string, error) {
	var (
		hash string
		cerr error
	)
	err := g.mutateGrants(cmd.ErrOrStderr(), s, func(st *grants.Store) (bool, error) {
		now := clock()
		tok := grants.IssueToken(st, req.Name, req.Layer, req.RecordID, req.Scope, req.Session, req.TTL, now)
		hash, cerr = grants.ConsumeToken(st, tok, req.Name, req.Layer, req.RecordID, req.Scope, req.Session, req.TTL, now)
		return false, nil // issued and redeemed: the stored tokens do not change
	})
	if err != nil {
		return "", err
	}
	if cerr != nil {
		return "", grantErr(cerr, req.Name)
	}
	return hash, nil
}

// create persists the confirmed grant. The audit record is written first and
// a failed append stops the grant (L4).
func (g *globals) create(cmd *cobra.Command, s *session, req grants.Request, tokenHash string) (grants.Grant, error) {
	var out grants.Grant
	req.PromptTokenHash = tokenHash
	err := g.mutateGrants(cmd.ErrOrStderr(), s, func(st *grants.Store) (bool, error) {
		gr, err := grants.Add(st, req, clock())
		if err != nil {
			return false, grantErr(err, req.Name)
		}
		rec := audit.Record{Event: audit.EventGrant, Names: []string{req.Name}, Layer: req.Layer, Scope: string(req.Scope)}
		if gr.ExpiresAt != nil {
			rec.ExpiresAt = gr.ExpiresAt.Format(time.RFC3339)
		}
		rec.Detail = "terminal"
		if tokenHash != "" {
			rec.Detail = "prompt token"
		}
		if err := g.recordStrict(rec); err != nil {
			return false, err
		}
		out = gr
		return true, nil
	})
	return out, err
}

// grantOut is a grant as the CLI reports it.
type grantOut struct {
	Name      string  `json:"name"`
	Layer     string  `json:"layer"`
	Scope     string  `json:"scope"`
	Session   *string `json:"session"`
	ExpiresAt *string `json:"expires_at"`
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func expiryText(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.UTC().Format(time.RFC3339)
	return &s
}

func layerKind(layer string) string {
	if _, ok := grants.ProjectRootOf(layer); ok {
		return "project"
	}
	return "global"
}

func toGrantOut(gr grants.Grant) grantOut {
	return grantOut{
		Name: gr.Name, Layer: layerKind(gr.Layer), Scope: string(gr.Scope),
		Session: nullable(gr.Session), ExpiresAt: expiryText(gr.ExpiresAt),
	}
}

// grantText is "<scope>, session S, until TS" for human output.
func grantText(gr grants.Grant) string {
	var b strings.Builder
	b.WriteString(string(gr.Scope))
	if gr.Session != "" {
		b.WriteString(", for " + oneLine(gr.Session))
	}
	if gr.ExpiresAt != nil {
		b.WriteString(", until " + gr.ExpiresAt.UTC().Format(time.RFC3339))
	} else {
		b.WriteString(", until revoked")
	}
	return b.String()
}

type grantBody struct {
	OK    bool     `json:"ok"`
	Grant grantOut `json:"grant"`
}

func newGrant(g *globals) *cobra.Command {
	var (
		lf layerFlags
		gf grantFlags
	)
	cmd := &cobra.Command{
		Use:   "grant NAME [--global|--project] --scope once|session|project [--ttl 30m] [--from-prompt-token T]",
		Short: "Allow a secret to be injected (asks you to confirm)",
		Args:  nameArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if err := lf.validate(); err != nil {
				return err
			}
			if gf.scope == "" {
				return usageError{"choose --scope once, session or project"}
			}
			scope, ttl, err := gf.parse(cmd, gf.scope, g.Session)
			if err != nil {
				return err
			}
			if err := checkName(name); err != nil {
				return err
			}
			cwd, err := getwd()
			if err != nil {
				return err
			}
			s, err := g.openSession()
			if err != nil {
				return err
			}
			defer s.close()
			e, err := findEntry(s, name, lf, cwd)
			if err != nil {
				return err
			}
			e.Record.Value.Wipe()
			req := grants.Request{Name: name, Layer: e.Layer.Key(), RecordID: e.Record.ID, Scope: scope, TTL: ttl, Sensitive: e.Record.Sensitive}
			if scope != grants.ScopeProject {
				req.Session = g.Session
			}
			if err := grants.Validate(req); err != nil {
				return grantErr(err, name)
			}
			hash, err := g.confirm(cmd, s, req, e.Layer, gf.token, cmd.Flags().Changed("from-prompt-token"))
			if err != nil {
				return err
			}
			gr, err := g.create(cmd, s, req, hash)
			if err != nil {
				return err
			}
			if g.JSON {
				return writeJSON(cmd.OutOrStdout(), grantBody{OK: true, Grant: toGrantOut(gr)})
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "granted %s (%s): %s\n", name, layerText(e.Layer), grantText(gr))
			return err
		},
	}
	lf.bind(cmd)
	cmd.Flags().StringVar(&gf.scope, "scope", "", "once, session or project")
	cmd.Flags().DurationVar(&gf.ttl, "ttl", 0, "session scope lifetime, 1m to 24h (default 30m)")
	cmd.Flags().StringVar(&gf.token, "from-prompt-token", "", "confirm with a token issued by the prompt backend instead of a terminal")
	return cmd
}

type revokeBody struct {
	OK      bool `json:"ok"`
	Revoked int  `json:"revoked"`
}

func newRevoke(g *globals) *cobra.Command {
	var (
		lf          layerFlags
		all         bool
		sessionOnly bool
	)
	cmd := &cobra.Command{
		Use:   "revoke NAME [--global|--project] | --all | --session-only",
		Short: "Revoke grants",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) > 1 {
				return usageError{"unexpected arguments"}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := lf.validate(); err != nil {
				return err
			}
			modes := 0
			for _, on := range []bool{len(args) == 1, all, sessionOnly} {
				if on {
					modes++
				}
			}
			if modes != 1 {
				return usageError{"give exactly one of NAME, --all or --session-only"}
			}
			if len(args) == 0 && lf.explicit() {
				return usageError{"--global and --project apply to NAME only"}
			}
			if sessionOnly && g.Session == "" {
				return usageError{"--session-only requires --session"}
			}
			var name string
			if len(args) == 1 {
				name = args[0]
				if err := checkName(name); err != nil {
					return err
				}
			}
			layerKey := ""
			if lf.explicit() {
				cwd, err := getwd()
				if err != nil {
					return err
				}
				layer, err := lf.pick(cwd)
				if err != nil {
					return err
				}
				layerKey = layer.Key()
			}
			s, err := g.openSession()
			if err != nil {
				return err
			}
			defer s.close()

			n, err := g.revokeGrants(cmd.ErrOrStderr(), s, name, layerKey, all, sessionOnly)
			if err != nil {
				return err
			}
			if g.JSON {
				return writeJSON(cmd.OutOrStdout(), revokeBody{OK: true, Revoked: n})
			}
			noun := "grants"
			if n == 1 {
				noun = "grant"
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "revoked %d %s\n", n, noun)
			return err
		},
	}
	lf.bind(cmd)
	cmd.Flags().BoolVar(&all, "all", false, "revoke every grant")
	cmd.Flags().BoolVar(&sessionOnly, "session-only", false, "revoke the grants of --session only")
	return cmd
}

// revokeGrants drops grants by name (in layerKey, or every layer when it is
// empty), all of them, or those of g.Session, and audits it best effort.
func (g *globals) revokeGrants(stderr io.Writer, s *session, name, layerKey string, all, sessionOnly bool) (int, error) {
	var (
		n    int
		mode string
	)
	err := g.mutateGrants(stderr, s, func(st *grants.Store) (bool, error) {
		hadTokens := len(st.Tokens) > 0
		switch {
		case all:
			mode, n = "all", grants.RevokeAll(st)
			return n > 0 || hadTokens, nil
		case sessionOnly:
			mode, n = "session", grants.RevokeSession(st, g.Session)
		default:
			mode, n = "name", grants.RevokeName(st, name, layerKey)
		}
		return n > 0, nil
	})
	if err != nil {
		return 0, err
	}
	rec := audit.Record{Event: audit.EventRevoke, Layer: layerKey, Detail: fmt.Sprintf("%s revoked=%d", mode, n)}
	if name != "" {
		rec.Names = []string{name}
	}
	g.record(stderr, rec)
	return n, nil
}

type grantRow struct {
	Name      string      `json:"name"`
	Layer     string      `json:"layer"`
	Project   *projectRef `json:"project"`
	Scope     string      `json:"scope"`
	Session   *string     `json:"session"`
	ExpiresAt *string     `json:"expires_at"`
	Remaining *string     `json:"remaining"`
}

type grantsBody struct {
	OK     bool       `json:"ok"`
	Grants []grantRow `json:"grants"`
}

func remaining(gr grants.Grant, now time.Time) *string {
	if gr.ExpiresAt == nil {
		return nil
	}
	s := gr.ExpiresAt.Sub(now).Round(time.Second).String()
	return &s
}

// activeGrants purges what expired (persisting that) and returns the live
// grants, sorted.
func (g *globals) activeGrants(stderr io.Writer, s *session) (*grants.Store, []grants.Grant, error) {
	var (
		live []grants.Grant
		view *grants.Store
	)
	err := g.mutateGrants(stderr, s, func(st *grants.Store) (bool, error) {
		now := clock()
		changed := grants.Purge(st, now)
		live, view = grants.Active(st, now), st
		return changed, nil
	})
	return view, live, err
}

func newGrantsList(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "grants [--json]",
		Short: "List active grants",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := g.openSession()
			if err != nil {
				return err
			}
			defer s.close()
			_, live, err := g.activeGrants(cmd.ErrOrStderr(), s)
			if err != nil {
				return err
			}
			now := clock()
			out := cmd.OutOrStdout()
			if g.JSON {
				body := grantsBody{OK: true, Grants: []grantRow{}}
				for _, gr := range live {
					row := grantRow{
						Name: gr.Name, Layer: layerKind(gr.Layer), Scope: string(gr.Scope),
						Session: nullable(gr.Session), ExpiresAt: expiryText(gr.ExpiresAt), Remaining: remaining(gr, now),
					}
					if root, ok := grants.ProjectRootOf(gr.Layer); ok {
						row.Project = &projectRef{Root: root, Label: filepath.Base(root)}
					}
					body.Grants = append(body.Grants, row)
				}
				return writeJSON(out, body)
			}
			_, err = io.WriteString(out, grantsTable(live, now))
			return err
		},
	}
}

// grantsTable renders grants as an aligned table.
func grantsTable(live []grants.Grant, now time.Time) string {
	if len(live) == 0 {
		return "no active grants\n"
	}
	rows := [][6]string{{"NAME", "LAYER", "SCOPE", "SESSION", "EXPIRES", "REMAINING"}}
	for _, gr := range live {
		layer := "global"
		if root, ok := grants.ProjectRootOf(gr.Layer); ok {
			layer = "project:" + filepath.Base(root)
		}
		session, exp, rem := "-", "-", "-"
		if gr.Session != "" {
			session = gr.Session
		}
		if gr.ExpiresAt != nil {
			exp = gr.ExpiresAt.UTC().Format(time.RFC3339)
			rem = *remaining(gr, now)
		}
		rows = append(rows, [6]string{gr.Name, oneLine(layer), string(gr.Scope), oneLine(session), exp, rem})
	}
	var w [5]int
	for _, r := range rows {
		for i := range w {
			w[i] = max(w[i], len(r[i]))
		}
	}
	var b strings.Builder
	for _, r := range rows {
		line := fmt.Sprintf("%-*s  %-*s  %-*s  %-*s  %-*s  %s", w[0], r[0], w[1], r[1], w[2], r[2], w[3], r[3], w[4], r[4], r[5])
		b.WriteString(strings.TrimRight(line, " "))
		b.WriteByte('\n')
	}
	return b.String()
}

// describeGrant is a grant as `describe` reports it.
type describeGrant struct {
	Scope     string  `json:"scope"`
	Session   *string `json:"session"`
	ExpiresAt *string `json:"expires_at"`
}

// recordGrants returns the live grants of one record for `describe`.
func (g *globals) recordGrants(stderr io.Writer, s *session, name string, layer vault.Layer, recordID string) ([]grants.Grant, error) {
	st, _, err := g.activeGrants(stderr, s)
	if err != nil {
		return nil, err
	}
	return grants.ForRecord(st, name, layer.Key(), recordID, clock()), nil
}
