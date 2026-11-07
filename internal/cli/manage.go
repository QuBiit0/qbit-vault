package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/QuBiit0/qbit-vault/internal/audit"
	"github.com/QuBiit0/qbit-vault/internal/broker"
	"github.com/QuBiit0/qbit-vault/internal/grants"
	"github.com/QuBiit0/qbit-vault/internal/prompt"
	"github.com/QuBiit0/qbit-vault/internal/refusal"
	"github.com/QuBiit0/qbit-vault/internal/secret"
	"github.com/QuBiit0/qbit-vault/internal/vault"
)

// coolingDown reports whether name is in its per-session cooldown.
func (g *globals) coolingDown(s *session, name string) (bool, error) {
	on := false
	err := g.mutateGrants(io.Discard, s, func(st *grants.Store) (bool, error) {
		_, on = grants.CoolingDown(st, name, g.Session, clock())
		return false, nil
	})
	return on, err
}

// coolDown starts the cooldown of name after a decline (R-CAP-05), best
// effort: a failure only means the agent may ask again sooner.
func (g *globals) coolDown(s *session, name string) {
	_ = g.mutateGrants(io.Discard, s, func(st *grants.Store) (bool, error) {
		grants.Cool(st, name, g.Session, clock())
		return true, nil
	})
}

// coolingDownIn reports whether name is cooling down in this session or, in
// any of layers, for every session.
func (g *globals) coolingDownIn(s *session, name string, layers []string) (bool, error) {
	on := false
	err := g.mutateGrants(io.Discard, s, func(st *grants.Store) (bool, error) {
		_, on = grants.CoolingDown(st, name, g.Session, clock())
		for _, l := range layers {
			on = on || grants.CoolingDownShared(st, name, l, clock())
		}
		return false, nil
	})
	return on, err
}

// coolDownIn is coolDown plus the all-sessions cooldown of name in layers.
func (g *globals) coolDownIn(s *session, name string, layers []string) {
	_ = g.mutateGrants(io.Discard, s, func(st *grants.Store) (bool, error) {
		grants.Cool(st, name, g.Session, clock())
		for _, l := range layers {
			grants.CoolShared(st, name, l, clock())
		}
		return true, nil
	})
}

// Manage is CONTRACT.md § manage (R-API-07, R-API-08): the agent proposes,
// the user confirms out of band, and only then the change is applied. A
// decline starts the same cooldown as request. Only replace can create a
// grant, and only the one the user picks in its single decision (approve,
// for how long the new value may be used, or replace only): a replaced value
// drops its old grants, and asking for a new one right after would be a
// second dialog for the same intent.
func (b *cliBackend) Manage(_ context.Context, e broker.Envelope, r broker.ManageRequest) (broker.ManageResponse, error) {
	g := b.hot(e)
	s, err := g.openSession()
	if err != nil {
		return broker.ManageResponse{}, asRefusal(err)
	}
	defer s.close()
	if on, err := g.coolingDown(s, r.Name); err != nil {
		return broker.ManageResponse{}, asRefusal(err)
	} else if on {
		return broker.ManageResponse{}, refusal.New(refusal.RateLimited, r.Name)
	}
	en, err := findEntry(s, r.Name, layerFlags{global: r.Layer == "global", project: r.Layer == "project"}, e.Cwd)
	if err != nil {
		return broker.ManageResponse{}, asRefusal(err)
	}
	defer en.Record.Value.Wipe()

	var to vault.Layer
	targetExists := false
	if r.Action == "move" {
		if to, err = (layerFlags{global: r.To == "global", project: r.To == "project"}).pick(e.Cwd); err != nil {
			return broker.ManageResponse{}, asRefusal(err)
		}
		if t, terr := findEntry(s, r.Name, layerFlags{global: r.To == "global", project: r.To == "project"}, e.Cwd); terr == nil {
			t.Record.Value.Wipe()
			targetExists = true
		}
	}
	rec := en.Record
	diff := ""
	if r.Action == "edit" {
		diff = applyChanges(&rec, r.Changes)
	}

	ask, err := g.backend()
	if err != nil {
		return broker.ManageResponse{}, refusal.New(refusal.Internal, "").WithMessage(msgNoPrompt)
	}
	audited := func(outcome string) {
		g.record(io.Discard, audit.Record{Event: audit.EventManage, Names: []string{r.Name}, Layer: auditLayer(en.Layer),
			By: "agent", Reason: r.Reason, Detail: r.Action, Outcome: outcome})
	}
	declined := func() error {
		g.coolDown(s, r.Name)
		audited("declined")
		return refusal.New(refusal.UserDeclined, r.Name)
	}
	q := manageQuestion(prompt.Requester(hostOf(e.Session), ""), r, en.Layer, to, targetExists, diff)
	var (
		ok         bool
		grantScope grants.Scope // replace: the permission picked with it, if any
	)
	if r.Action == "replace" {
		scopes := agentScopes(g.allowedScopes(r.Name, en.Layer, en.Record.Sensitive, scopeOrder))
		_, def := scopeLabels(scopes, "", false)
		opts := make([]string, 0, len(scopes)+2)
		for _, sc := range scopes {
			opts = append(opts, replaceOption(sc))
		}
		opts = append(opts, "Replace, but ask me before each use", "Don't replace")
		var i int
		i, err = ask.Choose(q, opts, def)
		ok = err == nil && i < len(opts)-1
		if ok && i < len(scopes) {
			grantScope = scopes[i]
		}
	} else {
		ok, err = ask.Confirm(q)
	}
	switch {
	case errors.Is(err, prompt.ErrUnavailable):
		return broker.ManageResponse{}, refusal.New(refusal.Internal, "").WithMessage(msgNoPrompt)
	case err != nil && !gaveUp(err):
		return broker.ManageResponse{}, asRefusal(mapErr(err, ""))
	case err != nil || !ok:
		return broker.ManageResponse{}, declined()
	}

	ed := newGrantsEditor()
	var after *string
	switch r.Action {
	case "remove":
		_, err = s.v.RemoveWithGrants(en.Layer, r.Name, ed)
	case "edit":
		_, err = s.v.EditWithGrants(en.Layer, r.Name, rec, ed)
		after = ptr(layerName(en.Layer))
	case "move":
		_, err = s.v.MoveWithGrants(r.Name, en.Layer, to, true, ed)
		after = ptr(layerName(to))
	case "replace":
		sec, aerr := ask.Secret(prompt.SecretRequest{Name: r.Name, Reason: r.Reason, Host: hostOf(e.Session),
			Session: e.Session, Project: layerRequest(en.Layer), Existing: true})
		if aerr != nil {
			if gaveUp(aerr) {
				return broker.ManageResponse{}, declined()
			}
			return broker.ManageResponse{}, refusal.New(refusal.Internal, "").WithMessage(msgNoPrompt)
		}
		raw := sec.Reveal()
		sec.Wipe()
		defer clear(raw)
		v := bytes.TrimSpace(raw)
		if len(v) == 0 || len(v) > maxValueBytes {
			return broker.ManageResponse{}, refusal.New(refusal.Internal, "").WithMessage("empty or too large value")
		}
		reviewed, rerr := reviewValue(ask, r.Name, v)
		if rerr != nil {
			if gaveUp(rerr) {
				return broker.ManageResponse{}, declined()
			}
			return broker.ManageResponse{}, refusal.New(refusal.Internal, "").WithMessage(msgNoPrompt)
		}
		defer clear(reviewed)
		rec.Value = secret.New(r.Name, reviewed)
		_, err = s.v.ReplaceWithGrants(en.Layer, r.Name, rec, ed)
		after = ptr(layerName(en.Layer))
	}
	if err != nil {
		return broker.ManageResponse{}, asRefusal(mapErr(err, r.Name))
	}
	audited("applied")
	if grantScope != "" {
		// The value is already replaced: a grant that cannot be stored now only
		// means the next exec asks for one (grant_required), so the replace
		// still reports success instead of a failure the agent would retry.
		_ = g.grantReplaced(s, r.Name, en.Layer, en.Record.Sensitive, grantScope, e.Cwd)
	}
	g.pushAfter(context.Background(), stderrOf(g), s)
	return broker.ManageResponse{OK: true, Applied: true, Action: r.Action, Name: r.Name, Layer: after}, nil
}

func ptr(s string) *string { return &s }

// grantReplaced creates the grant the user picked together with a replace,
// on the new record, through the same prompt-token path as request.
func (g *globals) grantReplaced(s *session, name string, layer vault.Layer, sensitive bool, scope grants.Scope, cwd string) error {
	now, err := findEntry(s, name, layerFlags{global: !layer.Project, project: layer.Project}, cwd)
	if err != nil {
		return err
	}
	now.Record.Value.Wipe()
	cmd := quiet()
	req := g.grantRequest(name, layer, now.Record.ID, scope, 0, sensitive)
	hash, err := g.promptToken(cmd, s, req)
	if err != nil {
		return err
	}
	_, err = g.create(cmd, s, req, hash)
	return err
}

// applyChanges edits rec and returns the before/after diff the user sees.
// Clearing sensitive or emptying an allowlist widens access and is marked.
func applyChanges(rec *vault.Record, c *broker.ManageChanges) string {
	var parts []string
	list := func(l []string) string {
		if len(l) == 0 {
			return "any"
		}
		return strings.Join(l, ",")
	}
	if c.Description != nil {
		parts = append(parts, fmt.Sprintf("description: %q -> %q", rec.Description, *c.Description))
		rec.Description = *c.Description
	}
	if c.Sensitive != nil {
		p := fmt.Sprintf("sensitive: %t -> %t", rec.Sensitive, *c.Sensitive)
		if rec.Sensitive && !*c.Sensitive {
			p += " (widening)"
		}
		parts = append(parts, p)
		rec.Sensitive = *c.Sensitive
	}
	for _, f := range []struct {
		label string
		cur   *[]string
		next  *[]string
	}{{"binaries", &rec.Binaries, c.Binaries}, {"hosts", &rec.Hosts, c.Hosts}} {
		if f.next == nil {
			continue
		}
		next := cleanList(*f.next) // what is stored, so what the user is told
		p := fmt.Sprintf("%s: %s -> %s", f.label, list(*f.cur), list(next))
		if len(*f.cur) > 0 && len(next) == 0 {
			p += " (widening)"
		}
		parts = append(parts, p)
		*f.cur = next
	}
	return strings.Join(parts, "; ")
}

func manageQuestion(who string, r broker.ManageRequest, from, to vault.Layer, targetExists bool, diff string) string {
	var what string
	switch r.Action {
	case "move":
		what = fmt.Sprintf("move %s from %s to %s", r.Name, whereText(from), whereText(to))
		if targetExists {
			what += " (overwriting the " + r.Name + " already there)"
		}
	case "edit":
		what = fmt.Sprintf("edit %s (%s): %s", r.Name, whereText(from), prompt.Escape(diff))
	case "replace":
		what = fmt.Sprintf("replace the value of %s (%s)", r.Name, whereText(from))
	default:
		what = fmt.Sprintf("remove %s (%s)", r.Name, whereText(from))
	}
	return fmt.Sprintf("%s wants to %s.\nWhy: %s", who, what, prompt.Escape(r.Reason))
}

// replaceOption is the answer that replaces a value and also gives the agent
// the permission to use it.
func replaceOption(sc grants.Scope) string {
	switch sc {
	case grants.ScopeOnce:
		return "Replace, allow once"
	default:
		return "Replace, always in this project"
	}
}
