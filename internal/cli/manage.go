package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/QuBiit0/gentle-vault/internal/audit"
	"github.com/QuBiit0/gentle-vault/internal/broker"
	"github.com/QuBiit0/gentle-vault/internal/grants"
	"github.com/QuBiit0/gentle-vault/internal/prompt"
	"github.com/QuBiit0/gentle-vault/internal/refusal"
	"github.com/QuBiit0/gentle-vault/internal/secret"
	"github.com/QuBiit0/gentle-vault/internal/vault"
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

// Manage is CONTRACT.md § manage (R-API-07, R-API-08): the agent proposes,
// the user confirms out of band, and only then the change is applied. It
// never creates a grant. A decline starts the same cooldown as request.
func (b *cliBackend) Manage(_ context.Context, e broker.Envelope, r broker.ManageRequest) (broker.ManageResponse, error) {
	g := b.bound(e)
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
	q := manageQuestion(r, en.Layer, to, targetExists, diff)
	ok, err := ask.Confirm(q)
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
		rec.Value = secret.New(r.Name, v)
		_, err = s.v.ReplaceWithGrants(en.Layer, r.Name, rec, ed)
		after = ptr(layerName(en.Layer))
	}
	if err != nil {
		return broker.ManageResponse{}, asRefusal(mapErr(err, r.Name))
	}
	audited("applied")
	return broker.ManageResponse{OK: true, Applied: true, Action: r.Action, Name: r.Name, Layer: after}, nil
}

func ptr(s string) *string { return &s }

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

func manageQuestion(r broker.ManageRequest, from, to vault.Layer, targetExists bool, diff string) string {
	var what string
	switch r.Action {
	case "move":
		what = fmt.Sprintf("move %s from %s to %s", r.Name, layerText(from), layerText(to))
		if targetExists {
			what += " (overwriting the " + r.Name + " already there)"
		}
	case "edit":
		what = fmt.Sprintf("edit %s (%s): %s", r.Name, layerText(from), diff)
	case "replace":
		what = fmt.Sprintf("replace the value of %s (%s); you will type the new value", r.Name, layerText(from))
	default:
		what = fmt.Sprintf("remove %s (%s)", r.Name, layerText(from))
	}
	return fmt.Sprintf("The agent proposes to %s. Reason: %s. Apply?", what, r.Reason)
}
