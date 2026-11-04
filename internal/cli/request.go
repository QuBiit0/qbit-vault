package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/QuBiit0/gentle-vault/internal/audit"
	"github.com/QuBiit0/gentle-vault/internal/broker"
	"github.com/QuBiit0/gentle-vault/internal/grants"
	"github.com/QuBiit0/gentle-vault/internal/prompt"
	"github.com/QuBiit0/gentle-vault/internal/refusal"
	"github.com/QuBiit0/gentle-vault/internal/secret"
	"github.com/QuBiit0/gentle-vault/internal/vault"
)

const msgNoPrompt = "no prompt is available to ask the user"

// gaveUp reports a prompt the user cancelled, let time out or answered no.
func gaveUp(err error) bool {
	var ce codedError
	return errors.Is(err, prompt.ErrCancelled) || errors.Is(err, prompt.ErrTimeout) ||
		(errors.As(err, &ce) && ce.code == "cancelled")
}

// Request is CONTRACT.md § request for one field (R-API-02, R-CAP-02..05):
// one out-of-band prompt that asks the layer and the value when the name
// does not resolve, then the scope; nothing is stored or granted unless the
// user completes it. The response is the same whether the value existed, so
// the model cannot enumerate the vault. A decline or cancel starts the
// per-session cooldown of the name.
func (b *cliBackend) Request(_ context.Context, e broker.Envelope, r broker.RequestRequest) (broker.RequestResponse, error) {
	if len(r.Fields) != 1 {
		return broker.RequestResponse{}, refusal.New(refusal.Internal, "").WithMessage("invalid request: fields")
	}
	f := r.Fields[0]
	name := f.Name
	g := b.bound(e)
	s, err := g.openSession()
	if err != nil {
		return broker.RequestResponse{}, asRefusal(err)
	}
	defer s.close()
	cmd := quiet()

	cooling, err := g.coolingDown(s, name)
	if err != nil {
		return broker.RequestResponse{}, asRefusal(err)
	}
	if cooling {
		return broker.RequestResponse{}, refusal.New(refusal.RateLimited, name)
	}

	// Where the name resolves now, before anything is asked.
	var (
		layer     vault.Layer
		recordID  string
		sensitive bool
		exists    bool
	)
	rec, l, rerr := s.v.Resolve(name, e.Cwd)
	switch {
	case rerr == nil:
		rec.Value.Wipe()
		layer, recordID, sensitive, exists = l, rec.ID, rec.Sensitive, true
	case !errors.Is(rerr, vault.ErrNotFound):
		return broker.RequestResponse{}, asRefusal(mapErr(rerr, name))
	}
	proj, perr := vault.ProjectLayer(e.Cwd)
	inProject := perr == nil
	if perr != nil && !errors.Is(perr, vault.ErrNoProject) {
		return broker.RequestResponse{}, asRefusal(mapErr(perr, ""))
	}
	if !exists && r.SuggestedLayer == "project" && !inProject {
		return broker.RequestResponse{}, refusal.New(refusal.NoProject, "")
	}

	ask, err := g.backend()
	if err != nil {
		return broker.RequestResponse{}, refusal.New(refusal.Internal, "").WithMessage(msgNoPrompt)
	}
	declined := func(outcome string) error {
		g.coolDown(s, name)
		g.record(io.Discard, audit.Record{Event: audit.EventPrompt, Names: []string{name}, Layer: auditLayer(layer), Outcome: outcome})
		return refusal.New(refusal.UserDeclined, name)
	}
	fail := func(err error) error {
		switch {
		case gaveUp(err):
			return declined("cancelled")
		case errors.Is(err, prompt.ErrUnavailable):
			return refusal.New(refusal.Internal, "").WithMessage(msgNoPrompt)
		}
		return asRefusal(err)
	}

	var value []byte
	if !exists {
		layer = vault.Global()
		if inProject {
			def := 0
			if r.SuggestedLayer == "project" {
				def = 1
			}
			i, err := ask.Choose("Which layer is "+name+" for?", []string{"global", "this project (" + proj.Label + ")"}, def)
			if err != nil {
				return broker.RequestResponse{}, fail(err)
			}
			if i == 1 {
				layer = proj
			}
		}
		sec, err := ask.Secret(prompt.SecretRequest{
			Name: name, Reason: r.Reason, Host: hostOf(e.Session), Session: e.Session,
			Project: layerRequest(layer), Existing: false,
		})
		if err != nil {
			return broker.RequestResponse{}, fail(err)
		}
		raw := sec.Reveal()
		sec.Wipe()
		defer clear(raw)
		switch value = bytes.TrimSpace(raw); {
		case len(value) == 0:
			return broker.RequestResponse{}, refusal.New(refusal.Internal, "").WithMessage("empty value")
		case len(value) > maxValueBytes:
			return broker.RequestResponse{}, refusal.New(refusal.Internal, "").WithMessage("value too large")
		}
	}

	scopes := g.allowedScopes(name, layer, sensitive, scopeOrder)
	if len(scopes) == 0 {
		return broker.RequestResponse{}, refusal.New(refusal.ScopeNotAllowed, name)
	}
	proposed, _ := grants.ParseScope(r.SuggestedScope)
	opts, def := scopeLabels(e.Session, scopes, proposed)
	i, err := ask.Choose(fmt.Sprintf("Allow %s (%s) for: %s", name, layerText(layer), r.Reason), append(opts, "deny"), def)
	if err != nil {
		return broker.RequestResponse{}, fail(err)
	}
	if i >= len(scopes) {
		return broker.RequestResponse{}, declined("denied")
	}
	scope := scopes[i]

	if !exists {
		res, err := s.v.ReplaceWithGrants(layer, name, vault.Record{Value: secret.New(name, value), Description: f.Description}, newGrantsEditor())
		if err != nil {
			return broker.RequestResponse{}, asRefusal(mapErr(err, name))
		}
		recordID = res.RecordID
		g.record(io.Discard, audit.Record{Event: audit.EventCapture, Names: []string{name}, Layer: auditLayer(layer), By: "agent", Reason: r.Reason})
	}
	req := g.grantRequest(name, layer, recordID, scope, 0, sensitive)
	hash, err := g.promptToken(cmd, s, req)
	if err != nil {
		return broker.RequestResponse{}, asRefusal(err)
	}
	gr, err := g.create(cmd, s, req, hash)
	if err != nil {
		return broker.RequestResponse{}, asRefusal(err)
	}
	g.record(io.Discard, audit.Record{Event: audit.EventPrompt, Names: []string{name}, Layer: auditLayer(layer), Scope: string(scope), Outcome: "issued"})
	ref := broker.Ref{Name: name, Ref: "secret://" + name, Layer: layerName(layer)}
	out := broker.RequestResponse{OK: true, Refs: []broker.Ref{ref},
		Grant: broker.GrantInfo{Scope: string(gr.Scope), ExpiresAt: expiryText(gr.ExpiresAt)}}
	if r.Single {
		out.Ref, out.Layer = ref.Ref, ref.Layer
	}
	return out, nil
}
