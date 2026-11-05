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

const msgNoPrompt = "no prompt is available to ask the user"

// gaveUp reports a prompt the user cancelled, let time out or answered no.
func gaveUp(err error) bool {
	var ce codedError
	return errors.Is(err, prompt.ErrCancelled) || errors.Is(err, prompt.ErrTimeout) ||
		(errors.As(err, &ce) && ce.code == "cancelled")
}

// asked is one field of a request and where it stands before the prompt.
type asked struct {
	f         broker.Field
	exists    bool
	layer     vault.Layer
	recordID  string
	sensitive bool
	value     []byte
}

// Request is CONTRACT.md § request (R-API-02, R-CAP-02..05, R-CAP-08/09):
// one out-of-band prompt for every field. Fields whose name does not resolve
// from cwd get a box (masked for secret, visible for text) after one layer
// question; then one scope menu covers all of them, offering only scopes
// every field allows. It is all-or-nothing: nothing is stored or granted
// unless the user completes every step. The response is the same whether a
// value existed, so the model cannot enumerate the vault. A decline or
// cancel starts the cooldown of every name in the request.
func (b *cliBackend) Request(_ context.Context, e broker.Envelope, r broker.RequestRequest) (broker.RequestResponse, error) {
	g := b.bound(e)
	s, err := g.openSession()
	if err != nil {
		return broker.RequestResponse{}, asRefusal(err)
	}
	defer s.close()
	cmd := quiet()

	// Refused before any name is resolved, so the answer cannot tell whether
	// a name exists (R-API-02).
	proj, perr := vault.ProjectLayer(e.Cwd)
	inProject := perr == nil
	if perr != nil && !errors.Is(perr, vault.ErrNoProject) {
		return broker.RequestResponse{}, asRefusal(mapErr(perr, ""))
	}
	if r.SuggestedLayer == "project" && !inProject {
		return broker.RequestResponse{}, refusal.New(refusal.NoProject, "")
	}

	fields := make([]*asked, len(r.Fields))
	var fresh []*asked
	for i, f := range r.Fields {
		on, err := g.coolingDown(s, f.Name)
		if err != nil {
			return broker.RequestResponse{}, asRefusal(err)
		}
		if on {
			return broker.RequestResponse{}, refusal.New(refusal.RateLimited, f.Name)
		}
		a := &asked{f: f}
		rec, l, rerr := s.v.Resolve(f.Name, e.Cwd)
		switch {
		case rerr == nil:
			rec.Value.Wipe()
			a.exists, a.layer, a.recordID, a.sensitive = true, l, rec.ID, rec.Sensitive
		case errors.Is(rerr, vault.ErrNotFound):
			fresh = append(fresh, a)
		default:
			return broker.RequestResponse{}, asRefusal(mapErr(rerr, f.Name))
		}
		fields[i] = a
	}
	defer func() {
		for _, a := range fields {
			clear(a.value)
		}
	}()
	ask, err := g.backend()
	if err != nil {
		return broker.RequestResponse{}, refusal.New(refusal.Internal, "").WithMessage(msgNoPrompt)
	}
	declined := func(outcome string) error {
		for _, a := range fields {
			g.coolDown(s, a.f.Name)
		}
		g.record(io.Discard, audit.Record{Event: audit.EventPrompt, Names: namesOf(fields), Outcome: outcome})
		return refusal.New(refusal.UserDeclined, firstName(fields))
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

	// The layer of the new values, asked once.
	layer := vault.Global()
	if len(fresh) > 0 && inProject {
		def := 0
		if r.SuggestedLayer == "project" {
			def = 1
		}
		verb := "is " + namesOf(fresh)[0]
		if len(fresh) > 1 {
			verb = "are " + strings.Join(namesOf(fresh), ", ")
		}
		i, err := ask.Choose("Which layer "+verb+" for?", []string{"global", "this project (" + proj.Label + ")"}, def)
		if err != nil {
			return broker.RequestResponse{}, fail(err)
		}
		if i == 1 {
			layer = proj
		}
	}
	var stored []string
	for _, a := range fields {
		if a.exists {
			stored = append(stored, a.f.Name)
		}
	}
	reqs := make([]prompt.SecretRequest, len(fresh))
	for i, a := range fresh {
		a.layer = layer
		reqs[i] = prompt.SecretRequest{Name: a.f.Name, Reason: r.Reason, Host: hostOf(e.Session), Session: e.Session,
			Project: layerRequest(layer), Label: a.f.Label, Visible: a.f.Kind == "text",
			Description: a.f.Description, Stored: stored}
		if len(fresh) > 1 {
			reqs[i].Field, reqs[i].Fields = i+1, len(fresh)
		}
	}
	// One form where the backend has one (R-CAP-08), else one box per field.
	var secs []secret.Secret
	if fm, ok := ask.(prompt.Former); ok && len(fresh) > 1 {
		var ferr error
		if secs, ferr = fm.Form(reqs); ferr != nil && !errors.Is(ferr, prompt.ErrNoForm) {
			return broker.RequestResponse{}, fail(ferr)
		}
		defer func() {
			for _, s := range secs {
				s.Wipe()
			}
		}()
	}
	for i, a := range fresh {
		var sec secret.Secret
		if secs != nil {
			sec = secs[i]
		} else {
			var err error
			if sec, err = ask.Secret(reqs[i]); err != nil {
				return broker.RequestResponse{}, fail(err)
			}
		}
		raw := sec.Reveal()
		sec.Wipe()
		a.value = bytes.Clone(bytes.TrimSpace(raw))
		clear(raw)
		switch {
		case len(a.value) == 0:
			return broker.RequestResponse{}, refusal.New(refusal.Internal, "").WithMessage("empty value")
		case len(a.value) > maxValueBytes:
			return broker.RequestResponse{}, refusal.New(refusal.Internal, "").WithMessage("value too large")
		}
	}

	// One scope for all: only those every field allows.
	scopes := scopeOrder
	for _, a := range fields {
		scopes = intersect(scopes, g.allowedScopes(a.f.Name, a.layer, a.sensitive, scopeOrder))
	}
	if len(scopes) == 0 {
		return broker.RequestResponse{}, refusal.New(refusal.ScopeNotAllowed, firstName(fields))
	}
	proposed, _ := grants.ParseScope(r.SuggestedScope)
	opts, def := scopeLabels(e.Session, scopes, proposed, false)
	var who []string
	for _, a := range fields {
		if a.exists && len(fields) > 1 {
			who = append(who, fmt.Sprintf("%s (%s, already stored)", a.f.Name, layerText(a.layer)))
		} else {
			who = append(who, fmt.Sprintf("%s (%s)", a.f.Name, layerText(a.layer)))
		}
	}
	i, err := ask.Choose("Allow "+strings.Join(who, ", ")+" for: "+r.Reason, append(opts, "deny"), def)
	if err != nil {
		return broker.RequestResponse{}, fail(err)
	}
	if i >= len(scopes) {
		return broker.RequestResponse{}, declined("denied")
	}
	scope := scopes[i]

	if len(fresh) > 0 {
		names := namesOf(fresh)
		recs := make(map[string]vault.Record, len(fresh))
		for _, a := range fresh {
			recs[a.f.Name] = vault.Record{Value: secret.New(a.f.Name, a.value), Kind: a.f.Kind, Description: a.f.Description}
		}
		_, _, err := s.v.PutManyWithGrants(layer, names, recs, newGrantsEditor())
		for _, rec := range recs {
			rec.Value.Wipe()
		}
		if err != nil {
			return broker.RequestResponse{}, asRefusal(mapErr(err, ""))
		}
		for _, a := range fresh {
			rec, _, err := s.v.Resolve(a.f.Name, e.Cwd)
			if err != nil {
				return broker.RequestResponse{}, asRefusal(mapErr(err, a.f.Name))
			}
			rec.Value.Wipe()
			a.recordID = rec.ID
		}
		g.record(io.Discard, audit.Record{Event: audit.EventCapture, Names: names, Layer: auditLayer(layer), By: "agent", Reason: r.Reason})
	}

	out := broker.RequestResponse{OK: true}
	for _, a := range fields {
		req := g.grantRequest(a.f.Name, a.layer, a.recordID, scope, 0, a.sensitive)
		hash, err := g.promptToken(cmd, s, req)
		if err != nil {
			return broker.RequestResponse{}, asRefusal(err)
		}
		gr, err := g.create(cmd, s, req, hash)
		if err != nil {
			return broker.RequestResponse{}, asRefusal(err)
		}
		if len(out.Refs) == 0 {
			out.Grant = broker.GrantInfo{Scope: string(gr.Scope), ExpiresAt: expiryText(gr.ExpiresAt)}
		}
		out.Refs = append(out.Refs, broker.Ref{Name: a.f.Name, Ref: "secret://" + a.f.Name, Layer: layerName(a.layer)})
	}
	g.record(io.Discard, audit.Record{Event: audit.EventPrompt, Names: namesOf(fields), Scope: string(scope), Outcome: "issued"})
	if r.Single {
		out.Ref, out.Layer = out.Refs[0].Ref, out.Refs[0].Layer
	}
	return out, nil
}

func namesOf(as []*asked) []string {
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = a.f.Name
	}
	return out
}

func firstName(as []*asked) string {
	if len(as) == 1 {
		return as[0].f.Name
	}
	return ""
}

// intersect keeps the scopes of a that are also in b, in a's order.
func intersect(a, b []grants.Scope) []grants.Scope {
	var out []grants.Scope
	for _, x := range a {
		for _, y := range b {
			if x == y {
				out = append(out, x)
				break
			}
		}
	}
	return out
}
