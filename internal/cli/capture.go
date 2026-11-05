package cli

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/QuBiit0/qbit-vault/internal/grants"
	"github.com/QuBiit0/qbit-vault/internal/prompt"
	"github.com/QuBiit0/qbit-vault/internal/vault"
)

// manualEntry is the reason of a capture the user started themselves.
const manualEntry = "manual entry"

// scopeOrder is the order scopes are offered in.
var scopeOrder = []grants.Scope{grants.ScopeOnce, grants.ScopeSession, grants.ScopeProject}

// grantRequest is the grant a set asks for. recordID is empty until the
// value is stored.
func (g *globals) grantRequest(name string, layer vault.Layer, recordID string, scope grants.Scope, ttl time.Duration, sensitive bool) grants.Request {
	req := grants.Request{Name: name, Layer: layer.Key(), RecordID: recordID, Scope: scope, TTL: ttl, Sensitive: sensitive}
	if scope != grants.ScopeProject {
		req.Session = g.Session
	}
	return req
}

// allowedScopes keeps, in order, the scopes among want that a grant of name in
// layer may have (R-GRANT-02) for this session.
func (g *globals) allowedScopes(name string, layer vault.Layer, sensitive bool, want []grants.Scope) []grants.Scope {
	var out []grants.Scope
	for _, sc := range want {
		if grants.Validate(g.grantRequest(name, layer, "", sc, 0, sensitive)) == nil {
			out = append(out, sc)
		}
	}
	return out
}

// ttlText is d without the zero units Duration.String adds ("12h", not
// "12h0m0s").
func ttlText(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

// scopeLabels describes scopes for a menu and returns the index preselected.
// A scope the user typed on their own command line (userChose) wins; else
// session when it is offered, so one approval covers the whole session; else
// the proposed scope; else 0 (a sensitive record offers once only).
func scopeLabels(session string, scopes []grants.Scope, proposed grants.Scope, userChose bool) ([]string, int) {
	opts := make([]string, len(scopes))
	at := map[grants.Scope]int{}
	for i, sc := range scopes {
		at[sc] = i
		switch sc {
		case grants.ScopeOnce:
			opts[i] = "once (one command, for " + session + ")"
		case grants.ScopeSession:
			opts[i] = "session (" + ttlText(grants.DefaultSessionTTL) + ", for " + session + ")"
		default:
			opts[i] = "project (this project, until revoked)"
		}
	}
	if i, ok := at[proposed]; ok && userChose {
		return opts, i
	}
	if i, ok := at[grants.ScopeSession]; ok {
		return opts, i
	}
	if i, ok := at[proposed]; ok {
		return opts, i
	}
	return opts, 0
}

// layerRequest is how the prompt names the project of a layer: its label, or
// "" for the global layer.
func layerRequest(layer vault.Layer) string {
	if layer.Project {
		return layer.Label
	}
	return ""
}

// askValue asks for a masked value and checks it (R-CAP-04). The caller wipes
// the returned bytes, which are the value as typed: trim them with
// bytes.TrimSpace to get the value. Blank and oversized input are usage
// errors; nothing has been written either way.
func askValue(ask prompt.Backend, req prompt.SecretRequest, hint string) ([]byte, error) {
	sec, err := ask.Secret(req)
	if err != nil {
		return nil, promptFail(err, hint)
	}
	raw := sec.Reveal()
	sec.Wipe()
	switch v := bytes.TrimSpace(raw); {
	case len(v) == 0:
		clear(raw)
		return nil, usageError{"empty value"}
	case len(v) > maxValueBytes:
		clear(raw)
		return nil, usageError{"value too large"}
	}
	return raw, nil
}

// captureValue runs the interactive part of set on the prompt backend: the
// masked value then, when a grant was asked for, the scope. The caller wipes
// the returned bytes. Nothing has been written when it fails, so a cancel
// leaves the vault as it was (R-CAP-04).
func (g *globals) captureValue(ask prompt.Backend, name string, layer vault.Layer, existing bool, flagScope grants.Scope, sensitive bool) ([]byte, grants.Scope, error) {
	raw, err := askValue(ask, prompt.SecretRequest{
		Name: name, Reason: manualEntry, Host: "cli", Session: g.Session,
		Project: layerRequest(layer), Existing: existing,
	}, "use --stdin")
	if err != nil {
		return nil, "", err
	}
	if flagScope == "" {
		return raw, "", nil
	}
	scopes := g.allowedScopes(name, layer, sensitive, scopeOrder)
	opts, def := scopeLabels(g.Session, scopes, flagScope, flagScope != "")
	opts = append(opts, "no grant (store the value only)")
	i, err := ask.Choose(fmt.Sprintf("Grant %s (%s)? Choose a scope:", name, layerText(layer)), opts, def)
	if err != nil {
		clear(raw)
		return nil, "", promptFail(err, "use --stdin")
	}
	if i >= len(scopes) {
		return raw, "", nil
	}
	return raw, scopes[i], nil
}
