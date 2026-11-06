package cli

import (
	"bytes"
	"fmt"
	"slices"
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
	} else if !layer.Project {
		req.ProjectRoot = g.repoRoot()
	}
	return req
}

// repoRoot is the canonical repository root of the working directory (the
// broker call's, else the process's), or "" outside a repository. A project
// grant of a global secret is bound to it.
func (g *globals) repoRoot() string {
	dir := g.cwd
	if dir == "" && g.broker {
		return "" // never the server process's own directory
	}
	if dir == "" {
		var err error
		if dir, err = getwd(); err != nil {
			return ""
		}
	}
	root, ok, err := vault.ProjectRoot(dir)
	if err != nil || !ok {
		return ""
	}
	return root
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

// grantChoice is one answer of a permission question: a scope and, for a
// project grant that ends, its lifetime.
type grantChoice struct {
	Scope grants.Scope
	TTL   time.Duration
}

// plainChoices offers the scopes as they are.
func plainChoices(scopes []grants.Scope) []grantChoice {
	out := make([]grantChoice, len(scopes))
	for i, sc := range scopes {
		out[i] = grantChoice{Scope: sc}
	}
	return out
}

// timedChoices is plainChoices for a dialog that creates the grant itself:
// where a project grant is possible, the session answer becomes a project
// grant for DefaultSessionTTL. An agent restart is a new session, so a
// session grant would end with it; "12 hours in this project" does not.
func timedChoices(scopes []grants.Scope) []grantChoice {
	out := plainChoices(scopes)
	if !slices.Contains(scopes, grants.ScopeProject) {
		return out
	}
	for i, c := range out {
		if c.Scope == grants.ScopeSession {
			out[i] = grantChoice{Scope: grants.ScopeProject, TTL: grants.DefaultSessionTTL}
		}
	}
	return out
}

// scopeLabels describes the choices for a menu and returns the index
// preselected. A scope the user typed on their own command line (userChose)
// wins; else the middle answer (session, or 12 hours in this project), so
// one approval covers the work at hand; else the proposed scope; else 0 (a
// sensitive record offers once only).
func scopeLabels(choices []grantChoice, proposed grants.Scope, userChose bool) ([]string, int) {
	opts := make([]string, len(choices))
	at := map[grants.Scope]int{}
	middle := -1
	for i, c := range choices {
		switch {
		case c.Scope == grants.ScopeOnce:
			opts[i] = "Once: only the next command"
		case c.Scope == grants.ScopeSession:
			opts[i] = "Session: until the agent restarts (max " + ttlText(grants.DefaultSessionTTL) + ")"
			middle = i
		case c.TTL != 0:
			opts[i] = fmt.Sprintf("%d hours: in this project, even if the agent restarts", int(c.TTL.Hours()))
			middle = i
			continue // the plain project answer keeps at[ScopeProject]
		default:
			opts[i] = "Project: always in this project, until you revoke it"
		}
		at[c.Scope] = i
	}
	if i, ok := at[proposed]; ok && userChose {
		return opts, i
	}
	if middle >= 0 {
		return opts, middle
	}
	if i, ok := at[proposed]; ok {
		return opts, i
	}
	return opts, 0
}

// denyOption is the last choice of every permission question.
const denyOption = "Don't allow"

// allowQuestion is the permission question: the secrets (each with where it is
// saved) and the agent's reason.
func allowQuestion(secrets []string, reason string) string {
	return "Allow the agent to use " + strings.Join(secrets, ", ") + "? Why: " + reason
}

// whereText is where a layer's secrets apply, in plain words.
func whereText(l vault.Layer) string {
	if l.Project {
		return "project " + l.Label
	}
	return "all projects"
}

// layerOption is one answer of "Where should NAME be saved?".
func layerOption(l vault.Layer) string {
	if l.Project {
		return "Only this project (" + l.Label + ")"
	}
	return "All projects (global)"
}

// layerOptions are the two answers, global first, for a request in project p.
func layerOptions(p vault.Layer) []string {
	return []string{layerOption(vault.Global()), layerOption(p)}
}

// layerRequest is how the prompt names the project of a layer: its label, or
// "" for the global layer.
func layerRequest(layer vault.Layer) string {
	if layer.Project {
		return layer.Label
	}
	return ""
}

// askValue asks for a masked value and checks it (R-CAP-04), then offers to
// drop pasted quotes or invisible characters (reviewValue). The caller wipes
// the returned bytes, the trimmed value. Blank and oversized input are usage
// errors; nothing has been written either way.
func askValue(ask prompt.Backend, req prompt.SecretRequest, hint string) ([]byte, error) {
	sec, err := ask.Secret(req)
	if err != nil {
		return nil, promptFail(err, hint)
	}
	raw := sec.Reveal()
	sec.Wipe()
	defer clear(raw)
	v := bytes.TrimSpace(raw)
	switch {
	case len(v) == 0:
		return nil, usageError{"empty value"}
	case len(v) > maxValueBytes:
		return nil, usageError{"value too large"}
	}
	reviewed, err := reviewValue(ask, req.Name, v)
	if err != nil {
		return nil, promptFail(err, hint)
	}
	return reviewed, nil
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
	opts, def := scopeLabels(plainChoices(scopes), flagScope, flagScope != "")
	opts = append(opts, "No, just save the value")
	i, err := ask.Choose(fmt.Sprintf("Allow agents to use %s (%s) right away?", name, whereText(layer)), opts, def)
	if err != nil {
		clear(raw)
		return nil, "", promptFail(err, "use --stdin")
	}
	if i >= len(scopes) {
		return raw, "", nil
	}
	return raw, scopes[i], nil
}
