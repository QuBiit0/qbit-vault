// Package broker is the contract gentle-ai.secrets-broker/v1
// (contracts/secrets-broker/v1/CONTRACT.md): it decodes and validates one
// request envelope, applies the transport rules, dispatches the op to a
// Backend and answers with exactly one JSON object, a success payload or a
// typed refusal. No other error shape exists. Messages are fixed strings
// that may name a field or a validated secret name, never input text.
package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/QuBiit0/qbit-vault/internal/refusal"
)

const (
	// Contract is the only contract this broker speaks.
	Contract = "gentle-ai.secrets-broker/v1"
	// Capabilities is the capability version (CONTRACT.md header).
	Capabilities = "1.0"
	// MaxRequestBytes bounds one request.
	MaxRequestBytes = 64 << 10

	maxCommandBytes = 16 << 10
	maxExecSecrets  = 16
	minTimeoutMS    = 1000
	maxTimeoutMS    = 3600000
	defTimeoutMS    = 600000
	minTTLMS        = 60000
	maxTTLMS        = 86400000
	minReason       = 8
	maxReason       = 200
	minReasonWords  = 3
	maxLabel        = 40
	maxDescription  = 200
	minPromptToken  = 16
)

// FieldKinds and MaxFields are what `request` accepts (R-CAP-08, R-CAP-09);
// capabilities reports them.
var (
	FieldKinds = []string{"secret", "text"}
	MaxFields  = 8
)

// Transport says who sent the request. The model transport (MCP) can never
// send `grant`; the host transport (the Pi extension through `broker --op`)
// can, with a prompt token.
type Transport int

const (
	TransportHost Transport = iota
	TransportModel
)

var (
	ops       = []string{"request", "list", "exec", "manage", "grant", "revoke", "capabilities"}
	opFields  = map[string][]string{"request": {"name", "fields", "reason", "suggested_scope", "suggested_layer"}, "list": nil, "exec": {"command", "secrets", "timeout_ms", "shell"}, "manage": {"action", "name", "layer", "reason", "to", "changes"}, "grant": {"name", "layer", "scope", "ttl_ms", "prompt_token"}, "revoke": {"name", "all", "session_only"}, "capabilities": nil}
	envFields = []string{"contract", "op", "v", "session", "cwd", "host"}
	sessionRE = regexp.MustCompile(`^[a-z0-9-]+:[A-Za-z0-9._-]{4,128}$`)
	nameRE    = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	scopes    = []string{"once", "session", "project"}
	layers    = []string{"global", "project"}
	shells    = []string{"auto", "sh", "bash", "cmd", "pwsh"}
	actions   = []string{"remove", "edit", "move", "replace"}
)

// invalid is the refusal for a request that fails validation (L3).
func invalid(field string) refusal.Refusal {
	return refusal.New(refusal.Internal, "").WithMessage("invalid request: " + field)
}

var errMismatch = refusal.New(refusal.ContractMismatch, "")

// Handle answers one request. It never panics on input and never returns
// anything but one JSON object followed by a newline.
func Handle(ctx context.Context, raw []byte, b Backend, t Transport) []byte {
	v, err := handle(ctx, raw, b, t)
	if err != nil {
		v = asRefusal(err).Envelope()
	}
	out, merr := json.Marshal(v)
	if merr != nil {
		out, _ = json.Marshal(refusal.New(refusal.Internal, "").Envelope())
	}
	return append(out, '\n')
}

// asRefusal is the refusal an error stands for: a valid one as is, anything
// else the fixed `internal`.
func asRefusal(err error) refusal.Refusal {
	var rf refusal.Refusal
	if !errors.As(err, &rf) || !rf.Valid() {
		rf = refusal.New(refusal.Internal, "")
	}
	return rf
}

// Op reports the op of a raw request, or "" when it has none readable.
func Op(raw []byte) string {
	var m struct {
		Op string `json:"op"`
	}
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	return m.Op
}

type fields map[string]json.RawMessage

func handle(ctx context.Context, raw []byte, b Backend, t Transport) (any, error) {
	if len(raw) > MaxRequestBytes {
		return nil, invalid("too large")
	}
	var m fields
	if !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) || json.Unmarshal(raw, &m) != nil || m == nil {
		return nil, invalid("not a JSON object")
	}
	e, err := envelope(m)
	if err != nil {
		return nil, err
	}
	v, err := dispatch(ctx, e, m, b, t)
	if err != nil {
		// Every refusal of a request that carried a usable envelope is
		// audited, whichever transport asked and wherever it was decided.
		if a, ok := b.(Auditor); ok {
			a.Refused(e, asRefusal(err))
		}
		return nil, err
	}
	return v, nil
}

func dispatch(ctx context.Context, e Envelope, m fields, b Backend, t Transport) (any, error) {
	switch e.Op {
	case "capabilities":
		return capabilities(b.Info()), nil
	case "list":
		res, err := b.List(ctx, e)
		if err != nil {
			return nil, err
		}
		if res.Secrets == nil {
			res.Secrets = []SecretMeta{}
		}
		return ListResponse{OK: true, Project: res.Project, Secrets: res.Secrets, UnlinkedMatch: res.Unlinked, Policy: policy(res.Project != nil, res.Cooldowns)}, nil
	case "exec":
		r, err := execRequest(m)
		if err != nil {
			return nil, err
		}
		return b.Exec(ctx, e, r)
	case "grant":
		if t == TransportModel {
			return nil, refusal.New(refusal.NotModelCallable, "")
		}
		r, err := grantRequest(m)
		if err != nil {
			return nil, err
		}
		return b.Grant(ctx, e, r)
	case "revoke":
		r, err := revokeRequest(m)
		if err != nil {
			return nil, err
		}
		return b.Revoke(ctx, e, r)
	case "request":
		r, err := requestRequest(m)
		if err != nil {
			return nil, err
		}
		return b.Request(ctx, e, r)
	case "manage":
		r, err := manageRequest(m)
		if err != nil {
			return nil, err
		}
		return b.Manage(ctx, e, r)
	}
	return nil, invalid("op")
}

func envelope(m fields) (Envelope, error) {
	var e Envelope
	if str(m, "contract", &e.Contract) != nil || e.Contract != Contract {
		return e, errMismatch
	}
	if num(m, "v", &e.V) != nil || e.V != 1 {
		return e, errMismatch
	}
	if str(m, "op", &e.Op) != nil || !in(e.Op, ops) {
		return e, invalid("op")
	}
	allowed := append(append([]string(nil), envFields...), opFields[e.Op]...)
	for k := range m {
		if !in(k, allowed) {
			return e, invalid("unknown field")
		}
	}
	if str(m, "session", &e.Session) != nil || !sessionRE.MatchString(e.Session) {
		return e, invalid("session")
	}
	if str(m, "cwd", &e.Cwd) != nil || !filepath.IsAbs(e.Cwd) || !utf8.ValidString(e.Cwd) || strings.ContainsRune(e.Cwd, 0) {
		return e, invalid("cwd")
	}
	if raw, ok := m["host"]; ok {
		h := &Host{}
		if strict(raw, h) != nil {
			return e, invalid("host")
		}
		e.Host = h
	}
	return e, nil
}

func capabilities(info Info) any {
	type caps struct {
		OK             bool     `json:"ok"`
		Contract       string   `json:"contract"`
		Capabilities   string   `json:"capabilities"`
		Ops            []string `json:"ops"`
		Layers         []string `json:"layers"`
		PromptBackends []string `json:"prompt_backends"`
		FieldKinds     []string `json:"field_kinds"`
		MaxFields      int      `json:"max_fields"`
		Keychain       string   `json:"keychain"`
		Streaming      bool     `json:"streaming"`
		Sync           bool     `json:"sync"`
	}
	pb := info.PromptBackends
	if pb == nil {
		pb = []string{}
	}
	return caps{OK: true, Contract: Contract, Capabilities: Capabilities, Ops: ops, Layers: layers,
		PromptBackends: pb, FieldKinds: FieldKinds, MaxFields: MaxFields, Keychain: info.Keychain, Streaming: info.Streaming}
}

func execRequest(m fields) (ExecRequest, error) {
	r := ExecRequest{TimeoutMS: defTimeoutMS, Shell: "auto"}
	if str(m, "command", &r.Command) != nil || strings.TrimSpace(r.Command) == "" || len(r.Command) > maxCommandBytes {
		return r, invalid("command")
	}
	raw, ok := m["secrets"]
	if !ok || strict(raw, &r.Secrets) != nil || len(r.Secrets) == 0 || len(r.Secrets) > maxExecSecrets {
		return r, invalid("secrets")
	}
	seen := map[string]bool{}
	for i, s := range r.Secrets {
		if s.From == "" {
			r.Secrets[i].From = s.Name
		}
		if !nameRE.MatchString(s.Name) || !nameRE.MatchString(r.Secrets[i].From) {
			return r, refusal.New(refusal.InvalidName, "")
		}
		if seen[s.Name] {
			return r, invalid("secrets")
		}
		seen[s.Name] = true
	}
	if _, ok := m["timeout_ms"]; ok {
		if num(m, "timeout_ms", &r.TimeoutMS) != nil || r.TimeoutMS < minTimeoutMS || r.TimeoutMS > maxTimeoutMS {
			return r, invalid("timeout_ms")
		}
	}
	if _, ok := m["shell"]; ok {
		if str(m, "shell", &r.Shell) != nil || !in(r.Shell, shells) {
			return r, invalid("shell")
		}
	}
	return r, nil
}

func grantRequest(m fields) (GrantRequest, error) {
	var r GrantRequest
	if err := secretName(m, "name", &r.Name); err != nil {
		return r, err
	}
	if str(m, "layer", &r.Layer) != nil || !in(r.Layer, layers) {
		return r, invalid("layer")
	}
	if str(m, "scope", &r.Scope) != nil || !in(r.Scope, scopes) {
		return r, invalid("scope")
	}
	if _, ok := m["ttl_ms"]; ok {
		if r.Scope != "session" || num(m, "ttl_ms", &r.TTLMS) != nil || r.TTLMS < minTTLMS || r.TTLMS > maxTTLMS {
			return r, invalid("ttl_ms")
		}
	}
	if _, ok := m["prompt_token"]; !ok {
		// Over the host transport too: there is no person at a keyboard to
		// ask, so a grant needs a token from the broker's own prompt (L4).
		return r, refusal.New(refusal.NotModelCallable, r.Name)
	}
	if str(m, "prompt_token", &r.PromptToken) != nil || len(r.PromptToken) < minPromptToken {
		return r, invalid("prompt_token")
	}
	return r, nil
}

func revokeRequest(m fields) (RevokeRequest, error) {
	var r RevokeRequest
	n := 0
	if _, ok := m["name"]; ok {
		if err := secretName(m, "name", &r.Name); err != nil {
			return r, err
		}
		n++
	}
	for key, dst := range map[string]*bool{"all": &r.All, "session_only": &r.SessionOnly} {
		if raw, ok := m[key]; ok {
			if json.Unmarshal(raw, dst) != nil {
				return r, invalid(key)
			}
			if *dst {
				n++
			}
		}
	}
	if n != 1 {
		return r, invalid("revoke target")
	}
	return r, nil
}

func requestRequest(m fields) (RequestRequest, error) {
	var r RequestRequest
	_, hasName := m["name"]
	_, hasFields := m["fields"]
	switch {
	case hasName == hasFields:
		return r, invalid("name or fields")
	case hasName:
		var n string
		if err := secretName(m, "name", &n); err != nil {
			return r, err
		}
		r.Fields, r.Single = []Field{{Name: n, Kind: "secret"}}, true
	default:
		if strict(m["fields"], &r.Fields) != nil || len(r.Fields) == 0 || len(r.Fields) > MaxFields {
			return r, invalid("fields")
		}
		seen := map[string]bool{}
		for i, f := range r.Fields {
			if !nameRE.MatchString(f.Name) || seen[f.Name] {
				return r, refusal.New(refusal.InvalidName, "")
			}
			seen[f.Name] = true
			if f.Kind == "" {
				r.Fields[i].Kind = "secret"
			}
			if !in(r.Fields[i].Kind, FieldKinds) {
				return r, invalid("fields")
			}
			if _, ok := labelOK(f.Label); !ok || utf8.RuneCountInString(f.Description) > maxDescription {
				return r, invalid("fields")
			}
		}
	}
	if err := reason(m, &r.Reason); err != nil {
		return r, err
	}
	if _, ok := m["suggested_scope"]; ok {
		if str(m, "suggested_scope", &r.SuggestedScope) != nil || !in(r.SuggestedScope, scopes) {
			return r, invalid("suggested_scope")
		}
	}
	if _, ok := m["suggested_layer"]; ok {
		if str(m, "suggested_layer", &r.SuggestedLayer) != nil || !in(r.SuggestedLayer, layers) {
			return r, invalid("suggested_layer")
		}
	}
	return r, nil
}

func labelOK(l string) (string, bool) {
	return l, utf8.RuneCountInString(l) <= maxLabel
}

func manageRequest(m fields) (ManageRequest, error) {
	var r ManageRequest
	if str(m, "action", &r.Action) != nil || !in(r.Action, actions) {
		return r, invalid("action")
	}
	if err := secretName(m, "name", &r.Name); err != nil {
		return r, err
	}
	if str(m, "layer", &r.Layer) != nil || !in(r.Layer, layers) {
		return r, invalid("layer")
	}
	if err := reason(m, &r.Reason); err != nil {
		return r, err
	}
	_, hasTo := m["to"]
	switch {
	case r.Action == "move" && !hasTo, r.Action != "move" && hasTo:
		return r, invalid("to")
	case hasTo:
		if str(m, "to", &r.To) != nil || !in(r.To, layers) || r.To == r.Layer {
			return r, invalid("to")
		}
	}
	raw, hasChanges := m["changes"]
	switch {
	case r.Action == "edit" && !hasChanges, r.Action != "edit" && hasChanges:
		return r, invalid("changes")
	case hasChanges:
		c := &ManageChanges{}
		if strict(raw, c) != nil || (c.Description == nil && c.Binaries == nil && c.Hosts == nil && c.Sensitive == nil) {
			return r, invalid("changes")
		}
		if c.Description != nil && utf8.RuneCountInString(*c.Description) > maxDescription {
			return r, invalid("changes")
		}
		// A blank entry would vanish when stored and silently widen the list.
		for _, l := range []*[]string{c.Binaries, c.Hosts} {
			if l == nil {
				continue
			}
			for _, x := range *l {
				if strings.TrimSpace(x) == "" {
					return r, invalid("changes")
				}
			}
		}
		r.Changes = c
	}
	return r, nil
}

func reason(m fields, dst *string) error {
	if str(m, "reason", dst) != nil || !utf8.ValidString(*dst) || utf8.RuneCountInString(*dst) < minReason || utf8.RuneCountInString(*dst) > maxReason {
		return invalid("reason")
	}
	if len(strings.Fields(*dst)) < minReasonWords {
		return refusal.New(refusal.ReasonTooVague, "")
	}
	return nil
}

func secretName(m fields, key string, dst *string) error {
	if str(m, key, dst) != nil {
		return invalid(key)
	}
	if !nameRE.MatchString(*dst) {
		return refusal.New(refusal.InvalidName, "")
	}
	return nil
}

// str decodes a required string field.
func str(m fields, key string, dst *string) error {
	raw, ok := m[key]
	if !ok {
		return errors.New("missing")
	}
	return json.Unmarshal(raw, dst)
}

// num decodes a required integer field.
func num(m fields, key string, dst *int) error {
	raw, ok := m[key]
	if !ok {
		return errors.New("missing")
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err != nil || f != math.Trunc(f) || math.Abs(f) > math.MaxInt32 {
		return errors.New("not an integer")
	}
	*dst = int(f)
	return nil
}

// strict decodes raw into dst refusing unknown fields and trailing data.
func strict(raw json.RawMessage, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

func in(s string, set []string) bool {
	for _, x := range set {
		if s == x {
			return true
		}
	}
	return false
}
