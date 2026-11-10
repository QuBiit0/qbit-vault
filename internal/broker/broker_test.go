package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/refusal"
)

// fake records what the broker handed it and answers from fields.
type fake struct {
	calls   []string
	env     Envelope
	exec    ExecRequest
	grant   GrantRequest
	revoke  RevokeRequest
	list    ListResult
	execRes ExecResponse
	err     error
}

func (f *fake) List(_ context.Context, e Envelope) (ListResult, error) {
	f.calls, f.env = append(f.calls, "list"), e
	return f.list, f.err
}
func (f *fake) Exec(_ context.Context, e Envelope, r ExecRequest) (ExecResponse, error) {
	f.calls, f.env, f.exec = append(f.calls, "exec"), e, r
	return f.execRes, f.err
}
func (f *fake) Grant(_ context.Context, e Envelope, r GrantRequest) (GrantResponse, error) {
	f.calls, f.env, f.grant = append(f.calls, "grant"), e, r
	return GrantResponse{OK: true, Grant: GrantInfo{Scope: r.Scope}}, f.err
}
func (f *fake) Revoke(_ context.Context, e Envelope, r RevokeRequest) (RevokeResponse, error) {
	f.calls, f.env, f.revoke = append(f.calls, "revoke"), e, r
	return RevokeResponse{OK: true, Revoked: 2}, f.err
}
func (f *fake) Request(_ context.Context, e Envelope, _ RequestRequest) (RequestResponse, error) {
	f.calls = append(f.calls, "request")
	return RequestResponse{}, refusal.New(refusal.Internal, "").WithMessage("request is not available yet")
}
func (f *fake) Manage(_ context.Context, e Envelope, _ ManageRequest) (ManageResponse, error) {
	f.calls = append(f.calls, "manage")
	return ManageResponse{}, refusal.New(refusal.Internal, "").WithMessage("manage is not available yet")
}
func (f *fake) Info() Info {
	return Info{Keychain: "secret-service", PromptBackends: []string{"zenity", "tty"}, Streaming: true}
}

var cwd = func() string {
	d, _ := filepath.Abs(string(filepath.Separator) + "work")
	return d
}()

func env(op string, extra string) string {
	cwdJSON, _ := json.Marshal(cwd)
	s := `{"contract":"qbit-vault.secrets-broker/v1","op":"` + op + `","v":1,"session":"pi:2f1c00ab","cwd":` + string(cwdJSON)
	if extra != "" {
		s += "," + extra
	}
	return s + "}"
}

func call(t *testing.T, f Backend, tr Transport, raw string) map[string]any {
	t.Helper()
	out := Handle(context.Background(), []byte(raw), f, tr)
	if strings.Count(string(out), "\n") != 1 || !strings.HasSuffix(string(out), "\n") {
		t.Fatalf("not exactly one JSON line: %q", out)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("bad JSON %q: %v", out, err)
	}
	return m
}

func refusalOf(t *testing.T, m map[string]any) (string, string) {
	t.Helper()
	if m["ok"] != false {
		t.Fatalf("not a refusal: %v", m)
	}
	r := m["refusal"].(map[string]any)
	return r["type"].(string), r["message"].(string)
}

func TestEnvelopeValidation(t *testing.T) {
	cases := []struct {
		name, raw, typ, msg string
	}{
		{"not json", `nope`, "internal", "invalid request: not a JSON object"},
		{"array", `[1]`, "internal", "invalid request: not a JSON object"},
		{"wrong contract", strings.Replace(env("list", ""), "secrets-broker/v1", "secrets-broker/v2", 1), "contract_mismatch", "unsupported contract version"},
		{"missing contract", `{"op":"list","v":1}`, "contract_mismatch", "unsupported contract version"},
		{"wrong v", strings.Replace(env("list", ""), `"v":1`, `"v":2`, 1), "contract_mismatch", "unsupported contract version"},
		{"unknown op", env("TESTSECRET_op", ""), "internal", "invalid request: op"},
		{"bad session", strings.Replace(env("list", ""), "pi:2f1c00ab", "TESTSECRET bad", 1), "internal", "invalid request: session"},
		{"relative cwd", strings.Replace(env("list", ""), `"cwd":`, `"cwd":"rel","x":`, 1), "internal", "invalid request: unknown field"},
		{"unknown field", env("list", `"TESTSECRET_field":1`), "internal", "invalid request: unknown field"},
		{"bad host", env("list", `"host":{"name":1}`), "internal", "invalid request: host"},
	}
	for _, c := range cases {
		f := &fake{}
		typ, msg := refusalOf(t, call(t, f, TransportHost, c.raw))
		if typ != c.typ || msg != c.msg {
			t.Errorf("%s: %s %q", c.name, typ, msg)
		}
		if len(f.calls) != 0 {
			t.Errorf("%s reached the backend", c.name)
		}
	}
	rel := `{"contract":"qbit-vault.secrets-broker/v1","op":"list","v":1,"session":"pi:2f1c00ab","cwd":"relative/dir"}`
	if typ, msg := refusalOf(t, call(t, &fake{}, TransportHost, rel)); typ != "internal" || msg != "invalid request: cwd" {
		t.Errorf("relative cwd: %s %q", typ, msg)
	}
	big := env("exec", `"command":"`+strings.Repeat("a", MaxRequestBytes)+`","secrets":[{"name":"A"}]`)
	if typ, msg := refusalOf(t, call(t, &fake{}, TransportHost, big)); typ != "internal" || msg != "invalid request: too large" {
		t.Errorf("too large: %s %q", typ, msg)
	}
}

func TestErrorsNeverEchoInput(t *testing.T) {
	for _, raw := range []string{
		`{"TESTSECRET_k":"TESTSECRET_v"}`,
		env("exec", `"command":"TESTSECRET_cmd","secrets":[{"name":"TESTSECRET_bad name"}]`),
		env("grant", `"name":"TESTSECRET_x","layer":"global","scope":"once"`),
	} {
		out := Handle(context.Background(), []byte(raw), &fake{}, TransportHost)
		if strings.Contains(string(out), "TESTSECRET_") {
			t.Fatalf("response echoes input: %s", out)
		}
	}
}

func TestCapabilities(t *testing.T) {
	got := string(Handle(context.Background(), []byte(env("capabilities", "")), &fake{}, TransportHost))
	want := `{"ok":true,"contract":"qbit-vault.secrets-broker/v1","capabilities":"1.0","ops":["request","list","exec","manage","grant","revoke","capabilities"],"layers":["global","project"],"prompt_backends":["zenity","tty"],"field_kinds":["secret","text"],"max_fields":8,"keychain":"secret-service","streaming":true,"sync":false}` + "\n"
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestListAddsNormativePolicy(t *testing.T) {
	f := &fake{list: ListResult{
		Project:   &Project{Root: cwd, Label: "work"},
		Secrets:   []SecretMeta{{Name: "A", Layer: "global", Kind: "secret", Binaries: []string{}, Hosts: []string{}}},
		Cooldowns: []Cooldown{},
	}}
	m := call(t, f, TransportModel, env("list", ""))
	if m["ok"] != true || f.env.Cwd != cwd || f.env.Session != "pi:2f1c00ab" {
		t.Fatalf("m=%v env=%+v", m, f.env)
	}
	if m["unlinked_match"] != nil {
		t.Fatal("unlinked_match must be null")
	}
	p := m["policy"].(map[string]any)
	if !reflect.DeepEqual(p["layers"], []any{"global", "project"}) || !reflect.DeepEqual(p["scopes"], []any{"once", "session", "project"}) {
		t.Fatalf("policy layers/scopes: %v", p)
	}
	f.list.Project = nil
	p = call(t, f, TransportModel, env("list", ""))["policy"].(map[string]any)
	if !reflect.DeepEqual(p["layers"], []any{"global"}) {
		t.Fatalf("outside a repo layers=%v", p["layers"])
	}
}

// The policy strings must be the contract's, byte for byte (R-API-06).
func TestPolicyMatchesContractVerbatim(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "contracts", "secrets-broker", "v1", "CONTRACT.md"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(doc)
	i := strings.Index(s, `{ "can": [`)
	j := strings.Index(s[i:], "```")
	if i < 0 || j < 0 {
		t.Fatal("policy block not found in CONTRACT.md")
	}
	var block struct {
		Can    []string `json:"can"`
		Cannot []string `json:"cannot"`
	}
	if err := json.Unmarshal([]byte(s[i:i+j]), &block); err != nil {
		t.Fatalf("policy block: %v", err)
	}
	if !reflect.DeepEqual(block.Can, PolicyCan) || !reflect.DeepEqual(block.Cannot, PolicyCannot) {
		t.Fatalf("policy drifted from CONTRACT.md:\ncan=%q\ncannot=%q", block.Can, block.Cannot)
	}
	if !strings.Contains(Instructions(), PolicyCannot[0]) {
		t.Fatal("instructions do not carry the policy")
	}
}

func TestExecValidationAndDefaults(t *testing.T) {
	f := &fake{execRes: ExecResponse{OK: true, ExitCode: 3, Stdout: "x"}}
	m := call(t, f, TransportModel, env("exec", `"command":"gh auth status","secrets":[{"name":"GITHUB_TOKEN"},{"name":"GH_TOKEN","from":"GITHUB_TOKEN"}]`))
	if m["ok"] != true || m["exit_code"].(float64) != 3 {
		t.Fatalf("m=%v", m)
	}
	if f.exec.TimeoutMS != 600000 || f.exec.Shell != "auto" || len(f.exec.Secrets) != 2 || f.exec.Secrets[1].From != "GITHUB_TOKEN" {
		t.Fatalf("exec=%+v", f.exec)
	}
	many := make([]string, 17)
	for i := range many {
		many[i] = `{"name":"A` + strings.Repeat("B", i) + `"}`
	}
	cases := []struct{ extra, typ, msg string }{
		{`"command":"x","secrets":[]`, "internal", "invalid request: secrets"},
		{`"command":"x","secrets":[` + strings.Join(many, ",") + `]`, "internal", "invalid request: secrets"},
		{`"command":"x","secrets":[{"name":"bad"}]`, "invalid_name", "invalid secret name"},
		{`"command":"x","secrets":[{"name":"A","from":"bad"}]`, "invalid_name", "invalid secret name"},
		{`"command":"x","secrets":[{"name":"A"},{"name":"A"}]`, "internal", "invalid request: secrets"},
		{`"command":"x","secrets":[{"name":"A","x":1}]`, "internal", "invalid request: secrets"},
		{`"command":"","secrets":[{"name":"A"}]`, "internal", "invalid request: command"},
		{`"secrets":[{"name":"A"}]`, "internal", "invalid request: command"},
		{`"command":"x","secrets":[{"name":"A"}],"timeout_ms":999`, "internal", "invalid request: timeout_ms"},
		{`"command":"x","secrets":[{"name":"A"}],"timeout_ms":3600001`, "internal", "invalid request: timeout_ms"},
		{`"command":"x","secrets":[{"name":"A"}],"shell":"zsh"`, "internal", "invalid request: shell"},
	}
	for _, c := range cases {
		f := &fake{}
		if typ, msg := refusalOf(t, call(t, f, TransportModel, env("exec", c.extra))); typ != c.typ || msg != c.msg {
			t.Errorf("%s: %s %q", c.extra, typ, msg)
		}
		if len(f.calls) != 0 {
			t.Errorf("%s reached the backend", c.extra)
		}
	}
}

func TestGrantIsNeverModelCallable(t *testing.T) {
	ok := `"name":"A","layer":"global","scope":"session","prompt_token":"tok_0123456789abcdef"`
	f := &fake{}
	if typ, _ := refusalOf(t, call(t, f, TransportModel, env("grant", ok))); typ != "not_model_callable" || len(f.calls) != 0 {
		t.Fatalf("grant over the model transport: %s calls=%v", typ, f.calls)
	}
	if typ, _ := refusalOf(t, call(t, f, TransportHost, env("grant", `"name":"A","layer":"global","scope":"session"`))); typ != "not_model_callable" || len(f.calls) != 0 {
		t.Fatalf("grant without token: %s", typ)
	}
	m := call(t, f, TransportHost, env("grant", ok+`,"ttl_ms":120000`))
	if m["ok"] != true || f.grant.TTLMS != 120000 || f.grant.PromptToken != "tok_0123456789abcdef" {
		t.Fatalf("m=%v grant=%+v", m, f.grant)
	}
	for extra, msg := range map[string]string{
		`"name":"A","layer":"global","scope":"once","ttl_ms":120000,"prompt_token":"tok_0123456789abcdef"`:  "invalid request: ttl_ms",
		`"name":"A","layer":"global","scope":"session","ttl_ms":1000,"prompt_token":"tok_0123456789abcdef"`: "invalid request: ttl_ms",
		`"name":"A","layer":"elsewhere","scope":"once","prompt_token":"tok_0123456789abcdef"`:               "invalid request: layer",
		`"name":"A","layer":"global","scope":"forever","prompt_token":"tok_0123456789abcdef"`:               "invalid request: scope",
		`"name":"A","layer":"global","scope":"once","prompt_token":"short"`:                                 "invalid request: prompt_token",
	} {
		if typ, got := refusalOf(t, call(t, &fake{}, TransportHost, env("grant", extra))); typ != "internal" || got != msg {
			t.Errorf("%s: %s %q", extra, typ, got)
		}
	}
}

func TestRevokeTargets(t *testing.T) {
	for _, extra := range []string{`"name":"A"`, `"all":true`, `"session_only":true`} {
		f := &fake{}
		if m := call(t, f, TransportModel, env("revoke", extra)); m["ok"] != true || m["revoked"].(float64) != 2 {
			t.Fatalf("%s: %v", extra, m)
		}
	}
	for _, extra := range []string{``, `"name":"A","all":true`, `"all":false`, `"name":"bad"`} {
		if typ, _ := refusalOf(t, call(t, &fake{}, TransportModel, env("revoke", extra))); typ != "internal" && typ != "invalid_name" {
			t.Errorf("%q: %s", extra, typ)
		}
	}
}

func TestBackendErrorsBecomeRefusals(t *testing.T) {
	f := &fake{err: refusal.New(refusal.GrantRequired, "A")}
	if typ, msg := refusalOf(t, call(t, f, TransportModel, env("exec", `"command":"x","secrets":[{"name":"A"}]`))); typ != "grant_required" || msg != "A has no active grant" {
		t.Fatalf("%s %q", typ, msg)
	}
	f = &fake{err: errors.New("TESTSECRET_boom at /home/me")}
	out := Handle(context.Background(), []byte(env("list", "")), f, TransportModel)
	if typ, msg := refusalOf(t, mustJSON(t, out)); typ != "internal" || msg != "internal error" {
		t.Fatalf("%s %q", typ, msg)
	}
	if strings.Contains(string(out), "TESTSECRET_") {
		t.Fatal("backend error text leaked")
	}
}

// panicker is a backend whose every op panics with text that must not leave.
type panicker struct{ fake }

func (panicker) List(context.Context, Envelope) (ListResult, error) {
	panic("TESTSECRET_panic_text at /home/me")
}
func (panicker) Exec(context.Context, Envelope, ExecRequest) (ExecResponse, error) {
	panic(errors.New("TESTSECRET_panic_text"))
}

// A-F12: a panic in an op becomes the typed internal refusal; the panic text
// never reaches the answer and stderr gets one fixed line.
func TestPanicInAnOpBecomesInternalRefusal(t *testing.T) {
	var logged bytes.Buffer
	old := panicLog
	panicLog = &logged
	t.Cleanup(func() { panicLog = old })
	for _, raw := range []string{env("list", ""), env("exec", `"command":"x","secrets":[{"name":"A"}]`)} {
		logged.Reset()
		out := Handle(context.Background(), []byte(raw), &panicker{}, TransportModel)
		if typ, msg := refusalOf(t, mustJSON(t, out)); typ != "internal" || msg != "internal error" {
			t.Fatalf("%s %q", typ, msg)
		}
		if !bytes.HasSuffix(out, []byte("\n")) || bytes.Count(out, []byte("\n")) != 1 {
			t.Fatalf("not one line: %q", out)
		}
		if logged.String() != "qbit-vault: internal error while handling a request\n" {
			t.Fatalf("stderr line = %q", logged.String())
		}
		for _, leaked := range []string{string(out), logged.String()} {
			if strings.Contains(leaked, "TESTSECRET_") || strings.Contains(leaked, "goroutine") || strings.Contains(leaked, "/home/me") {
				t.Fatal("panic text leaked")
			}
		}
	}
	// The next request is answered normally.
	if m := mustJSON(t, Handle(context.Background(), []byte(env("capabilities", "")), &fake{}, TransportModel)); m["ok"] == false {
		t.Fatalf("after a panic: %v", m)
	}
}

func mustJSON(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// FuzzHandle: any input gives exactly one JSON object line, never a panic,
// and never echoes a TESTSECRET_ marker it was given.
func FuzzHandle(f *testing.F) {
	for _, s := range []string{env("list", ""), env("exec", `"command":"x","secrets":[{"name":"A"}]`), env("request", `"fields":[{"name":"A"}],"reason":"run the db migration now"`), `{}`, `[`, env("manage", `"action":"edit","name":"A","layer":"global","reason":"three word reason","changes":{}}`)} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		out := Handle(context.Background(), in, &fake{}, TransportModel)
		var m map[string]any
		if json.Unmarshal(out, &m) != nil || !bytes.HasSuffix(out, []byte("\n")) || bytes.Count(out, []byte("\n")) != 1 {
			t.Fatalf("bad response %q", out)
		}
		if m["ok"] == false && bytes.Contains(out, []byte("TESTSECRET_")) {
			t.Fatalf("refusal echoes input: %s", out)
		}
	})
}

// Reason and description limits count characters, not bytes (CONTRACT.md).
func TestLimitsCountCharacters(t *testing.T) {
	reason := strings.Repeat("ñ", 150) + " a b" // 154 characters, 304 bytes
	m := call(t, &fake{}, TransportModel, env("manage", `"action":"remove","name":"A","layer":"global","reason":"`+reason+`"`))
	if typ, msg := refusalOf(t, m); typ != "internal" || msg != "manage is not available yet" {
		t.Fatalf("a 154-character reason was refused: %s %q", typ, msg)
	}
}

// auditing is a fake backend that also keeps an audit log (D4).
type auditing struct {
	fake
	refused []refusal.Refusal
	envs    []Envelope
}

func (a *auditing) Refused(e Envelope, rf refusal.Refusal) {
	a.envs, a.refused = append(a.envs, e), append(a.refused, rf)
}

func TestRefusalsAreReportedToAnAuditingBackend(t *testing.T) {
	a := &auditing{}
	a.err = refusal.New(refusal.GrantRequired, "A_KEY")
	ctx := context.Background()

	// A backend refusal, a validation refusal and a transport refusal all
	// reach the log with the envelope that carried them.
	Handle(ctx, []byte(env("exec", `"command":"x","secrets":[{"name":"A_KEY"}]`)), a, TransportModel)
	Handle(ctx, []byte(env("exec", `"command":"","secrets":[{"name":"A_KEY"}]`)), a, TransportModel)
	Handle(ctx, []byte(env("grant", `"name":"A_KEY","layer":"global","scope":"once","prompt_token":"0123456789abcdef0123"`)), a, TransportModel)
	// A backend failure that is not a refusal becomes internal.
	a.err = errors.New("TESTSECRET_boom")
	Handle(ctx, []byte(env("list", ``)), a, TransportModel)

	want := []refusal.Type{refusal.GrantRequired, refusal.Internal, refusal.NotModelCallable, refusal.Internal}
	if len(a.refused) != len(want) {
		t.Fatalf("%d refusals reported, want %d", len(a.refused), len(want))
	}
	for i, typ := range want {
		if a.refused[i].Type != typ || a.envs[i].Session != "pi:2f1c00ab" || a.envs[i].Cwd != cwd {
			t.Errorf("report %d: %+v for %+v, want %s", i, a.refused[i], a.envs[i], typ)
		}
		if strings.Contains(a.refused[i].Message, "TESTSECRET_") {
			t.Errorf("report %d carries backend error text: %q", i, a.refused[i].Message)
		}
	}
	if a.refused[0].Name == nil || *a.refused[0].Name != "A_KEY" {
		t.Errorf("the secret name is lost: %+v", a.refused[0])
	}

	// Successes, and requests with no usable envelope, report nothing.
	a.err = nil
	n := len(a.refused)
	Handle(ctx, []byte(env("list", ``)), a, TransportModel)
	Handle(ctx, []byte(env("capabilities", ``)), a, TransportModel)
	Handle(ctx, []byte(`{"contract":"other"}`), a, TransportModel)
	Handle(ctx, []byte(`not json`), a, TransportModel)
	Handle(ctx, []byte(strings.Replace(env("list", ``), `"pi:2f1c00ab"`, `"bad session"`, 1)), a, TransportModel)
	if len(a.refused) != n {
		t.Fatalf("%d extra reports for successes and unattributable requests", len(a.refused)-n)
	}
}
