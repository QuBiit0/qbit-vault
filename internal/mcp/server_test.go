package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/QuBiit0/gentle-vault/internal/broker"
	"github.com/QuBiit0/gentle-vault/internal/refusal"
)

type fake struct {
	env  broker.Envelope
	exec broker.ExecRequest
}

func (f *fake) List(_ context.Context, e broker.Envelope) (broker.ListResult, error) {
	f.env = e
	return broker.ListResult{Secrets: []broker.SecretMeta{}}, nil
}
func (f *fake) Exec(_ context.Context, e broker.Envelope, r broker.ExecRequest) (broker.ExecResponse, error) {
	f.env, f.exec = e, r
	return broker.ExecResponse{OK: true, ExitCode: 0, Stdout: "[REDACTED:A]"}, nil
}
func (f *fake) Grant(context.Context, broker.Envelope, broker.GrantRequest) (broker.GrantResponse, error) {
	panic("grant must never reach the backend over MCP")
}
func (f *fake) Revoke(context.Context, broker.Envelope, broker.RevokeRequest) (broker.RevokeResponse, error) {
	return broker.RevokeResponse{OK: true}, nil
}
func (f *fake) Request(_ context.Context, e broker.Envelope, r broker.RequestRequest) (broker.RequestResponse, error) {
	f.env = e
	return broker.RequestResponse{}, refusal.New(refusal.UserDeclined, r.Fields[0].Name)
}
func (f *fake) Manage(_ context.Context, e broker.Envelope, r broker.ManageRequest) (broker.ManageResponse, error) {
	f.env = e
	l := r.Layer
	return broker.ManageResponse{OK: true, Applied: true, Action: r.Action, Name: r.Name, Layer: &l}, nil
}
func (f *fake) Info() broker.Info { return broker.Info{} }

func connect(t *testing.T, f broker.Backend) *sdk.ClientSession {
	t.Helper()
	ctx := context.Background()
	srv := NewServer(f, Options{Session: "claude:sess1234", Cwd: func() (string, error) { return filepath.Abs(".") }, Version: "test"})
	st, ct := sdk.NewInMemoryTransports()
	if _, err := srv.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "test", Version: "1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func callJSON(t *testing.T, cs *sdk.ClientSession, tool string, args map[string]any) (map[string]any, bool) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &sdk.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	if len(res.Content) != 1 {
		t.Fatalf("%s: content=%v", tool, res.Content)
	}
	txt := res.Content[0].(*sdk.TextContent).Text
	var m map[string]any
	if err := json.Unmarshal([]byte(txt), &m); err != nil {
		t.Fatalf("%s: not JSON: %q", tool, txt)
	}
	return m, res.IsError
}

func TestFourToolsWithNormativeDescriptions(t *testing.T) {
	cs := connect(t, &fake{})
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
		if tool.Description != ToolDescriptions[tool.Name] {
			t.Errorf("%s description drifted", tool.Name)
		}
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "secret_exec,secret_list,secret_manage,secret_request" {
		t.Fatalf("tools=%v", names)
	}
	if got := cs.InitializeResult().Instructions; got != broker.Instructions() {
		t.Fatalf("instructions=%q", got)
	}
}

// The descriptions shipped to the model are CONTRACT.md's, verbatim.
func TestDescriptionsMatchContract(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "contracts", "secrets-broker", "v1", "CONTRACT.md"))
	if err != nil {
		t.Fatal(err)
	}
	for name, d := range ToolDescriptions {
		if !strings.Contains(string(doc), "**`"+name+"`** — \""+d+"\"") {
			t.Errorf("%s description is not CONTRACT.md's", name)
		}
	}
	if len(ToolDescriptions) != 4 {
		t.Fatalf("%d descriptions", len(ToolDescriptions))
	}
}

func TestCallsGoThroughTheBrokerWithEnvelope(t *testing.T) {
	f := &fake{}
	cs := connect(t, f)
	m, isErr := callJSON(t, cs, "secret_list", map[string]any{})
	if isErr || m["ok"] != true || m["policy"] == nil {
		t.Fatalf("list: %v", m)
	}
	cwd, _ := filepath.Abs(".")
	if f.env.Session != "claude:sess1234" || f.env.Cwd != cwd || f.env.Contract != broker.Contract || f.env.Op != "list" {
		t.Fatalf("envelope=%+v", f.env)
	}
	m, isErr = callJSON(t, cs, "secret_exec", map[string]any{"command": "gh auth status", "secrets": []any{map[string]any{"name": "A"}}})
	if isErr || m["stdout"] != "[REDACTED:A]" || f.exec.Command != "gh auth status" || f.exec.TimeoutMS != 600000 {
		t.Fatalf("exec: %v %+v", m, f.exec)
	}
	m, isErr = callJSON(t, cs, "secret_request", map[string]any{"name": "A", "reason": "create the release for v1.2.0"})
	if !isErr || m["refusal"].(map[string]any)["type"] != "user_declined" {
		t.Fatalf("request refusal: isErr=%v m=%v", isErr, m)
	}
	m, isErr = callJSON(t, cs, "secret_manage", map[string]any{"action": "remove", "name": "A", "layer": "global", "reason": "no longer used by anything"})
	if isErr || m["applied"] != true {
		t.Fatalf("manage: %v", m)
	}
	// Validation stays the broker's: a vague reason is a typed refusal.
	m, isErr = callJSON(t, cs, "secret_request", map[string]any{"name": "A", "reason": "needed!!!"})
	if !isErr || m["refusal"].(map[string]any)["type"] != "reason_too_vague" {
		t.Fatalf("vague: %v", m)
	}
}

func TestGrantIsNotATool(t *testing.T) {
	cs := connect(t, &fake{})
	res, err := cs.CallTool(context.Background(), &sdk.CallToolParams{Name: "secret_grant", Arguments: map[string]any{"name": "A"}})
	if err == nil && (res == nil || !res.IsError) {
		t.Fatal("secret_grant answered")
	}
}

func TestNewSession(t *testing.T) {
	a, b := NewSession(), NewSession()
	if a == b || !strings.HasPrefix(a, "mcp:") || len(a) != len("mcp:")+16 {
		t.Fatalf("%q %q", a, b)
	}
}
