// Package mcp is the stdio MCP server of `qbit-vault mcp` (R-API-01,
// R-API-05, R-API-06): exactly four tools, secret_request, secret_list,
// secret_exec and secret_manage, with the normative descriptions of
// CONTRACT.md, and the policy text as the server instructions. Every call
// becomes a contract envelope handled by internal/broker over the model
// transport, so validation, refusals and the never-a-grant rule are the
// broker's. No tool returns a secret value.
package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/QuBiit0/qbit-vault/internal/broker"
)

// ToolDescriptions are CONTRACT.md § Model-facing tool definitions, verbatim.
var ToolDescriptions = map[string]string{
	"secret_request": "Ask the user for permission to use one or several named secrets (e.g. GITHUB_TOKEN, or DB_HOST, DB_USER and DB_PASSWORD together) in later commands. Ask for everything one task needs in a single call: up to 8 fields, each 'secret' (masked) or 'text' (visible, for non-secret values such as a hostname). The user will type or approve them outside the chat. You NEVER receive the values; you receive references and a grant. Give a concrete reason (what command, what for). Do not request secrets you do not need for the current task. If the user declines, do not ask again.",
	"secret_list":    "List the secrets available from this directory (global ones and this project's), and the rules for what you can and cannot do with them. Values are never returned. Call this first when you need a credential.",
	"secret_manage":  "Propose a change to a secret: remove it, edit its metadata, move it between global and this project, or replace its value. The user confirms or declines outside the chat; nothing changes without that. You never see values and you cannot grant access. Give a concrete reason.",
	"secret_exec":    "Run a shell command with named secrets injected as environment variables for that process only. Output is returned with secret values redacted. Commands that print the environment or a secret are refused; to use only a length, write ${#NAME}. Prefer this over asking the user to paste credentials.",
}

// Options configures the server.
type Options struct {
	// Session is the host session id every envelope carries.
	Session string
	// Cwd returns the working directory of a call (the host's project).
	Cwd func() (string, error)
	// Version is reported as the server version.
	Version string
}

// NewSession returns a fresh session id for a host that did not pass one.
func NewSession() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("mcp: random source failed")
	}
	return "mcp:" + hex.EncodeToString(b[:])
}

type requestIn struct {
	Name           string         `json:"name,omitempty" jsonschema:"one secret name, e.g. GITHUB_TOKEN; or use fields"`
	Fields         []broker.Field `json:"fields,omitempty" jsonschema:"several fields asked in one prompt: name, kind (secret or text), label, description"`
	Reason         string         `json:"reason" jsonschema:"what command needs it and what for, shown to the user verbatim"`
	SuggestedScope string         `json:"suggested_scope,omitempty" jsonschema:"once, session or project; a hint, the user chooses"`
	SuggestedLayer string         `json:"suggested_layer,omitempty" jsonschema:"global or project; a hint, the user chooses"`
}

type listIn struct{}

type execIn struct {
	Command   string              `json:"command" jsonschema:"the shell command to run"`
	Secrets   []broker.ExecSecret `json:"secrets" jsonschema:"secrets to inject: name is the variable, from the vault secret (default name)"`
	TimeoutMS int                 `json:"timeout_ms,omitempty" jsonschema:"1000 to 3600000, default 600000"`
	Shell     string              `json:"shell,omitempty" jsonschema:"auto, sh, bash, cmd or pwsh"`
}

type manageIn struct {
	Action  string                `json:"action" jsonschema:"remove, edit, move or replace"`
	Name    string                `json:"name" jsonschema:"the secret name"`
	Layer   string                `json:"layer" jsonschema:"global or project (the project of this directory)"`
	Reason  string                `json:"reason" jsonschema:"why, shown to the user verbatim"`
	To      string                `json:"to,omitempty" jsonschema:"move only: the other layer"`
	Changes *broker.ManageChanges `json:"changes,omitempty" jsonschema:"edit only: description, binaries, hosts, sensitive"`
}

// NewServer builds the MCP server over a broker backend.
func NewServer(b broker.Backend, o Options) *sdk.Server {
	srv := sdk.NewServer(&sdk.Implementation{Name: "qbit-vault", Version: o.Version}, &sdk.ServerOptions{Instructions: broker.Instructions()})
	add(srv, b, o, "secret_request", "request")
	add(srv, b, o, "secret_list", "list")
	add(srv, b, o, "secret_exec", "exec")
	add(srv, b, o, "secret_manage", "manage")
	return srv
}

func add(srv *sdk.Server, b broker.Backend, o Options, tool, op string) {
	t := &sdk.Tool{Name: tool, Description: ToolDescriptions[tool]}
	switch op {
	case "request":
		sdk.AddTool(srv, t, handler[requestIn](b, o, op))
	case "list":
		sdk.AddTool(srv, t, handler[listIn](b, o, op))
	case "exec":
		sdk.AddTool(srv, t, handler[execIn](b, o, op))
	case "manage":
		sdk.AddTool(srv, t, handler[manageIn](b, o, op))
	}
}

// handler turns the tool input into an envelope for op and answers with the
// broker's JSON as text, an error result when it is a refusal.
func handler[In any](b broker.Backend, o Options, op string) sdk.ToolHandlerFor[In, any] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in In) (*sdk.CallToolResult, any, error) {
		out := broker.Handle(ctx, envelope(o, op, in), b, broker.TransportModel)
		var ok struct {
			OK bool `json:"ok"`
		}
		_ = json.Unmarshal(out, &ok)
		return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: string(out)}}, IsError: !ok.OK}, nil, nil
	}
}

// envelope merges the tool input with the contract envelope. A cwd that
// cannot be read is sent empty, which the broker refuses as invalid.
func envelope(o Options, op string, in any) []byte {
	m := map[string]any{}
	if b, err := json.Marshal(in); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	cwd := ""
	if o.Cwd != nil {
		if d, err := o.Cwd(); err == nil {
			cwd = d
		}
	}
	m["contract"], m["op"], m["v"], m["session"], m["cwd"] = broker.Contract, op, 1, o.Session, cwd
	raw, _ := json.Marshal(m)
	return raw
}
