// Command mcpclient is the scripted MCP client of the Docker hosts battery
// (docs/TESTING.md § Tier 2 item 9). It starts `qbit-vault mcp` over stdio,
// the way a host such as Claude Code does, runs the calls of a JSON script in
// order in that one session, and prints one JSON line per call holding what
// the server returned and nothing else.
//
//	mcpclient [-server qbit-vault] script.json
//
// The script is an array of {"method":"tools/list"} and
// {"method":"tools/call","name":"secret_exec","arguments":{...}} entries.
// The server inherits this process's environment and working directory, and
// its stderr is forwarded to ours, so the scenario captures both. A line is
// {"method":...,"name":...,"result":<the SDK result as returned>}; a
// protocol-level failure is {"method":...,"name":...,"error":"..."}.
// Exit status: 0 when every call got an answer (a tool refusal is an answer),
// 1 otherwise.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type step struct {
	Method    string          `json:"method"`
	Name      string          `json:"name,omitempty"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

type line struct {
	Method string `json:"method"`
	Name   string `json:"name,omitempty"`
	Result any    `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}

func main() {
	os.Exit(run())
}

func run() int {
	server := flag.String("server", "qbit-vault", "the qbit-vault binary to start with the argument mcp")
	timeout := flag.Duration("timeout", 2*time.Minute, "time allowed for the whole script")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: mcpclient [-server qbit-vault] script.json")
		return 2
	}
	raw, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "mcpclient: cannot read the script:", err)
		return 2
	}
	var steps []step
	if err := json.Unmarshal(raw, &steps); err != nil {
		fmt.Fprintln(os.Stderr, "mcpclient: the script is not a JSON array of steps:", err)
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	cmd := exec.Command(*server, "mcp")
	cmd.Stderr = os.Stderr
	client := sdk.NewClient(&sdk.Implementation{Name: "qbit-vault-e2e-mcpclient", Version: "0"}, nil)
	session, err := client.Connect(ctx, &sdk.CommandTransport{Command: cmd}, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mcpclient: cannot start the server:", err)
		return 1
	}
	defer session.Close()

	enc := json.NewEncoder(os.Stdout)
	rc := 0
	for _, s := range steps {
		l := line{Method: s.Method, Name: s.Name}
		var res any
		switch s.Method {
		case "tools/list":
			res, err = session.ListTools(ctx, nil)
		case "tools/call":
			var args any
			if len(s.Arguments) > 0 {
				args = s.Arguments
			}
			res, err = session.CallTool(ctx, &sdk.CallToolParams{Name: s.Name, Arguments: args})
		default:
			err = fmt.Errorf("unknown method %q", s.Method)
		}
		if err != nil {
			l.Error, rc = err.Error(), 1
		} else {
			l.Result = res
		}
		if err := enc.Encode(l); err != nil {
			return 1
		}
	}
	return rc
}
