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
//
// Two optional fields of a tools/call step cover a call that waits for a
// dialog. "progress": true sends a progress token, and the line then holds
// "progress": the number of notifications/progress received for that call.
// "cancel_after": "2s" cancels the call that long after it started (the SDK
// sends notifications/cancelled); the line is {"cancelled":true,...} and it
// counts as answered, because the client chose to stop waiting.
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
	"sync/atomic"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type step struct {
	Method      string          `json:"method"`
	Name        string          `json:"name,omitempty"`
	Arguments   json.RawMessage `json:"arguments,omitempty"`
	Progress    bool            `json:"progress,omitempty"`
	CancelAfter string          `json:"cancel_after,omitempty"`
}

type line struct {
	Method string `json:"method"`
	Name   string `json:"name,omitempty"`
	Result any    `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
	// Progress counts the progress notifications of a call that asked for them.
	Progress  *int64 `json:"progress,omitempty"`
	Cancelled bool   `json:"cancelled,omitempty"`
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
	var progress atomic.Int64
	client := sdk.NewClient(&sdk.Implementation{Name: "qbit-vault-e2e-mcpclient", Version: "0"}, &sdk.ClientOptions{
		ProgressNotificationHandler: func(context.Context, *sdk.ProgressNotificationClientRequest) { progress.Add(1) },
	})
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
			params := &sdk.CallToolParams{Name: s.Name, Arguments: args}
			callCtx, stop := ctx, func() {}
			if s.Progress {
				params.SetProgressToken("mcpclient-" + s.Name)
				progress.Store(0)
			}
			if s.CancelAfter != "" {
				d, derr := time.ParseDuration(s.CancelAfter)
				if derr != nil {
					l.Error, rc = "bad cancel_after: "+derr.Error(), 1
					_ = enc.Encode(l)
					continue
				}
				callCtx, stop = context.WithTimeout(ctx, d)
			}
			res, err = session.CallTool(callCtx, params)
			if s.CancelAfter != "" && callCtx.Err() != nil && ctx.Err() == nil {
				l.Cancelled, err, res = true, nil, nil
			}
			stop()
			if s.Progress {
				n := progress.Load()
				l.Progress = &n
			}
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
