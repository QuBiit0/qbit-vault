package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qbitdevz/qbit-vault/internal/exitcode"
)

// rpc frames newline-delimited JSON-RPC requests for the MCP stdio server.
func rpc(lines ...string) string { return strings.Join(lines, "\n") + "\n" }

const (
	rpcInit     = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`
	rpcInited   = `{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`
	rpcTools    = `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`
	rpcListCall = `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"secret_list","arguments":{}}}`
)

// syncBuf is a bytes.Buffer safe for the server goroutine and the test.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// serveMCP runs `mcp` with the requests on an open stdin, as a host does, and
// closes it once stdout holds until (or after 10 s).
func (w *world) serveMCP(until string, reqs ...string) (int, string, string) {
	w.t.Helper()
	pr, pw := io.Pipe()
	stdinOverride = pr
	w.t.Cleanup(func() { stdinOverride = nil })
	var out, errb syncBuf
	done := make(chan int)
	go func() {
		done <- execute([]string{"--home", w.home, "--session", "claude:mcp12345", "mcp"}, &out, &errb, envFrom(nil))
	}()
	_, _ = io.WriteString(pw, rpc(reqs...))
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(out.String(), until) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	_ = pw.Close()
	code := <-done
	return code, out.String(), errb.String()
}

func responses(t *testing.T, out string) map[float64]map[string]any {
	t.Helper()
	got := map[float64]map[string]any{}
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("stdout is not JSON-RPC only: %q", sc.Text())
		}
		if id, ok := m["id"].(float64); ok {
			got[id] = m
		}
	}
	return got
}

func TestMCPServeOverStdio(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_mcp_value\n", "set", "A", "--stdin")
	code, out, errs := w.serveMCP(`"id":3`, rpcInit, rpcInited, rpcTools, rpcListCall)
	if code != exitcode.OK {
		t.Fatalf("code=%d err=%q", code, errs)
	}
	noFixtures(t, "mcp stdout", out+errs)
	rs := responses(t, out)
	if instr := rs[1]["result"].(map[string]any)["instructions"].(string); !strings.Contains(instr, "Read, print, copy or receive any secret value.") {
		t.Fatalf("instructions=%q", instr)
	}
	tools := rs[2]["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 4 {
		t.Fatalf("tools=%d", len(tools))
	}
	content := rs[3]["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(content, `"name":"A"`) || !strings.Contains(content, `"policy"`) {
		t.Fatalf("secret_list=%s", content)
	}
}
