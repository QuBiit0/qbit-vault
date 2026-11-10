package cli

import (
	"slices"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/audit"
)

// D4 (dogfood 1): a refusal answered over the broker or MCP is audited like a
// CLI refusal: event refusal, the reason code, the secret name when the
// refusal carries one, the session. Never a command, a reason or a value.

const mcpSession = "claude:mcp12345"

func (w *world) refusalsOf(session string) []audit.Record {
	var out []audit.Record
	for _, r := range w.auditEvents(audit.EventRefusal) {
		if r.Session == session {
			out = append(out, r)
		}
	}
	return out
}

func TestBrokerRefusalsAreAudited(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("A", xv, "--global")
	run := child(t, "mark", marker(t), 0)

	exec := func(command, secrets string) string {
		return envelope("exec", w.outside, `"command":`+jsonString(command)+`,"secrets":[`+secrets+`]`)
	}
	call := func(op, req string) { w.broker(op, req) }

	type step struct {
		name  string
		do    func()
		typ   string
		names []string
	}
	steps := []step{
		{"unknown secret", func() { call("exec", exec(run, `{"name":"NOPE"}`)) }, "unknown_secret", []string{"NOPE"}},
		{"no grant", func() { call("exec", exec(run, `{"name":"A"}`)) }, "grant_required", []string{"A"}},
		{"grant without a prompt token", func() {
			call("grant", envelope("grant", w.outside, `"name":"A","layer":"global","scope":"session"`))
		}, "not_model_callable", []string{"A"}},
		{"vague request reason", func() {
			call("request", envelope("request", w.outside, `"name":"A","reason":"please help"`))
		}, "reason_too_vague", nil},
		{"invalid request", func() { call("revoke", envelope("revoke", w.outside, ``)) }, "internal", nil},
	}
	for _, st := range steps {
		before := len(w.refusalsOf(brokerSession))
		st.do()
		got := w.refusalsOf(brokerSession)
		if len(got) != before+1 {
			t.Fatalf("%s: %d refusal records, want %d", st.name, len(got), before+1)
		}
		r := got[len(got)-1]
		if r.Refusal != st.typ || !slices.Equal(r.Names, st.names) {
			t.Errorf("%s: record %+v, want %s %v", st.name, r, st.typ, st.names)
		}
		if r.By != "agent" || r.Command != "" || r.Reason != "" || r.Detail != "" || r.Cwd != "" || r.Outcome != "" {
			t.Errorf("%s: the record carries more than the reason code: %+v", st.name, r)
		}
	}

	// After a grant, a dump command is a refusal without a name.
	w.grantTo(brokerSession, "A", "session")
	before := len(w.refusalsOf(brokerSession))
	call("exec", exec("env; "+run, `{"name":"A"}`))
	got := w.refusalsOf(brokerSession)
	if len(got) != before+1 || got[len(got)-1].Refusal != "dump_command" || len(got[len(got)-1].Names) != 0 {
		t.Fatalf("dump_command: %+v", got)
	}

	// What is not a refusal, and what cannot be attributed to a session, is
	// not written as one.
	before = len(w.auditEvents(audit.EventRefusal))
	call("exec", exec(run, `{"name":"A"}`)) // succeeds
	call("list", envelope("list", w.outside, ``))
	w.run(`{"contract":"nope"}`, "broker", "--op", "list")
	if n := len(w.auditEvents(audit.EventRefusal)); n != before {
		t.Fatalf("%d refusal records for successes and a malformed envelope, want none", n-before)
	}
	noFixtures(t, "audit log", w.auditText())
}

func TestMCPRefusalsAreAudited(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("A", xv, "--global")
	execCall := func(id, command string) string {
		return `{"jsonrpc":"2.0","id":` + id + `,"method":"tools/call","params":{"name":"secret_exec","arguments":{"command":` + jsonString(command) + `,"secrets":[{"name":"A"}]}}}`
	}

	_, out, _ := w.serveMCP(`"id":4`, rpcInit, rpcInited, execCall("4", "echo hi"))
	noFixtures(t, "mcp output", out)
	got := w.refusalsOf(mcpSession)
	if len(got) != 1 || got[0].Refusal != "grant_required" || !slices.Equal(got[0].Names, []string{"A"}) || got[0].Command != "" {
		t.Fatalf("grant_required over MCP: %+v", got)
	}

	w.grantTo(mcpSession, "A", "once")
	_, out, _ = w.serveMCP(`"id":5`, rpcInit, rpcInited, execCall("5", "env"))
	noFixtures(t, "mcp output", out)
	got = w.refusalsOf(mcpSession)
	if len(got) != 2 || got[1].Refusal != "dump_command" || got[1].By != "agent" || got[1].Command != "" {
		t.Fatalf("dump_command over MCP: %+v", got)
	}
	noFixtures(t, "audit log", w.auditText())
}
