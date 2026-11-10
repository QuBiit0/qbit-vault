package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/audit"
	"github.com/qbitdevz/qbit-vault/internal/broker"
	"github.com/qbitdevz/qbit-vault/internal/exitcode"
	"github.com/qbitdevz/qbit-vault/internal/prompt/prompttest"
)

// S5: an agent call that finds a passphrase-mode vault locked asks the
// passphrase out of band, in a dialog that names the requester and the secret.

const (
	fxAgentValue = "TESTSECRET_agent_unlock_value"
	fxWrongPass  = "TESTSECRET_wrong_passphrase"

	unlockReasonA  = "Pi wants to use A. Unlock the vault to continue."
	unlockReasonAG = "Pi wants to use A (global). Unlock the vault to continue."
	unlockReasonNo = "Pi needs the vault. Unlock it to continue."
)

// lockedWorld is a passphrase-mode vault holding the global secret A. The
// platforms under test have no unlock cache, so the vault is locked for every
// call that follows.
func lockedWorld(t *testing.T) *world {
	t.Helper()
	w := passphraseWorld(t)
	withBackend(t, answers(val(fxPass)))
	w.mustRun(fxAgentValue+"\n", "set", "A", "--global", "--stdin")
	return w
}

func (w *world) auditUnlocks() []audit.Record { return w.auditEvents("unlock") }

// brokerWithEnv is w.broker with an environment, for the opt-out switch.
func (w *world) brokerWithEnv(env map[string]string, op, req string) (int, string) {
	w.t.Helper()
	stdinOverride = strings.NewReader(req)
	w.t.Cleanup(func() { stdinOverride = nil })
	var out, errb bytes.Buffer
	code := execute([]string{"--home", w.home, "broker", "--op", op}, &out, &errb, envFrom(env))
	noFixtures(w.t, "broker response", out.String()+errb.String())
	return code, out.String()
}

func lockedRefusalMessage(t *testing.T, m map[string]any) string {
	t.Helper()
	r, _ := m["refusal"].(map[string]any)
	msg, _ := r["message"].(string)
	if refusalType(m) != "vault_locked" || r["retryable"] != true {
		t.Fatalf("want a retryable vault_locked, got %v", m)
	}
	return msg
}

// A request on a locked vault asks the passphrase first, with the requester
// and the secret in the dialog, then continues to its own grant question.
func TestAgentUnlockOnRequest(t *testing.T) {
	w := lockedWorld(t)
	f := withBackend(t, answers(val(fxPass), pick(0)))
	code, m, out := w.broker("request", reqFor(w.outside, ""))
	if code != exitcode.OK || m["ok"] != true {
		t.Fatalf("code=%d out=%s", code, out)
	}
	if len(f.Calls) != 2 || f.Calls[0].Kind != "passphrase" || f.Calls[1].Kind != "choose" {
		t.Fatalf("calls=%+v, want the passphrase, then the grant question", f.Calls)
	}
	p := f.Calls[0]
	if p.Confirm || p.Passphrase.Heading != "Vault passphrase" || p.Passphrase.Reason != unlockReasonA {
		t.Fatalf("passphrase request=%+v", p)
	}
	// Unlocking never grants: the grant is the user's answer to the second dialog.
	if !strings.Contains(f.Calls[1].Q, "Pi wants to use A") {
		t.Fatalf("grant question=%q", f.Calls[1].Q)
	}
}

// The layer is named when the caller states it, and never guessed.
func TestAgentUnlockTextNamesTheLayerOnlyWhenKnown(t *testing.T) {
	w := lockedWorld(t)
	f := withBackend(t, answers(val(fxPass), pick(0)))
	w.broker("request", reqFor(w.outside, `,"suggested_layer":"global"`))
	if got := f.Calls[0].Passphrase.Reason; got != unlockReasonAG {
		t.Fatalf("reason=%q", got)
	}
	f = withBackend(t, answers(val(fxPass), yes()))
	code, _, out := w.broker("manage", manageReq(w.outside, `"action":"remove","name":"A","layer":"global"`))
	if code != exitcode.OK {
		t.Fatalf("manage: code=%d out=%s", code, out)
	}
	if got := f.Calls[0].Passphrase.Reason; got != unlockReasonAG || f.Calls[0].Passphrase.Heading != "Vault passphrase" {
		t.Fatalf("manage reason=%q", got)
	}
	if len(f.Calls) != 2 || f.Calls[1].Kind != "confirm" {
		t.Fatalf("manage continued with %+v", f.Calls)
	}
}

// A wrong passphrase is the retryable vault_locked and unlocks nothing; the
// agent calls again and the user types it again.
func TestAgentUnlockWrongThenRight(t *testing.T) {
	w := lockedWorld(t)
	f := withBackend(t, answers(val(fxWrongPass)))
	code, m, out := w.broker("request", reqFor(w.outside, ""))
	if code != exitcode.Locked {
		t.Fatalf("code=%d out=%s", code, out)
	}
	lockedRefusalMessage(t, m)
	if len(f.Calls) != 1 || len(w.auditUnlocks()) != 0 {
		t.Fatalf("calls=%+v unlock records=%d after a wrong passphrase", f.Calls, len(w.auditUnlocks()))
	}
	f = withBackend(t, answers(val(fxPass), pick(0)))
	code, m, out = w.broker("request", reqFor(w.outside, ""))
	if code != exitcode.OK || m["ok"] != true || len(f.Calls) != 2 {
		t.Fatalf("code=%d out=%s calls=%+v", code, out, f.Calls)
	}
	if n := len(w.auditUnlocks()); n != 1 {
		t.Fatalf("%d unlock records, want 1", n)
	}
}

// Cancelling the passphrase dialog unlocks nothing and goes no further.
func TestAgentUnlockCancelLeavesNothingUnlocked(t *testing.T) {
	w := lockedWorld(t)
	grantsBefore := w.grantsSnapshot()
	f := withBackend(t, answers(cancel()))
	code, m, out := w.broker("request", reqFor(w.outside, ""))
	if code != exitcode.Refusal || refusalType(m) != "user_declined" {
		t.Fatalf("code=%d out=%s", code, out)
	}
	if len(f.Calls) != 1 || len(w.auditUnlocks()) != 0 {
		t.Fatalf("calls=%+v unlocks=%d", f.Calls, len(w.auditUnlocks()))
	}
	if w.grantsSnapshot() != grantsBefore {
		t.Fatal("a cancelled unlock changed the grants")
	}
	if w.auditHas(`"event":"grant"`) {
		t.Fatalf("a cancelled unlock granted: %s", w.auditText())
	}
}

// A call the client already gave up is the retryable, unaudited cancel of
// the other dialogs, not a decline.
func TestAgentUnlockCancelledCallIsNotADecline(t *testing.T) {
	w := lockedWorld(t)
	withBackend(t, answers(cancel()))
	ctx, stop := context.WithCancel(context.Background())
	stop()
	g := &globals{getenv: envFrom(nil), home: w.home}
	b := &cliBackend{g: g}
	_, err := b.Request(ctx, broker.Envelope{Session: brokerSession, Cwd: w.outside},
		broker.RequestRequest{Fields: []broker.Field{{Name: "A", Kind: "secret"}}, Reason: reqReason})
	rf := asRefusal(err)
	if rf == nil || !strings.Contains(rf.Error(), "cancelled before the user answered") {
		t.Fatalf("err=%v", err)
	}
	if len(w.auditUnlocks()) != 0 {
		t.Fatal("a cancelled call unlocked")
	}
}

// With nobody to ask, every agent path keeps today's retryable vault_locked.
func TestAgentPathsWithoutPromptBackendStayLocked(t *testing.T) {
	w := lockedWorld(t)
	execReq := envelope("exec", w.outside, `"command":"echo hi","secrets":[{"name":"TOKEN","from":"A"}]`)
	for _, c := range []struct{ op, req string }{
		{"request", reqFor(w.outside, "")},
		{"manage", manageReq(w.outside, `"action":"remove","name":"A","layer":"global"`)},
		{"list", envelope("list", w.outside, "")},
		{"exec", execReq},
	} {
		withBackend(t, &prompttest.Fake{Unavailable: true})
		code, m, _ := w.broker(c.op, c.req)
		if code != exitcode.Locked {
			t.Errorf("%s: code=%d m=%v", c.op, code, m)
			continue
		}
		lockedRefusalMessage(t, m)
	}
	if len(w.auditUnlocks()) != 0 {
		t.Fatal("an unlock was recorded without one")
	}
}

// QBIT_VAULT_NO_PROMPT_UNLOCK=1 keeps the old refusal for the agent paths and
// asks nothing; a command the user runs is not affected.
func TestAgentUnlockOptOut(t *testing.T) {
	w := lockedWorld(t)
	env := map[string]string{"QBIT_VAULT_NO_PROMPT_UNLOCK": "1"}
	f := withBackend(t, answers(val(fxPass), pick(0), val(fxPass), yes()))
	for _, c := range []struct{ op, req string }{
		{"request", reqFor(w.outside, "")},
		{"manage", manageReq(w.outside, `"action":"remove","name":"A","layer":"global"`)},
	} {
		code, out := w.brokerWithEnv(env, c.op, c.req)
		if code != exitcode.Locked || !strings.Contains(out, `"type":"vault_locked"`) {
			t.Errorf("%s: code=%d out=%s", c.op, code, out)
		}
	}
	if len(f.Calls) != 0 || len(w.auditUnlocks()) != 0 {
		t.Fatalf("the opt-out still asked: %+v", f.Calls)
	}
	// The user's own command prompts as before.
	stdinOverride = strings.NewReader("")
	var out, errb bytes.Buffer
	if code := execute([]string{"--home", w.home, "unlock"}, &out, &errb, envFrom(env)); code != exitcode.OK {
		t.Fatalf("unlock with the switch set: code=%d err=%q", code, errb.String())
	}
	if len(f.Calls) != 1 || f.Calls[0].Kind != "passphrase" {
		t.Fatalf("unlock calls=%+v", f.Calls)
	}
}

// exec never opens a dialog: it is how a command runs after the user said
// yes. Its refusal sends the agent to secret_request, which can unlock.
func TestAgentExecAndListNeverAskThePassphrase(t *testing.T) {
	w := lockedWorld(t)
	f := withBackend(t, answers(val(fxPass), val(fxPass)))
	for _, c := range []struct{ op, req string }{
		{"exec", envelope("exec", w.outside, `"command":"echo hi","secrets":[{"name":"TOKEN","from":"A"}]`)},
		{"list", envelope("list", w.outside, "")},
	} {
		code, m, _ := w.broker(c.op, c.req)
		msg := lockedRefusalMessage(t, m)
		if code != exitcode.Locked || !strings.Contains(msg, "secret_request") {
			t.Errorf("%s: code=%d msg=%q", c.op, code, msg)
		}
		if strings.Contains(msg, "terminal") || strings.Contains(msg, "qbit-vault unlock") {
			t.Errorf("%s: the message sends the user to a terminal: %q", c.op, msg)
		}
	}
	if len(f.Calls) != 0 {
		t.Fatalf("exec or list opened a dialog: %+v", f.Calls)
	}
}

// Hooks never prompt: pre-bash does not open the vault, the others fail open
// with a fixed note.
func TestHooksNeverAskThePassphrase(t *testing.T) {
	w := lockedWorld(t)
	f := withBackend(t, answers(val(fxPass), val(fxPass), val(fxPass)))
	pre := `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`
	if code, out, errs := w.run(pre, "hook", "pre-bash"); code != 0 || out != "" || errs != "" {
		t.Fatalf("pre-bash code=%d out=%q err=%q", code, out, errs)
	}
	if code, out, errs := w.run(postBashEvent(t, "k=v"), "hook", "post-bash"); code != 0 || out != wantHookLockedPost || errs != "" {
		t.Fatalf("post-bash code=%d out=%q err=%q", code, out, errs)
	}
	if code, out, errs := w.run(`{"hook_event_name":"UserPromptSubmit","prompt":"hi"}`, "hook", "user-prompt"); code != 0 || out != wantHookLockedPrompt || errs != "" {
		t.Fatalf("user-prompt code=%d out=%q err=%q", code, out, errs)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("a hook opened a dialog: %+v", f.Calls)
	}
}

// S5.3: the audit record names the requester and the secret, never a value.
func TestAgentUnlockAuditRecord(t *testing.T) {
	w := lockedWorld(t)
	withBackend(t, answers(val(fxPass), pick(0)))
	w.broker("request", reqFor(w.outside, ""))
	recs := w.auditUnlocks()
	if len(recs) != 1 {
		t.Fatalf("%d unlock records", len(recs))
	}
	r := recs[0]
	if r.By != "agent" || r.Session != brokerSession || r.Detail != "Pi" || len(r.Names) != 1 || r.Names[0] != "A" {
		t.Fatalf("record=%+v", r)
	}
	noFixtures(t, "audit log", w.auditText())
	if code, out, errs := w.run("", "audit", "--verify"); code != exitcode.OK {
		t.Fatalf("chain broken: %d %q %q", code, out, errs)
	}
}

// Over MCP the dialog names the product the permission dialog names.
func TestMCPRequestOnLockedVaultAsksTheNamedRequester(t *testing.T) {
	w := lockedWorld(t)
	t.Chdir(w.outside)
	f := withBackend(t, answers(val(fxPass), pick(0)))
	s := w.startMCP()
	s.send(requestCall(10, "A", ""))
	s.waitFor(`"id":10,`)
	out, errs := s.finish()
	if errs != "" {
		t.Fatalf("stderr=%q", errs)
	}
	noFixtures(t, "mcp output", out+errs)
	if len(f.Calls) != 2 || f.Calls[0].Kind != "passphrase" {
		t.Fatalf("calls=%+v out=%s", f.Calls, out)
	}
	if got := f.Calls[0].Passphrase; got.Heading != "Vault passphrase" || got.Reason != "Claude Code wants to use A. Unlock the vault to continue." {
		t.Fatalf("passphrase request=%+v", got)
	}
}

// The unlock text of a call with no name.
func TestAgentUnlockTextWithoutName(t *testing.T) {
	g := &globals{Session: brokerSession}
	if got := g.unlockReason(nil, ""); got != unlockReasonNo {
		t.Fatalf("got %q", got)
	}
	if got := g.unlockReason([]string{"A", "B"}, "project"); got != "Pi wants to use A, B (project). Unlock the vault to continue." {
		t.Fatalf("got %q", got)
	}
}

// grantsSnapshot is the grants list of the (locked) vault, unlocked for the
// reading; it replaces the prompt backend of the test.
func (w *world) grantsSnapshot() string {
	w.t.Helper()
	withBackend(w.t, answers(val(fxPass)))
	return w.grantsState()
}
