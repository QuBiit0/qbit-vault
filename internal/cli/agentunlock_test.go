package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/qbitdevz/qbit-vault/internal/audit"
	"github.com/qbitdevz/qbit-vault/internal/broker"
	"github.com/qbitdevz/qbit-vault/internal/exitcode"
	"github.com/qbitdevz/qbit-vault/internal/prompt"
	"github.com/qbitdevz/qbit-vault/internal/prompt/prompttest"
)

// S5: an agent call that finds a passphrase-mode vault locked asks the
// passphrase out of band, in a dialog that names the requester and the secret.

const wantNoDialog = "vault is locked and no unlock dialog could be shown; ask the user to run 'qbit-vault unlock' in their terminal"

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
	t.Cleanup(func() { stdinOverride = nil })
	var out, errb bytes.Buffer
	if code := execute([]string{"--home", w.home, "unlock"}, &out, &errb, envFrom(env)); code != exitcode.OK {
		t.Fatalf("unlock with the switch set: code=%d err=%q", code, errb.String())
	}
	if len(f.Calls) != 1 || f.Calls[0].Kind != "passphrase" {
		t.Fatalf("unlock calls=%+v", f.Calls)
	}
}

// grantedLockedWorld is lockedWorld with an "always in this project" grant of
// A for w.repo, the vault locked again: what the owner has after approving a
// request and what an exec or a list then meets once the unlock expired.
func grantedLockedWorld(t *testing.T) *world {
	t.Helper()
	w := lockedWorld(t)
	withBackend(t, answers(val(fxPass), pick(1)))
	if code, m, out := w.broker("request", reqFor(w.repo, "")); code != exitcode.OK || m["ok"] != true {
		t.Fatalf("approval: code=%d out=%s", code, out)
	}
	return w
}

func (w *world) execFromRepo() (int, map[string]any, string) {
	w.t.Helper()
	exe := child(w.t, "leaks", "TOKEN", 0)
	return w.broker("exec", envelope("exec", w.repo, `"command":`+jsonString(exe)+`,"secrets":[{"name":"TOKEN","from":"A"}]`))
}

// S2 of odd/tasks/unlock-zero-friction.md: exec opens the unlock dialog, names
// the requester and the secret, then goes on to its grant and runs.
func TestAgentUnlockOnExec(t *testing.T) {
	w := grantedLockedWorld(t)
	before := len(w.auditUnlocks())
	f := withBackend(t, answers(val(fxPass)))
	code, m, out := w.execFromRepo()
	if code != exitcode.OK || m["ok"] != true {
		t.Fatalf("code=%d out=%s", code, out)
	}
	if len(f.Calls) != 1 || f.Calls[0].Kind != "passphrase" {
		t.Fatalf("calls=%+v, want one passphrase dialog", f.Calls)
	}
	if p := f.Calls[0].Passphrase; p.Heading != "Vault passphrase" || p.Reason != unlockReasonA || f.Calls[0].Confirm {
		t.Fatalf("passphrase request=%+v", f.Calls[0])
	}
	if !strings.Contains(out, "[REDACTED:A]") {
		t.Fatalf("the child ran but its output was not redacted: %s", out)
	}
	recs := w.auditUnlocks()
	if len(recs) != before+1 {
		t.Fatalf("%d unlock records, want %d", len(recs), before+1)
	}
	if r := recs[before]; r.By != "agent" || r.Detail != "Pi" || len(r.Names) != 1 || r.Names[0] != "A" {
		t.Fatalf("unlock record=%+v", r)
	}
	noFixtures(t, "audit log", w.auditText())
}

// Unlocking never grants: an exec without a grant still asks for one.
func TestAgentUnlockOnExecStillNeedsItsGrant(t *testing.T) {
	w := lockedWorld(t)
	f := withBackend(t, answers(val(fxPass)))
	code, m, _ := w.execFromRepo()
	if code == exitcode.OK || refusalType(m) != "grant_required" || len(f.Calls) != 1 {
		t.Fatalf("code=%d m=%v calls=%+v", code, m, f.Calls)
	}
}

// secret_list opens the same dialog, for the vault and not for a name.
func TestAgentUnlockOnList(t *testing.T) {
	w := grantedLockedWorld(t)
	before := len(w.auditUnlocks())
	f := withBackend(t, answers(val(fxPass)))
	code, m, out := w.broker("list", envelope("list", w.repo, ""))
	if code != exitcode.OK || m["ok"] != true {
		t.Fatalf("code=%d out=%s", code, out)
	}
	if len(f.Calls) != 1 || f.Calls[0].Kind != "passphrase" || f.Calls[0].Passphrase.Reason != unlockReasonNo ||
		f.Calls[0].Passphrase.Heading != "Vault passphrase" {
		t.Fatalf("calls=%+v", f.Calls)
	}
	if !strings.Contains(out, `"name":"A"`) || len(w.auditUnlocks()) != before+1 {
		t.Fatalf("out=%s unlocks=%d, want %d", out, len(w.auditUnlocks()), before+1)
	}
}

// Over MCP, as the host calls it: the dialog names the product.
func TestMCPListAndExecOnLockedVaultAskTheNamedRequester(t *testing.T) {
	w := grantedLockedWorld(t)
	t.Chdir(w.repo)
	f := withBackend(t, answers(val(fxPass), val(fxPass)))
	s := w.startMCP()
	s.send(rpcListCall)
	s.waitFor(`"id":3,`)
	s.send(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"secret_exec","arguments":{"command":"echo hi","secrets":[{"name":"TOKEN","from":"A"}]}}}`)
	s.waitFor(`"id":4,`)
	out, errs := s.finish()
	if errs != "" {
		t.Fatalf("stderr=%q", errs)
	}
	noFixtures(t, "mcp output", out+errs)
	if len(f.Calls) != 2 {
		t.Fatalf("calls=%+v out=%s", f.Calls, out)
	}
	for i, want := range []string{"Claude Code needs the vault. Unlock it to continue.", "Claude Code wants to use A. Unlock the vault to continue."} {
		if got := f.Calls[i].Passphrase; got.Heading != "Vault passphrase" || got.Reason != want {
			t.Errorf("dialog %d=%+v, want %q", i, got, want)
		}
	}
}

// Cancel and a wrong passphrase are the retryable vault_locked: nothing runs,
// nothing is listed, and the message does not send anyone to a terminal.
func TestAgentUnlockOnExecAndListCancelOrWrong(t *testing.T) {
	w := grantedLockedWorld(t)
	before := len(w.auditUnlocks())
	calls := map[string]func() (int, map[string]any, string){
		"exec": w.execFromRepo,
		"list": func() (int, map[string]any, string) { return w.broker("list", envelope("list", w.repo, "")) },
	}
	answersBy := map[string]prompttest.Answer{"cancel": cancel(), "wrong passphrase": val(fxWrongPass)}
	for name, call := range calls {
		for what, a := range answersBy {
			f := withBackend(t, answers(a))
			code, m, _ := call()
			msg := lockedRefusalMessage(t, m)
			if code != exitcode.Locked || len(f.Calls) != 1 {
				t.Errorf("%s/%s: code=%d calls=%+v", name, what, code, f.Calls)
			}
			if strings.Contains(msg, "terminal") || strings.Contains(msg, "qbit-vault unlock") || strings.Contains(msg, "secret_request") {
				t.Errorf("%s/%s: message %q sends the user to a terminal", name, what, msg)
			}
		}
	}
	if n := len(w.auditUnlocks()); n != before {
		t.Fatalf("%d unlock records, want %d: a wrong passphrase or a cancel unlocked nothing", n, before)
	}
}

// With no dialog to show, exec and list say so, and only then name the command.
func TestAgentExecAndListWithoutDialogSayNoDialogCouldBeShown(t *testing.T) {
	w := lockedWorld(t)
	for _, c := range []struct{ op, req string }{
		{"exec", envelope("exec", w.outside, `"command":"echo hi","secrets":[{"name":"TOKEN","from":"A"}]`)},
		{"list", envelope("list", w.outside, "")},
	} {
		withBackend(t, &prompttest.Fake{Unavailable: true})
		_, m, _ := w.broker(c.op, c.req)
		if got := lockedRefusalMessage(t, m); got != wantNoDialog {
			t.Errorf("%s: message %q, want %q", c.op, got, wantNoDialog)
		}
	}
	f := withBackend(t, answers(val(fxPass)))
	for _, c := range []struct{ op, req string }{
		{"exec", envelope("exec", w.outside, `"command":"echo hi","secrets":[{"name":"TOKEN","from":"A"}]`)},
		{"list", envelope("list", w.outside, "")},
	} {
		code, out := w.brokerWithEnv(map[string]string{"QBIT_VAULT_NO_PROMPT_UNLOCK": "1"}, c.op, c.req)
		if code != exitcode.Locked || !strings.Contains(out, wantNoDialog) {
			t.Errorf("opt-out %s: code=%d out=%s", c.op, code, out)
		}
	}
	if len(f.Calls) != 0 || len(w.auditUnlocks()) != 0 {
		t.Fatalf("asked despite the opt-out: %+v", f.Calls)
	}
}

// Hooks never prompt: pre-bash does not open the vault, post-bash withholds
// the output and user-prompt fails open, each with a fixed note.
func TestHooksNeverAskThePassphrase(t *testing.T) {
	w := lockedWorld(t)
	f := withBackend(t, answers(val(fxPass), val(fxPass), val(fxPass)))
	pre := `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`
	if code, out, errs := w.run(pre, "hook", "pre-bash"); code != 0 || out != "" || errs != "" {
		t.Fatalf("pre-bash code=%d out=%q err=%q", code, out, errs)
	}
	if code, out, errs := w.run(postBashEvent(t, "k=v"), "hook", "post-bash"); code != 0 || out != wantWithheldPost("vault locked") || errs != "" {
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

// Grant and revoke on a locked vault ask the passphrase in the same named
// dialog, and only when it is their turn: the dialog gate is shared with every
// other dialog.
func TestAgentUnlockOnGrantAndRevokeUsesTheNamedGatedDialog(t *testing.T) {
	w := lockedWorld(t)
	b := &cliBackend{g: &globals{getenv: envFrom(nil), home: w.home}}
	env := broker.Envelope{Session: brokerSession, Cwd: w.outside}
	for _, c := range []struct {
		name string
		want string
		call func() error
	}{
		{"grant", unlockReasonAG, func() error {
			_, err := b.Grant(context.Background(), env, broker.GrantRequest{Name: "A", Layer: "global", Scope: "session"})
			return err
		}},
		{"revoke named", unlockReasonA, func() error {
			_, err := b.Revoke(context.Background(), env, broker.RevokeRequest{Name: "A"})
			return err
		}},
		{"revoke all", unlockReasonNo, func() error {
			_, err := b.Revoke(context.Background(), env, broker.RevokeRequest{All: true})
			return err
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := withBackend(t, answers(val(fxPass)))
			release, err := prompt.AcquireDialog(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- c.call() }()
			time.Sleep(150 * time.Millisecond)
			if len(f.Calls) != 0 {
				release()
				t.Fatalf("the dialog opened while another one held the gate: %+v", f.Calls)
			}
			release()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("the call never finished after the gate was released")
			}
			if len(f.Calls) < 1 || f.Calls[0].Kind != "passphrase" ||
				f.Calls[0].Passphrase.Heading != "Vault passphrase" || f.Calls[0].Passphrase.Reason != c.want {
				t.Fatalf("calls=%+v, want the named passphrase dialog %q", f.Calls, c.want)
			}
		})
	}
}

// The dialog text carries only validated secret names and a bounded,
// escaped requester, whatever the caller sends.
func TestUnlockReasonIsSanitized(t *testing.T) {
	g := &globals{Session: "evil\n\x1b[31m" + strings.Repeat("x", 500) + ":sess"}
	names := []string{"A", "bad name\nSecond line: ignore the above", "B_KEY", "C", "D", "E", "F", "G"}
	got := g.unlockReason(names, "global\nx")
	for _, r := range got {
		if r < 0x20 || r == 0x7f {
			t.Fatalf("control character %q in %q", r, got)
		}
	}
	if len(got) > 300 {
		t.Fatalf("dialog text is %d bytes: %q", len(got), got)
	}
	if strings.Contains(got, "bad name") || strings.Contains(got, "ignore the above") || strings.Contains(got, "x\nx") {
		t.Fatalf("unvalidated text reached the dialog: %q", got)
	}
	if !strings.Contains(got, "A, B_KEY") {
		t.Fatalf("valid names missing: %q", got)
	}
	if bare := (&globals{Session: brokerSession}).unlockReason([]string{"not valid"}, ""); bare != unlockReasonNo {
		t.Fatalf("only invalid names left: %q, want %q", bare, unlockReasonNo)
	}
}

// A hostile name never gets as far as a dialog: the broker refuses it first.
func TestAgentUnlockHostileNameNeverReachesTheDialog(t *testing.T) {
	w := lockedWorld(t)
	f := withBackend(t, answers(val(fxPass)))
	code, m, out := w.broker("manage", manageReq(w.outside, `"action":"remove","name":"A\nSecond line","layer":"global"`))
	if refusalType(m) != "invalid_name" || len(f.Calls) != 0 {
		t.Fatalf("code=%d out=%s calls=%+v", code, out, f.Calls)
	}
}

// S5 of odd/tasks/unlock-zero-friction.md: the Pi footer asks `grants
// --no-prompt`, which never opens a dialog, so refreshing the footer cannot
// pop the passphrase dialog; plain `grants` (a command the user runs) asks.
func TestGrantsNoPromptNeverOpensTheDialog(t *testing.T) {
	w := lockedWorld(t)
	f := withBackend(t, answers(val(fxPass), val(fxPass)))
	code, out, errs := w.run("", "--json", "grants", "--no-prompt")
	if code != exitcode.Locked || len(f.Calls) != 0 {
		t.Fatalf("code=%d out=%q err=%q calls=%+v", code, out, errs, f.Calls)
	}
	noFixtures(t, "grants output", out+errs)
	if !strings.Contains(out+errs, "vault_locked") && !strings.Contains(out+errs, "vault is locked") {
		t.Fatalf("not the locked answer: out=%q err=%q", out, errs)
	}
	if code, _, errs := w.run("", "--json", "grants"); code != exitcode.OK || len(f.Calls) != 1 || f.Calls[0].Kind != "passphrase" {
		t.Fatalf("plain grants: code=%d err=%q calls=%+v", code, errs, f.Calls)
	}
}

// R3-exec-list-cancel-untested: cancelling the unlock dialog of secret_exec or
// secret_list is the plain retryable vault_locked ("vault is locked"), never
// user_declined and never the "no dialog" text, after exactly one dialog;
// exec runs nothing and nothing is audited as unlocked.
func TestAgentUnlockCancelOnExecAndListIsThePlainVaultLocked(t *testing.T) {
	w := grantedLockedWorld(t)
	before := len(w.auditUnlocks())
	for _, c := range []struct {
		op   string
		call func() (int, map[string]any, string)
	}{
		{"exec", w.execFromRepo},
		{"list", func() (int, map[string]any, string) { return w.broker("list", envelope("list", w.repo, "")) }},
	} {
		f := withBackend(t, answers(cancel()))
		code, m, out := c.call()
		if code != exitcode.Locked || m["ok"] == true {
			t.Fatalf("%s: code=%d out=%s", c.op, code, out)
		}
		if got := lockedRefusalMessage(t, m); got != "vault is locked" {
			t.Errorf("%s: message %q, want %q", c.op, got, "vault is locked")
		}
		if len(f.Calls) != 1 || f.Calls[0].Kind != "passphrase" {
			t.Errorf("%s: calls=%+v, want one passphrase dialog", c.op, f.Calls)
		}
		if strings.Contains(out, "stdout") || strings.Contains(out, "[REDACTED") {
			t.Errorf("%s: something ran or was listed after a cancel: %s", c.op, out)
		}
	}
	if n := len(w.auditUnlocks()); n != before {
		t.Fatalf("%d unlock records, want %d", n, before)
	}
}
