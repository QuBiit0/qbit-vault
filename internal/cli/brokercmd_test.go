package cli

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/exitcode"
)

const brokerSession = "pi:broker1234"

// envelope builds a request for cwd with extra op fields.
func envelope(op, cwd, extra string) string {
	c, _ := json.Marshal(cwd)
	s := `{"contract":"gentle-ai.secrets-broker/v1","op":"` + op + `","v":1,"session":"` + brokerSession + `","cwd":` + string(c)
	if extra != "" {
		s += "," + extra
	}
	return s + "}"
}

func (w *world) broker(op, req string) (int, map[string]any, string) {
	w.t.Helper()
	code, out, errs := w.run(req, "broker", "--op", op)
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil || strings.Count(out, "\n") != 1 {
		w.t.Fatalf("broker %s: not one JSON line: %q (err %q)", op, out, errs)
	}
	noFixtures(w.t, "broker response", out+errs)
	return code, m, out
}

func refusalType(m map[string]any) string {
	if r, ok := m["refusal"].(map[string]any); ok {
		return r["type"].(string)
	}
	return ""
}

func TestBrokerCapabilities(t *testing.T) {
	w := newWorld(t)
	code, _, out := w.broker("capabilities", envelope("capabilities", w.outside, ""))
	want := `{"ok":true,"contract":"gentle-ai.secrets-broker/v1","capabilities":"1.0","ops":["request","list","exec","manage","grant","revoke","capabilities"],"layers":["global","project"],"prompt_backends":[],"field_kinds":["secret","text"],"max_fields":8,"keychain":"` + osMode() + `","streaming":true,"sync":false}` + "\n"
	if code != exitcode.OK || out != want {
		t.Fatalf("code=%d\n got %s\nwant %s", code, out, want)
	}
}

func TestBrokerOpMustMatch(t *testing.T) {
	w := newWorld(t)
	code, m, _ := w.broker("list", envelope("revoke", w.outside, `"all":true`))
	if code != exitcode.Refusal || refusalType(m) != "internal" || m["refusal"].(map[string]any)["message"] != "invalid request: op" {
		t.Fatalf("code=%d m=%v", code, m)
	}
	code, m, _ = w.broker("list", "not json")
	if code != exitcode.Refusal || refusalType(m) != "internal" {
		t.Fatalf("garbage: code=%d m=%v", code, m)
	}
}

func TestBrokerListUsesEnvelopeCwdAndSession(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_a\n", "set", "A", "--stdin")
	w.inRepo()
	w.mustRun("TESTSECRET_b\n", "set", "B", "--stdin", "--project")
	w.outRepo() // the process cwd is outside; the envelope says the repo
	withBackend(t, answers(yes()))
	w.mustRun("", "--session", brokerSession, "grant", "A", "--scope", "session")

	code, m, _ := w.broker("list", envelope("list", w.repo, ""))
	if code != exitcode.OK || m["ok"] != true {
		t.Fatalf("code=%d m=%v", code, m)
	}
	if p := m["project"].(map[string]any); p["label"] != "shop-api" {
		t.Fatalf("project=%v", p)
	}
	secrets := m["secrets"].([]any)
	if len(secrets) != 2 {
		t.Fatalf("secrets=%v", secrets)
	}
	byName := map[string]map[string]any{}
	for _, s := range secrets {
		e := s.(map[string]any)
		byName[e["name"].(string)] = e
	}
	if byName["B"]["layer"] != "project" || byName["B"]["grant"] != nil || byName["B"]["kind"] != "secret" {
		t.Fatalf("B=%v", byName["B"])
	}
	if g, ok := byName["A"]["grant"].(map[string]any); !ok || g["scope"] != "session" || g["expires_at"] == nil {
		t.Fatalf("A grant=%v", byName["A"]["grant"])
	}
	if pol := m["policy"].(map[string]any); len(pol["layers"].([]any)) != 2 || len(pol["cannot"].([]any)) != 8 {
		t.Fatalf("policy=%v", pol)
	}
	// Another session sees no grant on A; outside the repo there is no B.
	other := strings.Replace(envelope("list", w.outside, ""), brokerSession, "pi:other5678", 1)
	_, m, _ = w.broker("list", other)
	if s := m["secrets"].([]any); len(s) != 1 || s[0].(map[string]any)["grant"] != nil || m["project"] != nil {
		t.Fatalf("other session: %v", m)
	}
}

func TestBrokerExec(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_exec_value\n", "set", "A", "--stdin")
	exe := child(t, "leaks", "TOKEN", 0)
	req := envelope("exec", w.outside, `"command":`+jsonString(exe)+`,"secrets":[{"name":"TOKEN","from":"A"}]`)
	code, m, _ := w.broker("exec", req)
	if code != exitcode.Refusal || refusalType(m) != "grant_required" {
		t.Fatalf("no grant: code=%d m=%v", code, m)
	}
	withBackend(t, answers(yes()))
	w.mustRun("", "--session", brokerSession, "grant", "A", "--scope", "session")
	code, m, out := w.broker("exec", req)
	if code != exitcode.OK || m["ok"] != true || m["exit_code"].(float64) != 0 || m["redactions"].(float64) == 0 {
		t.Fatalf("code=%d out=%s", code, out)
	}
	if !strings.Contains(m["stdout"].(string), "raw:[REDACTED:A]") {
		t.Fatalf("stdout=%q", m["stdout"])
	}
	// The child must not inherit the broker's stdin (the request itself).
	cat := child(t, "cat", "", 0)
	_, m, _ = w.broker("exec", envelope("exec", w.outside, `"command":`+jsonString(cat)+`,"secrets":[{"name":"A"}]`))
	if m["ok"] != true || strings.Contains(m["stdout"].(string), "contract") {
		t.Fatalf("child read the request: %v", m)
	}
}

func TestBrokerGrantNeedsPromptToken(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_g\n", "set", "A", "--stdin")
	code, m, _ := w.broker("grant", envelope("grant", w.outside, `"name":"A","layer":"global","scope":"session"`))
	if code != exitcode.Refusal || refusalType(m) != "not_model_callable" {
		t.Fatalf("no token: code=%d m=%v", code, m)
	}
	code, m, _ = w.broker("grant", envelope("grant", w.outside, `"name":"A","layer":"global","scope":"session","prompt_token":"forged_token_0123456789"`))
	if code != exitcode.Refusal || refusalType(m) != "not_model_callable" {
		t.Fatalf("forged token: code=%d m=%v", code, m)
	}
	withBackend(t, answers(pick(1))) // the prompt's scope menu: once, session, ...
	out := w.mustRun("", "--session", brokerSession, "prompt", "--name", "A", "--reason", "release the new version", "--scopes", "once,session")
	var tok struct{ Token, Scope string }
	if err := json.Unmarshal([]byte(out), &tok); err != nil || tok.Scope != "session" {
		t.Fatalf("prompt: %q", out)
	}
	code, m, raw := w.broker("grant", envelope("grant", w.outside, `"name":"A","layer":"global","scope":"session","prompt_token":`+jsonString(tok.Token)))
	if code != exitcode.OK || m["ok"] != true {
		t.Fatalf("token grant: code=%d out=%s", code, raw)
	}
	if g := m["grant"].(map[string]any); g["scope"] != "session" || g["expires_at"] == nil || len(g) != 2 {
		t.Fatalf("grant=%v", g)
	}
	if strings.Contains(raw, tok.Token) {
		t.Fatal("token echoed")
	}
}

func TestBrokerRevoke(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_r\n", "set", "A", "--stdin")
	withBackend(t, answers(yes(), yes()))
	w.mustRun("", "--session", brokerSession, "grant", "A", "--scope", "session")
	w.mustRun("", "--session", "pi:other5678", "grant", "A", "--scope", "once")
	_, m, _ := w.broker("revoke", envelope("revoke", w.outside, `"session_only":true`))
	if m["ok"] != true || m["revoked"].(float64) != 1 {
		t.Fatalf("session_only: %v", m)
	}
	_, m, _ = w.broker("revoke", envelope("revoke", w.outside, `"name":"A"`))
	if m["ok"] != true || m["revoked"].(float64) != 1 {
		t.Fatalf("name: %v", m)
	}
	if !w.auditHas(`"event":"revoke"`) {
		t.Fatal("not audited")
	}
}

func TestBrokerWithoutVault(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	code, out, _ := h.run(envelope("list", dir, ""), "broker", "--op", "list")
	if code != exitcode.Refusal || !strings.Contains(out, `"message":"no vault here; run 'qbit-vault init'"`) {
		t.Fatalf("code=%d out=%q", code, out)
	}
	_ = os.Remove(dir)
}

func jsonString(s string) string { b, _ := json.Marshal(s); return string(b) }
