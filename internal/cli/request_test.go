package cli

import (
	"strings"
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/exitcode"
	"github.com/QuBiit0/qbit-vault/internal/grants"
	"github.com/QuBiit0/qbit-vault/internal/prompt"
	"github.com/QuBiit0/qbit-vault/internal/prompt/prompttest"
)

const reqReason = "create the github release for v1.2.0"

func reqFor(cwd, extra string) string {
	return envelope("request", cwd, `"name":"A","reason":"`+reqReason+`"`+extra)
}

// shape is a response with its expiry blanked, to compare two answers.
func shape(out string) string { return norm(out) }

func TestRequestNewSecretOutsideRepo(t *testing.T) {
	w := newWorld(t)
	f := withBackend(t, answers(val("TESTSECRET_request_value"), pick(0)))
	code, m, out := w.broker("request", reqFor(w.outside, `,"suggested_scope":"session"`))
	want := `{"ok":true,"refs":[{"name":"A","ref":"secret://A","layer":"global"}],"ref":"secret://A","layer":"global","grant":{"scope":"once","expires_at":"TS"}}` + "\n"
	if code != exitcode.OK || shape(out) != want {
		t.Fatalf("code=%d out=%s m=%v", code, out, m)
	}
	if len(f.Calls) != 2 || f.Calls[0].Kind != "secret" || f.Calls[1].Kind != "choose" {
		t.Fatalf("calls=%+v", f.Calls)
	}
	req := f.Calls[0].Request
	if req.Name != "A" || req.Reason != reqReason || req.Session != brokerSession || req.Host != "pi" || req.Existing {
		t.Fatalf("prompt request=%+v", req)
	}
	if f.Calls[1].Default != 0 || f.Calls[1].Q != "Pi wants to use A (all projects).\nWhy: "+reqReason {
		t.Fatalf("scope question=%+v", f.Calls[1])
	}
	if w.value("A") != "TESTSECRET_request_value" {
		t.Fatal("value not stored")
	}
	if !w.auditHas(`"event":"capture"`) || !w.auditHas(`"by":"agent"`) || !w.auditHas(`"reason":"`+reqReason+`"`) {
		t.Fatalf("audit: %s", w.auditText())
	}
	// The grant works for this session.
	g := w.mustRun("", "--json", "--session", brokerSession, "grants")
	if !strings.Contains(g, `"name":"A"`) || !strings.Contains(g, `"scope":"once"`) {
		t.Fatalf("grants=%s", g)
	}
}

func TestRequestExistingSecretAsksGrantOnlyAndLooksTheSame(t *testing.T) {
	w := newWorld(t)
	withBackend(t, answers(val("TESTSECRET_first"), pick(0)))
	_, _, first := w.broker("request", reqFor(w.outside, ""))
	f := withBackend(t, answers(pick(0)))
	code, _, second := w.broker("request", reqFor(w.outside, ""))
	if code != exitcode.OK || len(f.Calls) != 1 || f.Calls[0].Kind != "choose" {
		t.Fatalf("code=%d calls=%+v", code, f.Calls)
	}
	if shape(first) != shape(second) {
		t.Fatalf("the response tells existing from new:\n%s%s", first, second)
	}
	if w.value("A") != "TESTSECRET_first" {
		t.Fatal("a grant-only request replaced the value")
	}
}

func TestRequestInsideRepoAsksLayer(t *testing.T) {
	w := newWorld(t)
	f := withBackend(t, answers(pick(1), val("TESTSECRET_proj"), pick(0)))
	code, m, _ := w.broker("request", reqFor(w.repo, `,"suggested_layer":"project"`))
	if code != exitcode.OK || m["layer"] != "project" || m["grant"].(map[string]any)["scope"] != "once" {
		t.Fatalf("code=%d m=%v", code, m)
	}
	if f.Calls[0].Kind != "choose" || f.Calls[0].Default != 1 || f.Calls[0].Q != "Where should A be saved?" {
		t.Fatalf("layer question=%+v", f.Calls[0])
	}
	if !strings.Contains(w.snapshot(), `"layer":"project"`) {
		t.Fatal("not stored in the project")
	}
	code, m, _ = w.broker("request", envelope("request", w.outside, `"name":"B","reason":"`+reqReason+`","suggested_layer":"project"`))
	if code != exitcode.Refusal || refusalType(m) != "no_project" {
		t.Fatalf("project outside a repo: code=%d m=%v", code, m)
	}
}

func TestRequestDeclineStartsCooldown(t *testing.T) {
	w := newWorld(t)
	before := w.snapshot()
	withBackend(t, answers(val("TESTSECRET_declined"), pick(3))) // once, session, deny
	code, m, _ := w.broker("request", reqFor(w.outside, ""))
	if code != exitcode.Refusal || refusalType(m) != "user_declined" {
		t.Fatalf("deny: code=%d m=%v", code, m)
	}
	if w.snapshot() != before {
		t.Fatal("a declined request stored the value")
	}
	f := withBackend(t, answers())
	code, m, _ = w.broker("request", reqFor(w.outside, ""))
	if code != exitcode.Refusal || refusalType(m) != "rate_limited" || m["refusal"].(map[string]any)["name"] != "A" || len(f.Calls) != 0 {
		t.Fatalf("cooldown: code=%d m=%v calls=%d", code, m, len(f.Calls))
	}
	_, m, _ = w.broker("list", envelope("list", w.outside, ""))
	cd := m["policy"].(map[string]any)["cooldowns"].([]any)
	if len(cd) != 1 || cd[0].(map[string]any)["name"] != "A" {
		t.Fatalf("policy cooldowns=%v", cd)
	}
}

// A decline also starts a short cooldown for the name and layer, so another
// session cannot re-prompt it at once; it ends sooner than the session one.
func TestRequestDeclineCoolsTheNameForOtherSessionsBriefly(t *testing.T) {
	w := newWorld(t)
	at := pinClock(t)
	before := w.snapshot()
	withBackend(t, answers(val("TESTSECRET_declined"), pick(3))) // once, session, deny
	if code, m, _ := w.broker("request", reqFor(w.outside, "")); code != exitcode.Refusal || refusalType(m) != "user_declined" {
		t.Fatalf("deny: code=%d m=%v", code, m)
	}
	other := strings.Replace(reqFor(w.outside, ""), brokerSession, "pi:other5678", 1)
	f := withBackend(t, answers())
	code, m, _ := w.broker("request", other)
	if code != exitcode.Refusal || refusalType(m) != "rate_limited" || m["refusal"].(map[string]any)["name"] != "A" || len(f.Calls) != 0 {
		t.Fatalf("other session: code=%d m=%v calls=%d", code, m, len(f.Calls))
	}
	if w.snapshot() != before {
		t.Fatal("a refused request stored the value")
	}
	// Another name is not blocked.
	withBackend(t, answers(val("TESTSECRET_b"), pick(0)))
	if code, _, out := w.broker("request", strings.Replace(other, `"name":"A"`, `"name":"B"`, 1)); code != exitcode.OK {
		t.Fatalf("other name: %s", out)
	}
	// The shared cooldown is shorter than the session one: the declining
	// session is still blocked, another one is free.
	at(gt0.Add(grants.SharedCooldown))
	if code, m, _ := w.broker("request", reqFor(w.outside, "")); code != exitcode.Refusal || refusalType(m) != "rate_limited" {
		t.Fatalf("declining session: code=%d m=%v", code, m)
	}
	withBackend(t, answers(val("TESTSECRET_other"), pick(0)))
	if code, _, out := w.broker("request", other); code != exitcode.OK {
		t.Fatalf("after the shared cooldown: %s", out)
	}
}

func TestRequestCancelAndNoPrompt(t *testing.T) {
	w := newWorld(t)
	before := w.snapshot()
	withBackend(t, answers(prompttest.Answer{Err: prompt.ErrCancelled}))
	if code, m, _ := w.broker("request", reqFor(w.outside, "")); code != exitcode.Refusal || refusalType(m) != "user_declined" {
		t.Fatalf("cancel: code=%d m=%v", code, m)
	}
	withBackend(t, answers(prompttest.Answer{Err: prompt.ErrTimeout}))
	b := strings.Replace(reqFor(w.outside, ""), `"name":"A"`, `"name":"B"`, 1)
	if code, m, _ := w.broker("request", b); code != exitcode.Refusal || refusalType(m) != "user_declined" {
		t.Fatalf("timeout: code=%d m=%v", code, m)
	}
	withBackend(t, &prompttest.Fake{Unavailable: true})
	c := strings.Replace(reqFor(w.outside, ""), `"name":"A"`, `"name":"C"`, 1)
	code, m, _ := w.broker("request", c)
	if code != exitcode.Refusal || refusalType(m) != "internal" || m["refusal"].(map[string]any)["message"] != "Nobody can answer here (no terminal or desktop session). Run it from a terminal." {
		t.Fatalf("no prompt: code=%d m=%v", code, m)
	}
	if w.snapshot() != before {
		t.Fatal("a failed request changed the vault")
	}
}

func TestRequestReasonAndSensitive(t *testing.T) {
	w := newWorld(t)
	code, m, _ := w.broker("request", envelope("request", w.outside, `"name":"A","reason":"need it!"`))
	if code != exitcode.Refusal || refusalType(m) != "reason_too_vague" {
		t.Fatalf("vague: code=%d m=%v", code, m)
	}
	w.mustRun("TESTSECRET_sensitive\n", "set", "S", "--stdin", "--sensitive")
	f := withBackend(t, answers(pick(0)))
	code, m, _ = w.broker("request", envelope("request", w.outside, `"name":"S","reason":"`+reqReason+`","suggested_scope":"project"`))
	if code != exitcode.OK || m["grant"].(map[string]any)["scope"] != "once" {
		t.Fatalf("sensitive: code=%d m=%v", code, m)
	}
	if opts := f.Calls[0].Options; len(opts) != 2 || !strings.HasPrefix(opts[0], "Once:") || opts[1] != "Don't allow" {
		t.Fatalf("sensitive offers %v", opts)
	}
}

const dbFields = `"fields":[{"name":"DB_HOST","kind":"text","label":"Host"},{"name":"DB_USER","kind":"text"},{"name":"DB_PASSWORD","label":"Password","description":"staging db"}]`

func TestRequestSeveralFieldsInOnePrompt(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_user\n", "set", "DB_USER", "--stdin") // already stored: no box
	f := withBackend(t, answers(val("db.internal"), val("TESTSECRET_db_password"), pick(0)))
	code, _, out := w.broker("request", envelope("request", w.outside, dbFields+`,"reason":"run the shop-api migrations"`))
	if code != exitcode.OK {
		t.Fatalf("code=%d out=%s", code, out)
	}
	want := `{"ok":true,"refs":[{"name":"DB_HOST","ref":"secret://DB_HOST","layer":"global"},{"name":"DB_USER","ref":"secret://DB_USER","layer":"global"},{"name":"DB_PASSWORD","ref":"secret://DB_PASSWORD","layer":"global"}],"grant":{"scope":"once","expires_at":"TS"}}` + "\n"
	if shape(out) != want {
		t.Fatalf("got  %s\nwant %s", out, want)
	}
	if len(f.Calls) != 3 {
		t.Fatalf("calls=%+v", f.Calls)
	}
	host, pass := f.Calls[0].Request, f.Calls[1].Request
	if !host.Visible || host.Label != "Host" || host.Field != 1 || host.Fields != 2 || pass.Visible || pass.Field != 2 || pass.Label != "Password" {
		t.Fatalf("boxes: %+v / %+v", host, pass)
	}
	if q := f.Calls[2].Q; q != "Pi wants to use DB_HOST (all projects), DB_USER (all projects, already saved), DB_PASSWORD (all projects).\nWhy: run the shop-api migrations" {
		t.Fatalf("scope question=%q", q)
	}
	w.outRepo()
	if w.value("DB_HOST") != "db.internal" || w.value("DB_PASSWORD") != "TESTSECRET_db_password" || w.value("DB_USER") != "TESTSECRET_user" {
		t.Fatal("values")
	}
	_, lm, _ := w.broker("list", envelope("list", w.outside, ""))
	kinds := map[string]string{}
	for _, s := range lm["secrets"].([]any) {
		e := s.(map[string]any)
		kinds[e["name"].(string)] = e["kind"].(string)
		if e["grant"] == nil {
			t.Errorf("%s has no grant", e["name"])
		}
	}
	if kinds["DB_HOST"] != "text" || kinds["DB_PASSWORD"] != "secret" || kinds["DB_USER"] != "secret" {
		t.Fatalf("kinds=%v", kinds)
	}
	noFixtures(t, "multi-field response", out)
}

func TestRequestSeveralFieldsAllOrNothing(t *testing.T) {
	w := newWorld(t)
	before := w.snapshot()
	withBackend(t, answers(val("db.internal"), prompttest.Answer{Err: prompt.ErrCancelled}))
	req := envelope("request", w.outside, dbFields+`,"reason":"run the shop-api migrations"`)
	if code, m, _ := w.broker("request", req); code != exitcode.Refusal || refusalType(m) != "user_declined" {
		t.Fatalf("cancel at the second box: code=%d m=%v", code, m)
	}
	if w.snapshot() != before {
		t.Fatal("a cancelled multi-field request stored something")
	}
	// Every name of the request is cooling down now.
	withBackend(t, answers())
	one := envelope("request", w.outside, `"name":"DB_PASSWORD","reason":"run the shop-api migrations"`)
	if code, m, _ := w.broker("request", one); code != exitcode.Refusal || refusalType(m) != "rate_limited" {
		t.Fatalf("cooldown: code=%d m=%v", code, m)
	}
	nine := `"fields":[`
	for i := 0; i < 9; i++ {
		if i > 0 {
			nine += ","
		}
		nine += `{"name":"F` + strings.Repeat("X", i) + `"}`
	}
	if code, m, _ := w.broker("request", envelope("request", w.outside, nine+`],"reason":"too many fields at once"`)); code != exitcode.Refusal || refusalType(m) != "internal" {
		t.Fatalf("nine fields: code=%d m=%v", code, m)
	}
}

func TestRequestSeveralFieldsUsesOneFormWhereThereIsOne(t *testing.T) {
	w := newWorld(t)
	f := &prompttest.FormFake{Fake: prompttest.Fake{Script: []prompttest.Answer{val("db.internal|TESTSECRET_user|TESTSECRET_pw"), pick(0)}}}
	withFormBackend(t, f)
	code, _, out := w.broker("request", envelope("request", w.outside, dbFields+`,"reason":"run the shop-api migrations"`))
	if code != exitcode.OK {
		t.Fatalf("code=%d out=%s", code, out)
	}
	if len(f.Calls) != 2 || f.Calls[0].Kind != "form" || len(f.Calls[0].Requests) != 3 {
		t.Fatalf("calls=%+v", f.Calls)
	}
	if rs := f.Calls[0].Requests; !rs[0].Visible || rs[2].Visible || rs[0].Label != "Host" {
		t.Fatalf("form requests=%+v", rs)
	}
	if w.value("DB_PASSWORD") != "TESTSECRET_pw" || w.value("DB_HOST") != "db.internal" {
		t.Fatal("form values not stored")
	}
	// One new field does not need a form.
	f = &prompttest.FormFake{Fake: prompttest.Fake{Script: []prompttest.Answer{val("TESTSECRET_one"), pick(0)}}}
	withFormBackend(t, f)
	w.broker("request", envelope("request", w.outside, `"name":"SOLO","reason":"run the shop-api migrations"`))
	if f.Calls[0].Kind != "secret" {
		t.Fatalf("single field used %s", f.Calls[0].Kind)
	}
}

func withFormBackend(t *testing.T, f *prompttest.FormFake) {
	t.Helper()
	old := newPrompt
	newPrompt = func(*globals) (prompt.Backend, error) { return f, nil }
	t.Cleanup(func() { newPrompt = old })
}

// W1: suggesting the project layer outside a repository is refused the same
// way whether the name exists, so the refusal cannot probe the vault.
func TestRequestNoProjectDoesNotDiscloseExistence(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_w1\n", "set", "HAVE", "--stdin")
	f := withBackend(t, answers())
	for _, n := range []string{"HAVE", "MISSING"} {
		code, m, _ := w.broker("request", envelope("request", w.outside, `"name":"`+n+`","reason":"deploy the shop api now","suggested_layer":"project"`))
		if code != exitcode.Refusal || refusalType(m) != "no_project" {
			t.Fatalf("%s: code=%d m=%v", n, code, m)
		}
	}
	if len(f.Calls) != 0 {
		t.Fatalf("asked the user: %+v", f.Calls)
	}
}

// W3, W4: the user sees each field's description, and which fields are
// already stored.
func TestRequestShowsDescriptionsAndStoredFields(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_user\n", "set", "DB_USER", "--stdin")
	f := withBackend(t, answers(val("db.internal"), val("TESTSECRET_pw"), pick(0)))
	w.broker("request", envelope("request", w.outside, dbFields+`,"reason":"run the shop-api migrations"`))
	pass := f.Calls[1].Request
	if pass.Description != "staging db" || len(pass.Stored) != 1 || pass.Stored[0] != "DB_USER" {
		t.Fatalf("box request=%+v", pass)
	}
	if q := f.Calls[2].Q; !strings.Contains(q, "DB_USER (all projects, already saved)") {
		t.Fatalf("scope question=%q", q)
	}
}

// Three answers at most: once (preselected whatever the agent suggested),
// always in this project (inside a repository only), or no. Never session:
// a restarted agent is a new session, so it kept asking again.
func TestRequestOffersOnceAlwaysOrNo(t *testing.T) {
	for _, extra := range []string{"", `,"suggested_scope":"once"`, `,"suggested_scope":"project"`, `,"suggested_scope":"session"`} {
		w := newWorld(t)
		f := withBackend(t, answers(val("TESTSECRET_preselect"), pick(0)))
		code, m, _ := w.broker("request", reqFor(w.outside, extra))
		if code != exitcode.OK {
			t.Fatalf("%q: code=%d m=%v", extra, code, m)
		}
		c := f.Calls[1]
		if c.Default != 0 || strings.Join(c.Options, "|") != "Once: only the next command|Don't allow" {
			t.Fatalf("%q: default=%d options=%v", extra, c.Default, c.Options)
		}
	}
}

// A sensitive record does not offer session, so the old default stays.
func TestRequestSensitiveKeepsOldDefault(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_sensitive\n", "set", "S", "--stdin", "--sensitive")
	f := withBackend(t, answers(pick(0)))
	w.broker("request", envelope("request", w.outside, `"name":"S","reason":"`+reqReason+`","suggested_scope":"project"`))
	c := f.Calls[0]
	if c.Default != 0 || len(c.Options) != 2 || !strings.HasPrefix(c.Options[0], "Once:") {
		t.Fatalf("default=%d options=%v", c.Default, c.Options)
	}
}

// midPrompt runs hook once, when the scope question is asked: the moment a
// `set` of the same name can land while a request waits for its answer.
type midPrompt struct {
	*prompttest.Fake
	hook func()
}

func (m *midPrompt) Choose(q string, options []string, def int) (int, error) {
	if m.hook != nil {
		h := m.hook
		m.hook = nil
		h()
	}
	return m.Fake.Choose(q, options, def)
}

// A `set` of the same name between the request's lookup and its store must
// win: the store re-checks under the vault lock and never overwrites.
func TestRequestDoesNotOverwriteASetThatLandedWhileAsking(t *testing.T) {
	w := newWorld(t)
	f := answers(val("TESTSECRET_from_request"), pick(0))
	m := &midPrompt{Fake: f}
	m.hook = func() { w.mustRun("TESTSECRET_from_set", "set", "A", "--global", "--stdin") }
	old := newPrompt
	newPrompt = func(*globals) (prompt.Backend, error) { return m, nil }
	t.Cleanup(func() { newPrompt = old })

	code, r, out := w.broker("request", reqFor(w.outside, ""))
	if code != exitcode.Failure && code != exitcode.Refusal {
		t.Fatalf("code=%d out=%s", code, out)
	}
	if refusalType(r) != "internal" || r["refusal"].(map[string]any)["message"] != "A changed while it was being asked; ask again" ||
		r["refusal"].(map[string]any)["retryable"] != true {
		t.Fatalf("refusal = %s", out)
	}
	if w.value("A") != "TESTSECRET_from_set" {
		t.Fatal("the request overwrote the value `set` stored")
	}
	if strings.Count(w.auditText(), `"event":"capture"`) != 1 {
		t.Fatalf("a refused store was audited as a capture: %s", w.auditText())
	}
	if g := w.mustRun("", "--json", "--session", brokerSession, "grants"); strings.Contains(g, `"name":"A"`) {
		t.Fatalf("a refused store left a grant: %s", g)
	}
}

// R3-conflict-name: when several fields are asked and one of them was stored
// meanwhile, the refusal names that field, not the first one asked, and
// nothing of the request is stored.
func TestRequestConflictNamesTheFieldThatExists(t *testing.T) {
	w := newWorld(t)
	f := answers(val("db.internal"), val("TESTSECRET_user"), val("TESTSECRET_db_password"), pick(0))
	m := &midPrompt{Fake: f}
	m.hook = func() { w.mustRun("TESTSECRET_from_set", "set", "DB_PASSWORD", "--global", "--stdin") }
	old := newPrompt
	newPrompt = func(*globals) (prompt.Backend, error) { return m, nil }
	t.Cleanup(func() { newPrompt = old })

	code, r, out := w.broker("request", envelope("request", w.outside, dbFields+`,"reason":"run the shop-api migrations"`))
	if code != exitcode.Failure && code != exitcode.Refusal {
		t.Fatalf("code=%d out=%s", code, out)
	}
	ref := r["refusal"].(map[string]any)
	if refusalType(r) != "internal" || ref["message"] != "DB_PASSWORD changed while it was being asked; ask again" || ref["retryable"] != true {
		t.Fatalf("refusal = %s", out)
	}
	if w.value("DB_PASSWORD") != "TESTSECRET_from_set" {
		t.Fatal("the request overwrote the value `set` stored")
	}
	if got := w.mustRun("", "--json", "list", "--layer", "all"); strings.Contains(got, "DB_HOST") || strings.Contains(got, "DB_USER") {
		t.Fatalf("a refused request stored other fields: %s", got)
	}
	noFixtures(t, "the refusal", out)
}
