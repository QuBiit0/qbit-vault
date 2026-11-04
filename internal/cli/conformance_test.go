package cli

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/conformance"
	"github.com/QuBiit0/qbit-vault/internal/prompt/prompttest"
	"github.com/QuBiit0/qbit-vault/internal/refusal"
)

// TestContractConformance drives every op through `broker --op` against a real
// vault and checks each request and response against the contract schema
// (TESTING.md § Contract conformance, roadmap slice 2.4).
func TestContractConformance(t *testing.T) {
	sch, err := conformance.Load(filepath.Join("..", "..", "contracts", "secrets-broker", "v1", "secrets-broker.v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	w := newWorld(t)
	w.mustRun("TESTSECRET_conf_a\n", "set", "A", "--stdin", "--description", "conformance")
	w.inRepo()
	w.mustRun("TESTSECRET_conf_p\n", "set", "P", "--stdin", "--project", "--binaries", "gh")
	w.outRepo()
	withBackend(t, answers(yes()))
	w.mustRun("", "--session", brokerSession, "grant", "A", "--scope", "session")
	exe := child(t, "leaks", "TOKEN", 0)

	type step struct {
		name, op, extra, cwd string
		script               []prompttest.Answer
		want                 string // "" = ok, else the refusal type
	}
	steps := []step{
		{"capabilities", "capabilities", "", w.outside, nil, ""},
		{"list outside", "list", "", w.outside, nil, ""},
		{"list in repo", "list", "", w.repo, nil, ""},
		{"exec", "exec", `"command":` + jsonString(exe) + `,"secrets":[{"name":"TOKEN","from":"A"}],"timeout_ms":60000,"shell":"auto"`, w.outside, nil, ""},
		{"exec no grant", "exec", `"command":"x","secrets":[{"name":"P"}]`, w.repo, nil, "grant_required"},
		{"exec unknown", "exec", `"command":"x","secrets":[{"name":"NOPE"}]`, w.outside, nil, "unknown_secret"},
		{"exec dump", "exec", `"command":"env","secrets":[{"name":"A"}]`, w.outside, nil, "dump_command"},
		{"request new", "request", `"name":"NEW_ONE","reason":"deploy the shop api now","suggested_scope":"once"`, w.outside, []prompttest.Answer{val("TESTSECRET_conf_new"), pick(0)}, ""},
		{"request fields", "request", `"fields":[{"name":"F_HOST","kind":"text","label":"Host"},{"name":"F_PASS"}],"reason":"run the migrations now"`, w.outside, []prompttest.Answer{val("h.internal"), val("TESTSECRET_conf_f"), pick(1)}, ""},
		{"request declined", "request", `"name":"DECL","reason":"deploy the shop api now"`, w.outside, []prompttest.Answer{val("TESTSECRET_conf_d"), pick(3)}, "user_declined"},
		{"request cooldown", "request", `"name":"DECL","reason":"deploy the shop api now"`, w.outside, nil, "rate_limited"},
		{"request three words", "request", `"name":"A","reason":"need it now"`, w.outside, []prompttest.Answer{pick(0)}, ""},
		{"request too vague", "request", `"name":"A","reason":"needed!!"`, w.outside, nil, "reason_too_vague"},
		{"request bad name", "request", `"name":"bad","reason":"deploy the shop api now"`, w.outside, nil, "invalid_name"},
		{"request no project", "request", `"name":"Q","reason":"deploy the shop api now","suggested_layer":"project"`, w.outside, nil, "no_project"},
		{"manage edit", "manage", `"action":"edit","name":"A","layer":"global","reason":"tighten the allowlist please","changes":{"binaries":["gh"]}`, w.outside, []prompttest.Answer{yes()}, ""},
		{"manage declined", "manage", `"action":"remove","name":"NEW_ONE","layer":"global","reason":"no longer used by anything"`, w.outside, []prompttest.Answer{no()}, "user_declined"},
		{"manage unknown", "manage", `"action":"remove","name":"NOPE","layer":"global","reason":"no longer used by anything"`, w.outside, nil, "unknown_secret"},
		{"grant no token", "grant", `"name":"A","layer":"global","scope":"once"`, w.outside, nil, "not_model_callable"},
		{"revoke", "revoke", `"session_only":true`, w.outside, nil, ""},
		{"bad contract", "list", `"x":1`, w.outside, nil, "internal"},
	}
	seen := map[string]bool{}
	for _, s := range steps {
		withBackend(t, answers(s.script...))
		req := envelope(s.op, s.cwd, s.extra)
		if s.want == "" {
			if err := sch.Request(s.op, []byte(req)); err != nil {
				t.Errorf("%s: our own request is not conformant: %v", s.name, err)
			}
		}
		_, out, errs := w.run(req, "broker", "--op", s.op)
		noFixtures(t, s.name, out+errs)
		def, err := sch.Response(s.op, []byte(out))
		if err != nil {
			t.Errorf("%s: %v\n%s", s.name, err, out)
			continue
		}
		var m map[string]any
		_ = json.Unmarshal([]byte(out), &m)
		got := ""
		if def == "refusal" {
			got = m["refusal"].(map[string]any)["type"].(string)
			seen[got] = true
		}
		if got != s.want {
			t.Errorf("%s: got %q want %q: %s", s.name, got, s.want, out)
		}
	}
	// Every refusal type of the schema is a refusal type of the code, and
	// the reverse (CONTRACT.md § Refusals).
	var code []string
	for _, ty := range refusal.Types() {
		code = append(code, string(ty))
	}
	schema := sch.RefusalTypes()
	sort.Strings(code)
	sort.Strings(schema)
	if !reflect.DeepEqual(code, schema) {
		t.Fatalf("refusal types drifted:\ncode   %v\nschema %v", code, schema)
	}
	t.Logf("refusal types exercised: %s", strings.Join(keys(seen), ", "))
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
