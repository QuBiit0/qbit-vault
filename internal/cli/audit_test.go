package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"

	"github.com/qbitdevz/qbit-vault/internal/audit"
	"github.com/qbitdevz/qbit-vault/internal/exitcode"
	"github.com/qbitdevz/qbit-vault/internal/keychain"
	"github.com/qbitdevz/qbit-vault/internal/vault"
)

const auditWarning = "warning: audit log write failed\n"

type auditList struct {
	OK      bool           `json:"ok"`
	Records []audit.Record `json:"records"`
}

// records reads the whole audit log through the CLI.
func (w *world) records(args ...string) []audit.Record {
	w.t.Helper()
	code, out, errs := w.run("", append([]string{"--json", "audit", "--tail", "1000"}, args...)...)
	if code != exitcode.OK || errs != "" {
		w.t.Fatalf("audit: code=%d out=%q err=%q", code, out, errs)
	}
	var l auditList
	if err := json.Unmarshal([]byte(out), &l); err != nil || !l.OK {
		w.t.Fatalf("audit json: %v", err)
	}
	return l.Records
}

func (w *world) auditFile() string { return filepath.Join(w.home, "audit.jsonl") }

// view is the part of a record the event writers decide.
type view struct {
	Event, Session, Layer, By, Detail, Refusal, Cwd string
	Names                                           []string
}

func viewOf(r audit.Record) view {
	return view{r.Event, r.Session, r.Layer, r.By, r.Detail, r.Refusal, r.Cwd, r.Names}
}

func sameView(a, b view) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

func TestEndToEndAuditTrail(t *testing.T) {
	w := newBareWorld(t)
	var all strings.Builder
	must := func(stdin string, args ...string) {
		t.Helper()
		code, out, errs := w.run(stdin, args...)
		all.WriteString(out + errs)
		if code != 0 || errs != "" {
			t.Fatalf("%v: code=%d out=%q err=%q", args, code, out, errs)
		}
	}

	mode := string(keychain.NewOS().Name())
	must("", "init")
	must("", "init") // already initialized: not an event
	must(fxVal, "set", "GITHUB_TOKEN", "--global", "--stdin", "--description", fxVal+"_desc", "--binaries", "gh")
	must(fxVal+"_2", "set", "GITHUB_TOKEN", "--global", "--stdin")
	w.inRepo()
	must("", "edit", "GITHUB_TOKEN", "--description", fxVal+"_edited")
	must("", "mv", "GITHUB_TOKEN", "--to", "project", "--yes")
	w.mustRun("", "--json", "describe", "GITHUB_TOKEN") // reads are not events (and print the description)
	must("", "rm", "GITHUB_TOKEN", "--yes")
	code, out, errs := w.run("", "rm", "MISSING_KEY", "--yes")
	if code != exitcode.Refusal || out != "" || errs != "error: MISSING_KEY is not stored\n" {
		t.Fatalf("refusal: code=%d out=%q err=%q", code, out, errs)
	}

	proj := "project:" + w.root
	want := []view{
		{Event: "init", Session: "cli", By: "user", Detail: mode},
		{Event: "capture", Session: "cli", By: "user", Layer: "global", Names: []string{"GITHUB_TOKEN"}},
		{Event: "capture", Session: "cli", By: "user", Layer: "global", Names: []string{"GITHUB_TOKEN"}, Detail: "replaced"},
		{Event: "edit", Session: "cli", By: "user", Layer: "global", Names: []string{"GITHUB_TOKEN"}},
		{Event: "mv", Session: "cli", By: "user", Layer: proj, Names: []string{"GITHUB_TOKEN"}, Detail: "global->project"},
		{Event: "rm", Session: "cli", By: "user", Layer: proj, Names: []string{"GITHUB_TOKEN"}},
		{Event: "refusal", Session: "cli", By: "user", Refusal: "unknown_secret", Names: []string{"MISSING_KEY"}},
	}
	got := w.records()
	if len(got) != len(want) {
		t.Fatalf("%d records, want %d", len(got), len(want))
	}
	for i := range want {
		if !sameView(viewOf(got[i]), want[i]) {
			t.Errorf("record %d = %+v, want %+v", i+1, viewOf(got[i]), want[i])
		}
		if got[i].Seq != uint64(i+1) {
			t.Errorf("record %d has seq %d", i+1, got[i].Seq)
		}
	}

	if code, out, errs := w.run("", "audit", "--verify"); code != 0 || out != "audit log ok (7 records)\n" || errs != "" {
		t.Fatalf("verify: code=%d out=%q err=%q", code, out, errs)
	}
	if code, out, errs := w.run("", "--json", "audit", "--verify"); code != 0 || out != `{"ok":true,"valid":true,"records":7}`+"\n" || errs != "" {
		t.Fatalf("verify json: code=%d out=%q err=%q", code, out, errs)
	}

	// The file holds names and layers, never values, descriptions or
	// binaries, and nothing any command printed contained a value either.
	b, err := os.ReadFile(w.auditFile())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "TESTSECRET_") || strings.Contains(all.String(), "TESTSECRET_") {
		t.Fatal("a value, description or fixture reached the audit log or the output")
	}
	for _, frag := range []string{`"gh"`, "binaries", "description"} {
		if strings.Contains(string(b), frag) {
			t.Fatalf("metadata %q reached the audit log", frag)
		}
	}

	// Tamper with record 4: verify names the line and the reason.
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	lines[3] = strings.Replace(lines[3], `"event":"edit"`, `"event":"rm"`, 1)
	if err := os.WriteFile(w.auditFile(), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, errs := w.run("", "audit", "--verify"); code != exitcode.Failure || out != "audit log broken at line 4 (seq 4): bad_hash\n" || errs != "" {
		t.Fatalf("tampered verify: code=%d out=%q err=%q", code, out, errs)
	}
	wantJSON := `{"ok":true,"valid":false,"records":3,"problem":{"line":4,"seq":4,"reason":"bad_hash"}}` + "\n"
	if code, out, errs := w.run("", "--json", "audit", "--verify"); code != exitcode.Failure || out != wantJSON || errs != "" {
		t.Fatalf("tampered verify json: code=%d out=%q err=%q", code, out, errs)
	}
}

func TestRelinkIsAudited(t *testing.T) {
	w := newWorld(t)
	w.inRepo()
	w.mustRun(fxVal, "set", "A_KEY", "--project", "--stdin")
	newRepo := filepath.Join(filepath.Dir(w.repo), "shop-api-2")
	if err := os.MkdirAll(filepath.Join(newRepo, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	w.mustRun("", "relink", w.root, newRepo)
	recs := w.records("--event", "relink")
	if len(recs) != 1 {
		t.Fatalf("%d relink records", len(recs))
	}
	cwd, _ := os.Getwd()
	want := view{Event: "relink", Session: "cli", By: "user", Cwd: cwd}
	if !sameView(viewOf(recs[0]), want) {
		t.Fatalf("record = %+v, want %+v", viewOf(recs[0]), want)
	}
}

func TestAuditSessionFlag(t *testing.T) {
	w := newWorld(t)
	w.mustRun(fxVal, "--session", "pi:abcd1234", "set", "A_KEY", "--global", "--stdin")
	recs := w.records("--event", "capture")
	if len(recs) != 1 || recs[0].Session != "pi:abcd1234" {
		t.Fatalf("records = %+v", recs)
	}
	if recs := w.records("--event", "init"); len(recs) != 1 || recs[0].Session != "cli" {
		t.Fatalf("init records = %+v", recs)
	}
}

func TestRefusalsAreAudited(t *testing.T) {
	w := newWorld(t)
	for _, args := range [][]string{
		{"set", "A_KEY", "--project", "--stdin"},           // no_project
		{"set", "TESTSECRET_lower", "--global", "--stdin"}, // invalid_name
	} {
		if code, _, _ := w.run(fxVal, args...); code != exitcode.Refusal {
			t.Fatalf("%v: code=%d", args, code)
		}
	}
	got := w.records("--event", "refusal")
	want := []view{
		{Event: "refusal", Session: "cli", By: "user", Refusal: "no_project"},
		{Event: "refusal", Session: "cli", By: "user", Refusal: "invalid_name"},
	}
	if len(got) != 2 {
		t.Fatalf("%d refusal records", len(got))
	}
	for i := range want {
		if !sameView(viewOf(got[i]), want[i]) {
			t.Errorf("record %d = %+v, want %+v", i+1, viewOf(got[i]), want[i])
		}
	}
	if b, _ := os.ReadFile(w.auditFile()); strings.Contains(string(b), "TESTSECRET_") {
		t.Fatal("a rejected name reached the audit log")
	}
}

func TestUsageErrorsAreNotAudited(t *testing.T) {
	w := newWorld(t)
	w.run("", "rm", "A_KEY") // usage: --yes required
	w.run("", "audit", "--event", "bogus")
	if recs := w.records(); len(recs) != 1 || recs[0].Event != "init" {
		t.Fatalf("records = %+v", recs)
	}
}

// A failing audit write is a warning, never a different outcome (L4).
func TestAuditFailureIsOnlyAWarning(t *testing.T) {
	w := newWorld(t)
	if err := os.Remove(w.auditFile()); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(w.auditFile(), 0o700); err != nil { // the log path is a directory
		t.Fatal(err)
	}

	code, out, errs := w.run(fxVal, "set", "A_KEY", "--global", "--stdin")
	if code != 0 || out != "stored A_KEY (global)\n" || errs != auditWarning {
		t.Fatalf("set: code=%d out=%q err=%q", code, out, errs)
	}
	code, out, errs = w.run(fxVal, "--json", "set", "A_KEY", "--global", "--stdin")
	if code != 0 || out != `{"ok":true,"name":"A_KEY","layer":"global","project":null,"replaced":true}`+"\n" || errs != auditWarning {
		t.Fatalf("set json: code=%d out=%q err=%q", code, out, errs)
	}
	code, out, errs = w.run("", "rm", "A_KEY", "--yes")
	if code != 0 || out != "removed A_KEY (global)\n" || errs != auditWarning {
		t.Fatalf("rm: code=%d out=%q err=%q", code, out, errs)
	}
	code, out, errs = w.run("", "rm", "A_KEY", "--yes")
	if code != exitcode.Refusal || out != "" || errs != "error: A_KEY is not stored\n"+auditWarning {
		t.Fatalf("refusal: code=%d out=%q err=%q", code, out, errs)
	}
	// The vault change itself went through.
	if out := w.mustRun("", "list", "--layer", "all"); out != "no secrets\n" {
		t.Fatalf("list = %q", out)
	}
}

func TestInitAuditFailureIsOnlyAWarning(t *testing.T) {
	h := newHarness(t)
	if err := os.MkdirAll(filepath.Join(h.home, "audit.jsonl"), 0o700); err != nil {
		t.Fatal(err)
	}
	code, out, errs := h.run("", "init")
	want := "vault initialized at " + h.home + " (keychain: " + keychain.NewOS().Name() + ")\n"
	if code != 0 || out != want || errs != auditWarning {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
}

func TestAuditListOutput(t *testing.T) {
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	w.mustRun(fxVal, "set", "B_KEY", "--global", "--stdin")
	w.mustRun("", "rm", "A_KEY", "--yes")

	full := "TS init - - cli\n" +
		"TS capture A_KEY global cli\n" +
		"TS capture B_KEY global cli\n" +
		"TS rm A_KEY global cli\n"
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"default shows everything newest last", []string{"audit"}, full},
		{"tail", []string{"audit", "--tail", "2"}, "TS capture B_KEY global cli\nTS rm A_KEY global cli\n"},
		{"name", []string{"audit", "--name", "A_KEY"}, "TS capture A_KEY global cli\nTS rm A_KEY global cli\n"},
		{"event", []string{"audit", "--event", "rm"}, "TS rm A_KEY global cli\n"},
		{"since keeps recent", []string{"audit", "--since", "1h"}, full},
		{"since drops old", []string{"audit", "--since", "1ns"}, "no audit records\n"},
		{"filters combine, tail last", []string{"audit", "--name", "A_KEY", "--tail", "1"}, "TS rm A_KEY global cli\n"},
		{"no match", []string{"audit", "--name", "C_KEY"}, "no audit records\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out, errs := w.run("", tt.args...)
			if code != 0 || norm(out) != tt.want || errs != "" {
				t.Fatalf("code=%d\nout =%q\nwant=%q\nerr =%q", code, out, tt.want, errs)
			}
		})
	}

	// JSON: one object, records in the wire form.
	code, out, errs := w.run("", "--json", "audit", "--event", "rm")
	if code != 0 || errs != "" || !strings.HasPrefix(out, `{"ok":true,"records":[{"ts":"`) || !strings.HasSuffix(out, "}]}\n") {
		t.Fatalf("json: code=%d out=%q err=%q", code, out, errs)
	}
	var l auditList
	if err := json.Unmarshal([]byte(out), &l); err != nil || len(l.Records) != 1 || l.Records[0].Seq != 4 {
		t.Fatalf("json records: %v %+v", err, l)
	}
	if code, out, errs := w.run("", "--json", "audit", "--name", "C_KEY"); code != 0 || out != `{"ok":true,"records":[]}`+"\n" || errs != "" {
		t.Fatalf("empty json: code=%d out=%q err=%q", code, out, errs)
	}
}

func TestAuditListDefaultsToFifty(t *testing.T) {
	w := newWorld(t)
	for range 52 {
		w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	}
	out := w.mustRun("", "audit")
	if n := strings.Count(out, "\n"); n != 50 {
		t.Fatalf("%d lines, want 50", n)
	}
	if !strings.Contains(out, "capture A_KEY global cli") || strings.Contains(out, " init ") {
		t.Fatalf("tail did not keep the newest: %q", out)
	}
}

func TestAuditListShowsExitCode(t *testing.T) {
	w := newWorld(t)
	code := 7
	if err := audit.Append(w.home, audit.Record{Event: audit.EventExec, Session: "pi:abcd1234", Names: []string{"A_KEY"}, Layer: "global", ExitCode: &code}); err != nil {
		t.Fatal(err)
	}
	if out := w.mustRun("", "audit", "--event", "exec"); norm(out) != "TS exec A_KEY global pi:abcd1234 exit=7\n" {
		t.Fatalf("out = %q", out)
	}
	zero := 0
	_ = audit.Append(w.home, audit.Record{Event: audit.EventExec, Session: "pi:abcd1234", Names: []string{"A_KEY", "B_KEY"}, ExitCode: &zero})
	if out := w.mustRun("", "audit", "--tail", "1"); norm(out) != "TS exec A_KEY,B_KEY - pi:abcd1234 exit=0\n" {
		t.Fatalf("out = %q", out)
	}
}

func TestAuditVerifyOutput(t *testing.T) {
	w := newWorld(t)
	if code, out, errs := w.run("", "audit", "--verify"); code != 0 || out != "audit log ok (1 record)\n" || errs != "" {
		t.Fatalf("one record: code=%d out=%q err=%q", code, out, errs)
	}
	// Whole last record gone: the head anchor reports the truncation.
	if err := os.WriteFile(w.auditFile(), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, errs := w.run("", "audit", "--verify"); code != exitcode.Failure || out != "audit log broken at line 1 (seq 1): truncated\n" || errs != "" {
		t.Fatalf("truncated: code=%d out=%q err=%q", code, out, errs)
	}
}

func TestAuditVerifyOnEmptyHome(t *testing.T) {
	h := newHarness(t)
	if err := os.MkdirAll(h.home, 0o700); err != nil {
		t.Fatal(err)
	}
	if code, out, errs := h.run("", "audit", "--verify"); code != 0 || out != "audit log ok (0 records)\n" || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if code, out, errs := h.run("", "audit"); code != 0 || out != "no audit records\n" || errs != "" {
		t.Fatalf("list: code=%d out=%q err=%q", code, out, errs)
	}
}

func TestAuditWorksWithoutTheKey(t *testing.T) {
	w := newWorld(t)
	id, err := vault.ReadID(w.home)
	if err != nil {
		t.Fatal(err)
	}
	if err := keyring.Delete("qbit-vault", "master:"+id); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := w.run("", "list"); code == 0 {
		t.Fatal("vault should be locked without its key")
	}
	if out := w.mustRun("", "audit", "--verify"); !strings.HasPrefix(out, "audit log ok") {
		t.Fatalf("verify out = %q", out)
	}
	if out := w.mustRun("", "audit", "--event", "init"); norm(out) != "TS init - - cli\n" {
		t.Fatalf("list out = %q", out)
	}
}

func TestAuditWithoutVault(t *testing.T) {
	h := newHarness(t)
	for _, args := range [][]string{{"audit"}, {"audit", "--verify"}} {
		code, out, errs := h.run("", args...)
		if code != exitcode.Failure || out != "" || errs != "error: no vault here; run 'qbit-vault init'\n" {
			t.Fatalf("%v: code=%d out=%q err=%q", args, code, out, errs)
		}
	}
	code, out, errs := h.run("", "--json", "audit")
	if code != exitcode.Failure || errs != "" || out != `{"ok":false,"error":{"code":"not_initialized","message":"no vault here; run 'qbit-vault init'"}}`+"\n" {
		t.Fatalf("json: code=%d out=%q err=%q", code, out, errs)
	}
	if _, err := os.Stat(h.home); err == nil {
		t.Fatal("audit created the home")
	}
}

func TestAuditUsageErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
		msg  string
	}{
		{"tail zero", []string{"audit", "--tail", "0"}, "invalid --tail: must be a positive number"},
		{"tail negative", []string{"audit", "--tail", "-3"}, "invalid --tail: must be a positive number"},
		{"tail not a number", []string{"audit", "--tail", "many"}, "invalid value for --tail; see 'qbit-vault audit --help'"},
		{"since garbage", []string{"audit", "--since", "TESTSECRET_x"}, "invalid --since: use a duration such as 24h"},
		{"since zero", []string{"audit", "--since", "0s"}, "invalid --since: use a duration such as 24h"},
		{"since negative", []string{"audit", "--since", "-1h"}, "invalid --since: use a duration such as 24h"},
		{"event unknown", []string{"audit", "--event", "TESTSECRET_x"}, "invalid --event: not a known event"},
		{"name invalid", []string{"audit", "--name", "TESTSECRET_lower"}, "invalid --name: not a valid secret name"},
		{"verify with filter", []string{"audit", "--verify", "--tail", "5"}, "--verify cannot be combined with filters"},
		{"verify with name", []string{"audit", "--verify", "--name", "A_KEY"}, "--verify cannot be combined with filters"},
		{"extra argument", []string{"audit", "TESTSECRET_x"}, "unexpected arguments"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newWorld(t)
			code, out, errs := w.run("", tt.args...)
			if code != exitcode.Usage || out != "" || errs != usageErr(tt.msg) {
				t.Fatalf("code=%d out=%q err=%q", code, out, errs)
			}
			code, out, errs = w.run("", append([]string{"--json"}, tt.args...)...)
			if code != exitcode.Usage || errs != "" || out != jsonUsage(tt.msg) {
				t.Fatalf("json: code=%d out=%q err=%q", code, out, errs)
			}
			if strings.Contains(out+errs, "TESTSECRET_") {
				t.Fatal("input echoed")
			}
		})
	}
}

func TestInitWritesTheAuditHeadAndAMissingOneIsReported(t *testing.T) {
	w := newWorld(t)
	head := filepath.Join(w.home, "audit.head")
	if _, err := os.Stat(head); err != nil {
		t.Fatalf("init left no audit.head: %v", err)
	}
	for range 2 {
		if err := audit.Append(w.home, audit.Record{Event: audit.EventWarning, Session: "cli", Detail: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(head); err != nil {
		t.Fatal(err)
	}
	if code, out, errs := w.run("", "audit", "--verify"); code != exitcode.Failure || out != "audit log broken at line 3 (seq 4): head_mismatch\n" || errs != "" {
		t.Fatalf("verify: code=%d out=%q err=%q", code, out, errs)
	}
	code, out, errs := w.run("", "doctor")
	if code != exitcode.Failure || errs != "" || doctorStatus(out, "audit") != "fail" ||
		!strings.Contains(out, "audit chain broken at line 3 (head_mismatch)") {
		t.Fatalf("doctor: code=%d out=%q err=%q", code, out, errs)
	}
}
