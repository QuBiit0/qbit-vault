package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/QuBiit0/gentle-vault/internal/exitcode"
	"github.com/QuBiit0/gentle-vault/internal/prompt/prompttest"
)

// Slice S.9b: server history and restore (REMOTE_SYNC § 7.6).

type historyRow struct {
	Version int64  `json:"version"`
	Device  string `json:"device"`
	At      string `json:"at"`
}

func ver(n int64) string { return strconv.FormatInt(n, 10) }

func (w *world) history() []historyRow {
	w.t.Helper()
	out := w.mustRun("", "--json", "remote", "history")
	noFixtures(w.t, "remote history --json", out)
	var got struct {
		OK       bool
		Versions []historyRow
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil || !got.OK {
		w.t.Fatalf("history json = %q (%v)", out, err)
	}
	return got.Versions
}

func TestHistoryListsTheLastTenVersionsWithLabels(t *testing.T) {
	_, _, a, b := syncPair(t)
	a.mustRun("TESTSECRET_h1", "set", "H_KEY", "--global", "--stdin")
	b.mustRun("", "remote", "sync")
	b.mustRun("TESTSECRET_h2", "set", "H_KEY2", "--global", "--stdin")
	rows := a.history()
	if len(rows) < 3 || rows[0].Device != "Laptop B" || rows[0].Version != readState(t, b).LastVersion || rows[0].At == "" {
		t.Fatalf("history = %+v", rows)
	}
	if rows[1].Device != deviceLabel() || rows[0].Version != rows[1].Version+1 {
		t.Fatalf("history (newest first, labels from the roster) = %+v", rows)
	}
	human := a.mustRun("", "remote", "history")
	if !strings.Contains(human, "Laptop B") || !strings.Contains(human, deviceLabel()) {
		t.Fatalf("human = %q", human)
	}
	noFixtures(t, "history", human)
	for i := 0; i < 6; i++ {
		a.mustRun("TESTSECRET_hx", "set", "H_MANY", "--global", "--stdin")
		a.mustRun("TESTSECRET_hy", "set", "H_MANY2", "--global", "--stdin")
	}
	if rows := a.history(); len(rows) != 10 {
		t.Fatalf("%d versions, want the last 10", len(rows))
	}
}

func TestHistoryNeedsTheServer(t *testing.T) {
	_, tp, a, _ := syncPair(t)
	tp.down.Store(true)
	if code, id := jsonErrCode(t, a, "remote", "history"); code != exitcode.Failure || id != "remote_unreachable" {
		t.Fatalf("code=%d id=%q", code, id)
	}
	plain := newWorld(t)
	if code, id := jsonErrCode(t, plain, "remote", "history"); code != exitcode.Failure || id != "remote_not_configured" {
		t.Fatalf("code=%d id=%q", code, id)
	}
}

// restorePair is two devices with history: version vN holds R1=one and
// R2=two; after it R1 changed, R2 was removed and R3 was added.
func restorePair(t *testing.T) (ss *syncServer, a, b *world, vN int64) {
	t.Helper()
	ss, _, a, b = syncPair(t)
	a.mustRun("TESTSECRET_one", "set", "R1", "--global", "--stdin")
	a.mustRun("TESTSECRET_two", "set", "R2", "--global", "--stdin")
	vN = readState(t, a).LastVersion
	a.mustRun("TESTSECRET_uno", "set", "R1", "--global", "--stdin")
	a.mustRun("", "rm", "R2", "--global", "--yes")
	a.mustRun("TESTSECRET_three", "set", "R3", "--global", "--stdin")
	b.mustRun("", "remote", "sync")
	return
}

func TestRestoreMakesBothDevicesEqualTheVersion(t *testing.T) {
	_, a, b, vN := restorePair(t)
	if b.value("R1") != "TESTSECRET_uno" {
		t.Fatal("setup: B should hold the current state")
	}
	backups := len(a.backupIDs())
	f := answers(yes())
	asBackend(t, keepBackend{f})
	code, out, errs := a.run("", "remote", "restore", "--version", ver(vN))
	if code != exitcode.OK || errs != "" || !strings.Contains(out, ver(vN)) {
		t.Fatalf("restore: code=%d out=%q err=%q", code, out, errs)
	}
	noFixtures(t, "restore", out+errs)
	if len(f.Calls) != 1 || f.Calls[0].Kind != "confirm" {
		t.Fatalf("prompts = %v", kindsOf(f))
	}
	if a.value("R1") != "TESTSECRET_one" || a.value("R2") != "TESTSECRET_two" {
		t.Fatal("A does not hold the restored values")
	}
	if strings.Contains(a.names(), "R3") {
		t.Fatal("R3 should be gone after restoring a version without it")
	}
	if len(a.backupIDs()) <= backups {
		t.Fatal("the replaced state was not snapshotted")
	}
	if st := readState(t, a); st.PendingPush || st.LastVersion <= vN {
		t.Fatalf("restore not pushed as a new version: %+v", st)
	}
	// The restore syncs as an ordinary edit and wins over what B had.
	b.mustRun("", "remote", "sync")
	if b.value("R1") != "TESTSECRET_one" || b.value("R2") != "TESTSECRET_two" || strings.Contains(b.names(), "R3") {
		t.Fatalf("B after sync: names=%s", b.names())
	}
	if !a.auditHas("restored version " + ver(vN)) {
		t.Fatalf("audit: %s", a.auditText())
	}
	noFixtures(t, "audit", a.auditText())
	// Any device can restore, and the others follow.
	asBackend(t, keepBackend{answers(yes())})
	b.mustRun("", "remote", "restore", "--version", ver(vN))
	a.mustRun("", "remote", "sync")
	if a.value("R1") != "TESTSECRET_one" {
		t.Fatal("a second restore changed the wrong values")
	}
}

func TestRestoreGivesRestoredRecordsFreshClocksAndIDs(t *testing.T) {
	_, a, _, vN := restorePair(t)
	before := a.hlcs()
	asBackend(t, keepBackend{answers(yes())})
	a.mustRun("", "remote", "restore", "--version", ver(vN))
	after := a.hlcs()
	for _, name := range []string{"global/R1", "global/R2"} {
		if after[name] == "" || after[name] <= before[name] {
			t.Fatalf("%s: clock %q is not newer than %q", name, after[name], before[name])
		}
	}
}

func TestRestoreRefusals(t *testing.T) {
	ss, a, _, vN := restorePair(t)
	before := a.snapshot()
	current := readState(t, a).LastVersion
	cases := []struct {
		name string
		args []string
		ans  []prompttest.Answer
		code int
		want string
	}{
		{"no version", nil, nil, exitcode.Usage, "--version"},
		{"zero", []string{"--version", "0"}, nil, exitcode.Usage, "--version"},
		{"negative", []string{"--version", "-3"}, nil, exitcode.Usage, "--version"},
		{"not a number", []string{"--version", "abc"}, nil, exitcode.Usage, "--version"},
		{"unknown", []string{"--version", "9999"}, nil, exitcode.Failure, "that version is not on the server"},
		{"cancel", []string{"--version", ver(vN)}, []prompttest.Answer{no()}, exitcode.Failure, "cancelled"},
	}
	for _, c := range cases {
		asBackend(t, keepBackend{answers(c.ans...)})
		code, out, errs := a.run("", append([]string{"remote", "restore"}, c.args...)...)
		if code != c.code || out != "" || !strings.HasPrefix(errs, "error: ") || !strings.Contains(errs, c.want) {
			t.Errorf("%s: code=%d out=%q err=%q", c.name, code, out, errs)
		}
		noFixtures(t, c.name, out+errs)
	}
	if a.snapshot() != before || readState(t, a).LastVersion != current || readState(t, a).PendingPush {
		t.Fatal("a refused restore changed the vault or pushed")
	}

	// A hostile server that flips a byte inside the sealed version.
	ss.proxy(func(w http.ResponseWriter, r *http.Request) bool {
		// The forwarded request reaches this proxy again: let it through, or
		// the flip would recurse and cancel itself out an even number of times.
		if r.Method != "GET" || r.URL.Path != "/v1/vault" || r.URL.Query().Get("version") == "" || r.Header.Get("X-Test-Forwarded") != "" {
			return false
		}
		req, _ := http.NewRequest("GET", ss.ts.URL+r.URL.RequestURI(), nil)
		req.Header = r.Header.Clone()
		req.Header.Set("X-Test-Forwarded", "1")
		res, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			return false
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		var m map[string]any
		if json.Unmarshal(raw, &m) != nil {
			return false
		}
		if blob, ok := m["blob"].(string); ok && len(blob) > 80 {
			bs := []byte(blob)
			i := len(bs) - 20
			bs[i] = map[bool]byte{true: 'B', false: 'A'}[bs[i] == 'A']
			m["blob"] = string(bs)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(res.StatusCode)
		_ = json.NewEncoder(w).Encode(m)
		return true
	})
	asBackend(t, keepBackend{answers(yes())})
	code, out, errs := a.run("", "remote", "restore", "--version", ver(vN))
	if code != exitcode.Failure || out != "" || !strings.Contains(errs, "could not be verified") {
		t.Fatalf("tampered: code=%d out=%q err=%q", code, out, errs)
	}
	if a.snapshot() != before {
		t.Fatal("a tampered version changed the vault")
	}
	noFixtures(t, "tampered", errs)
}

func TestRestoreRefusesAVersionOfAnOlderGeneration(t *testing.T) {
	_, a, b, c, _ := threeDevices(t)
	old := readState(t, a).LastVersion // sealed under generation 1
	asBackend(t, keepBackend{answers(yes(), no())})
	if code, out, errs := a.run("", "remote", "revoke-device", c.devID()); code != exitcode.OK {
		t.Fatalf("revoke: code=%d out=%q err=%q", code, out, errs)
	}
	b.mustRun("", "remote", "sync")
	before := a.snapshot()
	asBackend(t, keepBackend{answers(yes())})
	code, out, errs := a.run("", "remote", "restore", "--version", ver(old))
	if code != exitcode.Failure || out != "" || !strings.Contains(errs, "older account key") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if a.snapshot() != before {
		t.Fatal("a refused restore changed the vault")
	}
	noFixtures(t, "older generation", errs)
}

func TestRestoreAndHistoryNeedNoPromptForHistoryAndABackendForRestore(t *testing.T) {
	_, a, _, vN := restorePair(t)
	noBackend(t)
	a.mustRun("", "remote", "history") // read-only: no prompt
	if code, out, _ := a.run("", "--json", "remote", "restore", "--version", ver(vN)); code != exitcode.Refusal || !strings.Contains(out, `"not_model_callable"`) {
		t.Fatalf("code=%d out=%q", code, out)
	}
	plain := newWorld(t)
	asBackend(t, keepBackend{answers(yes())})
	if code, id := jsonErrCode(t, plain, "remote", "restore", "--version", "1"); code != exitcode.Failure || id != "remote_not_configured" {
		t.Fatalf("code=%d id=%q", code, id)
	}
}

// hlcs returns the clock of every global record, read from the body.
func (w *world) hlcs() map[string]string {
	w.t.Helper()
	g := &globals{getenv: envFrom(nil), home: w.home}
	s, err := g.openSession()
	if err != nil {
		w.t.Fatal(err)
	}
	defer s.close()
	raw, err := s.v.Body()
	if err != nil {
		w.t.Fatal(err)
	}
	var body struct {
		Global map[string]struct {
			HLC string `json:"hlc"`
		} `json:"global"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		w.t.Fatal(err)
	}
	out := map[string]string{}
	for n, r := range body.Global {
		out["global/"+n] = r.HLC
	}
	return out
}

func TestRestoreJSONAndTheServerNeverSeesValues(t *testing.T) {
	ss, a, _, vN := restorePair(t)
	asBackend(t, keepBackend{answers(yes())})
	code, out, errs := a.run("", "--json", "remote", "restore", "--version", ver(vN))
	var got struct {
		OK       bool
		Restored int64
		Changed  int
		Remote   string
	}
	if err := json.Unmarshal([]byte(out), &got); code != exitcode.OK || err != nil || !got.OK || got.Restored != vN || got.Changed != 3 || got.Remote != "synced" || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	noFixtures(t, "restore --json", out+errs)
	noFixtures(t, "server data", ss.held(t))
}
