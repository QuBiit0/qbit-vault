package cli

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/QuBiit0/gentle-vault/internal/exitcode"
	"github.com/QuBiit0/gentle-vault/internal/prompt/prompttest"
)

// Slice S.9b: conflicts and their resolution (REMOTE_SYNC § 7.4).

const (
	conflictOld = "TESTSECRET_conflict_old_9b"
	conflictA   = "TESTSECRET_conflict_a_9b"
	conflictB   = "TESTSECRET_conflict_b_9b"
)

type conflictJSON struct {
	Name    string `json:"name"`
	Layer   string `json:"layer"`
	LostAt  string `json:"lost_at"`
	Winner  string `json:"winner"`
	Deleted bool   `json:"deleted"`
}

func (w *world) conflicts() []conflictJSON {
	w.t.Helper()
	out := w.mustRun("", "--json", "remote", "conflicts")
	noFixtures(w.t, "remote conflicts --json", out)
	var got struct {
		OK        bool
		Conflicts []conflictJSON
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil || !got.OK {
		w.t.Fatalf("conflicts json = %q (%v)", out, err)
	}
	return got.Conflicts
}

// conflictPair is two synced devices where both edited SHARED while A was
// offline; B's edit is the later one, so B wins and A's version is kept as a
// conflict on both devices after one more round each.
func conflictPair(t *testing.T) (*syncServer, *tap, *world, *world) {
	t.Helper()
	ss, tp, a, b := syncPair(t)
	a.mustRun(conflictOld, "set", "SHARED", "--global", "--stdin")
	b.mustRun("", "remote", "sync")
	tp.down.Store(true)
	a.mustRun(conflictA, "set", "SHARED", "--global", "--stdin")
	tp.down.Store(false)
	time.Sleep(5 * time.Millisecond)
	b.mustRun(conflictB, "set", "SHARED", "--global", "--stdin")
	a.mustRun("", "remote", "sync")
	b.mustRun("", "remote", "sync")
	return ss, tp, a, b
}

func TestDoubleEditCreatesAConflictVisibleOnBothDevices(t *testing.T) {
	_, _, a, b := conflictPair(t)
	if a.value("SHARED") != conflictB || b.value("SHARED") != conflictB {
		t.Fatal("the later edit should win on both devices")
	}
	for name, w := range map[string]*world{"A": a, "B": b} {
		rows := w.conflicts()
		if len(rows) != 1 || rows[0].Name != "SHARED" || rows[0].Layer != "global" || rows[0].Winner != "Laptop B" || rows[0].Deleted || rows[0].LostAt == "" {
			t.Fatalf("%s conflicts = %+v", name, rows)
		}
		human := w.mustRun("", "remote", "conflicts")
		if !strings.Contains(human, "SHARED") || !strings.Contains(human, "global") || !strings.Contains(human, "Laptop B") {
			t.Fatalf("%s human = %q", name, human)
		}
		noFixtures(t, "remote conflicts", human)
		// status and list say so
		_, sout, serr := w.run("", "--json", "remote", "status")
		if !strings.Contains(sout, `"conflicts":1`) || !strings.Contains(serr+sout, "1 sync conflicts") {
			t.Fatalf("%s status: out=%q err=%q", name, sout, serr)
		}
		code, lout, lerr := w.run("", "list", "--layer", "global")
		if code != exitcode.OK || strings.Contains(lout, "conflict") || !strings.Contains(lerr, "1 sync conflicts") {
			t.Fatalf("%s list: code=%d out=%q err=%q", name, code, lout, lerr)
		}
		if _, jout, jerr := w.run("", "--json", "list", "--layer", "global"); strings.Contains(jout+jerr, "conflict") {
			t.Fatalf("%s list --json mentions conflicts: %q %q", name, jout, jerr)
		}
	}
}

func TestListWithoutConflictsSaysNothing(t *testing.T) {
	_, _, a, _ := syncPair(t)
	if _, _, errs := a.run("", "list", "--layer", "global"); strings.Contains(errs, "conflict") {
		t.Fatalf("err = %q", errs)
	}
}

func TestResolveKeepConflictSwapsAndSyncs(t *testing.T) {
	_, _, a, b := conflictPair(t)
	f := answers(yes())
	asBackend(t, keepBackend{f})
	code, out, errs := a.run("", "remote", "resolve", "SHARED", "--global", "--keep", "conflict")
	if code != exitcode.OK || errs != "" || out == "" {
		t.Fatalf("resolve: code=%d out=%q err=%q", code, out, errs)
	}
	noFixtures(t, "resolve", out+errs)
	if len(f.Calls) != 1 || f.Calls[0].Kind != "confirm" {
		t.Fatalf("prompts = %v", kindsOf(f))
	}
	if a.value("SHARED") != conflictA {
		t.Fatal("the kept version did not become current")
	}
	if st := readState(t, a); st.PendingPush {
		t.Fatal("the resolution was not pushed")
	}
	b.mustRun("", "remote", "sync")
	if b.value("SHARED") != conflictA {
		t.Fatal("B did not receive the resolution")
	}
	// A swap: the replaced version is now the kept one, on both devices.
	for name, w := range map[string]*world{"A": a, "B": b} {
		if rows := w.conflicts(); len(rows) != 1 || rows[0].Name != "SHARED" {
			t.Fatalf("%s conflicts after swap = %+v", name, rows)
		}
	}
	if !a.auditHas(`"event":"remote"`) || !a.auditHas("conflict resolved") {
		t.Fatalf("audit: %s", a.auditText())
	}
	noFixtures(t, "audit", a.auditText())
	// Swapping back needs no new conflict: --keep conflict again returns B's.
	asBackend(t, keepBackend{answers(yes())})
	a.mustRun("", "remote", "resolve", "SHARED", "--global", "--keep", "conflict")
	if a.value("SHARED") != conflictB {
		t.Fatal("the second swap did not restore the first winner")
	}
}

func TestResolveKeepCurrentDropsTheConflictEverywhere(t *testing.T) {
	_, _, a, b := conflictPair(t)
	asBackend(t, keepBackend{answers(yes())})
	a.mustRun("", "remote", "resolve", "SHARED", "--global", "--keep", "current")
	if a.value("SHARED") != conflictB || len(a.conflicts()) != 0 {
		t.Fatal("keeping the current version must only drop the kept one")
	}
	b.mustRun("", "remote", "sync")
	if len(b.conflicts()) != 0 {
		t.Fatalf("the conflict came back from B: %+v", b.conflicts())
	}
	a.mustRun("", "remote", "sync")
	if len(a.conflicts()) != 0 {
		t.Fatal("the conflict came back to A")
	}
	_, _, serr := a.run("", "list", "--layer", "global")
	if strings.Contains(serr, "conflict") {
		t.Fatalf("list still warns: %q", serr)
	}
}

func TestResolveRefusals(t *testing.T) {
	_, _, a, _ := conflictPair(t)
	before := a.snapshot()
	state := a.value("SHARED")
	cases := []struct {
		name    string
		args    []string
		answers []prompttest.Answer
		code    int
		want    string
	}{
		{"no keep", []string{"SHARED", "--global"}, nil, exitcode.Usage, "--keep"},
		{"bad keep", []string{"SHARED", "--global", "--keep", "both"}, nil, exitcode.Usage, "--keep"},
		{"both layers", []string{"SHARED", "--global", "--project", "--keep", "current"}, nil, exitcode.Usage, "--global and --project"},
		{"unknown name", []string{"NO_SUCH_NAME", "--keep", "current"}, nil, exitcode.Failure, "no sync conflict for that name"},
		{"no conflict in that layer", []string{"SHARED", "--project", "--keep", "current"}, nil, exitcode.Refusal, ""},
		{"invalid name", []string{"bad name", "--keep", "current"}, nil, exitcode.Refusal, ""},
		{"cancel", []string{"SHARED", "--global", "--keep", "conflict"}, []prompttest.Answer{no()}, exitcode.Failure, "cancelled"},
	}
	for _, c := range cases {
		asBackend(t, keepBackend{answers(c.answers...)})
		code, out, errs := a.run("", append([]string{"remote", "resolve"}, c.args...)...)
		if code == exitcode.OK || (c.code != 0 && code != c.code) || out != "" || !strings.HasPrefix(errs, "error: ") || !strings.Contains(errs, c.want) {
			t.Errorf("%s: code=%d out=%q err=%q", c.name, code, out, errs)
		}
		for _, leak := range []string{"NO_SUCH_NAME", "bad name"} {
			if strings.Contains(errs, leak) {
				t.Errorf("%s: the name was echoed: %q", c.name, errs)
			}
		}
		noFixtures(t, c.name, out+errs)
	}
	if a.snapshot() != before || a.value("SHARED") != state || len(a.conflicts()) != 1 {
		t.Fatal("a refused resolve changed the vault")
	}
	// No prompt backend: not_model_callable; no sync: remote_not_configured.
	noBackend(t)
	if code, out, _ := a.run("", "--json", "remote", "resolve", "SHARED", "--global", "--keep", "current"); code != exitcode.Refusal || !strings.Contains(out, `"not_model_callable"`) {
		t.Fatalf("no backend: code=%d out=%q", code, out)
	}
	plain := newWorld(t)
	asBackend(t, keepBackend{answers(yes())})
	if code, id := jsonErrCode(t, plain, "remote", "resolve", "SHARED", "--global", "--keep", "current"); code != exitcode.Failure || id != "remote_not_configured" {
		t.Fatalf("no sync: code=%d id=%q", code, id)
	}
	if code, id := jsonErrCode(t, plain, "remote", "conflicts"); code != exitcode.Failure || id != "remote_not_configured" {
		t.Fatalf("no sync conflicts: code=%d id=%q", code, id)
	}
}

func TestResolveWorksOfflineAndConflictsListMakesNoRequest(t *testing.T) {
	_, tp, a, _ := conflictPair(t)
	tp.down.Store(true)
	asBackend(t, keepBackend{answers(yes())})
	code, _, errs := a.run("", "remote", "resolve", "SHARED", "--global", "--keep", "current")
	if code != exitcode.OK || !strings.Contains(errs, "will retry") {
		t.Fatalf("offline resolve: code=%d err=%q", code, errs)
	}
	tp.down.Store(false)
	before := tp.n.Load()
	a.mustRun("", "remote", "conflicts")
	if tp.n.Load() != before {
		t.Fatal("remote conflicts made a request")
	}
}

func TestResolveAndConflictsKeepValuesOffTheServerAndOutOfJSON(t *testing.T) {
	ss, _, a, _ := conflictPair(t)
	noFixtures(t, "server data", ss.held(t))
	asBackend(t, keepBackend{answers(yes())})
	code, out, errs := a.run("", "--json", "remote", "resolve", "SHARED", "--global", "--keep", "conflict")
	var got struct {
		OK     bool
		Name   string
		Layer  string
		Keep   string
		Remote string
	}
	if err := json.Unmarshal([]byte(out), &got); code != exitcode.OK || err != nil || !got.OK || got.Name != "SHARED" || got.Layer != "global" || got.Keep != "conflict" || got.Remote != "synced" || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	noFixtures(t, "resolve --json", out+errs)
	noFixtures(t, "server data", ss.held(t))
	noFixtures(t, "audit", a.auditText())
}
