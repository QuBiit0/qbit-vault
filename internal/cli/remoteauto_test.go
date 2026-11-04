package cli

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QuBiit0/qbit-vault/internal/exitcode"
	"github.com/QuBiit0/qbit-vault/internal/vault"
)

// Slice S.8: the sync round inside the ordinary commands (REMOTE_SYNC § 7.1).
// Two devices share one in-process server; a tap in front of it counts the
// requests and can drop every connection.

const (
	wantUnreachable = "warning: not synced (server unreachable); will retry\n"
	wantRollback    = "warning: not synced (remote_rollback); the change is kept on this device; run 'qbit-vault remote status'\n"
)

type tap struct {
	n    atomic.Int64
	down atomic.Bool
}

// tap puts a counter in front of the server; while down is set the
// connection is closed without an answer, which the client sees as an
// unreachable server.
func (ss *syncServer) tap() *tap {
	tp := &tap{}
	inner := ss.ts.Config.Handler
	ss.ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tp.n.Add(1)
		if tp.down.Load() {
			if hj, ok := w.(http.Hijacker); ok {
				if conn, _, err := hj.Hijack(); err == nil {
					_ = conn.Close()
				}
			}
			return
		}
		inner.ServeHTTP(w, r)
	})
	return tp
}

// syncPair is two registered devices of one account; later commands never
// prompt.
func syncPair(t *testing.T) (*syncServer, *tap, *world, *world) {
	t.Helper()
	ss := newSyncServer(t)
	tp := ss.tap()
	a, b := newWorld(t), newWorld(t)
	a.register(ss)
	if code, out, errs, _ := joinPairing(t, b, a, ss); code != exitcode.OK {
		t.Fatalf("join: code=%d out=%q err=%q", code, out, errs)
	}
	asBackend(t, keepBackend{answers()})
	return ss, tp, a, b
}

func (w *world) editState(f func(*vault.Remote)) {
	w.t.Helper()
	st := readState(w.t, w)
	f(st)
	if err := vault.WriteRemote(w.home, st); err != nil {
		w.t.Fatal(err)
	}
}

// stale makes the last pull older than the pull interval.
func (w *world) stale() {
	w.t.Helper()
	w.editState(func(st *vault.Remote) { st.LastPullAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339) })
}

func (w *world) globalList() string {
	w.t.Helper()
	return w.mustRun("", "--json", "list", "--layer", "global")
}

func TestSyncEnabledMutationsPushAndAnotherDeviceSeesThem(t *testing.T) {
	_, _, a, b := syncPair(t)
	var lastVersion int64
	push := func(stdin string, args ...string) string {
		t.Helper()
		code, out, errs := a.run(stdin, append([]string{"--json"}, args...)...)
		if code != exitcode.OK || errs != "" || !strings.HasSuffix(out, `,"remote":"synced"}`+"\n") {
			t.Fatalf("%v: code=%d out=%q err=%q", args, code, out, errs)
		}
		st := readState(t, a)
		if st.PendingPush || st.LastVersion <= lastVersion {
			t.Fatalf("%v: state after push = %+v (was version %d)", args, st, lastVersion)
		}
		lastVersion = st.LastVersion
		noFixtures(t, "output", out)
		return out
	}

	out := push(fxVal+"_1", "set", "S1", "--global", "--stdin")
	if want := `{"ok":true,"name":"S1","layer":"global","project":null,"replaced":false,"remote":"synced"}` + "\n"; out != want {
		t.Fatalf("set json = %q", out)
	}
	push("", "edit", "S1", "--global", "--description", "edited")
	a.inRepo()
	push(fxVal+"_2", "set", "S2", "--project", "--stdin")
	push("", "mv", "S2", "--to", "global", "--yes")
	a.outRepo()
	push("", "rm", "S2", "--global", "--yes")
	code, out, errs := a.runEnv(map[string]string{"IMP_A": fxVal + "_imp"}, "", "--json", "import", "--from-env", "IMP_A", "--global", "--yes")
	if code != 0 || !strings.HasSuffix(out, `"source_removed":false,"remote":"synced"}`+"\n") || !strings.Contains(errs, "hint: unset IMP_A") {
		t.Fatalf("import: code=%d out=%q err=%q", code, out, errs)
	}
	if readState(t, a).PendingPush || readState(t, a).LastVersion <= lastVersion {
		t.Fatal("import did not push")
	}
	lastVersion = readState(t, a).LastVersion

	// relink: a project layer follows its repository to a new directory.
	a.inRepo()
	push(fxVal+"_3", "set", "S3", "--project", "--stdin")
	moved := filepath.Join(t.TempDir(), "moved")
	if err := os.MkdirAll(filepath.Join(moved, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	push("", "relink", a.repo, moved)
	a.outRepo()

	// restore: the oldest backup, then the round pushes the result.
	ids := a.backupIDs()
	push("", "restore", "--from", ids[len(ids)-1], "--yes")

	if code, out, errs := b.run("", "remote", "sync"); code != 0 || errs != "" || !strings.HasPrefix(out, "synced (version ") {
		t.Fatalf("B sync: code=%d out=%q err=%q", code, out, errs)
	}
	if a.globalList() != b.globalList() {
		t.Fatalf("devices differ after sync:\nA %s\nB %s", a.globalList(), b.globalList())
	}
}

func TestSyncEnabledLinkAndManagePush(t *testing.T) {
	_, _, a, b := syncPair(t)

	a.syncedProject()
	a.inRepo()
	withBackend(t, answers(yes()))
	before := readState(t, a).LastVersion
	code, out, errs := a.run("", "--json", "link", "shop-api")
	if code != 0 || errs != "" || !strings.HasSuffix(out, `,"remote":"synced"}`+"\n") || readState(t, a).LastVersion <= before {
		t.Fatalf("link: code=%d out=%q err=%q state=%+v", code, out, errs, readState(t, a))
	}
	a.outRepo()

	a.mustRun(fxVal+"_m", "set", "M1", "--global", "--stdin")
	before = readState(t, a).LastVersion
	withBackend(t, answers(yes()))
	code, m, raw := a.broker("manage", manageReq(a.outside, `"action":"remove","name":"M1","layer":"global"`))
	// The contract response is pinned: no remote field.
	if code != 0 || raw != `{"ok":true,"applied":true,"action":"remove","name":"M1","layer":null}`+"\n" || m["applied"] != true {
		t.Fatalf("manage: code=%d out=%s", code, raw)
	}
	if st := readState(t, a); st.PendingPush || st.LastVersion <= before {
		t.Fatalf("manage did not push: %+v", st)
	}
	b.mustRun("", "remote", "sync")
	if strings.Contains(b.globalList(), `"M1"`) {
		t.Fatal("B still has the secret the agent removed")
	}
}

func TestSyncPushFailureKeepsTheChangeAndRetries(t *testing.T) {
	_, tp, a, b := syncPair(t)
	tp.down.Store(true)

	code, out, errs := a.run(fxVal+"_p", "--json", "set", "P1", "--global", "--stdin")
	want := `{"ok":true,"name":"P1","layer":"global","project":null,"replaced":false,"remote":"pending"}` + "\n"
	if code != 0 || out != want || errs != wantUnreachable {
		t.Fatalf("json: code=%d out=%q err=%q", code, out, errs)
	}
	if !readState(t, a).PendingPush || a.value("P1") != fxVal+"_p" {
		t.Fatalf("state=%+v", readState(t, a))
	}
	code, out, errs = a.run(fxVal+"_q", "set", "P2", "--global", "--stdin")
	if code != 0 || out != "stored P2 (global)\n" || errs != wantUnreachable {
		t.Fatalf("human: code=%d out=%q err=%q", code, out, errs)
	}

	// The next moment someone reads, the pending push is retried.
	tp.down.Store(false)
	a.mustRun("", "list")
	if readState(t, a).PendingPush {
		t.Fatal("the pending push was not retried by a read")
	}
	b.mustRun("", "remote", "sync")
	if b.value("P1") != fxVal+"_p" || b.value("P2") != fxVal+"_q" {
		t.Fatal("B did not receive the changes made while the server was down")
	}
}

func TestSyncPullBeforeReading(t *testing.T) {
	_, tp, a, b := syncPair(t)

	t.Run("list describe and broker list pull when the last pull is stale", func(t *testing.T) {
		a.mustRun(fxVal+"_1", "set", "R1", "--global", "--stdin")
		b.stale()
		tp.n.Store(0)
		if out := b.mustRun("", "list"); !strings.Contains(out, "R1") || tp.n.Load() == 0 {
			t.Fatalf("list: out=%q requests=%d", out, tp.n.Load())
		}
		a.mustRun(fxVal+"_2", "set", "R2", "--global", "--stdin")
		b.stale()
		tp.n.Store(0)
		if out := b.mustRun("", "describe", "R2"); !strings.Contains(out, "R2") || tp.n.Load() == 0 {
			t.Fatalf("describe: out=%q requests=%d", out, tp.n.Load())
		}
		a.mustRun(fxVal+"_3", "set", "R3", "--global", "--stdin")
		b.stale()
		tp.n.Store(0)
		if _, _, raw := b.broker("list", envelope("list", b.outside, "")); !strings.Contains(raw, `"R3"`) || tp.n.Load() == 0 {
			t.Fatalf("broker list: out=%s requests=%d", raw, tp.n.Load())
		}
	})

	t.Run("set prompt and broker request pull first", func(t *testing.T) {
		for name, run := range map[string]func(){
			"set": func() { b.run(fxVal+"_x", "set", "R4", "--global", "--stdin") },
			"prompt": func() {
				withBackend(t, answers())
				b.run("", "--session", sessA, "prompt", "--name", "R4", "--reason", "r")
			},
			"request": func() {
				withBackend(t, answers())
				b.broker("request", envelope("request", b.outside, `"name":"R5","reason":"`+reqReason+`"`))
			},
		} {
			b.stale()
			tp.n.Store(0)
			run()
			if tp.n.Load() == 0 {
				t.Errorf("%s did not pull", name)
			}
			asBackend(t, keepBackend{answers()})
		}
	})

	t.Run("a recent pull is not repeated", func(t *testing.T) {
		a.mustRun(fxVal+"_f", "set", "FRESH", "--global", "--stdin")
		b.editState(func(st *vault.Remote) { st.LastPullAt = nowUTC() })
		tp.n.Store(0)
		if out := b.mustRun("", "list"); strings.Contains(out, "FRESH") || tp.n.Load() != 0 {
			t.Fatalf("list: out=%q requests=%d", out, tp.n.Load())
		}
	})

	t.Run("a failed pull is silent", func(t *testing.T) {
		b.stale()
		tp.down.Store(true)
		defer tp.down.Store(false)
		code, out, errs := b.run("", "list")
		if code != 0 || errs != "" || out == "" {
			t.Fatalf("code=%d out=%q err=%q", code, out, errs)
		}
		if readState(t, b).PendingPush {
			t.Fatal("a failed pull marked a push pending")
		}
	})
}

func TestSyncNeverOnTheHotPath(t *testing.T) {
	_, tp, a, _ := syncPair(t)
	asTerminal(t, true)
	a.setSecret("HOT", xv, "--global")
	a.grantTo(sessA, "HOT", "session")
	a.stale()
	a.editState(func(st *vault.Remote) { st.PendingPush = true }) // the most tempting moment to sync
	tp.n.Store(0)

	mk := marker(t)
	cmds := []struct {
		name string
		args []string
	}{
		{"exec", execArgs(sessA, []string{"HOT"}, child(t, "mark", mk, 0))},
		{"grants", []string{"grants"}},
		{"audit", []string{"audit"}},
		{"grant", []string{"--session", sessA, "grant", "HOT", "--scope", "once"}},
		{"revoke", []string{"revoke", "--all"}},
	}
	for _, c := range cmds {
		stdin := ""
		if c.name == "grant" || c.name == "revoke" {
			stdin = "y\n"
		}
		a.run(stdin, c.args...)
		if n := tp.n.Load(); n != 0 {
			t.Fatalf("%s made %d requests", c.name, n)
		}
	}
	if !ran(mk) {
		t.Fatal("exec did not run")
	}
	if !readState(t, a).PendingPush {
		t.Fatal("a hot command cleared the pending push")
	}
}

func TestSyncOffSwitchMarksPendingAndMakesNoCall(t *testing.T) {
	_, tp, a, _ := syncPair(t)
	env := map[string]string{envNoRemote: "1"}
	tp.n.Store(0)

	code, out, errs := a.runEnv(env, fxVal+"_o", "--json", "set", "O1", "--global", "--stdin")
	want := `{"ok":true,"name":"O1","layer":"global","project":null,"replaced":false,"remote":"pending"}` + "\n"
	if code != 0 || out != want || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	a.stale()
	if code, _, errs := a.runEnv(env, "", "list"); code != 0 || errs != "" {
		t.Fatalf("list: code=%d err=%q", code, errs)
	}
	if tp.n.Load() != 0 || !readState(t, a).PendingPush {
		t.Fatalf("requests=%d state=%+v", tp.n.Load(), readState(t, a))
	}
	a.mustRun("", "remote", "sync") // back online: one round pushes it
	if readState(t, a).PendingPush {
		t.Fatal("still pending after sync")
	}
}

func TestVaultWithoutSyncMakesNoCallAndAddsNothing(t *testing.T) {
	w := newWorld(t)
	code, out, errs := w.run(fxVal, "--json", "set", "N1", "--global", "--stdin")
	if want := `{"ok":true,"name":"N1","layer":"global","project":null,"replaced":false}` + "\n"; code != 0 || out != want || errs != "" {
		t.Fatalf("set: code=%d out=%q err=%q", code, out, errs)
	}
	if out := w.mustRun("", "list"); !strings.Contains(out, "N1") {
		t.Fatalf("list = %q", out)
	}
	if _, err := os.Stat(filepath.Join(w.home, "remote")); !os.IsNotExist(err) {
		t.Fatal("a vault that does not sync grew remote state")
	}
}

func TestSyncRefusedRoundIsWarnedNotSwallowed(t *testing.T) {
	_, _, a, _ := syncPair(t)
	a.editState(func(st *vault.Remote) { st.LastVersion += 5 }) // the server now looks older than what was seen

	code, out, errs := a.run(fxVal+"_r", "--json", "set", "RB", "--global", "--stdin")
	want := `{"ok":true,"name":"RB","layer":"global","project":null,"replaced":false,"remote":"pending"}` + "\n"
	if code != 0 || out != want || errs != wantRollback {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if !readState(t, a).PendingPush || a.value("RB") != fxVal+"_r" {
		t.Fatalf("the local change must stay: %+v", readState(t, a))
	}

	// A read hits the same refusal and says so instead of reporting an outage.
	a.stale()
	if code, _, errs := a.run("", "list"); code != 0 || errs != wantRollback {
		t.Fatalf("list: code=%d err=%q", code, errs)
	}
}
