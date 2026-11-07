package cli

import (
	"context"
	"crypto/rand"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/exitcode"
	"github.com/QuBiit0/qbit-vault/internal/remote"
	"github.com/QuBiit0/qbit-vault/internal/secret"
)

// S2 of the Phase 2S hardening: a command that fails after the account or
// the key already changed says what state the device is in and what to run.

// blocked puts a plain file where the vault wants a directory, so the next
// write into it fails; the returned func removes it.
func (w *world) blocked(name string) func() {
	w.t.Helper()
	p := filepath.Join(w.home, name)
	if err := os.RemoveAll(p); err != nil {
		w.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		w.t.Fatal(err)
	}
	return func() {
		w.t.Helper()
		if err := os.Remove(p); err != nil {
			w.t.Fatal(err)
		}
	}
}

// failVaultGets makes GET /v1/vault fail while the returned flag is set: with
// the connection dropped (unreachable) or with a 500.
func (ss *syncServer) failVaultGets(drop bool) *atomic.Bool {
	var on atomic.Bool
	ss.proxy(func(w http.ResponseWriter, r *http.Request) bool {
		if !on.Load() || r.Method != "GET" || r.URL.Path != "/v1/vault" {
			return false
		}
		if drop {
			if hj, ok := w.(http.Hijacker); ok {
				if conn, _, err := hj.Hijack(); err == nil {
					_ = conn.Close()
				}
			}
			return true
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(500)
		_, _ = io.WriteString(w, `{"api":1,"error":{"code":"internal","message":"SERVER-TEXT"}}`)
		return true
	})
	return &on
}

// joinUntil is joinPairing with a hook that runs once the approval is done,
// while the new device still waits.
func joinUntil(t *testing.T, w, a *world, ss *syncServer, afterApprove func(), extra ...string) (int, string, string) {
	t.Helper()
	fb := answers(yes())
	asBackend(t, keepBackend{fb})
	withPairing(t, func(code string) {
		fa := answers(val(code), val("Laptop B"), no())
		prev := newPrompt
		asBackend(t, keepBackend{fa})
		a.mustRun("", "remote", "approve")
		newPrompt = prev
		fb.Script = append(fb.Script, val(confirmationIn(fa)))
		afterApprove()
	})
	return w.run("", append([]string{"remote", "join", "--server", ss.ts.URL}, extra...)...)
}

func TestJoinFirstRoundFailureSaysWhatToRun(t *testing.T) {
	const msg = "error: this device joined the account but the first sync did not finish; run 'qbit-vault remote sync'\n"
	for _, c := range []struct {
		name string
		drop bool
	}{{"server error", false}, {"unreachable", true}} {
		t.Run(c.name, func(t *testing.T) {
			ss := newSyncServer(t)
			a, b := newWorld(t), newWorld(t)
			a.register(ss)
			b.mustRun("TESTSECRET_b_only", "set", "B_ONLY", "--global", "--stdin")
			fail := ss.failVaultGets(c.drop)
			code, out, errs := joinUntil(t, b, a, ss, func() { fail.Store(true) })
			if code != exitcode.Failure || strings.Contains(out, "joined") || errs != msg {
				t.Fatalf("code=%d out=%q err=%q", code, out, errs)
			}
			noFixtures(t, "stderr", errs)
			if st := readState(t, b); st == nil || st.AccountID == "" {
				t.Fatal("the join left no sync state to finish from")
			}
			// The command named in the message finishes it.
			fail.Store(false)
			asBackend(t, keepBackend{answers()})
			if out := b.mustRun("", "remote", "sync"); !strings.HasPrefix(out, "synced") {
				t.Fatalf("remote sync = %q", out)
			}
			a.mustRun("", "remote", "sync")
			if a.value("B_ONLY") != "TESTSECRET_b_only" {
				t.Fatal("the joined device's secret did not reach the account")
			}
		})
	}
	t.Run("json keeps the typed code", func(t *testing.T) {
		ss := newSyncServer(t)
		a, b := newWorld(t), newWorld(t)
		a.register(ss)
		fail := ss.failVaultGets(true)
		code, out, _ := joinUntil(t, b, a, ss, func() { fail.Store(true) }, "--json")
		if code != exitcode.Failure || !strings.Contains(out, `"code":"remote_unreachable"`) || !strings.Contains(out, "run 'qbit-vault remote sync'") {
			t.Fatalf("code=%d out=%q", code, out)
		}
	})
}

func TestJoinLocalFailureAfterTheKeySwapIsFinishedByRecovery(t *testing.T) {
	const msg = "error: the vault now uses the account key but this device could not save its sync state; run 'qbit-vault remote join --recovery' to finish\n"
	ss := newSyncServer(t)
	a, b := newWorld(t), newWorld(t)
	rk := a.register(ss)
	a.mustRun("TESTSECRET_a_only", "set", "A_ONLY", "--global", "--stdin")
	b.mustRun("TESTSECRET_b_only", "set", "B_ONLY", "--global", "--stdin")
	keyBefore := b.masterKey()
	unblock := b.blocked("remote")
	code, out, errs := joinUntil(t, b, a, ss, func() {})
	if code != exitcode.Failure || strings.Contains(out, "joined") || errs != msg {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	noFixtures(t, "stderr", errs)
	if b.masterKey() == keyBefore {
		t.Fatal("the vault is still on its old key: the failure was before the swap")
	}
	asBackend(t, keepBackend{answers()})
	if b.value("B_ONLY") != "TESTSECRET_b_only" {
		t.Fatal("the local vault no longer opens or lost a secret")
	}
	if readState(t, b) != nil {
		t.Fatal("sync state written although the join failed")
	}
	// The command named in the message finishes it.
	unblock()
	asBackend(t, keepBackend{answers(yes(), val(rk))})
	if code, out, errs := b.run("", "remote", "join", "--server", ss.ts.URL, "--recovery"); code != exitcode.OK {
		t.Fatalf("second join: code=%d out=%q err=%q", code, out, errs)
	}
	asBackend(t, keepBackend{answers()})
	a.mustRun("", "remote", "sync")
	if a.value("B_ONLY") != "TESTSECRET_b_only" || b.value("A_ONLY") != "TESTSECRET_a_only" {
		t.Fatal("the two devices do not hold each other's secrets after the second join")
	}
}

func TestRegisterLocalFailureAfterTheAccountExistsCanBeRegisteredAgain(t *testing.T) {
	const msg = "error: the account was created on the server but this device could not save its sync state; run 'qbit-vault remote register' again with a new invite code\n"
	ss := newSyncServer(t)
	w := newWorld(t)
	w.mustRun("TESTSECRET_w", "set", "W_KEY", "--global", "--stdin")
	unblock := w.blocked("remote")
	f := answers(val(ss.invite(t)), yes())
	asBackend(t, keepBackend{f})
	code, out, errs := w.run("", "remote", "register", "--server", ss.ts.URL)
	if code != exitcode.Failure || out != "" || errs != msg {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	noFixtures(t, "stderr", errs)
	for _, c := range f.Calls {
		if c.Kind == "show" {
			t.Fatal("the recovery key of an account this device cannot keep was shown")
		}
	}
	if readState(t, w) != nil {
		t.Fatal("state written by the failed registration")
	}
	unblock()
	if w.value("W_KEY") != "TESTSECRET_w" {
		t.Fatal("the vault changed")
	}
	if rk := w.register(ss); rk == "" {
		t.Fatal("registering again did not work")
	}
	if st := readState(t, w); st == nil || st.Generation != 1 {
		t.Fatalf("state = %+v", st)
	}
}

func TestApproveShowsTheCodeWhenTheRosterWriteFails(t *testing.T) {
	ss := newSyncServer(t)
	a := newWorld(t)
	a.register(ss)
	nk := make([]byte, 32)
	_, _ = rand.Read(nk)
	nc, _ := remote.NewClient(ss.ts.URL, "")
	newID := strings.Repeat("d", 32)
	p, err := nc.CreatePairing(context.Background(), newID, remote.DeviceFromSecret(secret.New("dk", nk)))
	if err != nil {
		t.Fatal(err)
	}
	unblock := a.blocked("backups")
	defer unblock()
	f := answers(val(p.Code), val("Laptop X"), no())
	asBackend(t, keepBackend{f})
	code, out, errs := a.run("", "remote", "approve")
	if code != exitcode.OK || errs != "warning: the new device was approved on the server but this vault could not record it in the roster; check 'qbit-vault remote devices'\n" ||
		out != "approved Laptop X ("+newID+")\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if confirmationIn(f) == "" {
		t.Fatal("the confirmation code was not shown")
	}
	noFixtures(t, "stderr", errs)
}

// C-S06: the server accepted the approval, so the confirmation code is shown
// even when the round after it fails; the failure is a warning, exit 0.
func TestApproveShowsTheCodeWhenTheFollowingSyncFails(t *testing.T) {
	ss := newSyncServer(t)
	a := newWorld(t)
	a.register(ss)
	nk := make([]byte, 32)
	_, _ = rand.Read(nk)
	nc, _ := remote.NewClient(ss.ts.URL, "")
	newID := strings.Repeat("e", 32)
	p, err := nc.CreatePairing(context.Background(), newID, remote.DeviceFromSecret(secret.New("dk", nk)))
	if err != nil {
		t.Fatal(err)
	}
	approved := false
	ss.proxy(func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasPrefix(r.URL.Path, "/v1/pairings/") && r.Method != "GET" {
			approved = true
			return false
		}
		if approved && r.URL.Path == "/v1/vault" {
			w.WriteHeader(500)
			_, _ = io.WriteString(w, "not json")
			return true
		}
		return false
	})
	f := answers(val(p.Code), val("Laptop Y"), no())
	asBackend(t, keepBackend{f})
	code, out, errs := a.run("", "remote", "approve")
	if code != exitcode.OK || out != "approved Laptop Y ("+newID+")\n" || !strings.HasPrefix(errs, "warning: ") || strings.Count(errs, "\n") != 1 {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if !approved {
		t.Fatal("the approval never reached the server")
	}
	if confirmationIn(f) == "" {
		t.Fatal("the confirmation code was not shown")
	}
	noFixtures(t, "stderr", errs)
}

func TestPushWarningAfterConflictRetriesNamesTheConflict(t *testing.T) {
	ss, _, a, _ := syncPair(t)
	var seen atomic.Int32
	ss.proxy(func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != "PUT" || r.URL.Path != "/v1/vault" {
			return false
		}
		seen.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(409)
		_, _ = io.WriteString(w, `{"api":1,"error":{"code":"conflict","message":"x"}}`)
		return true
	})
	code, out, errs := a.run("TESTSECRET_c", "set", "C_KEY", "--global", "--stdin")
	if code != exitcode.OK || errs != "warning: not synced (the server changed while syncing); will retry\n" || seen.Load() != maxRoundTries {
		t.Fatalf("code=%d out=%q err=%q puts=%d", code, out, errs, seen.Load())
	}
	if !readState(t, a).PendingPush {
		t.Fatal("the push is not pending")
	}
}
