package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/QuBiit0/gentle-vault/internal/exitcode"
	"github.com/QuBiit0/gentle-vault/internal/grants"
	"github.com/QuBiit0/gentle-vault/internal/keychain"
	"github.com/QuBiit0/gentle-vault/internal/prompt/prompttest"
	"github.com/QuBiit0/gentle-vault/internal/secret"
	"github.com/QuBiit0/gentle-vault/internal/vault"
)

// Phase 2S hardening (odd/tasks/remote-sync-hardening.md, H1).

// corruptState makes the remote object of state.json unreadable, the rest
// of the file intact.
func (w *world) corruptState() {
	w.t.Helper()
	p := filepath.Join(w.home, "state.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		w.t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		w.t.Fatal(err)
	}
	m["remote"] = json.RawMessage("5")
	raw, _ = json.Marshal(m)
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		w.t.Fatal(err)
	}
}

// syncingPassphraseWorld is a passphrase-mode vault whose state.json says it
// syncs with server; no account exists there, which a command that must not
// prompt never gets far enough to notice.
func syncingPassphraseWorld(t *testing.T, server string) *world {
	t.Helper()
	w := passphraseWorld(t)
	st := &vault.Remote{Server: server, AccountID: "0123456789abcdef0123456789abcdef", Generation: 2, LastVersion: 7, LastPullAt: "2026-01-02T03:04:05Z"}
	if err := vault.WriteRemote(w.home, st); err != nil {
		t.Fatal(err)
	}
	return w
}

// ---- S3: no hidden prompts or mutations ----

func TestOpenSessionQuietNeverPromptsNorFinishesARekey(t *testing.T) {
	t.Run("passphrase vault without a cached key is locked and unasked", func(t *testing.T) {
		w := passphraseWorld(t)
		f := withBackend(t, answers(val(fxPass)))
		g := &globals{getenv: envFrom(nil), home: w.home}
		if s, err := g.openSessionQuiet(); err == nil {
			s.close()
			t.Fatal("opened a passphrase vault with no cached key")
		} else if err != errSessionLocked {
			t.Fatalf("err = %v, want errSessionLocked", err)
		}
		if len(f.Calls) != 0 {
			t.Fatalf("prompted: %+v", f.Calls)
		}
		// openSession is unchanged: it asks once and opens.
		s, err := g.openSession()
		if err != nil {
			t.Fatalf("openSession: %v", err)
		}
		s.close()
		if len(f.Calls) != 1 || f.Calls[0].Kind != "passphrase" {
			t.Fatalf("openSession calls = %+v, want one passphrase prompt", f.Calls)
		}
	})
	t.Run("a staged rekey is left alone", func(t *testing.T) {
		w := newWorld(t)
		w.mustRun("TESTSECRET_a\n", "set", "A", "--stdin")
		w.interruptRekey()
		g := &globals{getenv: envFrom(nil), home: w.home}
		if s, err := g.openSessionQuiet(); err != errSessionLocked {
			if err == nil {
				s.close()
			}
			t.Fatalf("err = %v, want errSessionLocked", err)
		}
		id, _ := vault.ReadID(w.home)
		if has, _ := keychain.HasStaged(w.home, id, keychain.Options{}); !has {
			t.Fatal("the quiet open finished the rekey")
		}
		// openSession is unchanged: it finishes the rekey.
		s, err := g.openSession()
		if err != nil {
			t.Fatalf("openSession: %v", err)
		}
		s.close()
		if has, _ := keychain.HasStaged(w.home, id, keychain.Options{}); has {
			t.Fatal("openSession no longer finishes an interrupted rekey")
		}
	})
	t.Run("an unlocked vault opens", func(t *testing.T) {
		w := newWorld(t)
		g := &globals{home: w.home, getenv: envFrom(nil)}
		s, err := g.openSessionQuiet()
		if err != nil {
			t.Fatal(err)
		}
		s.close()
	})
}

func TestRemoteStatusNeverPromptsAndSaysWhatIsLocked(t *testing.T) {
	ss := newSyncServer(t)
	tp := ss.tap()
	w := syncingPassphraseWorld(t, ss.ts.URL)
	f := withBackend(t, answers(val(fxPass)))
	before := w.auditText()

	code, out, errs := w.run("", "remote", "status")
	if code != exitcode.OK || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	for _, want := range []string{"server:        " + ss.ts.URL + "\n", "account:       01234567\n", "generation:    2\n", "version:       7\n",
		"last sync:     2026-01-02T03:04:05Z\n", "pending push:  no\n", "conflicts:     locked (run 'gentle-vault unlock')\n",
		"devices:       locked (run 'gentle-vault unlock')\n", "anchor:        none uploaded\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("status lacks %q:\n%s", want, out)
		}
	}
	code, out, errs = w.run("", "--json", "remote", "status")
	var o struct {
		OK        bool
		Locked    bool
		Version   int
		Conflicts *int
		Devices   *int
	}
	if err := json.Unmarshal([]byte(out), &o); code != exitcode.OK || errs != "" || err != nil || !o.OK || !o.Locked || o.Version != 7 || o.Conflicts != nil || o.Devices != nil {
		t.Fatalf("json: code=%d out=%q err=%q (%v)", code, out, errs, err)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("status prompted: %+v", f.Calls)
	}
	if tp.n.Load() != 0 {
		t.Fatalf("status made %d requests", tp.n.Load())
	}
	if w.auditText() != before {
		t.Fatal("status wrote to the audit log")
	}
}

func TestRemoteStatusDoesNotFinishAnInterruptedRekey(t *testing.T) {
	ss := newSyncServer(t)
	w := newWorld(t)
	w.register(ss)
	asBackend(t, keepBackend{answers()})
	w.interruptRekey()
	id, _ := vault.ReadID(w.home)

	code, out, errs := w.run("", "remote", "status")
	if code != exitcode.OK || errs != "" || !strings.Contains(out, "conflicts:     locked (run 'gentle-vault unlock')\n") || !strings.Contains(out, "version:       1\n") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if has, _ := keychain.HasStaged(w.home, id, keychain.Options{}); !has {
		t.Fatal("remote status finished the rekey")
	}
	if strings.Contains(w.auditText(), "interrupted rekey finished") {
		t.Fatal("remote status audited a finished rekey")
	}
}

func TestAuditVerifyNeverPromptsNorFinishesARekeyForTheAnchorCheck(t *testing.T) {
	t.Run("passphrase vault", func(t *testing.T) {
		ss := newSyncServer(t)
		tp := ss.tap()
		w := syncingPassphraseWorld(t, ss.ts.URL)
		f := withBackend(t, answers(val(fxPass)))
		code, out, errs := w.run("", "audit", "--verify")
		if code != exitcode.OK || errs != "" || !strings.Contains(out, "audit log ok") || !strings.Contains(out, "remote anchor: unavailable\n") {
			t.Fatalf("code=%d out=%q err=%q", code, out, errs)
		}
		if len(f.Calls) != 0 || tp.n.Load() != 0 {
			t.Fatalf("prompts=%+v requests=%d", f.Calls, tp.n.Load())
		}
		_, jout, _ := w.run("", "--json", "audit", "--verify")
		if !strings.Contains(jout, `"anchor":"unavailable"`) {
			t.Fatalf("json = %q", jout)
		}
	})
	t.Run("interrupted rekey", func(t *testing.T) {
		ss := newSyncServer(t)
		w := newWorld(t)
		w.register(ss)
		asBackend(t, keepBackend{answers()})
		w.interruptRekey()
		id, _ := vault.ReadID(w.home)
		code, out, errs := w.run("", "audit", "--verify")
		if code != exitcode.OK || errs != "" || !strings.Contains(out, "remote anchor: unavailable\n") {
			t.Fatalf("code=%d out=%q err=%q", code, out, errs)
		}
		if has, _ := keychain.HasStaged(w.home, id, keychain.Options{}); !has {
			t.Fatal("audit --verify finished the rekey")
		}
	})
}

func TestAuditVerifyReportsAnUnreadableRemoteState(t *testing.T) {
	ss := newSyncServer(t)
	tp := ss.tap()
	w := newWorld(t)
	w.register(ss)
	asBackend(t, keepBackend{answers()})
	w.corruptState()
	before := tp.n.Load()
	code, out, errs := w.run("", "audit", "--verify")
	if code != exitcode.OK || errs != "" || !strings.Contains(out, "audit log ok") || !strings.HasSuffix(out, "remote anchor: unavailable\n") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	_, jout, _ := w.run("", "--json", "audit", "--verify")
	if !strings.Contains(jout, `"anchor":"unavailable"`) {
		t.Fatalf("json = %q", jout)
	}
	if tp.n.Load() != before {
		t.Fatal("made a request with an unreadable state")
	}
}

// ---- S4: restore asks before it syncs ----

// vaultBytes is the sealed vault file: any write changes it (a command that
// reads would sync first, so the file is the way to see that nothing wrote).
func (w *world) vaultBytes() string {
	w.t.Helper()
	b, err := os.ReadFile(filepath.Join(w.home, "vault.enc"))
	if err != nil {
		w.t.Fatal(err)
	}
	return string(b)
}

// changes counts the requests that can change something on the server
// (anything but a GET or the login handshake).
func (ss *syncServer) changes() *atomic.Int64 {
	var n atomic.Int64
	ss.proxy(func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != "GET" && !strings.HasPrefix(r.URL.Path, "/v1/auth/") {
			n.Add(1)
		}
		return false
	})
	return &n
}

func TestRestoreCancelMakesNoChangingRequestAndKeepsPendingWork(t *testing.T) {
	ss, a, b, vN := restorePair(t)
	// A change made while the vault could not reach the server stays pending.
	if code, _, errs := a.runEnv(map[string]string{envNoRemote: "1"}, "TESTSECRET_pending", "set", "P_LOCAL", "--global", "--stdin"); code != exitcode.OK {
		t.Fatalf("setup: code=%d err=%q", code, errs)
	}
	asBackend(t, keepBackend{answers()})
	before, stBefore := a.vaultBytes(), *readState(t, a)
	if !stBefore.PendingPush {
		t.Fatal("setup: the change is not pending")
	}
	puts := ss.changes()

	for _, c := range []struct {
		name string
		ans  []prompttest.Answer
	}{{"no", []prompttest.Answer{no()}}, {"cancel", []prompttest.Answer{cancel()}}} {
		asBackend(t, keepBackend{answers(c.ans...)})
		code, out, errs := a.run("", "remote", "restore", "--version", ver(vN))
		if code != exitcode.Failure || out != "" || errs != msgCancelled {
			t.Fatalf("%s: code=%d out=%q err=%q", c.name, code, out, errs)
		}
		if n := puts.Load(); n != 0 {
			t.Fatalf("%s: %d requests that change the server", c.name, n)
		}
		if a.vaultBytes() != before {
			t.Fatalf("%s: the vault changed", c.name)
		}
		if st := readState(t, a); *st != stBefore {
			t.Fatalf("%s: state %+v -> %+v", c.name, stBefore, st)
		}
	}
	// Nothing reached the other device, and the change is still waiting.
	asBackend(t, keepBackend{answers()})
	b.mustRun("", "remote", "sync")
	if strings.Contains(b.names(), "P_LOCAL") {
		t.Fatal("a cancelled restore pushed the pending change")
	}
	if out := a.mustRun("", "remote", "sync"); !strings.HasPrefix(out, "synced") {
		t.Fatalf("the pending change did not sync afterwards: %q", out)
	}
}

func TestRestoreOnAStaleKeyAsksForASyncFirst(t *testing.T) {
	_, a, b, c, _ := threeDevices(t)
	asBackend(t, keepBackend{answers(yes(), no())})
	b.mustRun("", "remote", "revoke-device", c.devID())
	asBackend(t, keepBackend{answers()})
	b.mustRun("TESTSECRET_after", "set", "AFTER", "--global", "--stdin")
	newest := readState(t, b).LastVersion // sealed under generation 2; A is still on 1
	before, stBefore := a.vaultBytes(), *readState(t, a)
	f := answers(yes())
	asBackend(t, keepBackend{f})
	code, out, errs := a.run("", "remote", "restore", "--version", ver(newest))
	if code != exitcode.Failure || out != "" || errs != "error: the account key changed since the last sync; run 'gentle-vault remote sync', then try again\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if len(f.Calls) != 0 || a.vaultBytes() != before || *readState(t, a) != stBefore {
		t.Fatalf("a refused restore asked or changed something: calls=%d", len(f.Calls))
	}
}

// ---- S5: swapKey keeps the session when it cannot finish ----

func TestSwapKeyFailureLeavesTheSessionAndTheCallersKeyUsable(t *testing.T) {
	ss := newSyncServer(t)
	w := newWorld(t)
	w.register(ss)
	asBackend(t, keepBackend{answers()})
	// A device file that no key opens: the re-seal of the remote files fails
	// after the new vault handle was opened.
	if err := os.WriteFile(filepath.Join(w.home, "remote", "device.enc"), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	g := &globals{getenv: envFrom(nil), home: w.home}
	s, err := g.openSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	cur := string(s.key.Reveal())
	raw := s.key.Reveal()
	mk := secret.New("master", raw)
	clear(raw)
	defer mk.Wipe()

	if err := g.swapKey(s, mk); err == nil {
		t.Fatal("swapKey succeeded with an unreadable device file")
	}
	if string(s.key.Reveal()) != cur {
		t.Fatal("a failed swap changed or wiped the session key")
	}
	if string(mk.Reveal()) != cur {
		t.Fatal("a failed swap wiped the caller's key")
	}
	if _, err := s.v.Roster(); err != nil {
		t.Fatalf("the session vault no longer opens: %v", err)
	}
}

// ---- S6: tests the earlier slices left out ----

// tamperVaultGets flips a byte inside the sealed vault the server returns for
// a plain GET /v1/vault (not a version), as a hostile server could.
func (ss *syncServer) tamperVaultGets() {
	ss.proxy(func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != "GET" || r.URL.Path != "/v1/vault" || r.URL.Query().Get("version") != "" || r.Header.Get("X-Test-Forwarded") != "" {
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
}

func TestSyncRoundRefusesAnOlderGenerationAndATamperedBlobWithoutChangingAnything(t *testing.T) {
	ss, _, a, b := syncPair(t)
	a.mustRun("TESTSECRET_news", "set", "NEWS", "--global", "--stdin") // b has not seen it: the server sends a blob
	changes := ss.changes()
	ss.tamperVaultGets()

	t.Run("tampered blob", func(t *testing.T) {
		before, stBefore := b.vaultBytes(), *readState(t, b)
		code, out, errs := b.run("", "remote", "sync")
		if code != exitcode.Failure || out != "" || errs != "error: the server's vault could not be verified\n" {
			t.Fatalf("code=%d out=%q err=%q", code, out, errs)
		}
		if b.vaultBytes() != before || *readState(t, b) != stBefore || changes.Load() != 0 {
			t.Fatalf("the refused round changed something (requests that change: %d)", changes.Load())
		}
		noFixtures(t, "stderr", errs)
	})
	t.Run("older generation", func(t *testing.T) {
		b.editState(func(st *vault.Remote) { st.Generation = 5 })
		before, stBefore := b.vaultBytes(), *readState(t, b)
		code, out, errs := b.run("", "remote", "sync")
		if code != exitcode.Corrupt || out != "" || errs != "error: the server offered a version older than one already seen\n" {
			t.Fatalf("code=%d out=%q err=%q", code, out, errs)
		}
		if b.vaultBytes() != before || *readState(t, b) != stBefore || changes.Load() != 0 {
			t.Fatalf("the refused round changed something (requests that change: %d)", changes.Load())
		}
	})
}

func TestGrantsAfterAnUnchangedAndAReplacedRecordAreRestored(t *testing.T) {
	pinClock(t)
	_, _, a, _ := syncPair(t)
	asTerminal(t, false)
	a.mustRun("TESTSECRET_keep", "set", "KEEP", "--global", "--stdin")
	a.mustRun("TESTSECRET_one", "set", "SWAP", "--global", "--stdin")
	vN := readState(t, a).LastVersion
	a.mustRun("TESTSECRET_two", "set", "SWAP", "--global", "--stdin") // replaced after vN
	for _, name := range []string{"KEEP", "SWAP"} {
		tok := a.issueTokenFor(name, "global", a.recordID(name), grants.ScopeSession, sessA, 0)
		a.mustRun("", "--session", sessA, "grant", name, "--scope", "session", "--from-prompt-token", tok)
		if err := a.execCheck(name, sessA); err != nil {
			t.Fatalf("setup: %s is not granted: %v", name, err)
		}
	}
	asBackend(t, keepBackend{answers(yes())})
	a.mustRun("", "remote", "restore", "--version", ver(vN))
	if a.value("SWAP") != "TESTSECRET_one" {
		t.Fatal("setup: SWAP was not restored")
	}
	if err := a.execCheck("KEEP", sessA); err != nil {
		t.Fatalf("a grant on a record restored unchanged stopped working: %v", err)
	}
	if err := a.execCheck("SWAP", sessA); err == nil {
		t.Fatal("a grant on a replaced record still authorizes the new one")
	}
}

func TestRevokedDeviceStaysRevokedAfterARestore(t *testing.T) {
	ss, a, b, c, _ := threeDevices(t)
	asBackend(t, keepBackend{answers(yes(), no())})
	a.mustRun("", "remote", "revoke-device", c.devID())
	asBackend(t, keepBackend{answers()})
	a.mustRun("TESTSECRET_x1", "set", "X1", "--global", "--stdin")
	v1 := readState(t, a).LastVersion // generation 2, C revoked
	a.mustRun("TESTSECRET_x2", "set", "X2", "--global", "--stdin")
	asBackend(t, keepBackend{answers(yes())})
	a.mustRun("", "remote", "restore", "--version", ver(v1))
	if strings.Contains(a.names(), "X2") {
		t.Fatal("setup: the restore did not apply")
	}
	if a.roster()[c.devID()].RevokedAt == nil {
		t.Fatal("the restore un-revoked a device on A")
	}
	asBackend(t, keepBackend{answers()})
	b.mustRun("", "remote", "sync")
	if b.roster()[c.devID()].RevokedAt == nil {
		t.Fatal("the restore un-revoked a device on B")
	}
	if ids, _ := serverView(t, ss, a); len(ids) != 2 {
		t.Fatalf("the server holds %d devices, want 2", len(ids))
	}
	if code, _, errs := c.run("", "remote", "sync"); code != exitcode.Failure || !strings.Contains(errs, "this device was revoked") {
		t.Fatalf("revoked device: code=%d err=%q", code, errs)
	}
}

func TestPlainAuditMakesNoRequestWithSyncEnabled(t *testing.T) {
	_, tp, a, _ := syncPair(t)
	a.mustRun("TESTSECRET_au", "set", "AU", "--global", "--stdin")
	a.stale()
	tp.n.Store(0)
	for _, args := range [][]string{{"audit"}, {"--json", "audit"}, {"audit", "--tail", "3"}, {"audit", "--verify", "--offline"}} {
		if code, _, errs := a.run("", args...); code != exitcode.OK || errs != "" {
			t.Fatalf("%v: code=%d err=%q", args, code, errs)
		}
	}
	if n := tp.n.Load(); n != 0 {
		t.Fatalf("audit made %d requests", n)
	}
}

// A vault that cannot open without a prompt (passphrase mode, no cached
// key) still shows the counts and warnings of its last sync round, marked as
// such, instead of losing the conflicts it must warn about.
func TestRemoteStatusLockedUsesTheLastSyncCounts(t *testing.T) {
	ss := newSyncServer(t)
	w := syncingPassphraseWorld(t, ss.ts.URL)
	w.editState(func(st *vault.Remote) {
		st.Summary = vault.RemoteSummary{At: "2026-01-02T03:04:05Z", Conflicts: 2, Devices: 3, RecoveryAdded: 1}
	})
	f := withBackend(t, answers(val(fxPass)))
	code, out, errs := w.run("", "remote", "status")
	if code != exitcode.Failure || !strings.Contains(out, "conflicts:     2 (as of the last sync)\n") || !strings.Contains(out, "devices:       3 (as of the last sync)\n") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if !strings.Contains(errs, "warning: 2 sync conflicts\n") || !strings.Contains(errs, "warning: 1 device added by recovery\n") {
		t.Fatalf("warnings: %q", errs)
	}
	_, jout, _ := w.run("", "--json", "remote", "status")
	var o struct {
		Locked     bool
		Conflicts  *int
		Devices    *int
		CountsFrom string `json:"counts_from"`
	}
	if err := json.Unmarshal([]byte(jout), &o); err != nil || !o.Locked || o.Conflicts == nil || *o.Conflicts != 2 || o.Devices == nil || *o.Devices != 3 || o.CountsFrom != "last_sync" {
		t.Fatalf("json = %q", jout)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("status prompted: %+v", f.Calls)
	}
}

func TestSyncRoundRecordsTheStatusCounts(t *testing.T) {
	_, _, a, _ := syncPair(t)
	a.mustRun("", "remote", "sync")
	st := readState(t, a)
	if st.Summary.At == "" || st.Summary.Devices != 2 || st.Summary.Conflicts != 0 || st.Summary.RecoveryAdded != 0 {
		t.Fatalf("summary = %+v", st.Summary)
	}
}
