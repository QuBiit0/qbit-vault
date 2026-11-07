package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/exitcode"
	"github.com/QuBiit0/qbit-vault/internal/merge"
	"github.com/QuBiit0/qbit-vault/internal/prompt/prompttest"
	"github.com/QuBiit0/qbit-vault/internal/remote"
	"github.com/QuBiit0/qbit-vault/internal/secret"
	"github.com/QuBiit0/qbit-vault/internal/vault"
)

// Master-key rotation and device revocation (REMOTE_SYNC § 4.5,
// § 4.6, § 7.2 step 2). Devices are vault homes against one real in-process
// server; a proxy in front of it plays the server answers the real one does
// does not give in every case or that a hostile server could give.

const secretA = "TESTSECRET_value_a_9a"

// proxy puts a handler in front of the server; it decides per request
// whether to answer itself (true) or let the server answer.
func (ss *syncServer) proxy(h func(w http.ResponseWriter, r *http.Request) bool) {
	inner := ss.ts.Config.Handler
	ss.ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h(w, r) {
			inner.ServeHTTP(w, r)
		}
	})
}

// asRevoked makes the server answer device_revoked at the login of the
// given devices, as a server that remembers its revocations would.
func (ss *syncServer) asRevoked(ids ...string) {
	ss.proxy(func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != "POST" || r.URL.Path != "/v1/auth/challenge" {
			return false
		}
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		for _, id := range ids {
			if bytes.Contains(body, []byte(`"`+id+`"`)) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(403)
				_, _ = io.WriteString(w, `{"api":1,"error":{"code":"device_revoked","message":"SERVER-TEXT"}}`)
				return true
			}
		}
		return false
	})
}

// conflictRekey answers 409 to the first n rekey calls.
func (ss *syncServer) conflictRekey(n int32) *atomic.Int32 {
	var seen atomic.Int32
	ss.proxy(func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != "POST" || r.URL.Path != "/v1/rekey" || seen.Add(1) > n {
			return false
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(409)
		_, _ = io.WriteString(w, `{"api":1,"error":{"code":"conflict","message":"x"}}`)
		return true
	})
	return &seen
}

// forgeKeys makes GET /v1/keys/self return env at generation gen.
func (ss *syncServer) forgeKeys(gen int, env []byte) {
	ss.proxy(func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != "GET" || r.URL.Path != "/v1/keys/self" {
			return false
		}
		w.Header().Set("Content-Type", "application/json")
		b, _ := json.Marshal(string(env))
		_, _ = io.WriteString(w, `{"api":1,"generation":`+strconv.Itoa(gen)+`,"envelope":`+string(b)+`}`)
		return true
	})
}

func (w *world) devID() string {
	w.t.Helper()
	id, err := vault.ReadDeviceID(w.home)
	if err != nil || id == "" {
		w.t.Fatalf("device id: %q %v", id, err)
	}
	return id
}

func (w *world) roster() map[string]merge.Device {
	w.t.Helper()
	g := &globals{getenv: envFrom(nil), home: w.home}
	s, err := g.openSession()
	if err != nil {
		w.t.Fatal(err)
	}
	defer s.close()
	r, err := s.v.Roster()
	if err != nil {
		w.t.Fatal(err)
	}
	return r
}

// serverView logs in as w and returns the account's device ids and the
// generation of its current vault version.
func serverView(t *testing.T, ss *syncServer, w *world) ([]string, int) {
	t.Helper()
	dk, err := w.deviceSecret()
	if err != nil {
		t.Fatal(err)
	}
	c, _ := remote.NewClient(ss.ts.URL, "")
	if err := c.Login(context.Background(), w.devID(), remote.DeviceFromSecret(dk)); err != nil {
		t.Fatalf("login: %v", err)
	}
	devs, err := c.Devices(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, d := range devs {
		ids = append(ids, d.ID)
	}
	vv, err := c.GetVault(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	return ids, vv.Generation
}

// threeDevices is an account with A (registered), B and C (paired through A).
// It returns the first recovery key. Later commands never prompt.
func threeDevices(t *testing.T) (ss *syncServer, a, b, c *world, rk0 string) {
	t.Helper()
	ss = newSyncServer(t)
	a, b, c = newWorld(t), newWorld(t), newWorld(t)
	rk0 = a.register(ss)
	for _, w := range []*world{b, c} {
		if code, out, errs, _ := joinPairing(t, w, a, ss); code != exitcode.OK {
			t.Fatalf("join: code=%d out=%q err=%q", code, out, errs)
		}
	}
	asBackend(t, keepBackend{answers()})
	a.mustRun(secretA, "set", "A_KEY", "--global", "--stdin")
	b.mustRun("", "remote", "sync")
	c.mustRun("", "remote", "sync")
	return
}

func (w *world) gen() int { return readState(w.t, w).Generation }

// noKeyIn fails when tape holds a key in any common encoding.
func noKeyIn(t *testing.T, what, tape string, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if k == "" {
			t.Fatal("empty key to look for")
		}
		raw := []byte(k)
		for _, form := range []string{k, strings.ReplaceAll(k, "-", ""), base64.StdEncoding.EncodeToString(raw),
			base64.RawURLEncoding.EncodeToString(raw), base64.URLEncoding.EncodeToString(raw), hex.EncodeToString(raw)} {
			if strings.Contains(tape, form) {
				t.Fatalf("a key leaked into %s", what)
			}
		}
	}
	noFixtures(t, what, tape)
}

func revokeWith(t *testing.T, w *world, f *prompttest.Fake, id string, extra ...string) (int, string, string) {
	t.Helper()
	asBackend(t, keepBackend{f})
	return w.run("", append(append([]string{}, extra...), "remote", "revoke-device", id)...)
}

// ---- revoke-device ----

func TestRevokeDeviceRotatesTheKeyAndTheOthersAdopt(t *testing.T) {
	ss, a, b, c, rk0 := threeDevices(t)
	cid := c.devID()
	keyA, keyB, keyC := a.masterKey(), b.masterKey(), c.masterKey()
	if keyA != keyB {
		t.Fatal("devices should hold the same account key")
	}

	f := answers(yes(), no())
	code, out, errs := revokeWith(t, a, f, cid)
	if code != exitcode.OK || errs != "" || out != "revoked Laptop B ("+cid+"); the account key is now generation 2\n" {
		t.Fatalf("revoke: code=%d out=%q err=%q", code, out, errs)
	}
	kinds := ""
	for _, c := range f.Calls {
		kinds += c.Kind + " "
	}
	if kinds != "confirm show secret " || !strings.Contains(f.Calls[0].Q, "Laptop B") || !strings.Contains(f.Calls[0].Q, "last sync") {
		t.Fatalf("prompts = %q (%q)", kinds, f.Calls[0].Q)
	}
	rk1 := recoveryKeyIn(f)
	if rk1 == "" || rk1 == rk0 {
		t.Fatal("the new recovery key was not shown")
	}
	st := readState(t, a)
	if st.Generation != 2 || st.RecoveryUnconfirmed || st.PendingPush || a.masterKey() == keyA {
		t.Fatalf("A after revoke: %+v", st)
	}
	if a.value("A_KEY") != secretA {
		t.Fatal("A lost its secret")
	}
	if ids, gen := serverView(t, ss, a); len(ids) != 2 || gen != 2 {
		t.Fatalf("server: devices=%v generation=%d", ids, gen)
	}
	if r := a.roster()[cid]; r.RevokedAt == nil {
		t.Fatal("the roster does not mark C as revoked")
	}
	if !a.auditHas(`"detail":"device revoked `+cid+`"`) || !a.auditHas(`"event":"rekey"`) {
		t.Fatalf("audit: %s", a.auditText())
	}

	// B adopts generation 2 on its next round and still reads everything.
	code, out2, errs2 := b.run("", "remote", "sync")
	if code != exitcode.OK || errs2 != "" {
		t.Fatalf("B sync: code=%d out=%q err=%q", code, out2, errs2)
	}
	if b.gen() != 2 || b.masterKey() == keyB || b.value("A_KEY") != secretA {
		t.Fatalf("B did not adopt generation 2: %+v", readState(t, b))
	}
	if r := b.roster()[cid]; r.RevokedAt == nil {
		t.Fatal("B's roster does not show C revoked after the round")
	}
	// B writes under the new key and A reads it.
	b.mustRun(fxVal+"_b", "set", "B_KEY", "--global", "--stdin")
	a.mustRun("", "remote", "sync")
	if a.value("B_KEY") != fxVal+"_b" {
		t.Fatal("A did not receive B's change under generation 2")
	}

	// C is told, turns sync off and keeps its vault and key.
	code, cout, _ := c.run("", "--json", "remote", "sync")
	if code != exitcode.Failure || !strings.Contains(cout, `"code":"device_revoked"`) {
		t.Fatalf("C sync (real server): code=%d out=%q", code, cout)
	}
	if readState(t, c) != nil || c.masterKey() != keyC || c.value("A_KEY") != secretA {
		t.Fatal("C lost its vault or kept sync state")
	}
	if _, err := vault.ReadRemote(c.home); err != nil {
		t.Fatal(err)
	}
	if code, id := jsonErrCode(t, c, "remote", "status"); code != exitcode.Failure || id != "remote_not_configured" {
		t.Fatalf("C status: code=%d id=%q", code, id)
	}
	if !c.auditHas("device revoked") {
		t.Fatalf("C audit: %s", c.auditText())
	}

	// The old recovery key stops working, the new one recovers the vault.
	url := ss.ts.URL
	d := newWorld(t)
	asBackend(t, keepBackend{answers(yes(), val(rk0))})
	code, _, errs3 := d.run("", "remote", "join", "--server", url, "--recovery")
	wantCoded(t, code, errs3, "remote_auth", exitcode.Failure)
	asBackend(t, keepBackend{answers(yes(), val(rk1))})
	if code, out, errs := d.run("", "remote", "join", "--server", url, "--recovery"); code != exitcode.OK {
		t.Fatalf("join with the new recovery key: code=%d out=%q err=%q", code, out, errs)
	}
	if d.value("A_KEY") != secretA || d.value("B_KEY") != fxVal+"_b" {
		t.Fatal("recovery with the new key did not bring the vault")
	}

	tape := out + errs + out2 + errs2 + cout + a.auditText() + b.auditText() + c.auditText() + ss.held(t)
	noKeyIn(t, "an output, an audit log or the server's data", tape, rk1, keyA, a.masterKey(), b.masterKey())
}

func TestRevokeDeviceRefusals(t *testing.T) {
	ss, a, _, c, _ := threeDevices(t)
	cid := c.devID()
	key, state := a.masterKey(), *readState(t, a)
	for _, tc := range []struct{ name, id, want string }{
		{"this device", a.devID(), "this device cannot revoke itself; use 'qbit-vault remote logout'"},
		{"unknown", strings.Repeat("e", 32), "no such device in this vault's roster"},
		{"bad shape", "../../etc", "no such device in this vault's roster"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := answers()
			code, out, errs := revokeWith(t, a, f, tc.id)
			if code != exitcode.Usage || out != "" || errs != usageErr(tc.want) || len(f.Calls) != 0 {
				t.Fatalf("code=%d out=%q err=%q calls=%d", code, out, errs, len(f.Calls))
			}
			noFixtures(t, "stderr", errs)
		})
	}
	if code, out, errs := revokeWith(t, a, answers(yes(), no()), cid); code != exitcode.OK {
		t.Fatalf("revoke: code=%d out=%q err=%q", code, out, errs)
	}
	f := answers()
	code, _, errs := revokeWith(t, a, f, cid)
	if code != exitcode.Usage || errs != usageErr("that device is already revoked") || len(f.Calls) != 0 {
		t.Fatalf("already revoked: code=%d err=%q", code, errs)
	}
	_ = ss
	_ = key
	_ = state
}

func TestRevokeDeviceNeedsAPromptBackendThatCanShow(t *testing.T) {
	ss, a, _, c, _ := threeDevices(t)
	_ = ss
	key := a.masterKey()
	noBackend(t)
	code, out, _ := a.run("", "--json", "remote", "revoke-device", c.devID())
	if code != exitcode.Refusal || !strings.Contains(out, `"not_model_callable"`) {
		t.Fatalf("no backend: code=%d out=%q", code, out)
	}
	asBackend(t, noShow{answers(yes(), no())})
	code, out, _ = a.run("", "--json", "remote", "revoke-device", c.devID())
	if code != exitcode.Refusal || !strings.Contains(out, `"not_model_callable"`) || a.masterKey() != key || a.gen() != 1 {
		t.Fatalf("cannot show: code=%d out=%q", code, out)
	}
	code, _, errs := a.run("", "remote", "revoke-device")
	if code != exitcode.Usage || !strings.Contains(errs, "error:") {
		t.Fatalf("no id: code=%d err=%q", code, errs)
	}
}

func TestRevokeDeviceCancelLeavesEverythingUnchanged(t *testing.T) {
	ss, a, _, c, _ := threeDevices(t)
	key, state := a.masterKey(), *readState(t, a)
	audit := a.auditText()
	for name, script := range map[string][]prompttest.Answer{
		"cancel at the confirmation": {cancel()},
		"declined":                   {no()},
	} {
		t.Run(name, func(t *testing.T) {
			code, out, errs := revokeWith(t, a, answers(script...), c.devID())
			if code != exitcode.Failure || out != "" || errs != "error: cancelled\n" {
				t.Fatalf("code=%d out=%q err=%q", code, out, errs)
			}
			if a.masterKey() != key || *readState(t, a) != state || a.auditText() != audit {
				t.Fatal("a cancelled revoke changed the key, the state or the audit log")
			}
			if ids, gen := serverView(t, ss, a); len(ids) != 3 || gen != 1 {
				t.Fatalf("server changed: %v %d", ids, gen)
			}
			if a.roster()[c.devID()].RevokedAt != nil {
				t.Fatal("roster changed")
			}
		})
	}
}

// Cancelling the recovery key screen happens after the server accepted the
// rotation: the account and this device are on generation 2, and the
// warning stays until the recovery key is rotated.
func TestRevokeDeviceCancelAtTheRecoveryKeyScreen(t *testing.T) {
	ss, a, _, c, _ := threeDevices(t)
	code, _, errs := revokeWith(t, a, answers(yes(), cancel()), c.devID())
	if code != exitcode.Failure || errs != "error: cancelled\n" {
		t.Fatalf("code=%d err=%q", code, errs)
	}
	st := readState(t, a)
	if st.Generation != 2 || !st.RecoveryUnconfirmed || a.value("A_KEY") != secretA {
		t.Fatalf("state = %+v", st)
	}
	if _, gen := serverView(t, ss, a); gen != 2 {
		t.Fatal("server not on generation 2")
	}
	code, _, errs = a.run("", "remote", "status")
	if code != exitcode.Failure || !strings.Contains(errs, "warning: recovery key not confirmed") {
		t.Fatalf("status: code=%d err=%q", code, errs)
	}
}

func TestRevokeDeviceRetriesOnConflict(t *testing.T) {
	t.Run("a stale base restarts from the pull", func(t *testing.T) {
		ss, a, _, c, _ := threeDevices(t)
		seen := ss.conflictRekey(1)
		f := answers(yes(), no())
		if code, out, errs := revokeWith(t, a, f, c.devID()); code != exitcode.OK {
			t.Fatalf("code=%d out=%q err=%q", code, out, errs)
		}
		if seen.Load() != 2 || a.gen() != 2 {
			t.Fatalf("rekey calls=%d generation=%d", seen.Load(), a.gen())
		}
		if n := strings.Count(strings.Join(kindsOf(f), " "), "confirm"); n != 1 {
			t.Fatalf("confirmed %d times", n)
		}
	})
	t.Run("bounded: nothing changes", func(t *testing.T) {
		ss, a, _, c, _ := threeDevices(t)
		key := a.masterKey()
		seen := ss.conflictRekey(100)
		f := answers(yes(), no())
		code, out, errs := revokeWith(t, a, f, c.devID())
		wantCoded(t, code, errs, "internal", exitcode.Failure)
		if out != "" || !strings.Contains(errs, "the server changed while rotating the key") || seen.Load() != maxRoundTries {
			t.Fatalf("out=%q err=%q calls=%d", out, errs, seen.Load())
		}
		if a.masterKey() != key || a.gen() != 1 || readState(t, a).RecoveryUnconfirmed || recoveryKeyIn(f) != "" {
			t.Fatal("a failed rotation changed this device")
		}
		if a.roster()[c.devID()].RevokedAt != nil {
			t.Fatal("roster marked C revoked although the server never accepted")
		}
	})
}

func kindsOf(f *prompttest.Fake) []string {
	var k []string
	for _, c := range f.Calls {
		k = append(k, c.Kind)
	}
	return k
}

// ---- adopting a higher generation (§ 7.2 step 2) ----

func TestForgedKeyEnvelopeIsRefused(t *testing.T) {
	for _, tc := range []string{"issuer not in the roster", "bad signature", "issuer revoked locally"} {
		t.Run(tc, func(t *testing.T) {
			ss, a, b, c, _ := threeDevices(t)
			if code, out, errs := revokeWith(t, a, answers(yes(), no()), c.devID()); code != exitcode.OK {
				t.Fatalf("revoke: code=%d out=%q err=%q", code, out, errs)
			}
			asBackend(t, keepBackend{answers()})
			keyB, stateB := b.masterKey(), *readState(t, b)
			aid := a.devID()

			rogue := remote.DeviceFromSecret(mustDK(t))
			bb := b.roster()[b.devID()]
			boxPub, _ := base64.StdEncoding.DecodeString(bb.BoxPub)
			mk, _ := newDeviceSecret() // not the account key: the attacker does not have it
			defer mk.Wipe()
			switch tc {
			case "issuer not in the roster":
				env, err := remote.SealKeyEnvelope(rogue, boxPub, remote.EnvelopeAAD{AccountID: stateB.AccountID, DeviceID: b.devID(), Generation: 2, Issuer: "rogue"}, mk)
				if err != nil {
					t.Fatal(err)
				}
				ss.forgeKeys(2, env)
			case "bad signature":
				env, err := remote.SealKeyEnvelope(rogue, boxPub, remote.EnvelopeAAD{AccountID: stateB.AccountID, DeviceID: b.devID(), Generation: 2, Issuer: aid}, mk)
				if err != nil {
					t.Fatal(err)
				}
				ss.forgeKeys(2, env)
			case "issuer revoked locally":
				// The envelope is genuine, but B's own roster says A is revoked.
				g := &globals{getenv: envFrom(nil), home: b.home}
				s, err := g.openSession()
				if err != nil {
					t.Fatal(err)
				}
				err = s.v.EditRoster(func(r map[string]merge.Device) {
					d := r[aid]
					at := nowUTC()
					d.RevokedAt = &at
					r[aid] = d
				})
				s.close()
				if err != nil {
					t.Fatal(err)
				}
			}
			code, out, errs := b.run("", "remote", "sync")
			wantCoded(t, code, errs, "remote_auth", exitcode.Failure)
			if out != "" || !strings.Contains(errs, "the new account key could not be verified") {
				t.Fatalf("out=%q err=%q", out, errs)
			}
			if b.masterKey() != keyB || b.gen() != 1 || b.value("A_KEY") != secretA {
				t.Fatal("B changed key or generation after a forged key envelope")
			}
			if st := readState(t, b); st.LastVersion != stateB.LastVersion {
				t.Fatalf("state advanced: %+v", st)
			}
		})
	}
}

func mustDK(t *testing.T) secret.Secret {
	t.Helper()
	s, err := newDeviceSecret()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestLowerGenerationStaysARollback(t *testing.T) {
	_, _, a, b := syncPair(t)
	b.editState(func(st *vault.Remote) { st.Generation, st.LastVersion = 5, 0 })
	_ = a
	code, _, errs := b.run("", "remote", "sync")
	wantCoded(t, code, errs, "remote_rollback", exitcode.Corrupt)
	if !strings.Contains(errs, "older") || b.gen() != 5 {
		t.Fatalf("err=%q gen=%d", errs, b.gen())
	}
}

// ---- rekey with sync enabled (§ 4.5 last paragraph) ----

func TestRekeyWithSyncMovesTheAccount(t *testing.T) {
	ss, tp, a, b := syncPair(t)
	_ = tp
	a.mustRun(secretA, "set", "A_KEY", "--global", "--stdin")
	b.mustRun("", "remote", "sync")
	keyA, keyB := a.masterKey(), b.masterKey()

	f := answers(yes(), no())
	asBackend(t, keepBackend{f})
	code, out, errs := a.run("", "--json", "rekey")
	if code != exitcode.OK || errs != "" || !strings.HasPrefix(out, `{"ok":true,"rekeyed":true,"keychain":"`) || !strings.Contains(out, `"remote":"synced"`) {
		t.Fatalf("rekey: code=%d out=%q err=%q", code, out, errs)
	}
	rk1 := recoveryKeyIn(f)
	if rk1 == "" || a.masterKey() == keyA || a.gen() != 2 || a.value("A_KEY") != secretA {
		t.Fatalf("A after rekey: %+v", readState(t, a))
	}
	if ids, gen := serverView(t, ss, a); len(ids) != 2 || gen != 2 {
		t.Fatalf("server: %v %d", ids, gen)
	}
	if !a.auditHas(`"event":"rekey"`) || !a.auditHas("remote generation 2") {
		t.Fatalf("audit: %s", a.auditText())
	}
	// Nobody was revoked: B adopts and keeps working.
	asBackend(t, keepBackend{answers()})
	b.mustRun("", "remote", "sync")
	if b.gen() != 2 || b.masterKey() == keyB || b.value("A_KEY") != secretA {
		t.Fatal("B did not adopt the new generation")
	}
	for _, r := range b.roster() {
		if r.RevokedAt != nil {
			t.Fatal("a rekey revoked a device")
		}
	}
	noKeyIn(t, "an output, an audit log or the server's data", out+errs+a.auditText()+b.auditText()+ss.held(t), rk1, keyA, a.masterKey())

	// Human output, and a refusal that changes nothing without a prompt backend.
	asBackend(t, keepBackend{answers(yes(), no())})
	code, out, errs = a.run("", "rekey")
	if code != exitcode.OK || errs != "" || out != "master key rotated (keychain: "+osMode()+"); the account is now generation 3\n" {
		t.Fatalf("human: code=%d out=%q err=%q", code, out, errs)
	}
	key := a.masterKey()
	noBackend(t)
	if code, jout, _ := a.run("", "--json", "rekey"); code != exitcode.Refusal || !strings.Contains(jout, `"not_model_callable"`) {
		t.Fatalf("no backend: code=%d out=%q", code, jout)
	}
	asBackend(t, keepBackend{answers(cancel())})
	if code, _, errs := a.run("", "rekey"); code != exitcode.Failure || errs != "error: cancelled\n" || a.masterKey() != key || a.gen() != 3 {
		t.Fatalf("cancel: code=%d err=%q", code, errs)
	}
}

// ---- recovery-key --rotate (§ 4.6) ----

func TestRecoveryKeyRotate(t *testing.T) {
	ss, a, b, _, rk0 := threeDevices(t)
	a.editState(func(st *vault.Remote) { st.RecoveryUnconfirmed = true })
	gen0, key0 := a.gen(), a.masterKey()

	f := answers(yes(), no())
	asBackend(t, keepBackend{f})
	code, out, errs := a.run("", "remote", "recovery-key", "--rotate")
	if code != exitcode.OK || errs != "" || out != "recovery key rotated\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	rk1 := recoveryKeyIn(f)
	if rk1 == "" || rk1 == rk0 || readState(t, a).RecoveryUnconfirmed {
		t.Fatalf("rk1=%q state=%+v", rk1, readState(t, a))
	}
	// Only the recovery key changes (REMOTE_SYNC § 4.6): same account key.
	if a.gen() != gen0 || a.masterKey() != key0 {
		t.Fatalf("the account key changed: generation %d -> %d", gen0, a.gen())
	}
	if code, _, errs := a.run("", "remote", "status"); code != exitcode.OK || errs != "" {
		t.Fatalf("status still warns: code=%d err=%q", code, errs)
	}
	if !a.auditHas(`"detail":"recovery key rotated"`) {
		t.Fatalf("audit: %s", a.auditText())
	}
	d := newWorld(t)
	asBackend(t, keepBackend{answers(yes(), val(rk0))})
	code, _, errs = d.run("", "remote", "join", "--server", ss.ts.URL, "--recovery")
	wantCoded(t, code, errs, "remote_auth", exitcode.Failure)
	asBackend(t, keepBackend{answers(yes(), val(rk1))})
	if code, out, errs := d.run("", "remote", "join", "--server", ss.ts.URL, "--recovery"); code != exitcode.OK {
		t.Fatalf("join: code=%d out=%q err=%q", code, out, errs)
	}
	if d.value("A_KEY") != secretA {
		t.Fatal("recovery with the rotated key failed")
	}
	// The other devices follow the new generation.
	asBackend(t, keepBackend{answers()})
	b.mustRun("", "remote", "sync")
	if b.value("A_KEY") != secretA || b.gen() != a.gen() {
		t.Fatal("B did not follow")
	}
	noKeyIn(t, "an output, an audit log or the server's data", out+errs+a.auditText()+ss.held(t), rk1)

	t.Run("needs --rotate", func(t *testing.T) {
		code, _, errs := a.run("", "remote", "recovery-key")
		if code != exitcode.Usage || errs != usageErr("give --rotate to replace the recovery key") {
			t.Fatalf("code=%d err=%q", code, errs)
		}
	})
	t.Run("cancel changes nothing", func(t *testing.T) {
		key, state := a.masterKey(), *readState(t, a)
		asBackend(t, keepBackend{answers(cancel())})
		code, _, errs := a.run("", "remote", "recovery-key", "--rotate")
		if code != exitcode.Failure || errs != "error: cancelled\n" || a.masterKey() != key || *readState(t, a) != state {
			t.Fatalf("code=%d err=%q", code, errs)
		}
	})
	t.Run("not model callable", func(t *testing.T) {
		noBackend(t)
		if code, jout, _ := a.run("", "--json", "remote", "recovery-key", "--rotate"); code != exitcode.Refusal || !strings.Contains(jout, `"not_model_callable"`) {
			t.Fatalf("code=%d out=%q", code, jout)
		}
	})
}

// ---- warnings ----

func TestRosterWarningWhenAnotherDeviceIsAdded(t *testing.T) {
	ss, _, a, b := syncPair(t)
	c := newWorld(t)
	if code, out, errs, _ := joinPairing(t, c, a, ss); code != exitcode.OK {
		t.Fatalf("join: code=%d out=%q err=%q", code, out, errs)
	}
	asBackend(t, keepBackend{answers()})
	want := `"event":"warning"`
	if b.auditHas("device added") {
		t.Fatal("warned before the round")
	}
	b.mustRun("", "remote", "sync")
	if !b.auditHas(want) || !b.auditHas(`"detail":"device added: Laptop B via pairing"`) {
		t.Fatalf("B audit: %s", b.auditText())
	}
	if a.auditHas("device added") || c.auditHas("device added") {
		t.Fatal("the approver and the new device must not warn")
	}
	n := strings.Count(b.auditText(), "device added")
	b.mustRun("", "remote", "sync")
	if strings.Count(b.auditText(), "device added") != n {
		t.Fatal("the same device was warned twice")
	}
}

func TestRevokedDeviceTurnsSyncOffInAutomaticRounds(t *testing.T) {
	ss, a, _, c, _ := threeDevices(t)
	cid := c.devID()
	if code, out, errs := revokeWith(t, a, answers(yes(), no()), cid); code != exitcode.OK {
		t.Fatalf("revoke: code=%d out=%q err=%q", code, out, errs)
	}
	ss.asRevoked(cid)
	asBackend(t, keepBackend{answers()})
	code, out, errs := c.run(fxVal+"_c", "--json", "set", "C_KEY", "--global", "--stdin")
	want := "warning: this device was revoked; sync is now off here and the local vault is intact\n"
	if code != 0 || errs != want || !strings.Contains(out, `"remote":"pending"`) {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if readState(t, c) != nil || c.value("C_KEY") != fxVal+"_c" {
		t.Fatal("sync is still on or the change was lost")
	}
	// Afterwards the vault is an ordinary local one.
	if code, _, errs := c.run("", "list"); code != 0 || errs != "" {
		t.Fatalf("list: code=%d err=%q", code, errs)
	}
}

// A recovery rotation against an account key this device does not have yet
// changes nothing and says to sync first.
func TestRecoveryKeyRotateOnAStaleGeneration(t *testing.T) {
	_, a, _, _, _ := threeDevices(t)
	a.editState(func(st *vault.Remote) { st.Generation = 7 })
	before := *readState(t, a)
	f := answers(yes())
	asBackend(t, keepBackend{f})
	code, out, errs := a.run("", "remote", "recovery-key", "--rotate")
	if code != exitcode.Failure || out != "" || errs != "error: the account key changed since the last sync; run 'qbit-vault remote sync', then try again\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if *readState(t, a) != before || recoveryKeyIn(f) != "" {
		t.Fatal("state changed or a recovery key was shown")
	}
}
