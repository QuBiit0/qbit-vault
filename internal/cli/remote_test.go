package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/QuBiit0/gentle-vault/internal/exitcode"
	"github.com/QuBiit0/gentle-vault/internal/prompt"
	"github.com/QuBiit0/gentle-vault/internal/prompt/prompttest"
	"github.com/QuBiit0/gentle-vault/internal/remote"
	"github.com/QuBiit0/gentle-vault/internal/secret"
	"github.com/QuBiit0/gentle-vault/internal/server"
	"github.com/QuBiit0/gentle-vault/internal/vault"
)

// The tests run two devices as two vault homes against one real in-process
// server (loopback http, which the client allows). Prompt answers come from
// scripted fakes; the pairing hook plays the second human who runs
// `remote approve` on the first device while the new one waits.

var (
	rkRE   = regexp.MustCompile(`GVR1(?:-[0-9A-Z]{4}){8}`)
	confRE = regexp.MustCompile(`\b[0-9A-Z]{4}-[0-9A-Z]{4}\b`)
)

type syncServer struct {
	srv  *server.Server
	ts   *httptest.Server
	data string
	// lie, when set, rewrites the signing key of the approver's pairing read.
	lie bool
	// forgeID, when set, rewrites the device id of the approver's pairing read.
	forgeID string
}

func newSyncServer(t *testing.T) *syncServer {
	t.Helper()
	ss := &syncServer{data: t.TempDir()}
	ss.ts = httptest.NewUnstartedServer(nil)
	ss.ts.Start()
	s, err := server.New(server.Config{Data: ss.data, PublicURL: ss.ts.URL})
	if err != nil {
		t.Fatal(err)
	}
	ss.srv = s
	h := s.Handler()
	ss.ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (!ss.lie && ss.forgeID == "") || r.Method != "GET" || !strings.HasPrefix(r.URL.Path, "/v1/pairings/") || r.URL.Query().Get("poll") != "" {
			h.ServeHTTP(w, r)
			return
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		var m map[string]any
		if json.Unmarshal(rec.Body.Bytes(), &m) == nil && m["sign_pub"] != nil && ss.forgeID != "" {
			m["device_id"] = ss.forgeID
		} else if m["sign_pub"] != nil {
			m["sign_pub"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
		}
		w.WriteHeader(rec.Code)
		_ = json.NewEncoder(w).Encode(m)
	})
	t.Cleanup(ss.ts.Close)
	return ss
}

func (ss *syncServer) invite(t *testing.T) string {
	t.Helper()
	inv, err := ss.srv.Invite(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

// every file the server holds, to prove it never sees a fixture.
func (ss *syncServer) held(t *testing.T) string {
	t.Helper()
	var all strings.Builder
	_ = filepath.WalkDir(ss.data, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := os.ReadFile(p)
			all.Write(b)
		}
		return nil
	})
	return all.String()
}

const (
	nameLast4 = "recovery key, last four characters"
	nameRK    = "recovery key"
)

// keepBackend is a Fake that answers the "last four characters" question
// from the recovery key it was just shown, as the person would.
type keepBackend struct{ *prompttest.Fake }

func (b keepBackend) Secret(req prompt.SecretRequest) (secret.Secret, error) {
	if req.Name != nameLast4 {
		return b.Fake.Secret(req)
	}
	b.Fake.Calls = append(b.Fake.Calls, prompttest.Call{Kind: "secret", Request: req})
	rk := recoveryKeyIn(b.Fake)
	return secret.New(req.Name, []byte(strings.ReplaceAll(rk, "-", "")[len(strings.ReplaceAll(rk, "-", ""))-4:])), nil
}

// noShow is a backend that can ask but cannot show text.
type noShow struct{ f *prompttest.Fake }

func (b noShow) Name() string { return "noshow" }
func (b noShow) Secret(r prompt.SecretRequest) (secret.Secret, error) {
	return b.f.Secret(r)
}
func (b noShow) Choose(q string, o []string, d int) (int, error) { return b.f.Choose(q, o, d) }
func (b noShow) Confirm(q string) (bool, error)                  { return b.f.Confirm(q) }
func (b noShow) Passphrase(c bool) (secret.Secret, error)        { return b.f.Passphrase(c) }

func asBackend(t *testing.T, b prompt.Backend) {
	t.Helper()
	old := newPrompt
	newPrompt = func(*globals) (prompt.Backend, error) { return b, nil }
	t.Cleanup(func() { newPrompt = old })
}

func recoveryKeyIn(f *prompttest.Fake) string {
	for i := len(f.Calls) - 1; i >= 0; i-- {
		if f.Calls[i].Kind == "show" {
			if m := rkRE.FindString(f.Calls[i].Text); m != "" {
				return m
			}
		}
	}
	return ""
}

func confirmationIn(f *prompttest.Fake) string {
	for i := len(f.Calls) - 1; i >= 0; i-- {
		if f.Calls[i].Kind == "show" && !rkRE.MatchString(f.Calls[i].Text) {
			return confRE.FindString(f.Calls[i].Text)
		}
	}
	return ""
}

// noBackend makes the next command find no prompt backend at all.
func noBackend(t *testing.T) {
	t.Helper()
	old := newPrompt
	newPrompt = func(*globals) (prompt.Backend, error) { return nil, prompt.ErrNoTerminal }
	t.Cleanup(func() { newPrompt = old })
}

func withPairing(t *testing.T, hook func(code string)) {
	t.Helper()
	oldHook, oldEvery, oldFor := pairingHook, pairPollEvery, pairPollFor
	pairingHook, pairPollEvery, pairPollFor = hook, 5*time.Millisecond, 5*time.Second
	t.Cleanup(func() { pairingHook, pairPollEvery, pairPollFor = oldHook, oldEvery, oldFor })
}

// register runs a successful `remote register` and returns the recovery key.
func (w *world) register(ss *syncServer) string {
	w.t.Helper()
	f := answers(val(ss.invite(w.t)), yes(), no())
	asBackend(w.t, keepBackend{f})
	code, out, errs := w.run("", "remote", "register", "--server", ss.ts.URL)
	if code != exitcode.OK {
		w.t.Fatalf("register: code=%d out=%q err=%q", code, out, errs)
	}
	return recoveryKeyIn(f)
}

// joinPairing joins w to the account of a (a human approves on a). It
// returns the join's stdout and stderr and the fake that played w's person.
func joinPairing(t *testing.T, w, a *world, ss *syncServer, extra ...string) (int, string, string, *prompttest.Fake) {
	t.Helper()
	fb := answers(yes())
	asBackend(t, keepBackend{fb})
	withPairing(t, func(code string) {
		fa := answers(val(code), val("Laptop B"), yes(), no())
		prev := newPrompt
		asBackend(t, keepBackend{fa})
		a.mustRun("", "remote", "approve")
		newPrompt = prev
		fb.Script = append(fb.Script, val(confirmationIn(fa)))
	})
	args := append([]string{"remote", "join", "--server", ss.ts.URL}, extra...)
	code, out, errs := w.run("", args...)
	return code, out, errs, fb
}

func wantCoded(t *testing.T, code int, errs, wantCode string, wantExit int) {
	t.Helper()
	if code != wantExit || !strings.HasPrefix(errs, "error: ") {
		t.Fatalf("%s: code=%d err=%q, want exit %d", wantCode, code, errs, wantExit)
	}
	noFixtures(t, "stderr", errs)
}

func jsonErrCode(t *testing.T, w *world, args ...string) (int, string) {
	t.Helper()
	code, out, _ := w.run("", append([]string{"--json"}, args...)...)
	var e struct {
		Error struct{ Code string }
	}
	_ = json.Unmarshal([]byte(out), &e)
	return code, e.Error.Code
}

func readState(t *testing.T, w *world) *vault.Remote {
	t.Helper()
	r, err := vault.ReadRemote(w.home)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// ---- register ----

func TestRemoteRegisterFlow(t *testing.T) {
	ss := newSyncServer(t)
	w := newWorld(t)
	w.mustRun(fxVal+"_a", "set", "A_KEY", "--global", "--stdin")
	inv := ss.invite(t)
	f := answers(val(inv), yes(), no())
	asBackend(t, keepBackend{f})
	code, out, errs := w.run("", "remote", "register", "--server", ss.ts.URL)
	st := readState(t, w)
	if code != exitcode.OK || errs != "" || st == nil {
		t.Fatalf("code=%d out=%q err=%q state=%+v", code, out, errs, st)
	}
	if want := "registered with " + strings.TrimPrefix(ss.ts.URL, "http://") + " (account " + st.AccountID[:8] + ")\n"; out != want {
		t.Fatalf("out=%q want %q", out, want)
	}
	if st.Generation != 1 || st.LastVersion != 1 || st.PendingPush || st.RecoveryUnconfirmed || st.Server != ss.ts.URL {
		t.Fatalf("state = %+v", st)
	}
	kinds := ""
	for _, c := range f.Calls {
		kinds += c.Kind + " "
	}
	if kinds != "secret confirm show secret " {
		t.Fatalf("prompts = %q", kinds)
	}
	if !strings.Contains(f.Calls[1].Q, "Sync this vault to") || !strings.Contains(f.Calls[1].Q, "the server can never read them") {
		t.Fatalf("confirmation = %q", f.Calls[1].Q)
	}
	if recoveryKeyIn(f) == "" {
		t.Fatal("the recovery key was not shown through the prompt backend")
	}
	rk := recoveryKeyIn(f)
	tape := out + errs + w.auditText()
	for _, name := range []string{"device.enc", "base.enc"} {
		raw, _ := os.ReadFile(filepath.Join(w.home, "remote", name))
		tape += string(raw)
	}
	if strings.Contains(tape, rk) || strings.Contains(tape, strings.ReplaceAll(rk, "-", "")) || strings.Contains(tape, "TESTSECRET_") {
		t.Fatal("the recovery key or a fixture leaked into stdout, stderr, audit or the remote files")
	}
	if !w.auditHas(`"event":"remote"`) || !w.auditHas(`"detail":"registered"`) {
		t.Fatalf("audit: %s", w.auditText())
	}
	for _, f := range []string{"device.enc", "base.enc"} {
		if _, err := os.Stat(filepath.Join(w.home, "remote", f)); err != nil {
			t.Fatalf("remote/%s: %v", f, err)
		}
	}
	// The vault still opens and syncs: the account key is the existing one.
	if w.value("A_KEY") != fxVal+"_a" {
		t.Fatal("registering changed the vault")
	}
	// --json: one object, no key.
	if code, out, _ := w.run("", "--json", "remote", "register", "--server", ss.ts.URL); code != exitcode.Usage || !strings.Contains(out, `"code":"usage"`) {
		t.Fatalf("second register: code=%d out=%q", code, out)
	}
}

func TestRemoteRegisterJSON(t *testing.T) {
	ss := newSyncServer(t)
	w := newWorld(t)
	f := answers(val(ss.invite(t)), yes(), no())
	asBackend(t, keepBackend{f})
	code, out, errs := w.run("", "--json", "remote", "register", "--server", ss.ts.URL)
	var got struct {
		OK         bool
		Registered bool
		Server     string
		Account    string
	}
	if err := json.Unmarshal([]byte(out), &got); code != 0 || err != nil || errs != "" || !got.OK || !got.Registered || len(got.Account) != 8 {
		t.Fatalf("code=%d out=%q err=%q (%v)", code, out, errs, err)
	}
	if strings.Contains(out, recoveryKeyIn(f)) {
		t.Fatal("the recovery key is in --json output")
	}
}

func TestRemoteRegisterRefusals(t *testing.T) {
	ss := newSyncServer(t)

	t.Run("plain http off loopback", func(t *testing.T) {
		w := newWorld(t)
		f := answers()
		asBackend(t, keepBackend{f})
		code, _, errs := w.run("", "remote", "register", "--server", "http://vault.example.com")
		if code != exitcode.Usage || !strings.Contains(errs, "https://") || len(f.Calls) != 0 || readState(t, w) != nil {
			t.Fatalf("code=%d err=%q calls=%d", code, errs, len(f.Calls))
		}
	})
	t.Run("wrong invite", func(t *testing.T) {
		w := newWorld(t)
		asBackend(t, keepBackend{answers(val("TESTSECRET_wrong_invite"), yes())})
		code, out, errs := w.run("", "remote", "register", "--server", ss.ts.URL)
		wantCoded(t, code, errs, "remote_auth", exitcode.Failure)
		noFixtures(t, "stdout", out)
		if readState(t, w) != nil {
			t.Fatal("state written after a refused registration")
		}
	})
	t.Run("invite is single use", func(t *testing.T) {
		w := newWorld(t)
		inv := ss.invite(t)
		asBackend(t, keepBackend{answers(val(inv), yes(), no())})
		w.mustRun("", "remote", "register", "--server", ss.ts.URL)
		w2 := newWorld(t)
		asBackend(t, keepBackend{answers(val(inv), yes())})
		if code, id := jsonErrCode(t, w2, "remote", "register", "--server", ss.ts.URL); code != 1 || id != "remote_auth" {
			t.Fatalf("code=%d id=%q", code, id)
		}
	})
	t.Run("no prompt backend", func(t *testing.T) {
		w := newWorld(t)
		code, out, errs := w.run("", "--json", "remote", "register", "--server", ss.ts.URL)
		if code != exitcode.Refusal || !strings.Contains(out, `"not_model_callable"`) || errs != "" {
			t.Fatalf("code=%d out=%q err=%q", code, out, errs)
		}
	})
	t.Run("backend that cannot show", func(t *testing.T) {
		w := newWorld(t)
		f := answers(val(ss.invite(t)), yes())
		asBackend(t, noShow{f})
		code, out, _ := w.run("", "--json", "remote", "register", "--server", ss.ts.URL)
		if code != exitcode.Refusal || !strings.Contains(out, `"not_model_callable"`) || len(f.Calls) != 0 || readState(t, w) != nil {
			t.Fatalf("code=%d out=%q calls=%d", code, out, len(f.Calls))
		}
	})
	t.Run("backend unavailable at a prompt", func(t *testing.T) {
		w := newWorld(t)
		asBackend(t, keepBackend{&prompttest.Fake{Unavailable: true}})
		code, out, _ := w.run("", "--json", "remote", "register", "--server", ss.ts.URL)
		if code != exitcode.Refusal || !strings.Contains(out, `"not_model_callable"`) {
			t.Fatalf("code=%d out=%q", code, out)
		}
	})
	t.Run("server down", func(t *testing.T) {
		down := httptest.NewServer(http.NotFoundHandler())
		url := down.URL
		down.Close()
		w := newWorld(t)
		f := answers()
		asBackend(t, keepBackend{f})
		if code, id := jsonErrCode(t, w, "remote", "register", "--server", url); code != 1 || id != "remote_unreachable" || len(f.Calls) != 0 {
			t.Fatalf("code=%d id=%q calls=%d", code, id, len(f.Calls))
		}
	})
	t.Run("server of another API", func(t *testing.T) {
		old := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"api":2}`) }))
		defer old.Close()
		w := newWorld(t)
		asBackend(t, keepBackend{answers()})
		if code, id := jsonErrCode(t, w, "remote", "register", "--server", old.URL); code != 1 || id != "server_incompatible" {
			t.Fatalf("code=%d id=%q", code, id)
		}
	})
	t.Run("no vault", func(t *testing.T) {
		w := newBareWorld(t)
		asBackend(t, keepBackend{answers()})
		if code, id := jsonErrCode(t, w, "remote", "register", "--server", ss.ts.URL); code != 1 || id != "not_initialized" {
			t.Fatalf("code=%d id=%q", code, id)
		}
	})
	t.Run("GENTLE_VAULT_NO_REMOTE", func(t *testing.T) {
		w := newWorld(t)
		f := answers()
		asBackend(t, keepBackend{f})
		code, _, errs := w.runEnv(map[string]string{"GENTLE_VAULT_NO_REMOTE": "1"}, "", "remote", "register", "--server", ss.ts.URL)
		wantCoded(t, code, errs, "remote_unreachable", exitcode.Failure)
		if len(f.Calls) != 0 {
			t.Fatal("prompted although remote calls are off")
		}
	})
}

func TestRemoteRegisterCancelAtEachPrompt(t *testing.T) {
	ss := newSyncServer(t)
	for _, tc := range []struct {
		name       string
		script     func() []prompttest.Answer
		registered bool
	}{
		{"invite", func() []prompttest.Answer { return []prompttest.Answer{cancel()} }, false},
		{"confirmation", func() []prompttest.Answer { return []prompttest.Answer{val(ss.invite(t)), cancel()} }, false},
		{"confirmation declined", func() []prompttest.Answer { return []prompttest.Answer{val(ss.invite(t)), no()} }, false},
		{"recovery key shown", func() []prompttest.Answer { return []prompttest.Answer{val(ss.invite(t)), yes(), cancel()} }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			asBackend(t, keepBackend{answers(tc.script()...)})
			code, out, errs := w.run("", "remote", "register", "--server", ss.ts.URL)
			if code != exitcode.Failure || errs != msgCancelled || out != "" {
				t.Fatalf("code=%d out=%q err=%q", code, out, errs)
			}
			st := readState(t, w)
			if (st != nil) != tc.registered {
				t.Fatalf("state = %+v, want registered=%v", st, tc.registered)
			}
			if tc.registered {
				if !st.RecoveryUnconfirmed {
					t.Fatal("an unconfirmed recovery key is not recorded")
				}
				// status keeps warning until the key is confirmed.
				asBackend(t, keepBackend{answers()})
				code, _, errs := w.run("", "remote", "status")
				if code != exitcode.Failure || !strings.Contains(errs, "recovery key not confirmed") {
					t.Fatalf("status: code=%d err=%q", code, errs)
				}
			}
		})
	}
}

func TestRemoteRegisterWrongLastFourShowsKeyAgain(t *testing.T) {
	ss := newSyncServer(t)
	w := newWorld(t)
	f := answers(val(ss.invite(t)), yes(), no(), val("ZZZZ"), no())
	asBackend(t, bothBackend{f})
	code, out, errs := w.run("", "remote", "register", "--server", ss.ts.URL)
	if code != 0 || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	shows := 0
	for _, c := range f.Calls {
		if c.Kind == "show" {
			shows++
		}
	}
	if shows != 2 || readState(t, w).RecoveryUnconfirmed {
		t.Fatalf("shows=%d state=%+v", shows, readState(t, w))
	}
}

// bothBackend plays a person who first mistypes the last four characters
// and then types them right.
type bothBackend struct{ *prompttest.Fake }

func (b bothBackend) Secret(req prompt.SecretRequest) (secret.Secret, error) {
	if req.Name == nameLast4 && !b.wasWrong() {
		return b.Fake.Secret(req) // the scripted wrong answer
	}
	return keepBackend{b.Fake}.Secret(req)
}

func (b bothBackend) wasWrong() bool {
	n := 0
	for _, c := range b.Fake.Calls {
		if c.Kind == "secret" && c.Request.Name == nameLast4 {
			n++
		}
	}
	return n >= 1
}

// ---- join ----

func TestRemoteJoinPairingMergesTwoDevices(t *testing.T) {
	ss := newSyncServer(t)
	a, b := newWorld(t), newWorld(t)
	a.mustRun(fxVal+"_a", "set", "A_KEY", "--global", "--stdin")
	b.mustRun(fxVal+"_b", "set", "B_KEY", "--global", "--stdin")
	b.mustRun(fxVal+"_b2", "set", "B_TWO", "--global", "--stdin")
	rk := a.register(ss)
	bKeyBefore := b.masterKey()

	code, out, errs, fb := joinPairing(t, b, a, ss)
	if code != exitcode.OK {
		t.Fatalf("join: code=%d out=%q err=%q", code, out, errs)
	}
	if !strings.Contains(out, "pairing code: ") || !strings.Contains(out, "gentle-vault remote approve") || !strings.Contains(out, "joined ") {
		t.Fatalf("join output = %q", out)
	}
	if !strings.Contains(fb.Calls[0].Q, "2 local secrets will be added to the synced vault on") {
		t.Fatalf("join confirmation = %q", fb.Calls[0].Q)
	}
	// B now holds the account key and everything.
	if b.masterKey() == bKeyBefore || b.masterKey() != a.masterKey() {
		t.Fatal("B did not adopt the account master key")
	}
	for name, want := range map[string]string{"A_KEY": fxVal + "_a", "B_KEY": fxVal + "_b", "B_TWO": fxVal + "_b2"} {
		if got := b.value(name); got != want {
			t.Fatalf("B %s = %q", name, got)
		}
	}
	if !b.auditHas(`"detail":"joined (pairing)"`) || !a.auditHas(`"detail":"approved `) {
		t.Fatalf("audit B=%s A=%s", b.auditText(), a.auditText())
	}
	// A pulls B's secrets with one round, and the rosters agree.
	if code, out, _ := a.run("", "remote", "sync"); code != 0 || !strings.HasPrefix(out, "synced (version ") {
		t.Fatalf("A sync: code=%d out=%q", code, out)
	}
	if a.value("B_KEY") != fxVal+"_b" {
		t.Fatal("A did not receive B's secret")
	}
	if code, out, _ := a.run("", "remote", "sync"); code != 0 || !strings.HasPrefix(out, "up to date (version ") {
		t.Fatalf("A second sync: code=%d out=%q", code, out)
	}
	_, devs, _ := b.run("", "remote", "devices")
	if strings.Count(devs, "\n") != 2 || !strings.Contains(devs, "Laptop B") || !strings.Contains(devs, "pairing") || !strings.Contains(devs, "register") {
		t.Fatalf("devices on B:\n%s", devs)
	}
	// Nothing sensitive ended up where it must not.
	var seen strings.Builder
	seen.WriteString(out + errs + a.auditText() + b.auditText() + ss.held(t) + devs)
	for _, h := range []*world{a, b} {
		for _, f := range []string{"device.enc", "base.enc"} {
			raw, err := os.ReadFile(filepath.Join(h.home, "remote", f))
			if err != nil {
				t.Fatal(err)
			}
			seen.Write(raw)
		}
	}
	noFixtures(t, "stdout/stderr/audit/remote files/server data", seen.String())
	if strings.Contains(seen.String(), rk) || strings.Contains(seen.String(), strings.ReplaceAll(rk, "-", "")) {
		t.Fatal("the recovery key leaked")
	}
}

func TestRemoteJoinPairingKeepsConfirmationCodeOffTheTape(t *testing.T) {
	ss := newSyncServer(t)
	a, b := newWorld(t), newWorld(t)
	a.register(ss)
	var fa *prompttest.Fake
	var approveTape string
	fb := answers(yes())
	asBackend(t, keepBackend{fb})
	withPairing(t, func(code string) {
		fa = answers(val(code), val("Laptop B"), yes(), no())
		prev := newPrompt
		asBackend(t, keepBackend{fa})
		_, ao, ae := a.run("", "--json", "remote", "approve")
		approveTape = ao + ae
		newPrompt = prev
		fb.Script = append(fb.Script, val(confirmationIn(fa)))
	})
	code, out, errs := b.run("", "--json", "remote", "join", "--server", ss.ts.URL)
	conf := confirmationIn(fa)
	if code != 0 || conf == "" {
		t.Fatalf("code=%d out=%q err=%q conf=%q", code, out, errs, conf)
	}
	var o struct {
		OK     bool
		Joined bool
	}
	if err := json.Unmarshal([]byte(out), &o); err != nil || !o.OK || !o.Joined {
		t.Fatalf("--json stdout is not exactly one object: %q (%v)", out, err)
	}
	if strings.Contains(out+errs+approveTape+b.auditText()+a.auditText(), conf) {
		t.Fatal("the confirmation code is on the tape")
	}
}

func TestRemoteJoinRecovery(t *testing.T) {
	ss := newSyncServer(t)
	a, b := newWorld(t), newWorld(t)
	a.mustRun(fxVal+"_a", "set", "A_KEY", "--global", "--stdin")
	rk := a.register(ss)

	t.Run("recovers the vault", func(t *testing.T) {
		f := answers(yes(), val(strings.ToLower(rk)))
		asBackend(t, keepBackend{f})
		code, out, errs := b.run("", "remote", "join", "--server", ss.ts.URL, "--recovery")
		if code != 0 || errs != "" || !strings.HasPrefix(out, "joined ") {
			t.Fatalf("code=%d out=%q err=%q", code, out, errs)
		}
		if b.value("A_KEY") != fxVal+"_a" || b.masterKey() != a.masterKey() {
			t.Fatal("B did not recover the account")
		}
		if !b.auditHas(`"detail":"joined (recovery)"`) {
			t.Fatalf("audit: %s", b.auditText())
		}
		_, devs, _ := b.run("", "remote", "devices")
		if !strings.Contains(devs, "recovery") || !strings.Contains(devs, "register") {
			t.Fatalf("devices:\n%s", devs)
		}
		if strings.Contains(out+b.auditText()+devs, rk) {
			t.Fatal("recovery key leaked")
		}
		// A sees the recovered device in the roster and in its status.
		a.mustRun("", "remote", "sync")
		_, devs, _ = a.run("", "remote", "devices")
		if !strings.Contains(devs, "recovery") {
			t.Fatalf("A does not see the recovery device:\n%s", devs)
		}
	})
	t.Run("unknown recovery key", func(t *testing.T) {
		c := newWorld(t)
		_, text, _ := remote.NewRecoveryKey()
		asBackend(t, keepBackend{answers(yes(), val(text))})
		code, out, errs := c.run("", "remote", "join", "--server", ss.ts.URL, "--recovery")
		wantCoded(t, code, errs, "remote_auth", exitcode.Failure)
		noFixtures(t, "stdout", out)
		if strings.Contains(errs, text) || readState(t, c) != nil {
			t.Fatalf("unknown key: err=%q state=%+v", errs, readState(t, c))
		}
	})
	t.Run("not a recovery key", func(t *testing.T) {
		c := newWorld(t)
		asBackend(t, keepBackend{answers(yes(), val("TESTSECRET_not_a_key"))})
		code, _, errs := c.run("", "remote", "join", "--server", ss.ts.URL, "--recovery")
		wantCoded(t, code, errs, "remote_auth", exitcode.Failure)
		if strings.Contains(errs, "TESTSECRET_") {
			t.Fatal("the typed text was echoed")
		}
	})
}

func TestRemoteJoinCancelAndRefusals(t *testing.T) {
	ss := newSyncServer(t)
	a := newWorld(t)
	rk := a.register(ss)

	for _, tc := range []struct {
		name   string
		args   []string
		script []prompttest.Answer
	}{
		{"confirmation cancelled", []string{"--recovery"}, []prompttest.Answer{cancel()}},
		{"confirmation declined", []string{"--recovery"}, []prompttest.Answer{no()}},
		{"recovery key cancelled", []string{"--recovery"}, []prompttest.Answer{yes(), cancel()}},
		{"pairing confirmation cancelled", nil, []prompttest.Answer{cancel()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newWorld(t)
			before := c.masterKey()
			asBackend(t, keepBackend{answers(tc.script...)})
			code, out, errs := c.run("", append([]string{"remote", "join", "--server", ss.ts.URL}, tc.args...)...)
			if code != exitcode.Failure || errs != msgCancelled || strings.Contains(out, "joined") {
				t.Fatalf("code=%d out=%q err=%q", code, out, errs)
			}
			if readState(t, c) != nil || c.masterKey() != before {
				t.Fatal("a cancelled join changed the vault")
			}
		})
	}
	t.Run("cancel at the confirmation code", func(t *testing.T) {
		c := newWorld(t)
		before := c.masterKey()
		fb := answers(yes())
		asBackend(t, keepBackend{fb})
		withPairing(t, func(code string) {
			fa := answers(val(code), val("Laptop C"), yes(), no())
			prev := newPrompt
			asBackend(t, keepBackend{fa})
			a.mustRun("", "remote", "approve")
			newPrompt = prev
			fb.Script = append(fb.Script, cancel())
		})
		code, _, errs := c.run("", "remote", "join", "--server", ss.ts.URL)
		if code != exitcode.Failure || errs != msgCancelled || readState(t, c) != nil || c.masterKey() != before {
			t.Fatalf("code=%d err=%q", code, errs)
		}
	})
	t.Run("no prompt backend", func(t *testing.T) {
		noBackend(t)
		c := newWorld(t)
		code, out, _ := c.run("", "--json", "remote", "join", "--server", ss.ts.URL)
		if code != exitcode.Refusal || !strings.Contains(out, `"not_model_callable"`) {
			t.Fatalf("code=%d out=%q", code, out)
		}
	})
	t.Run("plain http", func(t *testing.T) {
		c := newWorld(t)
		asBackend(t, keepBackend{answers()})
		code, _, errs := c.run("", "remote", "join", "--server", "http://vault.example.com")
		if code != exitcode.Usage || !strings.Contains(errs, "https://") {
			t.Fatalf("code=%d err=%q", code, errs)
		}
	})
	t.Run("already syncing", func(t *testing.T) {
		asBackend(t, keepBackend{answers()})
		if code, _, errs := a.run("", "remote", "join", "--server", ss.ts.URL); code != exitcode.Usage || !strings.Contains(errs, "already syncs") {
			t.Fatalf("code=%d err=%q", code, errs)
		}
	})
	t.Run("server down", func(t *testing.T) {
		down := httptest.NewServer(http.NotFoundHandler())
		url := down.URL
		down.Close()
		c := newWorld(t)
		asBackend(t, keepBackend{answers(yes())})
		if code, id := jsonErrCode(t, c, "remote", "join", "--server", url); code != 1 || id != "remote_unreachable" {
			t.Fatalf("code=%d id=%q", code, id)
		}
	})
	t.Run("pairing expires", func(t *testing.T) {
		c := newWorld(t)
		asBackend(t, keepBackend{answers(yes())})
		withPairing(t, nil)
		pairPollFor = 50 * time.Millisecond
		code, _, errs := c.run("", "remote", "join", "--server", ss.ts.URL)
		wantCoded(t, code, errs, "pairing_failed", exitcode.Failure)
		if readState(t, c) != nil {
			t.Fatal("state written for a pairing that expired")
		}
	})
	_ = rk
}

func TestRemoteJoinWrongConfirmationCodeWipesAndDeletesDevice(t *testing.T) {
	ss := newSyncServer(t)
	a, b := newWorld(t), newWorld(t)
	a.register(ss)
	before := b.masterKey()
	fb := answers(yes())
	asBackend(t, keepBackend{fb})
	withPairing(t, func(code string) {
		fa := answers(val(code), val("Laptop B"), yes(), no())
		prev := newPrompt
		asBackend(t, keepBackend{fa})
		a.mustRun("", "remote", "approve")
		newPrompt = prev
		fb.Script = append(fb.Script, val("AAAA-AAAA"))
	})
	code, out, errs := b.run("", "--json", "remote", "join", "--server", ss.ts.URL)
	if code != exitcode.Failure || !strings.Contains(out, `"pairing_failed"`) || strings.Contains(errs, "error:") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if readState(t, b) != nil || b.masterKey() != before {
		t.Fatal("the received key was kept")
	}
	if _, err := os.Stat(filepath.Join(b.home, "remote")); err == nil {
		t.Fatal("remote files were written")
	}
	// The server no longer lists the device that was approved.
	dk, err := a.deviceSecret()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := vault.ReadDeviceID(a.home)
	c, _ := remote.NewClient(ss.ts.URL, "")
	if err := c.Login(context.Background(), id, remote.DeviceFromSecret(dk)); err != nil {
		t.Fatal(err)
	}
	devs, err := c.Devices(context.Background())
	if err != nil || len(devs) != 1 || devs[0].ID != id {
		t.Fatalf("server devices = %+v, %v", devs, err)
	}
}

// deviceSecret reads the device secret of the world's vault (assertions only).
func (w *world) deviceSecret() (secret.Secret, error) {
	g := &globals{getenv: envFrom(nil), home: w.home}
	s, err := g.openSession()
	if err != nil {
		return secret.Secret{}, err
	}
	defer s.close()
	return s.v.DeviceSecret()
}

// ---- approve ----

func TestRemoteApprove(t *testing.T) {
	ss := newSyncServer(t)
	a := newWorld(t)
	a.register(ss)
	nk := make([]byte, 32)
	if _, err := rand.Read(nk); err != nil {
		t.Fatal(err)
	}
	nd := remote.DeviceFromSecret(secret.New("dk", nk))
	nc, _ := remote.NewClient(ss.ts.URL, "")
	pending, err := nc.CreatePairing(context.Background(), strings.Repeat("c", 32), nd)
	if err != nil {
		t.Fatal(err)
	}
	code := pending.Code
	newPending := func(*testing.T) string { return code }

	t.Run("fingerprint mismatch", func(t *testing.T) {
		code := newPending(t)
		ss.lie = true
		defer func() { ss.lie = false }()
		f := answers(val(code), val("Laptop X"))
		asBackend(t, keepBackend{f})
		c, out, errs := a.run("", "remote", "approve")
		wantCoded(t, c, errs, "pairing_failed", exitcode.Failure)
		noFixtures(t, "stdout", out)
		for _, call := range f.Calls {
			if call.Kind == "confirm" || call.Kind == "show" {
				t.Fatalf("asked %s after a bad fingerprint", call.Kind)
			}
		}
	})
	// The fingerprint covers the keys, not the device id: a pairing that
	// names a device already in the roster must not overwrite its entry.
	t.Run("device id already in the roster", func(t *testing.T) {
		own, err := vault.ReadDeviceID(a.home)
		if err != nil {
			t.Fatal(err)
		}
		ss.forgeID = own
		defer func() { ss.forgeID = "" }()
		before := readState(t, a)
		f := answers(val(newPending(t)), val("Laptop X"))
		asBackend(t, keepBackend{f})
		c, _, errs := a.run("", "remote", "approve")
		wantCoded(t, c, errs, "pairing_failed", exitcode.Failure)
		for _, call := range f.Calls {
			if call.Kind == "confirm" || call.Kind == "show" {
				t.Fatalf("asked %s for a device id already in the roster", call.Kind)
			}
		}
		if after := readState(t, a); *after != *before {
			t.Fatalf("state changed: %+v -> %+v", before, after)
		}
	})
	t.Run("unknown code", func(t *testing.T) {
		asBackend(t, keepBackend{answers(val("AAAA-AAAA-AAAA-AAAA"), val("Laptop X"))})
		c, _, errs := a.run("", "remote", "approve")
		wantCoded(t, c, errs, "pairing_failed", exitcode.Failure)
	})
	t.Run("declined", func(t *testing.T) {
		code := newPending(t)
		asBackend(t, keepBackend{answers(val(code), val("Laptop X"), no())})
		c, _, errs := a.run("", "remote", "approve")
		if c != exitcode.Failure || errs != msgCancelled {
			t.Fatalf("code=%d err=%q", c, errs)
		}
	})
	for i, script := range [][]prompttest.Answer{{cancel()}, {val("placeholder"), cancel()}, {val("placeholder"), val("Laptop X"), cancel()}} {
		t.Run([]string{"cancel at the code", "cancel at the label", "cancel at the confirmation"}[i], func(t *testing.T) {
			code := newPending(t)
			if len(script) > 1 {
				script[0] = val(code)
			}
			asBackend(t, keepBackend{answers(script...)})
			c, _, errs := a.run("", "remote", "approve")
			if c != exitcode.Failure || errs != msgCancelled {
				t.Fatalf("code=%d err=%q", c, errs)
			}
		})
	}
	t.Run("cancel when the code is shown", func(t *testing.T) {
		code := newPending(t)
		asBackend(t, keepBackend{answers(val(code), val("Laptop X"), yes(), cancel())})
		c, _, errs := a.run("", "remote", "approve")
		if c != exitcode.Failure || errs != msgCancelled || !a.auditHas(`"detail":"approved `) {
			t.Fatalf("code=%d err=%q", c, errs)
		}
	})
	t.Run("no prompt backend", func(t *testing.T) {
		noBackend(t)
		c, out, _ := a.run("", "--json", "remote", "approve")
		if c != exitcode.Refusal || !strings.Contains(out, `"not_model_callable"`) {
			t.Fatalf("code=%d out=%q", c, out)
		}
	})
	t.Run("backend that cannot show", func(t *testing.T) {
		f := answers()
		asBackend(t, noShow{f})
		c, out, _ := a.run("", "--json", "remote", "approve")
		if c != exitcode.Refusal || !strings.Contains(out, `"not_model_callable"`) || len(f.Calls) != 0 {
			t.Fatalf("code=%d out=%q", c, out)
		}
	})
	t.Run("vault that does not sync", func(t *testing.T) {
		w := newWorld(t)
		asBackend(t, keepBackend{answers()})
		if c, id := jsonErrCode(t, w, "remote", "approve"); c != 1 || id != "remote_not_configured" {
			t.Fatalf("code=%d id=%q", c, id)
		}
	})
}

// ---- sync ----

func TestRemoteSyncRound(t *testing.T) {
	ss := newSyncServer(t)
	a, b := newWorld(t), newWorld(t)
	a.register(ss)
	if code, _, _, _ := joinPairing(t, b, a, ss); code != 0 {
		t.Fatal("join failed")
	}
	asBackend(t, keepBackend{answers()}) // sync never prompts
	a.mustRun(fxVal+"_x", "set", "X_KEY", "--global", "--stdin")
	if code, out, errs := a.run("", "remote", "sync"); code != 0 || errs != "" || !strings.HasPrefix(out, "synced (version ") {
		t.Fatalf("push: code=%d out=%q err=%q", code, out, errs)
	}
	code, out, errs := b.run("", "--json", "remote", "sync")
	var o struct {
		OK      bool
		Result  string
		Version int
	}
	if err := json.Unmarshal([]byte(out), &o); code != 0 || err != nil || errs != "" || !o.OK || o.Result != "synced" || o.Version < 3 {
		t.Fatalf("pull: code=%d out=%q err=%q (%v)", code, out, errs, err)
	}
	if b.value("X_KEY") != fxVal+"_x" {
		t.Fatal("B did not get X_KEY")
	}
	if code, out, _ := b.run("", "remote", "sync"); code != 0 || !strings.HasPrefix(out, "up to date (version ") {
		t.Fatalf("no change: code=%d out=%q", code, out)
	}
	// Both change the same secret: the newer wins, the other is kept.
	a.mustRun(fxVal+"_1", "set", "X_KEY", "--global", "--stdin")
	time.Sleep(5 * time.Millisecond)
	b.mustRun(fxVal+"_2", "set", "X_KEY", "--global", "--stdin")
	a.mustRun("", "remote", "sync")
	b.mustRun("", "remote", "sync")
	a.mustRun("", "remote", "sync")
	if a.value("X_KEY") != fxVal+"_2" || b.value("X_KEY") != fxVal+"_2" {
		t.Fatalf("devices did not converge: %q %q", a.value("X_KEY"), b.value("X_KEY"))
	}
	_, st, _ := a.run("", "remote", "status")
	if !strings.Contains(st, "conflicts:") || strings.Contains(st, "conflicts:     0") {
		t.Fatalf("status shows no conflict:\n%s", st)
	}
	noFixtures(t, "status", st)
	noFixtures(t, "server data", ss.held(t))
}

func TestRemoteSyncOutcomes(t *testing.T) {
	ss := newSyncServer(t)
	w := newWorld(t)
	w.register(ss)
	asBackend(t, keepBackend{answers()})

	t.Run("offline switch marks pending", func(t *testing.T) {
		w.mustRun(fxVal, "set", "N_KEY", "--global", "--stdin")
		code, out, _ := w.runEnv(map[string]string{"GENTLE_VAULT_NO_REMOTE": "1"}, "", "remote", "sync")
		if code != 0 || !strings.HasPrefix(out, "pending: ") || !readState(t, w).PendingPush {
			t.Fatalf("code=%d out=%q state=%+v", code, out, readState(t, w))
		}
		if code, out, _ := w.run("", "remote", "sync"); code != 0 || !strings.HasPrefix(out, "synced (version ") || readState(t, w).PendingPush {
			t.Fatalf("retry: code=%d out=%q state=%+v", code, out, readState(t, w))
		}
	})
	t.Run("older version than seen is a rollback", func(t *testing.T) {
		st := readState(t, w)
		real := *st
		st.LastVersion += 5
		if err := vault.WriteRemote(w.home, st); err != nil {
			t.Fatal(err)
		}
		code, out, errs := w.run("", "remote", "sync")
		wantCoded(t, code, errs, "remote_rollback", exitcode.Corrupt)
		noFixtures(t, "stdout", out)
		if err := vault.WriteRemote(w.home, &real); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("server down", func(t *testing.T) {
		w.mustRun(fxVal+"_d", "set", "D_KEY", "--global", "--stdin")
		ss.ts.Close()
		code, id := jsonErrCode(t, w, "remote", "sync")
		if code != 1 || id != "remote_unreachable" || !readState(t, w).PendingPush {
			t.Fatalf("code=%d id=%q state=%+v", code, id, readState(t, w))
		}
		if w.value("D_KEY") != fxVal+"_d" {
			t.Fatal("the local change was lost")
		}
	})
	t.Run("vault that does not sync", func(t *testing.T) {
		n := newWorld(t)
		for _, cmd := range []string{"sync", "status", "devices", "logout"} {
			if code, id := jsonErrCode(t, n, "remote", cmd); code != 1 || id != "remote_not_configured" {
				t.Errorf("%s: code=%d id=%q", cmd, code, id)
			}
		}
	})
}

// ---- status, devices, logout ----

func TestRemoteStatusAndDevicesAreReadOnly(t *testing.T) {
	ss := newSyncServer(t)
	a, b := newWorld(t), newWorld(t)
	a.register(ss)
	joinPairing(t, b, a, ss)
	f := answers()
	asBackend(t, keepBackend{f})
	before := a.auditText()

	code, out, errs := a.run("", "remote", "status")
	st := readState(t, a)
	if code != 0 || errs != "" {
		t.Fatalf("status: code=%d out=%q err=%q", code, out, errs)
	}
	for _, want := range []string{"server:", ss.ts.URL, "account:", st.AccountID[:8], "generation:", "version:", "last sync:", "pending push:", "conflicts:", "devices:", "anchor:"} {
		if !strings.Contains(out, want) {
			t.Errorf("status lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, st.AccountID) {
		t.Error("status shows the full account id")
	}
	code, out, errs = a.run("", "--json", "remote", "status")
	var o struct {
		OK          bool
		Server      string
		Account     string
		Generation  int
		Version     int
		PendingPush bool `json:"pending_push"`
		Devices     int
		Conflicts   int
	}
	if err := json.Unmarshal([]byte(out), &o); code != 0 || err != nil || !o.OK || o.Generation != 1 || o.Devices != 2 || o.Account != st.AccountID[:8] {
		t.Fatalf("status json: code=%d out=%q (%v)", code, out, err)
	}
	code, out, errs = a.run("", "--json", "remote", "devices")
	var d struct {
		OK      bool
		Devices []struct {
			ID      string
			Label   string
			AddedBy string `json:"added_by"`
			Revoked bool
			This    bool
		}
	}
	if err := json.Unmarshal([]byte(out), &d); code != 0 || err != nil || errs != "" || len(d.Devices) != 2 {
		t.Fatalf("devices json: code=%d out=%q err=%q (%v)", code, out, errs, err)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("status/devices prompted: %+v", f.Calls)
	}
	if a.auditText() != before {
		t.Fatal("status/devices wrote to the audit log")
	}
	// Read-only on the server too: nothing changed there.
	if st2 := readState(t, a); *st2 != *st {
		t.Fatalf("status changed the state: %+v -> %+v", st, st2)
	}
}

func TestRemoteStatusWarnsAndExits1(t *testing.T) {
	ss := newSyncServer(t)
	w := newWorld(t)
	w.register(ss)
	asBackend(t, keepBackend{answers()})
	st := readState(t, w)
	st.PendingPush = true
	if err := vault.WriteRemote(w.home, st); err != nil {
		t.Fatal(err)
	}
	code, out, errs := w.run("", "remote", "status")
	if code != exitcode.Failure || !strings.Contains(errs, "warning: not synced") || !strings.Contains(out, "pending push:  yes") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	code, out, errs = w.run("", "--json", "remote", "status")
	if code != exitcode.Failure || errs != "" || !strings.Contains(out, `"warnings":["pending push"`) {
		t.Fatalf("json: code=%d out=%q err=%q", code, out, errs)
	}
}

func TestRemoteLogout(t *testing.T) {
	ss := newSyncServer(t)
	a, b := newWorld(t), newWorld(t)
	a.register(ss)
	joinPairing(t, b, a, ss)
	keyBefore := b.masterKey()

	t.Run("cancel and decline change nothing", func(t *testing.T) {
		for _, ans := range []prompttest.Answer{cancel(), no()} {
			asBackend(t, keepBackend{answers(ans)})
			if code, _, errs := b.run("", "remote", "logout"); code != exitcode.Failure || errs != msgCancelled || readState(t, b) == nil {
				t.Fatalf("code=%d err=%q", code, errs)
			}
		}
	})
	t.Run("no prompt backend", func(t *testing.T) {
		noBackend(t)
		if code, out, _ := b.run("", "--json", "remote", "logout"); code != exitcode.Refusal || !strings.Contains(out, `"not_model_callable"`) {
			t.Fatalf("code=%d out=%q", code, out)
		}
	})
	t.Run("logs out", func(t *testing.T) {
		b.mustRun(fxVal+"_l", "set", "L_KEY", "--global", "--stdin")
		asBackend(t, keepBackend{answers(yes())})
		code, out, errs := b.run("", "remote", "logout")
		if code != 0 || errs != "" || !strings.Contains(out, "logged out") {
			t.Fatalf("code=%d out=%q err=%q", code, out, errs)
		}
		if readState(t, b) != nil {
			t.Fatal("state.json.remote kept")
		}
		if _, err := os.Stat(filepath.Join(b.home, "remote")); err == nil {
			t.Fatal("remote/ kept")
		}
		if b.value("L_KEY") != fxVal+"_l" || b.masterKey() != keyBefore {
			t.Fatal("the local vault or key changed")
		}
		if !b.auditHas(`"detail":"logged out"`) {
			t.Fatalf("audit: %s", b.auditText())
		}
		// The server forgot the device: A still syncs, B cannot any more.
		dk, _ := a.deviceSecret()
		id, _ := vault.ReadDeviceID(a.home)
		c, _ := remote.NewClient(ss.ts.URL, "")
		if err := c.Login(context.Background(), id, remote.DeviceFromSecret(dk)); err != nil {
			t.Fatal(err)
		}
		if devs, _ := c.Devices(context.Background()); len(devs) != 1 {
			t.Fatalf("server devices after logout: %+v", devs)
		}
	})
	t.Run("server down still logs out", func(t *testing.T) {
		c := newWorld(t)
		c.register(ss)
		ss.ts.Close()
		asBackend(t, keepBackend{answers(yes())})
		if code, _, errs := c.run("", "remote", "logout"); code != 0 || errs != "" || readState(t, c) != nil {
			t.Fatalf("code=%d err=%q", code, errs)
		}
	})
}
