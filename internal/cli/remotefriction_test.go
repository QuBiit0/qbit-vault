package cli

import (
	"context"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/exitcode"
	"github.com/qbitdevz/qbit-vault/internal/prompt"
	"github.com/qbitdevz/qbit-vault/internal/prompt/prompttest"
	"github.com/qbitdevz/qbit-vault/internal/remote"
	"github.com/qbitdevz/qbit-vault/internal/secret"
	"github.com/qbitdevz/qbit-vault/internal/vault"
)

// Sync friction (odd/tasks/launch-polish.md S10.1-S10.3).

// msgKeyNotConfirmed is what a cancel at the recovery key check prints.
const msgKeyNotConfirmed = "error: cancelled; the recovery key was not confirmed; run 'qbit-vault remote recovery-key --rotate' to get a new recovery key\n"

// S10.1: a login refused because the URL differs from the server's configured
// origin says so, with both URLs, instead of a generic refusal.
func TestRemoteSyncNamesTheConfiguredOriginWhenTheURLDiffers(t *testing.T) {
	ss := newSyncServer(t)
	a := newWorld(t)
	a.register(ss)
	used := strings.Replace(ss.ts.URL, "127.0.0.1", "localhost", 1)
	a.editState(func(st *vault.Remote) { st.Server = used })
	asBackend(t, keepBackend{answers()})
	code, out, errs := a.run("", "remote", "sync")
	want := "error: the server is configured as " + ss.ts.URL + "; you used " + used +
		". Use the same URL (qbit-vault remote logout, then register or join with it).\n"
	if code != exitcode.Failure || errs != want || out != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	noFixtures(t, "stderr", errs)
	// --json keeps the typed code.
	if code, ecode := jsonErrCode(t, a, "remote", "sync"); code != exitcode.Failure || ecode != "remote_auth" {
		t.Fatalf("json: code=%d error code=%q", code, ecode)
	}
}

// S10.1: the URL may be written with another case, a default port or a
// trailing slash; both sides sign the same normalized origin.
func TestRemoteSyncWorksWithAnotherSpellingOfTheSameURL(t *testing.T) {
	ss := newSyncServer(t)
	a := newWorld(t)
	a.register(ss)
	a.editState(func(st *vault.Remote) { st.Server = strings.ToUpper(ss.ts.URL[:4]) + ss.ts.URL[4:] + "/" })
	asBackend(t, keepBackend{answers()})
	if code, out, errs := a.run("", "remote", "sync"); code != exitcode.OK {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
}

// pending announces a new device on the server and returns its pairing code
// and device id.
func pending(t *testing.T, ss *syncServer, idChar string) (string, string) {
	t.Helper()
	nk := make([]byte, 32)
	if _, err := rand.Read(nk); err != nil {
		t.Fatal(err)
	}
	nc, _ := remote.NewClient(ss.ts.URL, "")
	id := strings.Repeat(idChar, 32)
	p, err := nc.CreatePairing(context.Background(), id, remote.DeviceFromSecret(secret.New("dk", nk)))
	if err != nil {
		t.Fatal(err)
	}
	return p.Code, id
}

// S10.2: the device-name question takes Enter for "device <n>" and is the
// consent itself: approving asks the pairing code and the name, nothing else.
func TestApproveDefaultsTheNameAndAsksTwoThings(t *testing.T) {
	ss := newSyncServer(t)
	a := newWorld(t)
	a.register(ss)
	code, id := pending(t, ss, "a")
	f := answers(val(code), val("  "), no())
	asBackend(t, keepBackend{f})
	c, out, errs := a.run("", "remote", "approve")
	if c != exitcode.OK || errs != "" || out != "approved device 2 ("+id+")\n" {
		t.Fatalf("code=%d out=%q err=%q", c, out, errs)
	}
	var kinds []string
	for _, call := range f.Calls {
		kinds = append(kinds, call.Kind)
	}
	if strings.Join(kinds, " ") != "secret secret show" {
		t.Fatalf("prompts = %v, want the code, the name and the confirmation code shown", kinds)
	}
	name := f.Calls[1].Request
	if name.Name != nameLabel || !name.Visible || !strings.Contains(name.Reason, "read every secret") || !strings.Contains(name.Reason, `"device 2"`) {
		t.Fatalf("name request = %+v", name)
	}
	if confirmationIn(f) == "" {
		t.Fatal("the confirmation code was not shown")
	}
	// The next device defaults to the next number.
	code2, id2 := pending(t, ss, "b")
	asBackend(t, keepBackend{answers(val(code2), val(""), no())})
	if c, out, _ := a.run("", "remote", "approve"); c != exitcode.OK || out != "approved device 3 ("+id2+")\n" {
		t.Fatalf("second approval: code=%d out=%q", c, out)
	}
	// A typed name wins.
	code3, id3 := pending(t, ss, "c")
	asBackend(t, keepBackend{answers(val(code3), val("Desk"), no())})
	if c, out, _ := a.run("", "remote", "approve"); c != exitcode.OK || out != "approved Desk ("+id3+")\n" {
		t.Fatalf("named approval: code=%d out=%q", c, out)
	}
}

// S10.2: cancelling the name dialog refuses: nothing is approved or recorded.
func TestApproveCancelAtTheNameRefuses(t *testing.T) {
	ss := newSyncServer(t)
	a := newWorld(t)
	a.register(ss)
	code, _ := pending(t, ss, "d")
	before := readState(t, a)
	f := answers(val(code), cancel())
	asBackend(t, keepBackend{f})
	c, out, errs := a.run("", "remote", "approve")
	if c != exitcode.Failure || errs != msgCancelled || out != "" {
		t.Fatalf("code=%d out=%q err=%q", c, out, errs)
	}
	for _, call := range f.Calls {
		if call.Kind == "confirm" || call.Kind == "show" {
			t.Fatalf("asked %s after a refusal", call.Kind)
		}
	}
	if after := readState(t, a); *after != *before {
		t.Fatalf("state changed: %+v -> %+v", before, after)
	}
	// The pairing is still pending on the server: it can be approved later.
	asBackend(t, keepBackend{answers(val(code), val(""), no())})
	if c, _, errs := a.run("", "remote", "approve"); c != exitcode.OK {
		t.Fatalf("approve after the refusal: code=%d err=%q", c, errs)
	}
}

// manyWrong plays a person who mistypes the last four characters n times
// and then types them right.
type manyWrong struct {
	*prompttest.Fake
	n, asked int
}

func (b *manyWrong) Secret(req prompt.SecretRequest) (secret.Secret, error) {
	if req.Name == nameLast4 && b.asked < b.n {
		b.asked++
		return b.Fake.Secret(req) // the scripted wrong answer
	}
	return keepBackend{b.Fake}.Secret(req)
}

// S10.3: the last-four check has no dead end: a wrong answer shows the key
// again, however many times, until it is right.
func TestRegisterRecoveryCheckHasNoDeadEnd(t *testing.T) {
	ss := newSyncServer(t)
	w := newWorld(t)
	const wrong = 8
	script := []prompttest.Answer{val(ss.invite(t)), yes(), no()}
	for range wrong {
		script = append(script, val("ZZZZ"), no())
	}
	f := answers(script...)
	asBackend(t, &manyWrong{Fake: f, n: wrong})
	code, out, errs := w.run("", "remote", "register", "--server", ss.ts.URL)
	if code != exitcode.OK || errs != "" || !strings.HasPrefix(out, "registered with ") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	shows := 0
	for _, c := range f.Calls {
		if c.Kind == "show" {
			shows++
		}
	}
	if shows != wrong+1 || readState(t, w).RecoveryUnconfirmed {
		t.Fatalf("shows=%d state=%+v", shows, readState(t, w))
	}
}

// S10.3: cancelling the check keeps the account registered, status keeps
// warning, and the message says how to get a new recovery key.
func TestRegisterCancelAtTheRecoveryCheckSaysHowToRotate(t *testing.T) {
	ss := newSyncServer(t)
	w := newWorld(t)
	script := []prompttest.Answer{val(ss.invite(t)), yes(), no()}
	for range 5 {
		script = append(script, val("ZZZZ"), no())
	}
	script = append(script, val("ZZZZ"), cancel()) // the sixth wrong answer, then Cancel on the next screen
	asBackend(t, &manyWrong{Fake: answers(script...), n: 6})
	code, out, errs := w.run("", "remote", "register", "--server", ss.ts.URL)
	if code != exitcode.Failure || errs != msgKeyNotConfirmed || out != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if st := readState(t, w); st == nil || !st.RecoveryUnconfirmed {
		t.Fatalf("state = %+v", st)
	}
	asBackend(t, keepBackend{answers()})
	if code, _, errs := w.run("", "remote", "status"); code != exitcode.Failure || !strings.Contains(errs, "recovery key not confirmed") {
		t.Fatalf("status: code=%d err=%q", code, errs)
	}
}

// S12.5: the dialog that shows the confirmation code says so; "Pairing code"
// is the code the new device prints and the approver types.
func TestApproveShowsTheConfirmationCodeUnderItsOwnHeading(t *testing.T) {
	ss := newSyncServer(t)
	a := newWorld(t)
	a.register(ss)
	code, _ := pending(t, ss, "a")
	f := answers(val(code), val("Desk"), no())
	asBackend(t, keepBackend{f})
	if c, _, errs := a.run("", "remote", "approve"); c != exitcode.OK || errs != "" {
		t.Fatalf("code=%d err=%q", c, errs)
	}
	var titles []string
	for _, call := range f.Calls {
		if call.Kind == "show" {
			titles = append(titles, call.Q)
		}
	}
	if len(titles) != 1 || titles[0] != "Confirmation code" {
		t.Fatalf("show titles = %q, want [Confirmation code]", titles)
	}
}
