package cli

import (
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/exitcode"
	"github.com/qbitdevz/qbit-vault/internal/keychain"
	"github.com/qbitdevz/qbit-vault/internal/prompt"
	"github.com/qbitdevz/qbit-vault/internal/prompt/prompttest"
)

func osMode() string { return keychain.NewOS().Name() }

func TestLockUnlockKeychainMode(t *testing.T) {
	w := newWorld(t)
	f := withBackend(t, answers())
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"lock"}, "nothing to lock: the master key is in the OS keychain (" + osMode() + ")\n"},
		{[]string{"--json", "lock"}, `{"ok":true,"locked":false,"keychain":"` + osMode() + `"}` + "\n"},
		{[]string{"unlock"}, "unlocked: the master key is in the OS keychain (" + osMode() + ")\n"},
		{[]string{"--json", "unlock"}, `{"ok":true,"unlocked":true,"keychain":"` + osMode() + `","cached":false,"expires_at":null}` + "\n"},
	}
	for _, c := range cases {
		code, out, errs := w.run("", c.args...)
		if code != exitcode.OK || out != c.want || errs != "" {
			t.Errorf("%v: code=%d out=%q err=%q", c.args, code, out, errs)
		}
	}
	if len(f.Calls) != 0 {
		t.Fatalf("keychain mode asked %+v", f.Calls)
	}
}

func passphraseWorld(t *testing.T) *world {
	t.Helper()
	w := newBareWorld(t)
	w.mustRun(fxPass+"\n", "init", "--passphrase", "--passphrase-stdin")
	return w
}

func TestUnlockPassphraseModeWithoutCache(t *testing.T) {
	w := passphraseWorld(t)
	f := withBackend(t, answers(val(fxPass), val(fxPass)))
	code, out, errs := w.run("", "unlock")
	if code != exitcode.OK || errs != "" || out != "passphrase ok; this platform has no unlock cache, so the passphrase is asked on each use\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	code, out, errs = w.run("", "--json", "unlock")
	if code != exitcode.OK || errs != "" || out != `{"ok":true,"unlocked":true,"keychain":"passphrase-file","cached":false,"expires_at":null}`+"\n" {
		t.Fatalf("json: code=%d out=%q err=%q", code, out, errs)
	}
	if len(f.Calls) != 2 || f.Calls[0].Kind != "passphrase" || f.Calls[0].Confirm {
		t.Fatalf("calls=%+v, want two single passphrase prompts", f.Calls)
	}
	noFixtures(t, "unlock output", out+errs)
}

func TestUnlockPassphraseModeFailures(t *testing.T) {
	w := passphraseWorld(t)
	cases := []struct {
		name   string
		answer prompttest.Answer
		code   int
		errs   string
	}{
		{"wrong passphrase", val("TESTSECRET_wrong_passphrase"), exitcode.Locked, "error: vault is locked\n"},
		{"cancelled", prompttest.Answer{Err: prompt.ErrCancelled}, exitcode.Failure, msgCancelled},
		{"blank", val("   "), exitcode.Usage, usageErr("empty passphrase")},
	}
	for _, c := range cases {
		withBackend(t, answers(c.answer))
		code, out, errs := w.run("", "unlock")
		if code != c.code || out != "" || errs != c.errs {
			t.Errorf("%s: code=%d out=%q err=%q", c.name, code, out, errs)
		}
	}
	withBackend(t, &prompttest.Fake{Unavailable: true})
	code, out, errs := w.run("", "unlock")
	if code != exitcode.Usage || out != "" || errs != usageErr("no controlling terminal available") {
		t.Fatalf("no terminal: code=%d out=%q err=%q", code, out, errs)
	}
}

func TestLockPassphraseMode(t *testing.T) {
	w := passphraseWorld(t)
	f := withBackend(t, answers())
	code, out, errs := w.run("", "lock")
	if code != exitcode.OK || errs != "" || out != "vault locked: the cached master key was removed\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	code, out, errs = w.run("", "--json", "lock")
	if code != exitcode.OK || errs != "" || out != `{"ok":true,"locked":true,"keychain":"passphrase-file"}`+"\n" {
		t.Fatalf("json: code=%d out=%q err=%q", code, out, errs)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("lock asked %+v", f.Calls)
	}
}

func TestLockUnlockWithoutVaultAndBadArgs(t *testing.T) {
	h := newHarness(t)
	for _, cmd := range []string{"lock", "unlock"} {
		code, out, errs := h.run("", cmd)
		if code != exitcode.Failure || out != "" || errs != "error: no vault here; run 'qbit-vault init'\n" {
			t.Errorf("%s without vault: code=%d out=%q err=%q", cmd, code, out, errs)
		}
		code, out, errs = h.run("", cmd, "extra")
		if code != exitcode.Usage || out != "" || errs != usageErr("unexpected arguments") {
			t.Errorf("%s extra: code=%d out=%q err=%q", cmd, code, out, errs)
		}
	}
}
