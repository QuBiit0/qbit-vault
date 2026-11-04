//go:build crashseam

package cli

import (
	"errors"
	"testing"

	"github.com/QuBiit0/gentle-vault/internal/exitcode"
)

// These tests need the crash points of remotecrash_on.go, so they run in a
// build with -tags crashseam. A default `go test` runs them through
// TestCrashSeamTestsPassWithTheirTag (remotecrash_release_test.go).

// ---- crash safety of the order: server first, then the local swap ----

func TestCrashAfterTheServerAcceptedIsFinishedByTheNextRound(t *testing.T) {
	for _, step := range []string{"after-server", "after-rekey", "after-promote"} {
		t.Run(step, func(t *testing.T) {
			ss, a, b, c, _ := threeDevices(t)
			errCrash := errors.New("crash")
			rotateCrash = func(s string) error {
				if s == step {
					return errCrash
				}
				return nil
			}
			t.Cleanup(func() { rotateCrash = nil })
			f := answers(yes(), no())
			code, _, _ := revokeWith(t, a, f, c.devID())
			rotateCrash = nil
			if code == exitcode.OK || recoveryKeyIn(f) != "" {
				t.Fatalf("the simulated crash did not stop the command: code=%d", code)
			}
			if _, gen := serverView(t, ss, b); gen != 2 {
				t.Fatalf("the server did not rotate before the crash (generation %d)", gen)
			}
			// Whatever the crash left, A still opens its vault and the next
			// round brings it to generation 2 with all its secrets.
			asBackend(t, keepBackend{answers()})
			if a.value("A_KEY") != secretA {
				t.Fatal("A cannot read its vault after the crash")
			}
			code, out, errs := a.run("", "remote", "sync")
			if code != exitcode.OK {
				t.Fatalf("recovery round: code=%d out=%q err=%q", code, out, errs)
			}
			st := readState(t, a)
			if st.Generation != 2 || !st.RecoveryUnconfirmed || a.value("A_KEY") != secretA {
				t.Fatalf("after recovery: %+v", st)
			}
			if a.roster()[c.devID()].RevokedAt == nil {
				t.Fatal("the revocation did not reach A's roster")
			}
			asBackend(t, keepBackend{answers()})
			b.mustRun("", "remote", "sync")
			if b.value("A_KEY") != secretA || b.gen() != 2 {
				t.Fatal("B cannot follow after the crash")
			}
			a.mustRun(fxVal+"_after", "set", "AFTER", "--global", "--stdin")
			b.mustRun("", "remote", "sync")
			if b.value("AFTER") != fxVal+"_after" {
				t.Fatal("A and B no longer sync after recovery")
			}
		})
	}
}
