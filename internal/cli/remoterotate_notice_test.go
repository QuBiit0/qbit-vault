//go:build crashseam

package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/exitcode"
)

// S12.5: the orphan notice and the revoke audit are written as soon as the
// server accepted the rekey, so a local failure after that call cannot skip
// them (the orphan is already revoked on the server).
func TestOrphanNoticeSurvivesALocalFailureAfterTheServerCall(t *testing.T) {
	_, a, orphan := orphanedDevice(t)
	rotateCrash = func(s string) error {
		if s == "after-rekey" { // inside the local key swap, after the server call
			return errors.New("crash")
		}
		return nil
	}
	t.Cleanup(func() { rotateCrash = nil })
	f := answers(yes(), no())
	asBackend(t, keepBackend{f})
	code, out, errs := a.run("", "rekey")
	rotateCrash = nil
	if code == exitcode.OK || out != "" || recoveryKeyIn(f) != "" {
		t.Fatalf("the simulated failure did not stop the command: code=%d out=%q", code, out)
	}
	if !strings.Contains(errs, "unknown device "+orphan+" was revoked\n") {
		t.Fatalf("stderr lacks the orphan notice: %q", errs)
	}
	if !a.auditHas("device revoked " + orphan) {
		t.Fatalf("audit lacks the orphan revocation:\n%s", a.auditText())
	}
}

func TestExplicitRevokeIsAuditedAfterALocalFailureFollowingTheServerCall(t *testing.T) {
	_, a, _, c, _ := threeDevices(t)
	rotateCrash = func(s string) error {
		if s == "after-rekey" {
			return errors.New("crash")
		}
		return nil
	}
	t.Cleanup(func() { rotateCrash = nil })
	code, _, _ := revokeWith(t, a, answers(yes(), no()), c.devID())
	rotateCrash = nil
	if code == exitcode.OK {
		t.Fatal("the simulated failure did not stop the command")
	}
	if !a.auditHas("device revoked " + c.devID()) {
		t.Fatalf("audit lacks the revocation:\n%s", a.auditText())
	}
}
