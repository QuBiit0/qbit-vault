package cli

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/QuBiit0/qbit-vault/internal/exitcode"
	"github.com/QuBiit0/qbit-vault/internal/grants"
)

// Inside a repository the middle answer is "12 hours in this project": a
// project grant that expires, so it survives agent restarts (each one is a
// new session) instead of ending with them. Outside a repository there is no
// project to bind it to, and the session answer stays.

const twelveHours = "12 hours: in this project, even if the agent restarts"

func TestRequestInARepositoryOffersTwelveHoursInThisProject(t *testing.T) {
	pinClock(t)
	w := newWorld(t)
	w.mustRun("TESTSECRET_global\n", "set", "A", "--global", "--stdin")
	f := withBackend(t, answers(pick(1)))
	code, m, _ := w.broker("request", reqFor(w.repo, ""))
	if code != exitcode.OK {
		t.Fatalf("code=%d m=%v", code, m)
	}
	want := []string{"Once: only the next command", twelveHours, "Project: always in this project, until you revoke it", "Don't allow"}
	if strings.Join(f.Calls[0].Options, "|") != strings.Join(want, "|") || f.Calls[0].Default != 1 {
		t.Fatalf("options=%q default=%d", f.Calls[0].Options, f.Calls[0].Default)
	}
	gr := m["grant"].(map[string]any)
	if gr["scope"] != "project" || gr["expires_at"] != clock().Add(12*time.Hour).UTC().Format(time.RFC3339) {
		t.Fatalf("grant=%v", gr)
	}
	// A restarted agent (a new session) in the same repository needs no new approval...
	if err := w.checkIn("A", "mcp:restarted", w.repo); err != nil {
		t.Fatalf("after a restart: %v", err)
	}
	// ...another repository still asks.
	if err := w.checkIn("A", brokerSession, w.mkRepo("blog")); !errors.Is(err, grants.ErrGrantRequired) {
		t.Fatalf("another repository: err = %v", err)
	}
}

func TestRequestOutsideARepositoryKeepsTheSessionAnswer(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_global\n", "set", "A", "--global", "--stdin")
	f := withBackend(t, answers(pick(1)))
	code, m, _ := w.broker("request", reqFor(w.outside, ""))
	if code != exitcode.OK || m["grant"].(map[string]any)["scope"] != "session" {
		t.Fatalf("code=%d m=%v", code, m)
	}
	if o := f.Calls[0].Options; o[1] != "Session: until the agent restarts (max 12h)" {
		t.Fatalf("options=%q", o)
	}
}

// Replace inside a repository offers the same 12 hours answer, and the
// grant it makes outlives an agent restart.
func TestManageReplaceInARepositoryGrantsTwelveHoursInThisProject(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_old\n", "set", "A", "--global", "--stdin")
	f := withBackend(t, answers(pick(1), val("TESTSECRET_new")))
	if code, m, _ := w.broker("manage", manageReq(w.repo, `"action":"replace","name":"A","layer":"global"`)); code != exitcode.OK {
		t.Fatalf("code=%d m=%v", code, m)
	}
	if o := f.Calls[0].Options; len(o) < 2 || o[1] != "Replace, then "+twelveHours || f.Calls[0].Default != 1 {
		t.Fatalf("options=%q default=%d", o, f.Calls[0].Default)
	}
	if err := w.checkIn("A", "mcp:restarted", w.repo); err != nil {
		t.Fatalf("after a restart: %v", err)
	}
	if err := w.checkIn("A", brokerSession, w.mkRepo("blog")); !errors.Is(err, grants.ErrGrantRequired) {
		t.Fatalf("another repository: err = %v", err)
	}
}
