package cli

import (
	"context"
	"crypto/rand"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qbitdevz/qbit-vault/internal/exitcode"
	"github.com/qbitdevz/qbit-vault/internal/merge"
	"github.com/qbitdevz/qbit-vault/internal/remote"
	"github.com/qbitdevz/qbit-vault/internal/secret"
	"github.com/qbitdevz/qbit-vault/internal/vault"
)

// orphanedDevice registers a world and leaves on its server a device that is
// in no roster (an approve whose roster write failed).
func orphanedDevice(t *testing.T) (*syncServer, *world, string) {
	t.Helper()
	ss := newSyncServer(t)
	a := newWorld(t)
	a.register(ss)
	nk := make([]byte, 32)
	_, _ = rand.Read(nk)
	nc, _ := remote.NewClient(ss.ts.URL, "")
	orphan := strings.Repeat("d", 32)
	p, err := nc.CreatePairing(context.Background(), orphan, remote.DeviceFromSecret(secret.New("dk", nk)))
	if err != nil {
		t.Fatal(err)
	}
	unblock := a.blocked("backups")
	asBackend(t, keepBackend{answers(val(p.Code), val("Laptop X"), no())})
	if code, _, errs := a.run("", "remote", "approve"); code != exitcode.OK || !strings.Contains(errs, "could not record it in the roster") {
		t.Fatalf("approve: code=%d err=%q", code, errs)
	}
	unblock()
	if _, ok := a.roster()[orphan]; ok {
		t.Fatal("the setup should leave the device out of the roster")
	}
	if ids, _ := serverView(t, ss, a); !slices.Contains(ids, orphan) {
		t.Fatalf("the server should list the orphan: %v", ids)
	}
	return ss, a, orphan
}

// S11.2 (C-S07): a device the server lists but the roster lacks (an approve
// whose roster write failed) is revoked by the rotation instead of blocking it.
func TestRekeyRevokesADeviceMissingFromTheRoster(t *testing.T) {
	ss, a, orphan := orphanedDevice(t)

	asBackend(t, keepBackend{answers(yes(), no())})
	code, out, errs := a.run("", "rekey")
	if code != exitcode.OK || errs != "unknown device "+orphan+" was revoked\n" ||
		out != "master key rotated (keychain: "+osMode()+"); the account is now generation 2\n" {
		t.Fatalf("rekey: code=%d out=%q err=%q", code, out, errs)
	}
	if ids, gen := serverView(t, ss, a); slices.Contains(ids, orphan) || gen != 2 {
		t.Fatalf("server after rekey: %v %d", ids, gen)
	}
	if !a.auditHas("device revoked " + orphan) {
		t.Fatalf("audit: %s", a.auditText())
	}
}

// plantConflict adds a kept conflict that was lost age ago to w's body, as an
// older version of the vault would have stored it.
func (w *world) plantConflict(id string, age time.Duration) {
	w.t.Helper()
	g := &globals{getenv: envFrom(nil), home: w.home}
	s, err := g.openSession()
	if err != nil {
		w.t.Fatal(err)
	}
	defer s.close()
	err = s.v.ApplyBody(func(local []byte) ([]byte, error) {
		b, err := parseBody(local)
		if err != nil {
			return nil, err
		}
		b.Conflicts = append(b.Conflicts, merge.Conflict{ID: id, Key: "global/OLD", LostAt: time.Now().Add(-age).UTC().Format(time.RFC3339)})
		return canon(b), nil
	})
	if err != nil {
		w.t.Fatal(err)
	}
}

// S11.3 (C-S05): a conflict dropped for age is said once on stderr by
// `remote sync` and audited; the next round says nothing.
func TestSyncSaysWhenOldConflictsWereDiscarded(t *testing.T) {
	_, _, a, b := syncPair(t)
	a.plantConflict("old-1", 40*24*time.Hour)

	code, out, errs := a.run("", "remote", "sync")
	if code != exitcode.OK || !strings.HasPrefix(out, "synced") ||
		errs != "1 old conflict(s) were discarded; the current values are unchanged\n" {
		t.Fatalf("sync: code=%d out=%q err=%q", code, out, errs)
	}
	if !a.auditHas("1 old conflict(s) discarded") {
		t.Fatalf("audit: %s", a.auditText())
	}
	if code, out, errs = a.run("", "remote", "sync"); code != exitcode.OK || errs != "" || !strings.HasPrefix(out, "up to date") {
		t.Fatalf("second sync: code=%d out=%q err=%q", code, out, errs)
	}
	if code, _, errs = b.run("", "remote", "sync"); code != exitcode.OK || errs != "" {
		t.Fatalf("other device: code=%d err=%q", code, errs)
	}
}

// A conflict younger than the limit is kept and nothing is said.
func TestSyncSaysNothingWhenNoConflictWasDiscarded(t *testing.T) {
	_, _, a, _ := syncPair(t)
	a.plantConflict("recent-1", 24*time.Hour)
	if code, _, errs := a.run("", "remote", "sync"); code != exitcode.OK || errs != "" {
		t.Fatalf("sync: code=%d err=%q", code, errs)
	}
	if a.auditHas("old conflict") {
		t.Fatalf("audit: %s", a.auditText())
	}
}

// serveOldestVaultToFirstPulls answers a plain GET /v1/vault (a device with no
// base: a joiner's first round) with version 1, as a server that replays an
// old version could.
func (ss *syncServer) serveOldestVaultToFirstPulls() {
	ss.proxy(func(_ http.ResponseWriter, r *http.Request) bool {
		if r.Method == "GET" && r.URL.Path == "/v1/vault" && r.URL.Query().Get("version") == "" && r.Header.Get("If-None-Match") == "" {
			r.URL.RawQuery = "version=1"
		}
		return false
	})
}

// S11.1 (C-S04): the joiner starts with the approver's version floor, so an
// older version served on its first round is a rollback like on any device.
func TestJoinedDeviceRefusesAVersionOlderThanTheApproverHad(t *testing.T) {
	ss := newSyncServer(t)
	a, b := newWorld(t), newWorld(t)
	a.register(ss)
	asBackend(t, keepBackend{answers()})
	a.mustRun("TESTSECRET_join_floor", "set", "FLOOR", "--global", "--stdin")
	ss.serveOldestVaultToFirstPulls()

	code, out, errs, _ := joinPairing(t, b, a, ss)
	wantCoded(t, code, errs, "remote_rollback", exitcode.Corrupt)
	if !strings.Contains(errs, msgJoinHalf) || strings.Contains(out, "joined") {
		t.Fatalf("join: code=%d out=%q err=%q", code, out, errs)
	}
	// The approver sealed the version it had before it pushed the new roster entry.
	if got, had := readState(t, b).LastVersion, readState(t, a).LastVersion; got < 2 || got > had {
		t.Fatalf("the joiner floor is %d, the approver ended at %d", got, had)
	}
	if strings.Contains(b.globalList(), "FLOOR") {
		t.Fatal("the refused round changed the joiner's vault")
	}
}

// An envelope without last_version (an older approver) leaves the floor at 0
// and the join still works.
func TestJoinWithAnEnvelopeWithoutLastVersionStillJoins(t *testing.T) {
	old := envelopeVersion
	envelopeVersion = func(*vault.Remote) int64 { return 0 }
	t.Cleanup(func() { envelopeVersion = old })
	ss := newSyncServer(t)
	a, b := newWorld(t), newWorld(t)
	a.register(ss)
	asBackend(t, keepBackend{answers()})
	a.mustRun("TESTSECRET_join_floor", "set", "FLOOR", "--global", "--stdin")
	ss.serveOldestVaultToFirstPulls()

	code, out, errs, _ := joinPairing(t, b, a, ss)
	if code != exitcode.OK || !strings.Contains(out, "joined ") {
		t.Fatalf("join: code=%d out=%q err=%q", code, out, errs)
	}
}
