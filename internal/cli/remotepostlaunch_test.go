package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/exitcode"
)

// S4.2: the joiner's confirmation-code question is a plain question with its
// own heading, not a secret request (no Who / Secret / Saved in / Value).
func TestJoinAsksTheConfirmationCodeAsAPlainQuestion(t *testing.T) {
	ss := newSyncServer(t)
	a, b := newWorld(t), newWorld(t)
	a.register(ss)
	code, out, errs, fb := joinPairing(t, b, a, ss)
	if code != exitcode.OK || errs != "" {
		t.Fatalf("join: code=%d out=%q err=%q", code, out, errs)
	}
	var asked []string
	for _, c := range fb.Calls {
		if c.Kind == "secret" {
			asked = append(asked, c.Request.Name)
			if c.Request.Name != nameConfirm {
				continue
			}
			r := c.Request
			if r.Heading != "Confirmation code" || r.Reason != "Type the confirmation code shown on the device that approved this one" || r.Visible {
				t.Fatalf("confirmation question = %+v", r)
			}
		}
	}
	if strings.Join(asked, "|") != nameConfirm {
		t.Fatalf("secret prompts of the join = %v, want only the confirmation code", asked)
	}
	noFixtures(t, "the join output", out+errs)
}

func jsonDevices(t *testing.T, w *world) []map[string]any {
	t.Helper()
	code, out, errs := w.run("", "--json", "remote", "devices")
	var d struct {
		Devices []map[string]any
	}
	if err := json.Unmarshal([]byte(out), &d); code != 0 || err != nil || errs != "" {
		t.Fatalf("devices: code=%d out=%q err=%q (%v)", code, out, errs, err)
	}
	return d.Devices
}

// S4.3: a device that only pulls has no "last sync", but the server has seen
// it: the list says "last seen" from the server and never "last sync: never".
func TestDevicesShowLastSeenForADeviceThatOnlyPulls(t *testing.T) {
	ss := newSyncServer(t)
	a, b := newWorld(t), newWorld(t)
	a.register(ss)
	joinPairing(t, b, a, ss)
	asBackend(t, keepBackend{answers()})
	audit := a.auditText()

	code, out, errs := a.run("", "remote", "devices")
	if code != exitcode.OK || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if strings.Contains(out, "last sync: never") || strings.Contains(out, "never") {
		t.Fatalf("a pull-only device is reported as never synced:\n%s", out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 {
		t.Fatalf("out = %q", out)
	}
	for _, l := range lines {
		isB := strings.Contains(l, "Laptop B")
		hasSync, hasSeen := strings.Contains(l, "last sync: "), strings.Contains(l, "last seen: ")
		switch {
		case isB && (hasSync || !hasSeen):
			t.Errorf("B (pull-only) line = %q, want last seen only", l)
		case !isB && (!hasSync || !hasSeen):
			t.Errorf("A line = %q, want last sync and last seen", l)
		}
		if hasSeen && !tsRE.MatchString(l[strings.Index(l, "last seen: "):]) {
			t.Errorf("last seen is not a time: %q", l)
		}
	}

	rows := jsonDevices(t, a)
	for _, r := range rows {
		if r["last_seen"] == nil || !tsRE.MatchString(r["last_seen"].(string)) {
			t.Errorf("row without last_seen: %v", r)
		}
		for _, k := range []string{"id", "label", "added_by", "added_at", "revoked", "this"} {
			if _, ok := r[k]; !ok {
				t.Errorf("row lost %q: %v", k, r)
			}
		}
		_, hasSync := r["last_sync"]
		if (r["label"] == "Laptop B") == hasSync {
			t.Errorf("last_sync presence wrong for %v", r["label"])
		}
	}

	// Offline: only what the roster knows; no "never", no server call.
	code, out, errs = a.runEnv(map[string]string{envNoRemote: "1"}, "", "remote", "devices")
	if code != exitcode.OK || errs != "" || strings.Contains(out, "never") || strings.Contains(out, "last seen") || strings.Count(out, "last sync: ") != 1 {
		t.Fatalf("offline: code=%d out=%q err=%q", code, out, errs)
	}
	if a.auditText() != audit {
		t.Fatal("listing the devices wrote to the audit log")
	}
	noFixtures(t, "devices", out+errs)
}

const secretProj = "TESTSECRET_project_value_c1"

// revokedC is an account of A, B and C where C holds a project secret that
// only exists in its repository, then A revokes C and C learns it.
func revokedC(t *testing.T) (ss *syncServer, a, b, c *world, oldID string) {
	t.Helper()
	ss, a, b, c, _ = threeDevices(t)
	c.inRepo()
	c.mustRun(secretProj, "set", "PROJ_KEY", "--project", "--stdin")
	c.outRepo()
	c.mustRun("", "remote", "sync")
	oldID = c.devID()
	if code, out, errs := revokeWith(t, a, answers(yes(), no()), oldID); code != exitcode.OK {
		t.Fatalf("revoke: code=%d out=%q err=%q", code, out, errs)
	}
	if code, out, _ := c.run("", "--json", "remote", "sync"); code != exitcode.Failure || !strings.Contains(out, `"code":"device_revoked"`) {
		t.Fatalf("C was not told: code=%d out=%q", code, out)
	}
	return
}

// S4.1: a revoked device joins again by pairing. It takes a new device id, its
// project roots go with it, and the old id stays revoked.
func TestRevokedDeviceRejoinsByPairingWithANewID(t *testing.T) {
	ss, a, b, c, oldID := revokedC(t)
	before := c.snapshot()

	code, out, errs, fc := joinPairing(t, c, a, ss)
	if code != exitcode.OK || errs != "" || !strings.Contains(out, "joined ") {
		t.Fatalf("rejoin: code=%d out=%q err=%q", code, out, errs)
	}
	newID := c.devID()
	if newID == oldID {
		t.Fatal("the rejoined device kept its revoked id")
	}
	if st := readState(t, c); st == nil || st.Generation != 2 {
		t.Fatalf("C state after the rejoin: %+v", st)
	}
	// Everything C held is still there, project secrets included.
	if c.value("A_KEY") != secretA || c.snapshot() != before {
		t.Fatal("C lost data in the rejoin")
	}
	c.inRepo()
	if c.value("PROJ_KEY") != secretProj {
		t.Fatal("C's project secret no longer resolves in its repository")
	}
	c.outRepo()
	// The old id stays revoked everywhere; the new one is a member.
	a.mustRun("", "remote", "sync")
	b.mustRun("", "remote", "sync")
	for name, w := range map[string]*world{"A": a, "B": b} {
		r := w.roster()
		if r[oldID].RevokedAt == nil {
			t.Errorf("%s: the old id is no longer revoked", name)
		}
		if d, ok := r[newID]; !ok || d.RevokedAt != nil || d.AddedBy != "pairing" {
			t.Errorf("%s: the new id is %+v (%v)", name, d, ok)
		}
	}
	ids, gen := serverView(t, ss, c)
	if gen != 2 || !slices.Contains(ids, newID) || slices.Contains(ids, oldID) {
		t.Fatalf("server devices = %v generation=%d", ids, gen)
	}
	// It syncs under the new id.
	c.mustRun("", "remote", "sync")
	// The new id is also what `remote devices` calls this device.
	if d := jsonDevices(t, c); len(d) < 4 {
		t.Fatalf("devices = %v", d)
	}
	noFixtures(t, "the join output", out+errs)
	for _, call := range fc.Calls {
		if call.Kind == "secret" && call.Request.Name != nameConfirm {
			t.Errorf("unexpected question %+v", call.Request)
		}
	}
}

// A device that was never revoked keeps its id when it joins.
func TestJoinKeepsTheDeviceIDOfAVaultThatWasNeverRevoked(t *testing.T) {
	ss := newSyncServer(t)
	a, b := newWorld(t), newWorld(t)
	a.register(ss)
	id := b.devID()
	if code, out, errs, _ := joinPairing(t, b, a, ss); code != exitcode.OK {
		t.Fatalf("join: code=%d out=%q err=%q", code, out, errs)
	}
	if b.devID() != id {
		t.Fatal("a first join changed the device id")
	}
}

// A refused rejoin leaves the vault exactly as it was: same device id, same
// files, same sync state.
func TestRefusedRejoinLeavesTheVaultAsItWas(t *testing.T) {
	ss, a, _, c, oldID := revokedC(t)
	vaultFile, state := c.vaultBytes(), readFileT(t, filepath.Join(c.home, "state.json"))
	before := c.snapshot()

	fb := answers(yes())
	asBackend(t, keepBackend{fb})
	withPairing(t, func(code string) {
		fa := answers(val(code), val("Laptop C2"), no())
		prev := newPrompt
		asBackend(t, keepBackend{fa})
		a.mustRun("", "remote", "approve")
		newPrompt = prev
		fb.Script = append(fb.Script, val("WRNG-CODE"))
	})
	code, out, errs := c.run("", "remote", "join", "--server", ss.ts.URL)
	wantCoded(t, code, errs, "pairing_failed", exitcode.Failure)
	if strings.Contains(out, "joined ") || !strings.Contains(errs, "the pairing could not be confirmed") {
		t.Fatalf("out=%q err=%q", out, errs)
	}
	if c.devID() != oldID || c.vaultBytes() != vaultFile || readFileT(t, filepath.Join(c.home, "state.json")) != state || c.snapshot() != before {
		t.Fatal("a refused join changed the vault")
	}
	if readState(t, c) != nil {
		t.Fatal("a refused join left sync state")
	}
	c.inRepo()
	if c.value("PROJ_KEY") != secretProj {
		t.Fatal("the project secret no longer resolves")
	}
	c.outRepo()
	noFixtures(t, "the refusal", out+errs)
}

func readFileT(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A revoked device that never learned it (it did not sync since) logs out and
// joins again with the recovery key: the server tells the id is revoked, so it
// takes a new one here too.
func TestRevokedDeviceRejoinsByRecoveryWithANewID(t *testing.T) {
	ss, a, _, c, _ := threeDevices(t)
	c.inRepo()
	c.mustRun(secretProj, "set", "PROJ_KEY", "--project", "--stdin")
	c.outRepo()
	oldID := c.devID()
	f := answers(yes(), no())
	if code, out, errs := revokeWith(t, a, f, oldID); code != exitcode.OK {
		t.Fatalf("revoke: code=%d out=%q err=%q", code, out, errs)
	}
	rk := recoveryKeyIn(f)

	asBackend(t, keepBackend{answers(yes())})
	c.mustRun("", "remote", "logout")
	if c.devID() != oldID {
		t.Fatal("logout changed the device id")
	}
	asBackend(t, keepBackend{answers(yes(), val(rk))})
	code, out, errs := c.run("", "remote", "join", "--server", ss.ts.URL, "--recovery")
	if code != exitcode.OK || errs != "" || !strings.Contains(out, "joined ") {
		t.Fatalf("rejoin: code=%d out=%q err=%q", code, out, errs)
	}
	if c.devID() == oldID {
		t.Fatal("the rejoined device kept its revoked id")
	}
	c.inRepo()
	if c.value("PROJ_KEY") != secretProj || c.value("A_KEY") != secretA {
		t.Fatal("C lost secrets in the rejoin")
	}
	c.outRepo()
	a.mustRun("", "remote", "sync")
	if r := a.roster(); r[oldID].RevokedAt == nil || r[c.devID()].RevokedAt != nil || r[c.devID()].AddedBy != "recovery" {
		t.Fatalf("roster: old=%+v new=%+v", r[oldID], r[c.devID()])
	}
	if ids, _ := serverView(t, ss, c); slices.Contains(ids, oldID) || !slices.Contains(ids, c.devID()) {
		t.Fatalf("server devices = %v", ids)
	}
	noFixtures(t, "the join output", out+errs)
	noKeyIn(t, "the join output", out+errs, rk)
}
