package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/exitcode"
)

func TestDoctorStaysQuietAboutAuditAndGrantsWhenTheyAreFine(t *testing.T) {
	w := newWorld(t)
	w.mustRun("", "audit")
	code, out, errs := w.run("", "doctor")
	if code != exitcode.OK || errs != "" || strings.Contains(out, "audit") || strings.Contains(out, "grants") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
}

func TestDoctorReportsABrokenAuditChain(t *testing.T) {
	w := newWorld(t)
	f, err := os.OpenFile(w.auditFile(), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("{\"seq\":99,\"not\":\"a record\"}\n")
	f.Close()
	code, out, errs := w.run("", "doctor")
	if code != exitcode.Failure || errs != "" || doctorStatus(out, "audit") != "fail" ||
		!strings.Contains(out, "audit chain broken at line 2 (") || !strings.Contains(out, "run 'qbit-vault audit --verify'") {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

func TestDoctorReportsAnUnreadableGrantsStore(t *testing.T) {
	w := newWorld(t)
	if err := os.WriteFile(filepath.Join(w.home, "grants.enc"), []byte("not an envelope"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := w.run("", "doctor")
	if code != exitcode.Failure || errs != "" || doctorStatus(out, "grants") != "warn" ||
		!strings.Contains(out, "grants.enc is unreadable or was rolled back; its grants are treated as none") {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

func TestDoctorPointsDriftAtSync(t *testing.T) {
	w, h := registered(t)
	if err := os.WriteFile(filepath.Join(h.Dir, "config.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, out, _ := w.run("", "doctor")
	if !strings.Contains(out, "warn  host.fake.mcp    config changed since registration; run 'qbit-vault sync'\n") {
		t.Fatalf("out=%q", out)
	}
}

func TestDoctorWithAllChecksFailingStillWritesNothing(t *testing.T) {
	w, h := registered(t)
	if err := os.WriteFile(filepath.Join(h.Dir, "config.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(w.home, "grants.enc"), []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, _ := os.OpenFile(w.auditFile(), os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString("garbage\n")
	f.Close()
	b := withBackend(t, answers())
	before := tree(t, w.home, h.Dir)
	w.run("", "doctor")
	w.run("", "--json", "doctor")
	if after := tree(t, w.home, h.Dir); after != before {
		t.Fatalf("doctor wrote:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if len(b.Calls) != 0 {
		t.Fatalf("doctor prompted: %+v", b.Calls)
	}
}
