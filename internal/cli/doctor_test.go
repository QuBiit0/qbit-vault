package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/exitcode"
	"github.com/QuBiit0/qbit-vault/internal/keychain"
	"github.com/QuBiit0/qbit-vault/internal/vault"
)

// tree lists every file and directory under the roots with a digest of its
// bytes, so a test can prove that nothing was created, changed or removed.
func tree(t *testing.T, roots ...string) string {
	t.Helper()
	var lines []string
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				lines = append(lines, "d "+p)
				return nil
			}
			b, _ := os.ReadFile(p)
			sum := sha256.Sum256(b)
			lines = append(lines, "f "+p+" "+hex.EncodeToString(sum[:]))
			return nil
		})
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

func TestDoctorHealthyVaultOnly(t *testing.T) {
	w := newWorld(t)
	mode := keychain.NewOS().Name()
	code, out, errs := w.run("", "doctor")
	want := "ok    vault        unlocked (keychain: " + mode + ")\n" +
		"ok    permissions  owner-only\n" +
		"healthy\n"
	if code != exitcode.OK || out != want || errs != "" {
		t.Fatalf("code=%d out=%q want=%q err=%q", code, out, want, errs)
	}
	code, out, errs = w.run("", "--json", "doctor")
	wantJSON := `{"ok":true,"checks":[` +
		`{"name":"vault","status":"ok","detail":"unlocked (keychain: ` + mode + `)"},` +
		`{"name":"permissions","status":"ok","detail":"owner-only"}]}` + "\n"
	if code != exitcode.OK || out != wantJSON || errs != "" {
		t.Fatalf("json: code=%d out=%q want=%q err=%q", code, out, wantJSON, errs)
	}
}

func TestDoctorWithoutAVault(t *testing.T) {
	w := newBareWorld(t)
	code, out, errs := w.run("", "doctor")
	want := "fail  vault  no vault here; run 'qbit-vault init'\n1 problem\n"
	if code != exitcode.Failure || out != want || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if _, err := os.Stat(w.home); !os.IsNotExist(err) {
		t.Fatal("doctor created the vault home")
	}
	code, out, _ = w.run("", "--json", "doctor")
	if code != exitcode.Failure || out != `{"ok":false,"checks":[{"name":"vault","status":"fail","detail":"no vault here; run 'qbit-vault init'"}]}`+"\n" {
		t.Fatalf("json: code=%d out=%q", code, out)
	}
}

func TestDoctorChecksRegisteredHostsAndReportsDrift(t *testing.T) {
	w := newBareWorld(t)
	h := fakeHost(t, w)
	withHosts(t, h)
	w.mustRun("", "init")

	if code, out, errs := w.run("", "doctor"); code != exitcode.OK || errs != "" ||
		!strings.Contains(out, "ok    host.fake.mcp    registered\n") || !strings.HasSuffix(out, "healthy\n") {
		t.Fatalf("clean: code=%d out=%q err=%q", code, out, errs)
	}

	// The user removes our MCP entry from the host config.
	if err := os.WriteFile(filepath.Join(h.Dir, "config.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := w.run("", "doctor")
	if code != exitcode.Failure || errs != "" ||
		!strings.Contains(out, "warn  host.fake.mcp    config changed since registration; run 'qbit-vault init'\n") ||
		!strings.Contains(out, "ok    host.fake.hooks  registered\n") || !strings.HasSuffix(out, "1 problem\n") {
		t.Fatalf("drift: code=%d out=%q err=%q", code, out, errs)
	}
	var body struct {
		OK     bool `json:"ok"`
		Checks []struct{ Name, Status, Detail string }
	}
	code, out, _ = w.run("", "--json", "doctor")
	if err := json.Unmarshal([]byte(out), &body); err != nil || code != exitcode.Failure || body.OK {
		t.Fatalf("json: code=%d out=%q err=%v", code, out, err)
	}

	// init repairs it, idempotently.
	w.mustRun("", "init")
	if code, out, _ := w.run("", "doctor"); code != exitcode.OK || !strings.HasSuffix(out, "healthy\n") {
		t.Fatalf("after repair: code=%d out=%q", code, out)
	}
}

func TestDoctorReportsAHostThisBuildDoesNotKnow(t *testing.T) {
	w := newBareWorld(t)
	h := fakeHost(t, w)
	withHosts(t, h)
	w.mustRun("", "init")
	withHosts(t) // a build without that adapter
	code, out, _ := w.run("", "doctor")
	if code != exitcode.Failure || !strings.Contains(out, "warn  host.fake    registered, but this build has no adapter for it\n") {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

func TestDoctorIsReadOnlyAndNeverPrompts(t *testing.T) {
	t.Run("unlocked, with a drifted host", func(t *testing.T) {
		w := newBareWorld(t)
		h := fakeHost(t, w)
		withHosts(t, h)
		w.mustRun("", "init")
		if err := os.WriteFile(filepath.Join(h.Dir, "config.json"), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		f := withBackend(t, answers())
		before := tree(t, w.home, h.Dir)
		w.run("", "doctor")
		w.run("", "--json", "doctor")
		if after := tree(t, w.home, h.Dir); after != before {
			t.Fatalf("doctor changed the file system:\n--- before\n%s\n--- after\n%s", before, after)
		}
		if len(f.Calls) != 0 {
			t.Fatalf("prompted: %+v", f.Calls)
		}
	})
	t.Run("passphrase vault is locked, not asked", func(t *testing.T) {
		w := passphraseWorld(t)
		f := withBackend(t, answers(val(fxPass)))
		before := tree(t, w.home)
		code, out, errs := w.run("", "doctor")
		if code != exitcode.OK || errs != "" || !strings.HasPrefix(out, "ok    vault        locked") {
			t.Fatalf("code=%d out=%q err=%q", code, out, errs)
		}
		if len(f.Calls) != 0 {
			t.Fatalf("prompted: %+v", f.Calls)
		}
		if after := tree(t, w.home); after != before {
			t.Fatal("doctor changed the vault home")
		}
		noFixtures(t, "doctor output", out)
	})
}

func TestDoctorSyncSummary(t *testing.T) {
	w := newWorld(t)
	rem := &vault.Remote{
		Server: "https://vault.example", AccountID: "0123456789abcdef0123456789abcdef", Generation: 2, LastVersion: 9,
		PendingPush: true, LastPullAt: "2026-11-04T10:00:00Z",
		Summary: vault.RemoteSummary{At: "2026-11-04T10:00:00Z", Conflicts: 0, Devices: 3},
	}
	if err := vault.WriteRemote(w.home, rem); err != nil {
		t.Fatal(err)
	}
	code, out, errs := w.run("", "doctor")
	if code != exitcode.OK || errs != "" ||
		!strings.Contains(out, "ok    sync         https://vault.example; 3 devices, 0 conflicts, push pending; last round 2026-11-04T10:00:00Z\n") {
		t.Fatalf("clean: code=%d out=%q err=%q", code, out, errs)
	}

	rem.Summary.Conflicts = 2
	if err := vault.WriteRemote(w.home, rem); err != nil {
		t.Fatal(err)
	}
	before := tree(t, w.home)
	code, out, _ = w.run("", "doctor")
	if code != exitcode.Failure || !strings.Contains(out, "warn  sync         2 sync conflicts; run 'qbit-vault remote conflicts'\n") {
		t.Fatalf("conflicts: code=%d out=%q", code, out)
	}
	if tree(t, w.home) != before {
		t.Fatal("doctor changed the vault home")
	}

	rem.Summary, rem.PendingPush = vault.RemoteSummary{}, false
	if err := vault.WriteRemote(w.home, rem); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := w.run("", "doctor"); code != exitcode.OK || !strings.Contains(out, "ok    sync         https://vault.example; no sync round yet\n") {
		t.Fatalf("no round: code=%d out=%q", code, out)
	}
}

func TestDoctorRejectsArguments(t *testing.T) {
	w := newWorld(t)
	if code, _, errs := w.run("", "doctor", "TESTSECRET_x"); code != exitcode.Usage || strings.Contains(errs, "TESTSECRET_") {
		t.Fatalf("code=%d err=%q", code, errs)
	}
}
