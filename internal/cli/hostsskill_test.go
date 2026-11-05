package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/exitcode"
	"github.com/QuBiit0/qbit-vault/internal/hosts/skill"
)

// The skill an older release installed is stale for this build: doctor says
// so, sync rewrites it after a snapshot and then leaves it alone, and
// uninstall removes it (docs/AGENT_INTEGRATIONS.md § Agent skill).
func TestSyncKeepsTheAgentSkillCurrentAndUninstallRemovesIt(t *testing.T) {
	uh := isolateUserHome(t)
	w := newBareWorld(t)
	withHosts(t, claudeHost(uh))
	if code, out, errs := w.run("", "init", "--agents", "claude-code"); code != exitcode.OK || errs != "" {
		t.Fatalf("init: code=%d out=%q err=%q", code, out, errs)
	}
	path := filepath.Join(uh, ".claude", "skills", "qbit-vault", "SKILL.md")
	if got := readFile(t, uh, ".claude", "skills", "qbit-vault", "SKILL.md"); got != string(skill.Content) {
		t.Fatal("init did not install this build's skill")
	}

	// An older release's text.
	older := strings.Replace(string(skill.Content), "# qbit-vault", "# qbit-vault (an older release)", 1)
	if err := os.WriteFile(path, []byte(older), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := w.run("", "doctor")
	if code != exitcode.Failure || doctorStatus(out, "host.claude-code.skill") != "warn" || doctorStatus(out, "host.claude-code.mcp") != "ok" {
		t.Fatalf("stale skill: code=%d\n%s", code, out)
	}
	backups := len(dirNames(t, filepath.Join(w.home, "backups")))
	code, out, errs := w.run("", "sync")
	if code != exitcode.OK || errs != "" || !strings.Contains(out, "host claude-code: repaired (skill)\n") {
		t.Fatalf("sync: code=%d out=%q err=%q", code, out, errs)
	}
	if got := readFile(t, uh, ".claude", "skills", "qbit-vault", "SKILL.md"); got != string(skill.Content) {
		t.Fatal("sync did not update the skill")
	}
	if n := len(dirNames(t, filepath.Join(w.home, "backups"))); n <= backups {
		t.Fatal("sync replaced the skill without a snapshot")
	}

	// Current now: sync writes nothing.
	state := readFile(t, w.home, "state.json")
	if code, out, errs = w.run("", "sync"); code != exitcode.OK || !strings.Contains(out, "host claude-code: up to date\n") || readFile(t, w.home, "state.json") != state {
		t.Fatalf("second sync: code=%d out=%q err=%q", code, out, errs)
	}

	withBackend(t, answers(yes()))
	if code, out, errs = w.run("", "--session", sessA, "uninstall"); code != exitcode.OK || !strings.Contains(out, "skill deleted") {
		t.Fatalf("uninstall: code=%d out=%q err=%q", code, out, errs)
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatalf("uninstall left the skill: %v", err)
	}
}
