package skill_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/filemerge"
	"github.com/QuBiit0/qbit-vault/internal/hosts"
	"github.com/QuBiit0/qbit-vault/internal/hosts/claude"
	"github.com/QuBiit0/qbit-vault/internal/hosts/codex"
	"github.com/QuBiit0/qbit-vault/internal/hosts/pi"
	"github.com/QuBiit0/qbit-vault/internal/hosts/skill"
	"github.com/QuBiit0/qbit-vault/internal/mcp"
	"github.com/QuBiit0/qbit-vault/internal/refusal"
	"github.com/QuBiit0/qbit-vault/internal/secret"
	"github.com/QuBiit0/qbit-vault/internal/vault"
)

// skillHost is a host whose only step is the skill at path.
type skillHost struct {
	name string
	path func(hosts.Env) (string, error)
}

func (h skillHost) Name() string                 { return h.name }
func (h skillHost) Detect(hosts.Env) bool        { return true }
func (h skillHost) Steps(hosts.Env) []hosts.Step { return []hosts.Step{skill.Step(h.name, h.path)} }

func newEnv(t *testing.T) hosts.Env {
	t.Helper()
	base := t.TempDir()
	home := filepath.Join(base, "vault-home")
	if _, err := vault.Init(home, vault.NewID(), secret.New("k", bytes.Repeat([]byte{7}, 32))); err != nil {
		t.Fatal(err)
	}
	return hosts.Env{VaultHome: home, UserHome: filepath.Join(base, "user")}
}

func mustApply(t *testing.T, env hosts.Env, a ...hosts.Adapter) []hosts.Result {
	t.Helper()
	res := hosts.Apply(env, a)
	for _, r := range res {
		if err := r.Err(); err != nil {
			t.Fatalf("apply %s: %v", r.Host, err)
		}
	}
	return res
}

func TestPathsAreTheSkillLocationsOfEachAgent(t *testing.T) {
	env := hosts.Env{UserHome: filepath.FromSlash("/home/ana")}
	c, _ := skill.ClaudePath(env)
	a, _ := skill.AgentsPath(env)
	if c != filepath.FromSlash("/home/ana/.claude/skills/qbit-vault/SKILL.md") || a != filepath.FromSlash("/home/ana/.agents/skills/qbit-vault/SKILL.md") {
		t.Fatalf("paths = %s, %s", c, a)
	}
	if _, err := skill.ClaudePath(hosts.Env{}); err == nil {
		t.Fatal("no user home must be an error")
	}
}

func TestContentIsAValidSkillThatNamesEveryTool(t *testing.T) {
	s := string(skill.Content)
	if !strings.HasPrefix(s, "---\nname: qbit-vault\ndescription: ") || !strings.Contains(s, skill.Marker) {
		t.Fatalf("frontmatter or marker missing:\n%.200s", s)
	}
	desc := strings.SplitN(strings.SplitN(s, "description: ", 2)[1], "\n", 2)[0]
	if len(desc) == 0 || len(desc) > 1024 {
		t.Fatalf("description is %d bytes, want 1..1024", len(desc))
	}
	// A renamed or added tool must show up in the skill in the same change.
	for tool := range mcp.ToolDescriptions {
		if !strings.Contains(s, "`"+tool+"`") {
			t.Errorf("skill does not mention %s", tool)
		}
	}
	// So must the refusals it tells the model how to handle.
	for _, r := range []refusal.Type{refusal.GrantRequired, refusal.UnknownSecret, refusal.UserDeclined, refusal.DumpCommand} {
		if !strings.Contains(s, "`"+string(r)+"`") {
			t.Errorf("skill does not mention refusal %s", r)
		}
	}
	if bytes.Contains(skill.Content, []byte("TESTSECRET_")) {
		t.Fatal("skill holds a fixture value")
	}
}

func TestApplyInstallsTheSkillOnceAndThenWritesNothing(t *testing.T) {
	env := newEnv(t)
	h := skillHost{"claude-code", skill.ClaudePath}
	res := mustApply(t, env, h)
	if !res[0].Changed() {
		t.Fatal("first apply did not write")
	}
	p, _ := skill.ClaudePath(env)
	if b, err := os.ReadFile(p); err != nil || !bytes.Equal(b, skill.Content) {
		t.Fatalf("installed skill differs: %v", err)
	}
	if res := mustApply(t, env, h); res[0].Changed() {
		t.Fatal("second apply wrote again")
	}
	st, _ := vault.ReadHosts(env.VaultHome)
	if checks := hosts.Verify(env, h, st["claude-code"]); checks[0].Err != nil {
		t.Fatalf("verify = %v", checks[0].Err)
	}
}

func TestAStaleSkillIsDriftAndApplyUpdatesIt(t *testing.T) {
	env := newEnv(t)
	h := skillHost{"claude-code", skill.ClaudePath}
	mustApply(t, env, h)
	p, _ := skill.ClaudePath(env)
	old := strings.Replace(string(skill.Content), "# qbit-vault", "# qbit-vault (older text)", 1)
	if err := os.WriteFile(p, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	st, _ := vault.ReadHosts(env.VaultHome)
	if checks := hosts.Verify(env, h, st["claude-code"]); !errors.Is(checks[0].Err, hosts.ErrDrift) {
		t.Fatalf("verify = %v, want drift", checks[0].Err)
	}
	if res := mustApply(t, env, h); !res[0].Changed() {
		t.Fatal("apply did not update the stale skill")
	}
	if b, _ := os.ReadFile(p); !bytes.Equal(b, skill.Content) {
		t.Fatal("skill not updated")
	}
}

// A skill of the same name the user wrote wins: registration succeeds without
// touching it, doctor accepts it, and uninstall leaves it.
func TestTheUsersOwnSkillOfTheSameNameIsLeftAlone(t *testing.T) {
	env := newEnv(t)
	h := skillHost{"claude-code", skill.ClaudePath}
	p, _ := skill.ClaudePath(env)
	const mine = "---\nname: qbit-vault\n---\nmine\n"
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(mine), 0o600); err != nil {
		t.Fatal(err)
	}
	res := mustApply(t, env, h)
	if res[0].Changed() {
		t.Fatal("the user's skill was rewritten")
	}
	st, _ := vault.ReadHosts(env.VaultHome)
	if checks := hosts.Verify(env, h, st["claude-code"]); checks[0].Err != nil {
		t.Fatalf("verify = %v, want ok", checks[0].Err)
	}
	if steps, err := hosts.RevertHost(env, h); err != nil || steps[0].Outcome != filemerge.Unchanged {
		t.Fatalf("revert = %+v, %v", steps, err)
	}
	if b, _ := os.ReadFile(p); string(b) != mine {
		t.Fatalf("user's skill changed: %q", b)
	}
}

func TestASharedSkillStaysUntilTheLastHostIsRemoved(t *testing.T) {
	env := newEnv(t)
	codex := skillHost{"codex", skill.AgentsPath}
	pi := skillHost{"pi", skill.AgentsPath}
	mustApply(t, env, codex, pi)
	p, _ := skill.AgentsPath(env)

	if steps, err := hosts.RevertHost(env, codex); err != nil || steps[0].Outcome != filemerge.Unchanged {
		t.Fatalf("revert codex = %+v, %v", steps, err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal("the skill pi still uses was removed")
	}
	if steps, err := hosts.RevertHost(env, pi); err != nil || steps[0].Outcome != filemerge.Deleted {
		t.Fatalf("revert pi = %+v, %v", steps, err)
	}
	if _, err := os.Stat(filepath.Dir(p)); !os.IsNotExist(err) {
		t.Fatal("the skill directory was kept")
	}
}

func TestTheAdaptersInstallTheSkillWhereEachAgentReadsIt(t *testing.T) {
	env := newEnv(t)
	exe, _ := filepath.Abs(filepath.FromSlash("/opt/qbit/bin/qbit-vault"))
	noEnv := func(string) string { return "" }
	res := mustApply(t, env, claude.NewWithExe(exe), codex.NewWithExe(exe), pi.NewWithExe(exe).WithGetenv(noEnv))
	var changed []bool
	for _, r := range res {
		changed = append(changed, r.Steps[len(r.Steps)-1].Changed)
	}
	// Claude writes its own copy, Codex creates the shared one, Pi finds it current.
	if changed[0] != true || changed[1] != true || changed[2] != false {
		t.Fatalf("skill step changed per host = %v, want [true true false]", changed)
	}
	for _, p := range []func(hosts.Env) (string, error){skill.ClaudePath, skill.AgentsPath} {
		path, _ := p(env)
		if b, err := os.ReadFile(path); err != nil || !bytes.Equal(b, skill.Content) {
			t.Fatalf("%s: %v", path, err)
		}
	}
	if _, err := os.Stat(filepath.Join(env.UserHome, ".pi", "agent", "skills")); !os.IsNotExist(err) {
		t.Fatal("pi got a second copy that would collide with ~/.agents/skills")
	}
}
