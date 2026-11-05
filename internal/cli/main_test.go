package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zalando/go-keyring"

	"github.com/QuBiit0/qbit-vault/internal/prompt"
	"github.com/QuBiit0/qbit-vault/internal/vault"
)

// hostDirVars relocate a host's config dir away from the user home.
var hostDirVars = []string{"PI_CODING_AGENT_DIR", "CLAUDE_CONFIG_DIR", "CODEX_HOME"}

// TestMain swaps the OS keychain for go-keyring's in-memory mock so no test
// can reach the real one. When envChild is set the test binary is the child
// process of an exec test instead (see exechelper_test.go).
func TestMain(m *testing.M) {
	if mode := os.Getenv(envChild); mode != "" {
		childMain(mode)
	}
	keyring.MockInit()
	// No test may see the real user home: host adapters edit files such as
	// ~/.claude.json there. Every test of this binary gets a throwaway one.
	home, err := os.MkdirTemp("", "qbv-test-home")
	if err != nil {
		panic("cannot create a throwaway user home")
	}
	for _, k := range []string{"USERPROFILE", "HOME"} {
		if err := os.Setenv(k, home); err != nil {
			panic("cannot isolate the user home")
		}
	}
	// A host config dir override would bypass the throwaway home.
	for _, k := range hostDirVars {
		if err := os.Unsetenv(k); err != nil {
			panic("cannot clear a host config override")
		}
	}
	// No test may reach a real terminal: by default there is none. Tests that
	// need one install a fake with withBackend or asTerminal.
	newPrompt = func(*globals) (prompt.Backend, error) { return nil, prompt.ErrNoTerminal }
	// Isolate repository discovery from any checkout that contains %TEMP%.
	if tmp, err := filepath.EvalSymlinks(os.TempDir()); err == nil {
		vault.SetWalkStopForTesting(tmp)
	}
	code := m.Run()
	_ = os.RemoveAll(home)
	os.Exit(code)
}
