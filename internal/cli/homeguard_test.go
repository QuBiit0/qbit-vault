package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// No test of this package may see the real user home: host adapters write
// ~/.claude.json and friends, and a test that reached them once edited the
// developer's real Claude Code configuration. TestMain points the user home
// at a throwaway directory for the whole binary.
func TestUserHomeIsAThrowawayDirectory(t *testing.T) {
	got, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("user home: %v", err)
	}
	tmp, _ := filepath.EvalSymlinks(os.TempDir())
	real, _ := filepath.EvalSymlinks(got)
	if tmp == "" || !strings.HasPrefix(strings.ToLower(real), strings.ToLower(tmp)) || !strings.Contains(filepath.Base(real), "qbv-test-home") {
		t.Fatalf("tests run with the user home %q, not a throwaway directory under %q", got, tmp)
	}
}

// Variables that relocate a host's config dir would point an adapter at the
// developer's real config even with a throwaway home (Pi sets
// PI_CODING_AGENT_DIR for the processes it starts). TestMain clears them.
func TestHostConfigDirOverridesAreCleared(t *testing.T) {
	for _, k := range hostDirVars {
		if v, ok := os.LookupEnv(k); ok {
			t.Fatalf("%s is set to %q in the test process", k, v)
		}
	}
}
