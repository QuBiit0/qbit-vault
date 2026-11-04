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
