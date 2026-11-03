package vault

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMain isolates root discovery from any checkout that contains the temp
// directory (for example a home directory that is itself a Git repository).
func TestMain(m *testing.M) {
	if tmp, err := filepath.EvalSymlinks(os.TempDir()); err == nil {
		walkStop = tmp
	}
	os.Exit(m.Run())
}
