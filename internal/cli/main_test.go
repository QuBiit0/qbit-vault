package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zalando/go-keyring"

	"github.com/QuBiit0/gentle-vault/internal/vault"
)

// TestMain swaps the OS keychain for go-keyring's in-memory mock so no test
// can reach the real one. When envChild is set the test binary is the child
// process of an exec test instead (see exechelper_test.go).
func TestMain(m *testing.M) {
	if mode := os.Getenv(envChild); mode != "" {
		childMain(mode)
	}
	keyring.MockInit()
	// Isolate repository discovery from any checkout that contains %TEMP%.
	if tmp, err := filepath.EvalSymlinks(os.TempDir()); err == nil {
		vault.SetWalkStopForTesting(tmp)
	}
	os.Exit(m.Run())
}
