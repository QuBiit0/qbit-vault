package pi_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The Pi extension scans pasted text with its own copy of the secret patterns
// (docs/GENTLE_SHELL_EXTENSION.md, R-CAP-06). The two files must stay byte
// identical, like the embedded dumpguard defaults.
func TestExtensionSecretPatternsEqualDefaults(t *testing.T) {
	repo, err := os.ReadFile(filepath.Join("..", "..", "..", "defaults", "secret-patterns.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := os.ReadFile(filepath.Join("..", "..", "..", "packages", "qbit-vault-pi", "secret-patterns.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(repo, pkg) {
		t.Fatal("packages/qbit-vault-pi/secret-patterns.yaml differs from defaults/secret-patterns.yaml; copy it over")
	}
}
