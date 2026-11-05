package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Read errors must name the file, never the vault home path.
func TestReadErrorsOmitHomePath(t *testing.T) {
	home := filepath.Join(t.TempDir(), "homemarker")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := Open(home, testKey(1))
	if err == nil {
		t.Fatal("Open on an empty home succeeded")
	}
	if strings.Contains(err.Error(), "homemarker") {
		t.Fatalf("error contains the home path")
	}

	if _, err := loadState(home); err == nil || strings.Contains(err.Error(), "homemarker") {
		t.Fatalf("loadState error missing or contains the home path")
	}
}

// Leftover temp files are cleaned even when the home path contains glob
// metacharacters.
func TestCleanTempsWithGlobMetacharacters(t *testing.T) {
	home := filepath.Join(t.TempDir(), "br[b]kt")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, vaultFile)
	leftover := target + ".tmp.1.deadbeef"
	unrelated := filepath.Join(home, "other.tmp.1.deadbeef")
	for _, p := range []string{leftover, unrelated} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cleanTemps(target)
	if _, err := os.Stat(leftover); !os.IsNotExist(err) {
		t.Fatalf("leftover temp file was not removed")
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatalf("unrelated file was removed")
	}
}
