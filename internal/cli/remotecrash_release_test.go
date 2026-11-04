//go:build !crashseam

package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func goListFiles(t *testing.T, tags string) string {
	t.Helper()
	args := []string{"list", "-f", `{{join .GoFiles " "}}`}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	out, err := exec.Command("go", append(args, ".")...).Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	return string(out)
}

// The rotation crash seam is not compiled into a release build.
func TestRotateCrashSeamIsOnlyInTaggedBuilds(t *testing.T) {
	if got := goListFiles(t, ""); strings.Contains(got, "remotecrash_on.go") || !strings.Contains(got, "remotecrash_off.go") {
		t.Fatalf("a release build compiles the crash seam: %s", got)
	}
	if got := goListFiles(t, "crashseam"); !strings.Contains(got, "remotecrash_on.go") || strings.Contains(got, "remotecrash_off.go") {
		t.Fatalf("the crashseam build lacks the seam: %s", got)
	}
}

// The compiled release binary holds no trace of the seam.
func TestReleaseBinaryHasNoRotateCrashSeam(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	bin := filepath.Join(t.TempDir(), "qbit-vault")
	if out, err := exec.Command("go", "build", "-o", bin, "../../cmd/qbit-vault").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"rotateCrash", "crashseam"} {
		if bytes.Contains(raw, []byte(marker)) {
			t.Errorf("the release binary contains %q", marker)
		}
	}
}

// The crash tests live behind the tag; run them here so a plain `go test`
// still proves the order is crash safe.
func TestCrashSeamTestsPassWithTheirTag(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles and runs the package again")
	}
	cmd := exec.Command("go", "test", "-count=1", "-tags", "crashseam", "-run", "^TestCrashAfterTheServerAcceptedIsFinishedByTheNextRound$", ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("crash tests: %v\n%s", err, out)
	}
}
