//go:build !e2eprompt

package prompt

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The scripted backend answers prompts from a file, so a release binary must
// not hold it: no GENTLE_VAULT_PROMPT value may reach it.
func TestScriptedBackendIsUnknownInReleaseBuilds(t *testing.T) {
	_, err := SelectWith(Env{GOOS: "linux", Getenv: func(k string) string {
		if k == EnvBackend {
			return "scripted"
		}
		return ""
	}})
	if !errors.Is(err, ErrUnknownBackend) {
		t.Fatalf("err = %v, want ErrUnknownBackend", err)
	}
}

func goList(t *testing.T, tags string) string {
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

func TestScriptedCodeIsOnlyInTaggedBuilds(t *testing.T) {
	if got := goList(t, ""); strings.Contains(got, "scripted.go") {
		t.Fatalf("a release build compiles the scripted backend: %s", got)
	}
	if got := goList(t, "e2eprompt"); !strings.Contains(got, "scripted.go") {
		t.Fatalf("the e2eprompt build lacks the scripted backend: %s", got)
	}
}

// The compiled release binary holds none of the backend's strings.
func TestReleaseBinaryHasNoScriptedBackend(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	bin := filepath.Join(t.TempDir(), "gentle-vault")
	cmd := exec.Command("go", "build", "-o", bin, "../../cmd/gentle-vault")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"GENTLE_VAULT_SCRIPTED", "e2eprompt"} {
		if bytes.Contains(raw, []byte(marker)) {
			t.Errorf("the release binary contains %q", marker)
		}
	}
}
