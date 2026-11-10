package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/exitcode"
)

// The prompt line depends on the machine running the tests (a Windows box
// has a native dialog), so every test starts from the terminal backend.
func init() {
	describePrompt = func(*globals) (string, error) { return "tty", nil }
}

func TestDoctorNamesThePromptBackend(t *testing.T) {
	w := newWorld(t)
	old := describePrompt
	t.Cleanup(func() { describePrompt = old })
	describePrompt = func(*globals) (string, error) { return "powershell (WSL)", nil }
	code, out, errs := w.run("", "doctor")
	if code != exitcode.OK || errs != "" || doctorStatus(out, "prompt") != "ok" ||
		!strings.Contains(out, "ok    prompt       powershell (WSL)\n") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	_, out, _ = w.run("", "--json", "doctor")
	if !strings.Contains(out, `{"name":"prompt","status":"ok","detail":"powershell (WSL)"}`) {
		t.Fatalf("json: %q", out)
	}
}

func TestDoctorWarnsWhenTheNamedPromptBackendCannotRun(t *testing.T) {
	w := newWorld(t)
	old := describePrompt
	t.Cleanup(func() { describePrompt = old })
	describePrompt = func(*globals) (string, error) {
		return "", errors.New("prompt backend zenity is unavailable: zenity not found")
	}
	code, out, _ := w.run("", "doctor")
	if code != exitcode.Failure || doctorStatus(out, "prompt") != "warn" {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

func TestDoctorStaysQuietWhenThePromptIsTheTerminal(t *testing.T) {
	w := newWorld(t)
	_, out, _ := w.run("", "doctor")
	if strings.Contains(out, "prompt") {
		t.Fatalf("out=%q", out)
	}
}
