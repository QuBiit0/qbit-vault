package cli

import (
	"strings"
	"testing"
)

func runHook(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	stdinOverride = strings.NewReader(stdin)
	t.Cleanup(func() { stdinOverride = nil })
	return run(t, nil, append([]string{"hook"}, args...)...)
}

func TestHookPreBashDeniesOnStdoutOnly(t *testing.T) {
	ev := `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"qbit-vault set TESTSECRET_X"}}`
	code, out, errb := runHook(t, ev, "pre-bash")
	if code != 0 || errb != "" || !strings.Contains(out, `"permissionDecision":"deny"`) || strings.Contains(out, "TESTSECRET_") {
		t.Fatalf("out=%q err=%q code=%d", out, errb, code)
	}
}

func TestHookPreBashFailsOpenOnGarbage(t *testing.T) {
	code, out, errb := runHook(t, "{nope", "pre-bash")
	if code != 0 || errb != "" || !strings.Contains(out, "qbit-vault hook failed") {
		t.Fatalf("out=%q err=%q code=%d", out, errb, code)
	}
}

func TestHookPreBashPassesSilently(t *testing.T) {
	ev := `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`
	code, out, errb := runHook(t, ev, "pre-bash")
	if code != 0 || errb != "" || out != "" {
		t.Fatalf("out=%q err=%q code=%d", out, errb, code)
	}
}
