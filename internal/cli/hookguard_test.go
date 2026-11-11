package cli

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/exitcode"
)

// Output and write guard (odd/tasks/output-guard.md S2-S3): every case runs
// the real `hook` commands with the event on stdin.

const (
	withheldFmt   = "output withheld: qbit-vault could not check it for secrets (%s)"
	uncheckedFmt  = "qbit-vault could not check this edit for secrets (%s)"
	wantWriteOne  = "This edit would write the value of the stored secret %s to a file, so qbit-vault blocked it. Give the value to the command that needs it with secret_exec instead."
	wantWriteMany = "This edit would write the value of the stored secrets %s to a file, so qbit-vault blocked it. Give the value to the command that needs it with secret_exec instead."
)

// wantWithheldPost is the claude/pi answer for postBashEvent: the message
// takes the place of the stdout text, every other string is emptied.
func wantWithheldPost(reason string) string {
	return `{"hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":{"interrupted":false,"isImage":false,"stderr":"","stdout":"` + fmt.Sprintf(withheldFmt, reason) + `"}}}` + "\n"
}

func wantCodexBlock(reason string) string {
	b, _ := json.Marshal(reason)
	return `{"decision":"block","reason":` + string(b) + `}` + "\n"
}

func wantDeny(msg string) string {
	b, _ := json.Marshal(msg)
	return `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":` + string(b) + `}}` + "\n"
}

func preWriteEvent(t *testing.T, tool string, input map[string]any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"session_id": "abcd1234", "hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": input,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestHookPostLockedVaultWithholdsTheOutput(t *testing.T) {
	w := passphraseWorld(t)
	withBackend(t, answers()) // any prompt would fail the call
	ev := postBashEvent(t, "k="+hkA)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"hook", "post-bash"}, wantWithheldPost("vault locked")},
		{[]string{"hook", "post-bash", "--host", "claude"}, wantWithheldPost("vault locked")},
		{[]string{"hook", "post-bash", "--host", "pi"}, wantWithheldPost("vault locked")},
		{[]string{"hook", "post-bash", "--host", "codex"}, wantCodexBlock(fmt.Sprintf(withheldFmt, "vault locked"))},
		{[]string{"hook", "post-read"}, wantWithheldPost("vault locked")},
		{[]string{"hook", "post-read", "--host", "codex"}, wantCodexBlock(fmt.Sprintf(withheldFmt, "vault locked"))},
	} {
		code, out, errs := w.run(ev, c.args...)
		if code != 0 || errs != "" || out != c.want {
			t.Fatalf("%v: code=%d out=%q err=%q", c.args, code, out, errs)
		}
		noFixtures(t, "withheld output", out+errs)
	}
	// An event with no text has nothing to leak: the vault is not asked.
	if code, out, errs := w.run(postBashEvent(t, ""), "hook", "post-bash"); code != 0 || errs != "" || out != "" {
		t.Fatalf("empty: code=%d out=%q err=%q", code, out, errs)
	}
}

func TestHookPostBrokenVaultWithholdsAsInternalError(t *testing.T) {
	w := hookWorld(t)
	if err := os.WriteFile(filepath.Join(w.home, "state.json"), []byte("not a vault"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := w.run(postBashEvent(t, "k="+hkA), "hook", "post-bash")
	if code != 0 || errs != "" || out != wantWithheldPost("internal error") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	noFixtures(t, "withheld output", out+errs)
}

func TestHookPostHostProtocols(t *testing.T) {
	w := hookWorld(t)
	ev := postBashEvent(t, "k="+hkA+"\n")
	// pi answers like claude.
	for _, host := range []string{"claude", "pi"} {
		code, out, errs := w.run(ev, "hook", "post-bash", "--host", host)
		if code != 0 || errs != "" || out != postBashWant(t, "k=[REDACTED:API_KEY]\n", 1) {
			t.Fatalf("%s: code=%d out=%q err=%q", host, code, out, errs)
		}
	}
	// codex blocks with the redacted text as the reason.
	code, out, errs := w.run(ev, "hook", "post-bash", "--host", "codex")
	if code != 0 || errs != "" || out != wantCodexBlock("{\"interrupted\":false,\"isImage\":false,\"stderr\":\"\",\"stdout\":\"k=[REDACTED:API_KEY]\\n\"}") {
		t.Fatalf("codex: code=%d out=%q err=%q", code, out, errs)
	}
	// A string tool_response is the reason as is.
	str, _ := json.Marshal(map[string]any{"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_response": "out " + hkA})
	code, out, errs = w.run(string(str), "hook", "post-bash", "--host", "codex")
	if code != 0 || errs != "" || out != wantCodexBlock("out [REDACTED:API_KEY]") {
		t.Fatalf("codex string: code=%d out=%q err=%q", code, out, errs)
	}
	// No change: no output, on every host.
	for _, host := range []string{"claude", "pi", "codex"} {
		code, out, errs := w.run(postBashEvent(t, "all good"), "hook", "post-bash", "--host", host)
		if code != 0 || errs != "" || out != "" {
			t.Fatalf("%s clean: code=%d out=%q err=%q", host, code, out, errs)
		}
	}
	// No vault: nothing printed, on every host.
	bare := newBareWorld(t)
	for _, host := range []string{"claude", "pi", "codex"} {
		code, out, errs := bare.run(postBashEvent(t, "k="+hkA), "hook", "post-bash", "--host", host)
		if code != 0 || errs != "" || out != "" {
			t.Fatalf("%s no vault: code=%d out=%q err=%q", host, code, out, errs)
		}
	}
}

func TestHookUnknownHostIsAUsageError(t *testing.T) {
	w := hookWorld(t)
	for _, sub := range []string{"post-bash", "post-read", "pre-write"} {
		code, out, errs := w.run(postBashEvent(t, "k="+hkA), "hook", sub, "--host", "vim")
		if code != exitcode.Usage || out != "" || errs != usageErr("--host must be claude, codex or pi") {
			t.Fatalf("%s: code=%d out=%q err=%q", sub, code, out, errs)
		}
	}
}

func TestHookPreWriteDeniesAStoredValue(t *testing.T) {
	w := hookWorld(t)
	b64 := base64.StdEncoding.EncodeToString([]byte(hkA))
	cases := []struct {
		name, tool string
		input      map[string]any
		want       string
	}{
		{"Write raw", "Write", map[string]any{"file_path": "/p/.env", "content": "KEY=" + hkA + "\n"}, fmt.Sprintf(wantWriteOne, "API_KEY")},
		{"Edit new_string", "Edit", map[string]any{"file_path": "/p/x", "old_string": "a", "new_string": "k=" + b64}, fmt.Sprintf(wantWriteOne, "API_KEY")},
		{"MultiEdit", "MultiEdit", map[string]any{"file_path": "/p/x", "edits": []any{
			map[string]any{"old_string": "a", "new_string": "b"},
			map[string]any{"old_string": "c", "new_string": "q=" + url.QueryEscape(hkB)},
		}}, fmt.Sprintf(wantWriteOne, "ODD_KEY")},
		{"NotebookEdit", "NotebookEdit", map[string]any{"notebook_path": "/p/n.ipynb", "new_source": hkA}, fmt.Sprintf(wantWriteOne, "API_KEY")},
		{"two names", "Write", map[string]any{"file_path": "/p/x", "content": hkB + " " + hkA}, fmt.Sprintf(wantWriteMany, "API_KEY, ODD_KEY")},
	}
	for _, c := range cases {
		for _, host := range []string{"claude", "pi", "codex"} {
			t.Run(c.name+"/"+host, func(t *testing.T) {
				code, out, errs := w.run(preWriteEvent(t, c.tool, c.input), "hook", "pre-write", "--host", host)
				if code != 0 || errs != "" || out != wantDeny(c.want) {
					t.Fatalf("code=%d out=%q err=%q", code, out, errs)
				}
				noFixtures(t, "deny", out+errs)
			})
		}
	}
	// The default host is claude.
	code, out, errs := w.run(preWriteEvent(t, "Write", map[string]any{"file_path": "/p/x", "content": hkA}), "hook", "pre-write")
	if code != 0 || errs != "" || out != wantDeny(fmt.Sprintf(wantWriteOne, "API_KEY")) {
		t.Fatalf("default: code=%d out=%q err=%q", code, out, errs)
	}
}

// patchOf renders an apply_patch text (V4A) from its lines.
func patchOf(lines ...string) string {
	return "*** Begin Patch\n" + strings.Join(lines, "\n") + "\n*** End Patch"
}

// TestHookPreWriteScansOnlyWhatIsAdded: removing a stored value from a file is
// allowed, adding it is not, on every tool shape (S10.2).
func TestHookPreWriteScansOnlyWhatIsAdded(t *testing.T) {
	w := hookWorld(t)
	b64 := base64.StdEncoding.EncodeToString([]byte(hkA))
	patch := func(lines ...string) map[string]any { return map[string]any{"command": patchOf(lines...)} }
	cases := []struct {
		name, tool string
		input      map[string]any
		deny       string // API_KEY or "" for allowed
	}{
		{"Edit removes", "Edit", map[string]any{"file_path": "/p/x", "old_string": "k=" + hkA, "new_string": "k=ref"}, ""},
		{"Edit adds", "Edit", map[string]any{"file_path": "/p/x", "old_string": "k=ref", "new_string": "k=" + hkA}, "API_KEY"},
		{"MultiEdit removes", "MultiEdit", map[string]any{"file_path": "/p/x", "edits": []any{map[string]any{"old_string": hkA, "new_string": "z"}}}, ""},
		{"MultiEdit adds the second", "MultiEdit", map[string]any{"file_path": "/p/x", "edits": []any{
			map[string]any{"old_string": hkA, "new_string": "z"}, map[string]any{"old_string": "a", "new_string": b64}}}, "API_KEY"},
		{"NotebookEdit adds", "NotebookEdit", map[string]any{"notebook_path": "/p/n.ipynb", "cell_id": "c1", "edit_mode": "replace", "new_source": hkA}, "API_KEY"},
		{"Pi edit removes", "edit", map[string]any{"path": "/p/x", "edits": []any{map[string]any{"oldText": hkA, "newText": "z"}}}, ""},
		{"Pi edit adds", "edit", map[string]any{"path": "/p/x", "edits": []any{map[string]any{"oldText": "a", "newText": hkA}}}, "API_KEY"},
		{"Pi write adds", "write", map[string]any{"path": "/p/x", "content": hkA}, "API_KEY"},
		{"patch removes a line", "apply_patch", patch("*** Update File: /p/x", "@@", " keep", "-k="+hkA, "+k=ref"), ""},
		{"patch context line", "apply_patch", patch("*** Update File: /p/x", "@@ func main", " k="+hkA, "+added"), ""},
		{"patch deletes a file", "apply_patch", patch("*** Delete File: /p/x"), ""},
		{"patch adds a line", "apply_patch", patch("*** Update File: /p/x", "@@", " keep", "-old", "+k="+hkA), "API_KEY"},
		{"patch adds a file", "apply_patch", patch("*** Add File: /p/.env", "+A=1", "+KEY="+hkA), "API_KEY"},
		{"patch value in a later file", "apply_patch", patch("*** Update File: /p/a", "@@", "-"+hkA, "+x", "*** Add File: /p/b", "+"+hkB), "ODD_KEY"},
		{"patch as Edit alias", "Edit", patch("*** Update File: /p/x", "@@", "+"+hkA), "API_KEY"},
		{"unknown tool scans everything", "mcp__files__rewrite", map[string]any{"old_string": hkA, "new_string": "z"}, "API_KEY"},
		{"unknown key scans everything", "Edit", map[string]any{"file_path": "/p/x", "old_string": "a", "new_string": "b", "insert": hkA}, "API_KEY"},
		{"command that is not a patch scans everything", "apply_patch", map[string]any{"command": "echo " + hkA}, "API_KEY"},
	}
	for _, c := range cases {
		for _, host := range []string{"claude", "pi", "codex"} {
			t.Run(c.name+"/"+host, func(t *testing.T) {
				code, out, errs := w.run(preWriteEvent(t, c.tool, c.input), "hook", "pre-write", "--host", host)
				want := ""
				if c.deny != "" {
					want = wantDeny(fmt.Sprintf(wantWriteOne, c.deny))
				}
				if code != 0 || errs != "" || out != want {
					t.Fatalf("code=%d out=%q err=%q", code, out, errs)
				}
				noFixtures(t, "pre-write", out+errs)
			})
		}
	}
}

func TestHookPreWriteListsAtMostFiveNames(t *testing.T) {
	w := newExecWorld(t)
	var content strings.Builder
	for _, n := range []string{"A_KEY", "B_KEY", "C_KEY", "D_KEY", "E_KEY", "F_KEY", "G_KEY"} {
		v := "TESTSECRET_many_" + n + "_0123456789"
		w.setSecret(n, v)
		content.WriteString(v + "\n")
	}
	code, out, errs := w.run(preWriteEvent(t, "Write", map[string]any{"file_path": "/p/x", "content": content.String()}), "hook", "pre-write")
	if code != 0 || errs != "" || out != wantDeny(fmt.Sprintf(wantWriteMany, "A_KEY, B_KEY, C_KEY, D_KEY, E_KEY and 2 more")) {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	noFixtures(t, "deny", out+errs)
}

func TestHookPreWriteAllowsSilently(t *testing.T) {
	w := hookWorld(t)
	w.putText("PANEL_URL", "TESTSECRET_https://dokploy.example.test")
	for _, in := range []map[string]any{
		{"file_path": "/p/x", "content": "nothing here\n"},
		{"file_path": "/p/x", "content": "TESTSECRET_other_value_123"},
		{"file_path": "/p/x", "content": "see TESTSECRET_https://dokploy.example.test"}, // a visible (text) value is not a secret
		{"file_path": "/p/x", "content": ""},
	} {
		for _, host := range []string{"claude", "pi", "codex"} {
			code, out, errs := w.run(preWriteEvent(t, "Write", in), "hook", "pre-write", "--host", host)
			if code != 0 || errs != "" || out != "" {
				t.Fatalf("%s %v: code=%d out=%q err=%q", host, in, code, out, errs)
			}
		}
	}
	bare := newBareWorld(t)
	code, out, errs := bare.run(preWriteEvent(t, "Write", map[string]any{"file_path": "/p/x", "content": hkA}), "hook", "pre-write")
	if code != 0 || errs != "" || out != "" {
		t.Fatalf("no vault: code=%d out=%q err=%q", code, out, errs)
	}
}

func TestHookPreWriteCannotCheck(t *testing.T) {
	ev := func(t *testing.T) string {
		return preWriteEvent(t, "Write", map[string]any{"file_path": "/p/x", "content": "k=" + hkA})
	}
	w := passphraseWorld(t)
	withBackend(t, answers())
	for _, host := range []string{"claude", "codex"} {
		code, out, errs := w.run(ev(t), "hook", "pre-write", "--host", host)
		if code != 0 || errs != "" || out != wantDeny(fmt.Sprintf(uncheckedFmt, "vault locked")) {
			t.Fatalf("%s locked: code=%d out=%q err=%q", host, code, out, errs)
		}
		noFixtures(t, "deny", out+errs)
	}
	// An event with no text has nothing to check.
	code, out, errs := w.run(preWriteEvent(t, "Write", map[string]any{"file_path": ""}), "hook", "pre-write")
	if code != 0 || errs != "" || out != "" {
		t.Fatalf("no text: code=%d out=%q err=%q", code, out, errs)
	}
	b := hookWorld(t)
	if err := os.WriteFile(filepath.Join(b.home, "state.json"), []byte("not a vault"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs = b.run(ev(t), "hook", "pre-write")
	if code != 0 || errs != "" || out != wantDeny(fmt.Sprintf(uncheckedFmt, "internal error")) {
		t.Fatalf("broken: code=%d out=%q err=%q", code, out, errs)
	}
	noFixtures(t, "deny", out+errs)
}

func TestHookPreWriteGarbageFailsOpen(t *testing.T) {
	w := hookWorld(t)
	code, out, errs := w.run("{nope", "hook", "pre-write")
	if code != 0 || errs != "" || !strings.Contains(out, "qbit-vault hook failed") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
}

// TestHookGuardLeakBattery runs every new path (redacted, withheld, denied,
// every host) and scans all captured bytes for the fixtures in the raw,
// base64, base64url and percent-encoded forms (docs/TESTING.md § Leak battery).
func TestHookGuardLeakBattery(t *testing.T) {
	var captured strings.Builder
	capture := func(_ int, out, errs string) { captured.WriteString(out + errs) }
	w := hookWorld(t)
	for _, host := range []string{"claude", "pi", "codex"} {
		for _, sub := range []string{"post-bash", "post-read"} {
			capture(w.run(postBashEvent(t, "k="+hkA+" q="+url.QueryEscape(hkB)), "hook", sub, "--host", host))
		}
		capture(w.run(preWriteEvent(t, "Write", map[string]any{"file_path": "/p/x", "content": hkA + hkB}), "hook", "pre-write", "--host", host))
	}
	p := passphraseWorld(t)
	withBackend(t, answers())
	for _, host := range []string{"claude", "pi", "codex"} {
		capture(p.run(postBashEvent(t, "k="+hkA), "hook", "post-bash", "--host", host))
		capture(p.run(preWriteEvent(t, "Edit", map[string]any{"new_string": hkA}), "hook", "pre-write", "--host", host))
	}
	for _, host := range []string{"claude", "pi", "codex"} {
		// A removed value is allowed, an added one denied, in the same file.
		capture(w.run(preWriteEvent(t, "Edit", map[string]any{"old_string": hkA, "new_string": "ref"}), "hook", "pre-write", "--host", host))
		capture(w.run(preWriteEvent(t, "apply_patch", map[string]any{"command": patchOf("*** Update File: /p/x", "@@", "-"+hkA, "+"+hkB)}), "hook", "pre-write", "--host", host))
	}
	got := captured.String()
	for _, v := range []string{hkA, hkB} {
		for name, n := range map[string]string{
			"raw": v, "b64": base64.StdEncoding.EncodeToString([]byte(v)),
			"b64u": base64.URLEncoding.EncodeToString([]byte(v)), "pct": url.QueryEscape(v),
		} {
			if strings.Contains(got, n) {
				t.Errorf("captured hook output holds a fixture (%s)", name)
			}
		}
	}
	noFixtures(t, "captured hook output", got)
}
