package cli

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/qbitdevz/qbit-vault/internal/secret"
	"github.com/qbitdevz/qbit-vault/internal/vault"
)

const (
	hkA = "TESTSECRET_hook_api_0123456789"
	hkB = `TESTSECRET_hook_q"x\y/+_0123456789`
)

const (
	wantHookLockedPost   = `{"systemMessage":"qbit-vault could not check this output for secrets (vault locked); run 'qbit-vault unlock'","hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":"qbit-vault could not check this output for secrets (vault locked); run 'qbit-vault unlock'"}}` + "\n"
	wantHookLockedPrompt = `{"systemMessage":"qbit-vault could not check this prompt for secrets (vault locked); run 'qbit-vault unlock'","hookSpecificOutput":{"hookEventName":"UserPromptSubmit","additionalContext":"qbit-vault could not check this prompt for secrets (vault locked); run 'qbit-vault unlock'"}}` + "\n"
	wantHookBlockFmt     = `{"decision":"block","reason":"This message contains the value of the stored secret %s, so qbit-vault blocked it. If you typed or pasted it, store it with 'qbit-vault set NAME' in your own terminal and refer to it by name. If it came from a background job or another agent's report, the command printed the value: run it through qbit-vault (secret_exec), which redacts its output.","hookSpecificOutput":{"hookEventName":"UserPromptSubmit","suppressOriginalPrompt":true}}` + "\n"
)

func postBashEvent(t *testing.T, stdout string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"session_id": "abcd1234", "hook_event_name": "PostToolUse", "tool_name": "Bash",
		"tool_input":    map[string]any{"command": "cat .env"},
		"tool_response": map[string]any{"stdout": stdout, "stderr": "", "interrupted": false, "isImage": false},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func postBashWant(t *testing.T, stdout string, n int) string {
	t.Helper()
	b, err := json.Marshal(stdout)
	if err != nil {
		t.Fatal(err)
	}
	cnt, _ := json.Marshal(n)
	return `{"hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":"qbit-vault redacted ` + string(cnt) + ` occurrence(s) of stored secrets","updatedToolOutput":{"interrupted":false,"isImage":false,"stderr":"","stdout":` + string(b) + `}}}` + "\n"
}

func hookWorld(t *testing.T) *world {
	t.Helper()
	w := newExecWorld(t)
	w.setSecret("API_KEY", hkA)
	w.setSecret("ODD_KEY", hkB)
	w.grantTo("claude:abcd1234", "API_KEY", "session")
	return w
}

func TestHookPostBashRedactsThroughTheVault(t *testing.T) {
	w := hookWorld(t)
	b64 := base64.StdEncoding.EncodeToString([]byte(hkA))
	cases := []struct{ name, in, want string }{
		{"raw", "k=" + hkA + "\n", "k=[REDACTED:API_KEY]\n"},
		{"base64", "k=" + b64 + "\n", "k=[REDACTED:API_KEY]\n"},
		{"url-encoded", "q=" + url.QueryEscape(hkB), "q=[REDACTED:ODD_KEY]"},
		{"json-escaped", `{"k":` + func() string { b, _ := json.Marshal(hkB); return string(b) }() + `}`, `{"k":"[REDACTED:ODD_KEY]"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out, errs := w.run(postBashEvent(t, c.in), "hook", "post-bash")
			if code != 0 || errs != "" || out != postBashWant(t, c.want, 1) {
				t.Fatalf("code=%d out=%q err=%q", code, out, errs)
			}
			noFixtures(t, "hook output", out+errs)
		})
	}
}

func TestHookPostReadRedacts(t *testing.T) {
	w := hookWorld(t)
	ev, _ := json.Marshal(map[string]any{
		"hook_event_name": "PostToolUse", "tool_name": "Read",
		"tool_input":    map[string]any{"file_path": "/p/x"},
		"tool_response": map[string]any{"type": "text", "file": map[string]any{"filePath": "/p/x", "content": "1\tk=" + hkA, "numLines": 1}},
	})
	code, out, errs := w.run(string(ev), "hook", "post-read")
	want := `{"hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":"qbit-vault redacted 1 occurrence(s) of stored secrets","updatedToolOutput":{"file":{"content":"1\tk=[REDACTED:API_KEY]","filePath":"/p/x","numLines":1},"type":"text"}}}` + "\n"
	if code != 0 || errs != "" || out != want {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
}

// A-F4: a file PowerShell 5.1 wrote as UTF-16LE is redacted by post-read.
func TestHookPostReadRedactsUTF16(t *testing.T) {
	w := hookWorld(t)
	var enc strings.Builder
	enc.WriteString("ÿþ")
	for _, u := range utf16.Encode([]rune(hkA)) {
		enc.WriteByte(byte(u))
		enc.WriteByte(byte(u >> 8))
	}
	ev, _ := json.Marshal(map[string]any{
		"hook_event_name": "PostToolUse", "tool_name": "Read",
		"tool_input":    map[string]any{"file_path": "/p/x"},
		"tool_response": map[string]any{"type": "text", "file": map[string]any{"filePath": "/p/x", "content": enc.String(), "numLines": 1}},
	})
	code, out, errs := w.run(string(ev), "hook", "post-read")
	if code != 0 || errs != "" || !strings.Contains(out, "[REDACTED:API_KEY]") || !strings.Contains(out, "redacted 1 occurrence(s)") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	noFixtures(t, "hook output", out+errs)
}

func TestHookPostNoMatchPrintsNothing(t *testing.T) {
	w := hookWorld(t)
	for _, in := range []string{"nothing here\n", "TESTSECRET_other_value_123", ""} {
		code, out, errs := w.run(postBashEvent(t, in), "hook", "post-bash")
		if code != 0 || errs != "" || out != "" {
			t.Fatalf("%q: code=%d out=%q err=%q", in, code, out, errs)
		}
	}
}

func TestHookPostShortValuesNeedAGrant(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("SHORT_GRANTED", "Ab1xYz")
	w.setSecret("SHORT_PLAIN", "Qw9mNp")
	w.grantTo("claude:abcd1234", "SHORT_GRANTED", "session")
	code, out, errs := w.run(postBashEvent(t, "a Ab1xYz b Qw9mNp"), "hook", "post-bash")
	if code != 0 || errs != "" || out != postBashWant(t, "a [REDACTED:SHORT_GRANTED] b Qw9mNp", 1) {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
}

func TestHookPostLockedPassphraseVaultFailsOpen(t *testing.T) {
	w := passphraseWorld(t)
	withBackend(t, answers()) // any prompt would fail the call
	code, out, errs := w.run(postBashEvent(t, "k="+hkA), "hook", "post-bash")
	if code != 0 || errs != "" || out != wantHookLockedPost {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	code, out, errs = w.run(`{"hook_event_name":"UserPromptSubmit","prompt":"fix the build"}`, "hook", "user-prompt")
	if code != 0 || errs != "" || out != wantHookLockedPrompt {
		t.Fatalf("prompt: code=%d out=%q err=%q", code, out, errs)
	}
}

func TestHookPostWithoutVaultIsSilent(t *testing.T) {
	w := newBareWorld(t)
	code, out, errs := w.run(postBashEvent(t, "k=anything"), "hook", "post-bash")
	if code != 0 || errs != "" || out != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
}

func TestHookUserPromptBlocksStoredValueWithoutEchoing(t *testing.T) {
	w := hookWorld(t)
	for _, c := range []struct{ prompt, name string }{
		{"my key is " + hkA, "API_KEY"},
		{"basic " + base64.StdEncoding.EncodeToString([]byte(hkA)), "API_KEY"},
		{"q=" + url.QueryEscape(hkB), "ODD_KEY"},
	} {
		ev, _ := json.Marshal(map[string]any{"hook_event_name": "UserPromptSubmit", "prompt": c.prompt})
		code, out, errs := w.run(string(ev), "hook", "user-prompt")
		if code != 0 || errs != "" || out != fmt.Sprintf(wantHookBlockFmt, c.name) {
			t.Fatalf("code=%d out=%q err=%q", code, out, errs)
		}
		noFixtures(t, "hook output", out+errs)
	}
	code, out, errs := w.run(`{"hook_event_name":"UserPromptSubmit","prompt":"fix the build"}`, "hook", "user-prompt")
	if code != 0 || errs != "" || out != "" {
		t.Fatalf("clean: code=%d out=%q err=%q", code, out, errs)
	}
}

// putText stores a visible (`kind: text`) global entry, as a `text` field of
// `secret_request` does.
func (w *world) putText(name, value string) {
	w.t.Helper()
	g := &globals{getenv: envFrom(nil), home: w.home}
	s, err := g.openSession()
	if err != nil {
		w.t.Fatal(err)
	}
	defer s.close()
	if err := s.v.Put(vault.Global(), name, vault.Record{Value: secret.New(name, []byte(value)), Kind: "text"}); err != nil {
		w.t.Fatal(err)
	}
}

func TestHookUserPromptLetsTextEntriesThrough(t *testing.T) {
	const url = "TESTSECRET_https://dokploy.example.test"
	const shaped = "ghp_TESTSECRETtextshaped0123456789abcdefgh"
	w := hookWorld(t)
	w.putText("PANEL_URL", url)
	w.putText("SHAPED_TEXT", shaped)
	prompt := func(p string) (int, string, string) {
		ev, _ := json.Marshal(map[string]any{"hook_event_name": "UserPromptSubmit", "prompt": p})
		return w.run(string(ev), "hook", "user-prompt")
	}
	for _, p := range []string{"deploy to " + url, "basic " + base64.StdEncoding.EncodeToString([]byte(url))} {
		if code, out, errs := prompt(p); code != 0 || errs != "" || out != "" {
			t.Fatalf("text only %q: code=%d out=%q err=%q", p, code, out, errs)
		}
	}
	code, out, errs := prompt("deploy to " + url + " with " + hkA)
	if code != 0 || errs != "" || out != fmt.Sprintf(wantHookBlockFmt, "API_KEY") {
		t.Fatalf("text and secret: code=%d out=%q err=%q", code, out, errs)
	}
	noFixtures(t, "hook output", out+errs)
	code, out, errs = prompt("token " + shaped)
	if code != 0 || errs != "" || !strings.Contains(out, `"reason":"This message looks like it contains a GitHub token, so qbit-vault blocked it.`) {
		t.Fatalf("shaped text: code=%d out=%q err=%q", code, out, errs)
	}
	// Output redaction still covers a text entry.
	code, out, errs = w.run(postBashEvent(t, "url="+url), "hook", "post-bash")
	if code != 0 || errs != "" || out != postBashWant(t, "url=[REDACTED:PANEL_URL]", 1) {
		t.Fatalf("post-bash: code=%d out=%q err=%q", code, out, errs)
	}
}

func TestHookGarbageOnPostCommandsFailsOpen(t *testing.T) {
	w := hookWorld(t)
	for _, sub := range []string{"post-bash", "post-read", "user-prompt"} {
		code, out, errs := w.run("{nope", "hook", sub)
		if code != 0 || errs != "" || !strings.Contains(out, "qbit-vault hook failed") {
			t.Fatalf("%s: code=%d out=%q err=%q", sub, code, out, errs)
		}
	}
}

// TestHookPostLatency logs the cost of a whole in-process hook run with a
// vault of ten secrets (open, list, decode grants, redact, answer), and of
// the empty-output path that never opens the vault. It asserts nothing about
// time; run with -v to read it.
func TestHookPostLatency(t *testing.T) {
	w := newExecWorld(t)
	for i := 0; i < 10; i++ {
		w.setSecret("LAT_KEY_"+string(rune('A'+i)), "TESTSECRET_latency_"+strings.Repeat(string(rune('a'+i)), 20))
	}
	const n = 50
	for _, c := range []struct{ name, stdout string }{
		{"empty output", ""},
		{"2 KB, no match", strings.Repeat("0123456789abcdef", 128)},
		{"2 KB, 1 match", strings.Repeat("0123456789abcdef", 64) + "TESTSECRET_latency_" + strings.Repeat("a", 20)},
	} {
		ev := postBashEvent(t, c.stdout)
		start := time.Now()
		for i := 0; i < n; i++ {
			if code, _, errs := w.run(ev, "hook", "post-bash"); code != 0 || errs != "" {
				t.Fatalf("code=%d err=%q", code, errs)
			}
		}
		t.Logf("%-16s %v per run", c.name, time.Since(start)/n)
	}
}
