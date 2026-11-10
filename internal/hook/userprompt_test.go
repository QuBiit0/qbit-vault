package hook

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

const wantAdvice = "If you typed or pasted it, store it with 'qbit-vault set NAME' in your own terminal and refer to it by name. If it came from a background job or another agent's report, the command printed the value: run it through qbit-vault (secret_exec), which redacts its output."

// wantBlock is the exact hook output for a block with this reason.
func wantBlock(reason string) string {
	return `{"decision":"block","reason":` + plainJSON(reason) + `,"hookSpecificOutput":{"hookEventName":"UserPromptSubmit","suppressOriginalPrompt":true}}` + "\n"
}

func wantStored(what string) string {
	return "This message contains the value of the stored " + what + ", so qbit-vault blocked it. " + wantAdvice
}

func wantShape(what string) string {
	return "This message looks like it contains " + what + ", so qbit-vault blocked it. " + wantAdvice
}

func TestUserPromptBlocksStoredValuesAndNamesThem(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte(tsPlain))
	for _, c := range []struct{ prompt, name string }{
		{"use " + tsPlain + " please", "API_KEY"},
		{"<pasted_content id=1>\nKEY=" + tsPlain + "\n</pasted_content>", "API_KEY"},
		{"basic " + b64, "API_KEY"},
		{"q=" + url.QueryEscape(tsOdd), "ODD_KEY"},
	} {
		out, errb, code := runPrompt(t, newSource().get, promptEvent(t, c.prompt))
		if code != 0 || errb != "" || out != wantBlock(wantStored("secret "+c.name)) {
			t.Fatalf("%q: out=%q err=%q code=%d", c.prompt, out, errb, code)
		}
	}
}

func TestUserPromptNamesAreSortedUniqueAndCapped(t *testing.T) {
	vals := map[string]string{}
	var names []string
	for _, n := range []string{"G", "C", "A", "F", "B", "E", "D"} {
		vals[n+"_KEY"] = "TESTSECRET_many_" + n + "_0123456789"
		names = append(names, n+"_KEY")
	}
	src := &source{vals: vals}
	var msg string
	for _, n := range names {
		msg += vals[n] + " "
	}
	out, _, _ := runPrompt(t, src.get, promptEvent(t, msg))
	if want := wantBlock(wantStored("secrets A_KEY, B_KEY, C_KEY, D_KEY, E_KEY and 2 more")); out != want {
		t.Fatalf("seven: %q", out)
	}
	for _, n := range names {
		if strings.Contains(out, vals[n]) {
			t.Fatal("value leaked")
		}
	}
	out, _, _ = runPrompt(t, newSource().get, promptEvent(t, tsOdd+" and "+tsPlain))
	if want := wantBlock(wantStored("secrets API_KEY, ODD_KEY")); out != want {
		t.Fatalf("two: %q", out)
	}
	out, _, _ = runPrompt(t, newSource().get, promptEvent(t, tsPlain+" "+tsPlain+" "+tsPlain))
	if want := wantBlock(wantStored("secret API_KEY")); out != want {
		t.Fatalf("twice: %q", out)
	}
	five := &source{vals: map[string]string{}}
	msg = ""
	for _, n := range []string{"E", "D", "C", "B", "A"} {
		five.vals[n+"_KEY"] = "TESTSECRET_five_" + n + "_0123456789"
		msg += five.vals[n+"_KEY"] + " "
	}
	out, _, _ = runPrompt(t, five.get, promptEvent(t, msg))
	if want := wantBlock(wantStored("secrets A_KEY, B_KEY, C_KEY, D_KEY, E_KEY")); out != want {
		t.Fatalf("five: %q", out)
	}
}

func TestUserPromptIgnoresATokenAlreadyInTheMessage(t *testing.T) {
	msg := "see [REDACTED:OTHER] and " + tsPlain
	out, _, _ := runPrompt(t, newSource().get, promptEvent(t, msg))
	if want := wantBlock(wantStored("secret API_KEY")); out != want {
		t.Fatalf("out=%q", out)
	}
	for _, leak := range []string{"TESTSECRET_", "OTHER", "see "} {
		if strings.Contains(out, leak) {
			t.Fatalf("reason holds %q: %s", leak, out)
		}
	}
	// A literal token of the same name as a stored value still reports it.
	out, _, _ = runPrompt(t, newSource().get, promptEvent(t, "[REDACTED:API_KEY] "+tsPlain))
	if want := wantBlock(wantStored("secret API_KEY")); out != want {
		t.Fatalf("same name: %q", out)
	}
	// Only a literal token and nothing stored: nothing to block.
	out, _, _ = runPrompt(t, newSource().get, promptEvent(t, "[REDACTED:API_KEY] is shown by exec"))
	if out != "" {
		t.Fatalf("literal token alone blocked: %q", out)
	}
}

func TestUserPromptBlocksWellKnownShapesAndNamesTheKind(t *testing.T) {
	cases := []struct{ label, sample string }{
		{"a GitHub token", "gh" + "p_" + strings.Repeat("a1", 18)},
		{"a GitHub fine-grained token", "github" + "_pat_" + strings.Repeat("Ab1_", 8)},
		{"an AWS access key", "AK" + "IA" + strings.Repeat("ABCD1234", 2)},
		{"a Slack token", "xo" + "xb-" + "1234567890-abcdefghij"},
		{"a Stripe live key", "sk" + "_live_" + strings.Repeat("a1B2", 6)},
		{"an API key", "s" + "k-ant-" + strings.Repeat("a1B2c3", 8)},
		{"a private key", "-----BEGIN RSA " + "PRIVATE KEY-----"},
		{"a JWT", "ey" + "JhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r"},
	}
	for _, c := range cases {
		src := &source{err: ErrLocked}
		out, errb, code := runPrompt(t, src.get, promptEvent(t, "here: "+c.sample))
		if code != 0 || errb != "" || out != wantBlock(wantShape(c.label)) || src.calls != 0 {
			t.Fatalf("%s: out=%q err=%q code=%d calls=%d", c.label, out, errb, code, src.calls)
		}
		if strings.Contains(out, c.sample) {
			t.Fatalf("%s: sample echoed", c.label)
		}
	}
	// Several shapes: the first in table order is named.
	both := "ey" + "JhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r " + "gh" + "p_" + strings.Repeat("a1", 18)
	out, _, _ := runPrompt(t, newSource().get, promptEvent(t, both))
	if out != wantBlock(wantShape("a GitHub token")) {
		t.Fatalf("order: %q", out)
	}
}

func TestUserPromptCleanIsSilent(t *testing.T) {
	for _, p := range []string{"fix the build", "the sk-learn docs and ghp_ prefix talk", "AKIA is a prefix"} {
		out, errb, code := runPrompt(t, newSource().get, promptEvent(t, p))
		if code != 0 || errb != "" || out != "" {
			t.Fatalf("%q: out=%q err=%q code=%d", p, out, errb, code)
		}
	}
	src := newSource()
	if out, _, _ := runPrompt(t, src.get, promptEvent(t, "  \n")); out != "" || src.calls != 0 {
		t.Fatalf("blank prompt: out=%q calls=%d", out, src.calls)
	}
}

func TestUserPromptFailsOpen(t *testing.T) {
	in := promptEvent(t, "fix the build")
	out, errb, code := runPrompt(t, (&source{err: ErrLocked}).get, in)
	if code != 0 || errb != "" || out != wantLockedPrompt {
		t.Fatalf("locked: out=%q err=%q code=%d", out, errb, code)
	}
	out, errb, code = runPrompt(t, (&source{err: errString("boom")}).get, in)
	want := strings.Replace(wantWarn, "PreToolUse", "UserPromptSubmit", 1)
	if code != 0 || errb != "" || out != want {
		t.Fatalf("error: out=%q err=%q code=%d", out, errb, code)
	}
}

type errString string

func (e errString) Error() string { return string(e) }
