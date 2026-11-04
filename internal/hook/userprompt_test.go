package hook

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

func TestUserPromptBlocksStoredValues(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte(tsPlain))
	for _, p := range []string{
		"use " + tsPlain + " please",
		"<pasted_content id=1>\nKEY=" + tsPlain + "\n</pasted_content>",
		"basic " + b64,
		"q=" + url.QueryEscape(tsOdd),
	} {
		out, errb, code := runPrompt(t, newSource().get, promptEvent(t, p))
		if code != 0 || errb != "" || out != wantBlockStored {
			t.Fatalf("%q: out=%q err=%q code=%d", p, out, errb, code)
		}
	}
}

func TestUserPromptBlocksWellKnownShapesWithoutTheVault(t *testing.T) {
	shapes := []string{
		"ghp_" + strings.Repeat("a1", 18),
		"github_pat_" + strings.Repeat("Ab1_", 8),
		"AKIA" + strings.Repeat("ABCD1234", 2),
		"xoxb-" + "1234567890-abcdefghij",
		"sk_live_" + strings.Repeat("a1B2", 6),
		"sk-ant-" + strings.Repeat("a1B2c3", 8),
		"-----BEGIN RSA PRIVATE KEY-----",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r",
	}
	for _, s := range shapes {
		src := &source{err: ErrLocked}
		out, errb, code := runPrompt(t, src.get, promptEvent(t, "here: "+s))
		if code != 0 || errb != "" || out != wantBlockShape || src.calls != 0 {
			t.Fatalf("%q: out=%q err=%q code=%d calls=%d", s, out, errb, code, src.calls)
		}
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
