package hook

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/qbitdevz/qbit-vault/internal/redact"
)

// S2.2: when the check cannot run the output is withheld, with a fixed reason.
func TestPostWithholdsWhenItCannotCheck(t *testing.T) {
	in := postEvent(t, "posttooluse_bash.json", "KEY="+tsPlain)
	cases := []struct {
		name   string
		src    Source
		reason string
	}{
		{"locked", (&source{err: ErrLocked}).get, "vault locked"},
		{"locked, wrapped", (&source{err: errors.Join(errors.New("x"), ErrLocked)}).get, "vault locked"},
		{"other error", (&source{err: errors.New("boom " + tsPlain)}).get, "internal error"},
		{"panic", func() (*redact.Redactor, error) { panic(tsPlain) }, "internal error"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, errb, code := runPost(t, c.src, in)
			msg := "output withheld: qbit-vault could not check it for secrets (" + c.reason + ")"
			want := `{"hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":{"interrupted":false,"isImage":false,"stderr":"","stdout":"` + msg + `"}}}` + "\n"
			if code != 0 || errb != "" || out != want {
				t.Fatalf("out=%q err=%q code=%d", out, errb, code)
			}
			var codex bytes.Buffer
			if RunPostWith(bytes.NewReader(in), &codex, &bytes.Buffer{}, c.src, HostCodex) != 0 ||
				codex.String() != `{"decision":"block","reason":"`+msg+`"}`+"\n" {
				t.Fatalf("codex: %q", codex.String())
			}
			if strings.Contains(out+codex.String(), "TESTSECRET_") {
				t.Fatal("value leaked")
			}
		})
	}
}

func TestPostGarbageFailsOpen(t *testing.T) {
	out, errb, code := runPost(t, newSource().get, []byte("{nope"))
	if code != 0 || errb != "" || out != strings.Replace(wantWarn, "PreToolUse", "PostToolUse", 1) {
		t.Fatalf("out=%q err=%q code=%d", out, errb, code)
	}
}

// The withheld text keeps the shape of the tool result and drops every other
// string, so nothing of the original (the path, the value) survives.
func TestPostWithheldKeepsTheShape(t *testing.T) {
	locked := (&source{err: ErrLocked}).get
	msg := withheldText("vault locked")
	cases := []struct{ name, event, want string }{
		{"read", string(postEvent(t, "posttooluse_read.json", "k="+tsPlain)),
			`{"file":{"content":"` + msg + `","filePath":"","numLines":2,"startLine":1,"totalLines":2},"type":""}`},
		{"grep", `{"hook_event_name":"PostToolUse","tool_name":"Grep","tool_response":{"mode":"content","numFiles":1,"filenames":["/a/b"],"content":"a:` + tsPlain + `","numLines":1}}`,
			`{"content":"` + msg + `","filenames":[""],"mode":"","numFiles":1,"numLines":1}`},
		{"glob, longest string", `{"hook_event_name":"PostToolUse","tool_name":"Glob","tool_response":{"filenames":["/a","/a/bcd/` + tsPlain + `"],"numFiles":2}}`,
			`{"filenames":["","` + msg + `"],"numFiles":2}`},
		{"string result", `{"hook_event_name":"PostToolUse","tool_name":"x","tool_response":"` + tsPlain + `"}`, `"` + msg + `"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, errb, code := runPost(t, locked, []byte(c.event))
			want := `{"hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":` + c.want + `}}` + "\n"
			if code != 0 || errb != "" || out != want {
				t.Fatalf("out=%q err=%q code=%d", out, errb, code)
			}
		})
	}
}

// An event above the size limit cannot be parsed: with values to check the
// output is withheld, without them it passes.
func TestPostOversizeEvent(t *testing.T) {
	if _, over, err := readRaw(strings.NewReader(strings.Repeat("a", 4096)), 1024); err != nil || !over {
		t.Fatalf("readRaw over=%v err=%v", over, err)
	}
	run := func(src Source, host Host) string {
		var out bytes.Buffer
		emit(&out, postOversize(src, host))
		return out.String()
	}
	const msg = "output withheld: qbit-vault could not check it for secrets ("
	if got := run(newSource().get, HostClaude); got != `{"hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":"`+msg+`output too large)"}}`+"\n" {
		t.Fatalf("claude: %q", got)
	}
	if got := run(newSource().get, HostCodex); got != `{"decision":"block","reason":"`+msg+`output too large)"}`+"\n" {
		t.Fatalf("codex: %q", got)
	}
	if got := run((&source{err: ErrLocked}).get, HostPi); !strings.Contains(got, "(vault locked)") {
		t.Fatalf("locked: %q", got)
	}
	if got := run(func() (*redact.Redactor, error) { return nil, nil }, HostClaude); got != "" {
		t.Fatalf("no vault: %q", got)
	}
	if got := run(func() (*redact.Redactor, error) { return redact.New(nil) }, HostClaude); got != "" {
		t.Fatalf("no values: %q", got)
	}
}

func TestPreWriteOversizeEvent(t *testing.T) {
	run := func(src Source) string {
		var out bytes.Buffer
		emit(&out, preWriteOversize(src))
		return out.String()
	}
	deny := func(reason string) string {
		return `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"qbit-vault could not check this edit for secrets (` + reason + `)"}}` + "\n"
	}
	if got := run(newSource().get); got != deny("edit too large") {
		t.Fatalf("values: %q", got)
	}
	if got := run((&source{err: ErrLocked}).get); got != deny("vault locked") {
		t.Fatalf("locked: %q", got)
	}
	if got := run(func() (*redact.Redactor, error) { return nil, nil }); got != "" {
		t.Fatalf("no vault: %q", got)
	}
}

func TestParseHost(t *testing.T) {
	for in, want := range map[string]Host{"": HostClaude, "claude": HostClaude, "codex": HostCodex, "pi": HostPi} {
		if got, ok := ParseHost(in); !ok || got != want {
			t.Fatalf("%q: %q %v", in, got, ok)
		}
	}
	if _, ok := ParseHost("vim"); ok {
		t.Fatal("vim accepted")
	}
}

// S5: a Codex block above the model-visible limit is cut after the redaction,
// on a character boundary and never inside a [REDACTED:...] marker, and ends
// with the fixed line. Every alignment of the cut against the markers runs.
func TestCodexBlockIsTruncatedAfterRedaction(t *testing.T) {
	const line = "\n[output truncated by qbit-vault]"
	for _, pad := range []string{"", "é", "日本", "😀"} {
		for shift := 0; shift < 24; shift++ {
			out := strings.Repeat("x", shift) + pad + strings.Repeat(tsPlain+" "+pad+" ", 2000)
			ev := `{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_response":` + plainJSON(out) + `}`
			var got, errb bytes.Buffer
			if code := RunPostWith(strings.NewReader(ev), &got, &errb, newSource().get, HostCodex); code != 0 || errb.Len() != 0 {
				t.Fatalf("code=%d err=%q", code, errb.String())
			}
			var o struct{ Decision, Reason string }
			if err := json.Unmarshal(got.Bytes(), &o); err != nil || o.Decision != "block" {
				t.Fatalf("answer %q: %v", got.String(), err)
			}
			if len(o.Reason) > CodexReasonLimit || !strings.HasSuffix(o.Reason, line) || len(o.Reason) < CodexReasonLimit-64 {
				t.Fatalf("pad=%q shift=%d: reason is %d bytes, tail %q", pad, shift, len(o.Reason), o.Reason[max(0, len(o.Reason)-60):])
			}
			body := strings.TrimSuffix(o.Reason, line)
			if !utf8.ValidString(body) || strings.Contains(o.Reason, "TESTSECRET_") {
				t.Fatalf("pad=%q shift=%d: invalid text or leak", pad, shift)
			}
			if strings.Count(body, "[REDACTED:") != strings.Count(body, "[REDACTED:API_KEY]") || strings.HasSuffix(body, "[") || strings.HasSuffix(body, "[REDACTED") {
				t.Fatalf("pad=%q shift=%d: a marker was split: %q", pad, shift, body[max(0, len(body)-40):])
			}
		}
	}
}

// A redacted output under the limit is not touched, and neither is a withheld
// one.
func TestCodexBlockUnderTheLimitIsNotCut(t *testing.T) {
	out := strings.Repeat("y", CodexReasonLimit-100) + tsPlain
	ev := `{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_response":` + plainJSON(out) + `}`
	var got bytes.Buffer
	RunPostWith(strings.NewReader(ev), &got, &bytes.Buffer{}, newSource().get, HostCodex)
	want := `{"decision":"block","reason":"` + strings.Repeat("y", CodexReasonLimit-100) + `[REDACTED:API_KEY]"}` + "\n"
	if got.String() != want {
		t.Fatalf("got %d bytes: %q", got.Len(), got.String()[len(got.String())-80:])
	}
}
