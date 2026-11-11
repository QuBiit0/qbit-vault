package hook

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/redact"
	"github.com/qbitdevz/qbit-vault/internal/secret"
)

const (
	tsPlain = "TESTSECRET_post_0123456789"
	tsOdd   = `TESTSECRET_q"x\y/+_0123456789` // needs JSON and URL escapes
)

// source is a Source over fixed values; calls counts how often it ran.
type source struct {
	calls int
	err   error
	vals  map[string]string
}

func (s *source) get() (*redact.Redactor, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	var vs []secret.Secret
	for name, v := range s.vals {
		vs = append(vs, secret.New(name, []byte(v)))
	}
	return redact.New(vs)
}

func newSource() *source {
	return &source{vals: map[string]string{"API_KEY": tsPlain, "ODD_KEY": tsOdd}}
}

// plainJSON encodes like the hook does: no HTML escaping.
func plainJSON(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimSuffix(buf.String(), "\n")
}

func jstr(t testing.TB, s string) string {
	t.Helper()
	return plainJSON(s)
}

// postEvent renders a recorded PostToolUse fixture with another output text.
func postEvent(t testing.TB, fixtureName, out string) []byte {
	t.Helper()
	raw := string(fixture(t, fixtureName))
	if !strings.Contains(raw, `"__OUT__"`) {
		t.Fatal("fixture changed")
	}
	return []byte(strings.Replace(raw, `"__OUT__"`, jstr(t, out), 1))
}

func promptEvent(t testing.TB, prompt string) []byte {
	t.Helper()
	raw := string(fixture(t, "userpromptsubmit.json"))
	if !strings.Contains(raw, `"__PROMPT__"`) {
		t.Fatal("fixture changed")
	}
	return []byte(strings.Replace(raw, `"__PROMPT__"`, jstr(t, prompt), 1))
}

func runPost(t testing.TB, src Source, in []byte) (string, string, int) {
	t.Helper()
	var out, errb bytes.Buffer
	code := RunPostBash(bytes.NewReader(in), &out, &errb, src)
	return out.String(), errb.String(), code
}

func runPrompt(t testing.TB, src Source, in []byte) (string, string, int) {
	t.Helper()
	var out, errb bytes.Buffer
	code := RunUserPrompt(bytes.NewReader(in), &out, &errb, src)
	return out.String(), errb.String(), code
}

const (
	wantLockedPrompt = `{"systemMessage":"qbit-vault could not check this prompt for secrets (vault locked); run 'qbit-vault unlock'","hookSpecificOutput":{"hookEventName":"UserPromptSubmit","additionalContext":"qbit-vault could not check this prompt for secrets (vault locked); run 'qbit-vault unlock'"}}` + "\n"
)

func bashOut(stdout string, n int) string {
	return `{"hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":"qbit-vault redacted ` + itoa(n) + ` occurrence(s) of stored secrets","updatedToolOutput":{"interrupted":false,"isImage":false,"stderr":"","stdout":` + plainJSON(stdout) + `}}}` + "\n"
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func TestPostBashRedactsEveryEncoding(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte(tsPlain))
	b64url := base64.RawURLEncoding.EncodeToString([]byte(tsPlain))
	jsonBody := jstr(t, tsOdd)
	jsonBody = jsonBody[1 : len(jsonBody)-1]
	cases := []struct {
		name, in, out string
		n             int
	}{
		{"raw", "token=" + tsPlain + "\n", "token=[REDACTED:API_KEY]\n", 1},
		{"base64", "auth=" + b64 + "\n", "auth=[REDACTED:API_KEY]\n", 1},
		{"base64url", "auth=" + b64url + "\n", "auth=[REDACTED:API_KEY]\n", 1},
		{"url-encoded", "q=" + url.QueryEscape(tsOdd) + "&x=1\n", "q=[REDACTED:ODD_KEY]&x=1\n", 1},
		{"json-escaped", `{"k":"` + jsonBody + `"}` + "\n", `{"k":"[REDACTED:ODD_KEY]"}` + "\n", 1},
		{"twice", tsPlain + " " + tsPlain, "[REDACTED:API_KEY] [REDACTED:API_KEY]", 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, errb, code := runPost(t, newSource().get, postEvent(t, "posttooluse_bash.json", c.in))
			if code != 0 || errb != "" || out != bashOut(c.out, c.n) {
				t.Fatalf("out=%q err=%q code=%d", out, errb, code)
			}
			if strings.Contains(out, "TESTSECRET_") {
				t.Fatal("value leaked")
			}
		})
	}
}

func TestPostBashPowerShellSameShape(t *testing.T) {
	out, errb, code := runPost(t, newSource().get, postEvent(t, "posttooluse_powershell.json", "KEY="+tsPlain))
	if code != 0 || errb != "" || out != bashOut("KEY=[REDACTED:API_KEY]", 1) {
		t.Fatalf("out=%q err=%q code=%d", out, errb, code)
	}
}

func TestPostReadKeepsTheReadShape(t *testing.T) {
	var out, errb bytes.Buffer
	in := postEvent(t, "posttooluse_read.json", "1\tkey="+tsPlain+"\n2\tdone\n")
	if code := RunPostRead(bytes.NewReader(in), &out, &errb, newSource().get); code != 0 || errb.Len() != 0 {
		t.Fatalf("code=%d err=%q", code, errb.String())
	}
	want := `{"hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":"qbit-vault redacted 1 occurrence(s) of stored secrets","updatedToolOutput":{"file":{"content":"1\tkey=[REDACTED:API_KEY]\n2\tdone\n","filePath":"/home/user/my-project/config.txt","numLines":2,"startLine":1,"totalLines":2},"type":"text"}}}` + "\n"
	if out.String() != want {
		t.Fatalf("out=%q", out.String())
	}
}

func TestPostStaysSilent(t *testing.T) {
	src := newSource()
	for _, text := range []string{"all good\n", "TESTSECRET_other_9876543210"} {
		out, errb, code := runPost(t, src.get, postEvent(t, "posttooluse_bash.json", text))
		if code != 0 || errb != "" || out != "" {
			t.Fatalf("%q: out=%q err=%q code=%d", text, out, errb, code)
		}
	}
	if src.calls != 2 {
		t.Fatalf("source calls = %d, want 2", src.calls)
	}
}

func TestPostEmptyOutputNeverOpensTheVault(t *testing.T) {
	src := newSource()
	for _, in := range [][]byte{
		postEvent(t, "posttooluse_bash.json", ""),
		[]byte(`{"hook_event_name":"PostToolUse","tool_name":"Bash"}`),
		[]byte(`{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_response":null}`),
		[]byte(`{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_response":{"stdout":"","stderr":"","interrupted":false}}`),
	} {
		out, errb, code := runPost(t, src.get, in)
		if code != 0 || errb != "" || out != "" {
			t.Fatalf("%s: out=%q err=%q code=%d", in, out, errb, code)
		}
	}
	if src.calls != 0 {
		t.Fatalf("the vault was opened %d times for empty output", src.calls)
	}
}

func TestPostNothingToRedactIsSilent(t *testing.T) {
	out, _, code := runPost(t, func() (*redact.Redactor, error) { return nil, nil }, postEvent(t, "posttooluse_bash.json", "x "+tsPlain))
	if code != 0 || out != "" {
		t.Fatalf("out=%q code=%d", out, code)
	}
}

func TestPostRedactsAWholeLargeOutput(t *testing.T) {
	big := strings.Repeat("0123456789abcdef\n", 200_000) // 3.4 MB, above the pre-bash event limit
	in := postEvent(t, "posttooluse_bash.json", big+tsPlain+"\n"+big)
	out, errb, code := runPost(t, newSource().get, in)
	if code != 0 || errb != "" || strings.Contains(out, "TESTSECRET_") || !strings.Contains(out, "[REDACTED:API_KEY]") {
		t.Fatalf("code=%d err=%q leaked=%v len=%d", code, errb, strings.Contains(out, "TESTSECRET_"), len(out))
	}
}
