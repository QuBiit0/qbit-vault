package hook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/QuBiit0/qbit-vault/internal/redact"
)

const (
	postToolUse      = "PostToolUse"
	userPromptSubmit = "UserPromptSubmit"
)

// Source gives the redactor over the stored values. It must never prompt: a
// vault it cannot read without one is ErrLocked. A nil redactor with a nil
// error means there is nothing to redact (no vault yet). The hook wipes the
// redactor when done.
type Source func() (*redact.Redactor, error)

// RunPostBash is `qbit-vault hook post-bash` (Bash and PowerShell).
func RunPostBash(in io.Reader, out, _ io.Writer, src Source) int {
	return runEvent(in, out, postToolUse, maxPostEvent, PostTool(src))
}

// RunPostRead is `qbit-vault hook post-read`.
func RunPostRead(in io.Reader, out, _ io.Writer, src Source) int {
	return runEvent(in, out, postToolUse, maxPostEvent, PostTool(src))
}

// PostTool redacts stored secret values from a tool result before the model
// sees it (AGENTS.md invariant 5). It rewrites every string inside
// tool_response and leaves keys, numbers, booleans and nesting alone, so the
// replacement has exactly the shape of the original whatever the tool (the
// host silently keeps the original when the shape differs). With nothing to
// redact it prints nothing; with no text in the result it never calls src.
func PostTool(src Source) Handler {
	return func(ev Event) (*Output, error) {
		v, ok, err := decode(ev.ToolResponse)
		if err != nil || !ok || !hasText(v) {
			return nil, err
		}
		red, err := src()
		if err != nil || red == nil {
			return nil, err
		}
		defer red.Wipe()
		n, failed := 0, false
		v = mapStrings(v, func(s string) string {
			r, c := red.Bytes([]byte(s))
			if r == nil { // a wiped redactor fails closed
				failed = true
				return s
			}
			n += c
			return string(r)
		})
		if failed {
			return nil, errRedact
		}
		if n == 0 {
			return nil, nil
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(v); err != nil {
			return nil, err
		}
		return &Output{Specific: &Specific{
			HookEventName:     postToolUse,
			AdditionalContext: fmt.Sprintf("qbit-vault redacted %d occurrence(s) of stored secrets", n),
			UpdatedToolOutput: bytes.TrimSpace(buf.Bytes()),
		}}, nil
	}
}

type hookError string

func (e hookError) Error() string { return string(e) }

const errRedact = hookError("redaction failed")

// decode parses a JSON value keeping numbers exact. ok is false for an
// absent or null value.
func decode(raw json.RawMessage) (v any, ok bool, err error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, false, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, false, err
	}
	return v, v != nil, nil
}

// hasText reports whether v holds any non-empty string.
func hasText(v any) bool {
	switch x := v.(type) {
	case string:
		return x != ""
	case []any:
		for _, e := range x {
			if hasText(e) {
				return true
			}
		}
	case map[string]any:
		for _, e := range x {
			if hasText(e) {
				return true
			}
		}
	}
	return false
}

// mapStrings applies f to every string value in v (not to object keys).
func mapStrings(v any, f func(string) string) any {
	switch x := v.(type) {
	case string:
		if x == "" {
			return x
		}
		return f(x)
	case []any:
		for i, e := range x {
			x[i] = mapStrings(e, f)
		}
	case map[string]any:
		for k, e := range x {
			x[k] = mapStrings(e, f)
		}
	}
	return v
}
