package hook

import (
	"bytes"
	"encoding/json"
	"io"
	"sort"

	"github.com/qbitdevz/qbit-vault/internal/redact"
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

// RunPostBash is `qbit-vault hook post-bash` (Bash and PowerShell) with the claude
// protocol; the command picks the host with --host.
func RunPostBash(in io.Reader, out, errOut io.Writer, src Source) int {
	return RunPostWith(in, out, errOut, src, HostClaude)
}

// RunPostRead is `qbit-vault hook post-read` with the claude protocol.
func RunPostRead(in io.Reader, out, errOut io.Writer, src Source) int {
	return RunPostWith(in, out, errOut, src, HostClaude)
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
		// Sorted keys: the order f sees the strings in is deterministic.
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			x[k] = mapStrings(x[k], f)
		}
	}
	return v
}
