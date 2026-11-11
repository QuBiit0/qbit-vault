package hook

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"unicode/utf8"
)

// Host selects the output protocol of the post and pre-write hooks
// (odd/tasks/output-guard.md S3.3). claude and pi answer
// hookSpecificOutput.updatedToolOutput and permissionDecision: deny; codex
// answers PostToolUse with a block whose reason is the text the model sees.
type Host string

const (
	HostClaude Host = "claude"
	HostCodex  Host = "codex"
	HostPi     Host = "pi"
)

// ParseHost maps the --host value to a Host; the empty value is claude.
func ParseHost(s string) (Host, bool) {
	switch Host(s) {
	case "", HostClaude:
		return HostClaude, true
	case HostCodex:
		return HostCodex, true
	case HostPi:
		return HostPi, true
	}
	return "", false
}

// CodexReasonLimit is the most bytes of a Codex block reason. Codex shows the
// model about 2,500 tokens of one hook message and spills the rest to a file
// in its temp directory (https://learn.chatgpt.com/docs/hooks.md § Large hook
// output); at about 4 bytes a token that is 10,000 bytes, and the limit sits
// below it for text that tokenizes worse.
const CodexReasonLimit = 8000

// truncatedLine ends a reason cut at the limit.
const truncatedLine = "\n[output truncated by qbit-vault]"

// The reasons a check can fail. They are fixed strings: an error text could
// carry a value.
const (
	reasonLocked   = "vault locked"
	reasonTooLarge = "output too large"
	reasonEditSize = "edit too large"
	reasonInternal = "internal error"
)

// withheldText replaces a tool output that could not be checked (S2.2).
func withheldText(reason string) string {
	return "output withheld: qbit-vault could not check it for secrets (" + reason + ")"
}

// uncheckedEdit is the denial of a write that could not be checked (S3.2).
func uncheckedEdit(reason string) string {
	return "qbit-vault could not check this edit for secrets (" + reason + ")"
}

// reasonOf maps a Source failure to its fixed reason.
func reasonOf(err error) string {
	if errors.Is(err, ErrLocked) {
		return reasonLocked
	}
	return reasonInternal
}

// RunPostWith is the post-tool hook (`hook post-bash`, `hook post-read`) for
// one host. With no vault, nothing to redact or no text in the result it
// prints nothing (S2.1). When the vault cannot be checked it withholds the
// whole output (S2.2). An event that is not JSON fails open as before: there
// is no output to replace.
func RunPostWith(in io.Reader, out, _ io.Writer, src Source, host Host) int {
	raw, over, err := readRaw(in, maxPostEvent)
	if err != nil {
		return emit(out, failOpen(postToolUse, err))
	}
	if over {
		return emit(out, postOversize(src, host))
	}
	var ev Event
	if err := json.Unmarshal(raw, &ev); err != nil {
		return emit(out, failOpen(postToolUse, err))
	}
	return emit(out, postGuard(ev, src, host))
}

// RunPreWrite is `qbit-vault hook pre-write`: it denies a file write or edit
// whose input carries the value of a stored secret (S3.2).
func RunPreWrite(in io.Reader, out, _ io.Writer, src Source, host Host) int {
	raw, over, err := readRaw(in, maxPostEvent)
	if err != nil {
		return emit(out, failOpen(preToolUse, err))
	}
	if over {
		return emit(out, preWriteOversize(src))
	}
	var ev Event
	if err := json.Unmarshal(raw, &ev); err != nil {
		return emit(out, failOpen(preToolUse, err))
	}
	return emit(out, preWriteGuard(ev, src))
}

// readRaw reads at most limit bytes; over is true when the input is longer.
func readRaw(in io.Reader, limit int64) (raw []byte, over bool, err error) {
	raw, err = io.ReadAll(io.LimitReader(in, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(raw)) > limit {
		return nil, true, nil
	}
	return raw, false, nil
}

// emit prints o (nothing for nil) and returns the hook's exit code, always 0.
func emit(out io.Writer, o *Output) int {
	if o != nil {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if enc.Encode(o) == nil {
			_, _ = out.Write(buf.Bytes())
		}
	}
	return 0
}

// ---- post ----------------------------------------------------------------

// postGuard decides for one parsed PostToolUse event. A panic anywhere in it
// withholds the output; the panic value is dropped, it could hold the text.
func postGuard(ev Event, src Source, host Host) (o *Output) {
	defer func() {
		if recover() != nil {
			o = withheldPost(ev.ToolResponse, reasonInternal, host)
		}
	}()
	v, ok, err := decode(ev.ToolResponse)
	if err != nil {
		return withheldPost(ev.ToolResponse, reasonInternal, host)
	}
	if !ok || !hasText(v) {
		return nil
	}
	red, err := src()
	if err != nil {
		return withheldPost(ev.ToolResponse, reasonOf(err), host)
	}
	if red.Empty() {
		red.Wipe()
		return nil
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
		return withheldPost(ev.ToolResponse, reasonInternal, host)
	}
	if n == 0 {
		return nil
	}
	return redactedPost(v, n, host)
}

// postOversize answers an event above the size limit. It cannot be parsed, so
// the shape of the tool result is unknown: the withheld text replaces it as a
// bare string, which a host that wants another shape ignores. Hosts cap tool
// output far below the limit.
func postOversize(src Source, host Host) (o *Output) {
	defer func() {
		if recover() != nil {
			o = withheldPost(nil, reasonInternal, host)
		}
	}()
	red, err := src()
	if err != nil {
		return withheldPost(nil, reasonOf(err), host)
	}
	empty := red.Empty()
	red.Wipe()
	if empty {
		return nil
	}
	return withheldPost(nil, reasonTooLarge, host)
}

// redactedPost is the answer when the output changed.
func redactedPost(v any, n int, host Host) *Output {
	if host == HostCodex {
		return &Output{Decision: "block", Reason: cutReason(plainText(v))}
	}
	return &Output{Specific: &Specific{
		HookEventName:     postToolUse,
		AdditionalContext: "qbit-vault redacted " + jsonInt(n) + " occurrence(s) of stored secrets",
		UpdatedToolOutput: encodeJSON(v),
	}}
}

// withheldPost replaces the whole tool output with the withheld text. The
// replacement keeps the shape of the original (strings, arrays and objects
// stay what they were): every string is emptied and the text goes into the
// longest one, so nothing of the original survives. raw nil or unparseable
// gives a bare string.
func withheldPost(raw json.RawMessage, reason string, host Host) *Output {
	msg := withheldText(reason)
	if host == HostCodex {
		return &Output{Decision: "block", Reason: msg}
	}
	var shape any = msg
	if v, ok, err := decode(raw); err == nil && ok {
		shape = replaceText(v, msg)
	}
	return &Output{Specific: &Specific{HookEventName: postToolUse, UpdatedToolOutput: encodeJSON(shape)}}
}

// textKeys are the members that carry a tool's output, in the order the
// withheld text prefers them: Bash and PowerShell (stdout), Read and Grep
// (content), and the usual names of other tools.
var textKeys = []string{"stdout", "content", "output", "text", "result"}

// replaceText empties every string in v and puts msg in the one that carries
// the output: the first member named in textKeys, else the longest string
// (the first on a tie). A value with no string becomes msg.
func replaceText(v any, msg string) any {
	type ref struct {
		key string
		n   int
	}
	var refs []ref
	walkStrings(v, "", func(key, s string) string {
		refs = append(refs, ref{key, len(s)})
		return s
	})
	pick := -1
	for _, k := range textKeys {
		for i, r := range refs {
			if r.key == k {
				pick = i
				break
			}
		}
		if pick >= 0 {
			break
		}
	}
	if pick < 0 {
		best := 0
		for i, r := range refs {
			if r.n > best {
				pick, best = i, r.n
			}
		}
	}
	if pick < 0 {
		return msg
	}
	i := -1
	return walkStrings(v, "", func(string, string) string {
		i++
		if i == pick {
			return msg
		}
		return ""
	})
}

// walkStrings is mapStrings that also tells f the name of the object member
// holding the string (the member of the nearest enclosing object for an array
// element). Empty strings are skipped.
func walkStrings(v any, key string, f func(key, s string) string) any {
	switch x := v.(type) {
	case string:
		if x == "" {
			return x
		}
		return f(key, x)
	case []any:
		for i, e := range x {
			x[i] = walkStrings(e, key, f)
		}
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			x[k] = walkStrings(x[k], k, f)
		}
	}
	return v
}

// plainText is what the codex block carries: a string result as it is, any
// other shape as compact JSON.
func plainText(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return string(encodeJSON(v))
}

// cutReason limits a Codex reason to CodexReasonLimit bytes with the fixed
// truncation line. It runs on the redacted text, so the cut cannot expose a
// value, and it backs up to a character boundary and out of a
// [REDACTED:NAME] marker, so no half marker is left behind.
func cutReason(s string) string {
	if len(s) <= CodexReasonLimit {
		return s
	}
	cut := CodexReasonLimit - len(truncatedLine)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	const marker = "[REDACTED:"
	if i := strings.LastIndexByte(s[:cut], '['); i >= 0 && !strings.Contains(s[i:cut], "]") {
		if tail := s[i:cut]; strings.HasPrefix(marker, tail) || strings.HasPrefix(tail, marker) {
			cut = i
		}
	}
	return s[:cut] + truncatedLine
}

func encodeJSON(v any) json.RawMessage {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if enc.Encode(v) != nil {
		return json.RawMessage(`""`)
	}
	return bytes.TrimSpace(buf.Bytes())
}

func jsonInt(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// ---- pre-write -----------------------------------------------------------

// preWriteGuard decides for one parsed PreToolUse event of a write tool.
func preWriteGuard(ev Event, src Source) (o *Output) {
	defer func() {
		if recover() != nil {
			o = denyWrite(uncheckedEdit(reasonInternal))
		}
	}()
	v, ok, err := decode(ev.ToolInput)
	if err != nil {
		return denyWrite(uncheckedEdit(reasonInternal))
	}
	if !ok || !hasText(v) {
		return nil
	}
	// Only what the call adds to a file is scanned; an unknown shape is
	// scanned whole (S10.2).
	var scan []string
	if added, known := addedText(ev.ToolName, v); known {
		scan = added
	} else {
		mapStrings(v, func(s string) string { scan = append(scan, s); return s })
	}
	if !anyText(scan) {
		return nil
	}
	red, err := src()
	if err != nil {
		return denyWrite(uncheckedEdit(reasonOf(err)))
	}
	if red.Empty() {
		red.Wipe()
		return nil
	}
	defer red.Wipe()
	names := map[string]bool{}
	hit, failed := false, false
	for _, s := range scan {
		if s == "" {
			continue
		}
		r, c := red.Bytes([]byte(s))
		if r == nil {
			failed = true
			continue
		}
		if c > 0 {
			hit = true
			for _, n := range matchedNames(s, r) {
				names[n] = true
			}
		}
	}
	if failed {
		return denyWrite(uncheckedEdit(reasonInternal))
	}
	if !hit {
		return nil
	}
	list := make([]string, 0, len(names))
	for n := range names {
		list = append(list, n)
	}
	sort.Strings(list)
	return denyWrite(writeReason(list))
}

func preWriteOversize(src Source) (o *Output) {
	defer func() {
		if recover() != nil {
			o = denyWrite(uncheckedEdit(reasonInternal))
		}
	}()
	red, err := src()
	if err != nil {
		return denyWrite(uncheckedEdit(reasonOf(err)))
	}
	empty := red.Empty()
	red.Wipe()
	if empty {
		return nil
	}
	return denyWrite(uncheckedEdit(reasonEditSize))
}

// writeReason names the secrets a write would carry, never the values.
func writeReason(names []string) string {
	return "This edit would write the value of " + namesPhrase(names) + " to a file, so qbit-vault blocked it. Give the value to the command that needs it with secret_exec instead."
}

func denyWrite(reason string) *Output {
	return &Output{Specific: &Specific{
		HookEventName:            preToolUse,
		PermissionDecision:       "deny",
		PermissionDecisionReason: reason,
	}}
}

// anyText reports whether any string is non-empty.
func anyText(ss []string) bool {
	for _, s := range ss {
		if s != "" {
			return true
		}
	}
	return false
}
