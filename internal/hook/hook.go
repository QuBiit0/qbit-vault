// Package hook implements the host hooks behind `qbit-vault hook …`
// (docs/AGENT_INTEGRATIONS.md § Hook protocol): they read one hook event as
// JSON on stdin and answer with the protocol JSON on stdout, nothing else.
//
// A hook never prompts or touches the network, and a broken hook fails open:
// the host proceeds and the agent sees a fixed warning. Only the post and
// user-prompt hooks read stored values, through a Source that must not prompt.
// Nothing derived from the event (the command, a path, a prompt) is ever
// written back unredacted, so a secret that reached a hook cannot leave
// through it.
package hook

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// maxEvent bounds the event read from stdin; maxPostEvent bounds a PostToolUse
// event, which carries a whole tool output (hosts cap those far below this).
const (
	maxEvent     = 1 << 20
	maxPostEvent = 64 << 20
)

// FailOpenWarning is what the agent and the user see when a hook broke.
const FailOpenWarning = "qbit-vault hook failed; the command ran without its checks; run 'qbit-vault doctor'"

// ErrLocked is what a Source returns when the vault cannot be read without
// prompting (a passphrase vault with no unlock cache). The hook fails open
// with a warning that names the fix.
var ErrLocked = errors.New("vault locked")

// lockedWarning is the fail-open text per event when the vault is locked.
var lockedWarning = map[string]string{
	postToolUse:      "qbit-vault could not check this output for secrets (vault locked); run 'qbit-vault unlock'",
	userPromptSubmit: "qbit-vault could not check this prompt for secrets (vault locked); run 'qbit-vault unlock'",
}

// Event is the part of a host hook event the hooks use. ToolInput stays raw:
// its shape depends on the tool.
type Event struct {
	SessionID     string          `json:"session_id"`
	HookEventName string          `json:"hook_event_name"`
	ToolName      string          `json:"tool_name"`
	ToolInput     json.RawMessage `json:"tool_input"`
	ToolResponse  json.RawMessage `json:"tool_response"`
	Prompt        string          `json:"prompt"`
	Cwd           string          `json:"cwd"`
}

// Output is the protocol JSON a hook prints. A nil *Output prints nothing,
// which for the host means "no opinion, the normal flow applies".
type Output struct {
	SystemMessage string    `json:"systemMessage,omitempty"`
	Decision      string    `json:"decision,omitempty"`
	Reason        string    `json:"reason,omitempty"`
	Specific      *Specific `json:"hookSpecificOutput,omitempty"`
}

// Specific is hookSpecificOutput. HookEventName is mandatory for the host.
type Specific struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision,omitempty"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
	AdditionalContext        string `json:"additionalContext,omitempty"`
	// UpdatedToolOutput replaces the tool result; it must keep the tool's shape.
	UpdatedToolOutput json.RawMessage `json:"updatedToolOutput,omitempty"`
	// SuppressOriginalPrompt keeps a blocked prompt out of the block message.
	SuppressOriginalPrompt bool `json:"suppressOriginalPrompt,omitempty"`
}

// Handler decides for one event. An error or a panic is a hook failure.
type Handler func(Event) (*Output, error)

// Run reads the event from in, runs h and prints its answer to out. It always
// returns 0: a broken hook fails open with FailOpenWarning (the host only
// treats exit 2 as a block, and a hook failure must not block). errOut is
// never written, so stderr stays empty.
func Run(in io.Reader, out, _ io.Writer, eventName string, h Handler) int {
	return runEvent(in, out, eventName, maxEvent, h)
}

func runEvent(in io.Reader, out io.Writer, eventName string, limit int64, h Handler) int {
	o, err := safely(in, limit, h)
	if err != nil {
		o = failOpen(eventName, err)
	}
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

func safely(in io.Reader, limit int64, h Handler) (o *Output, err error) {
	defer func() {
		// Never keep or print the panic value: it could hold the command.
		if recover() != nil {
			o, err = nil, errPanic
		}
	}()
	ev, err := readEvent(in, limit)
	if err != nil {
		return nil, err
	}
	return h(ev)
}

var errPanic = errors.New("hook panicked")

func readEvent(in io.Reader, limit int64) (Event, error) {
	var ev Event
	raw, err := io.ReadAll(io.LimitReader(in, limit+1))
	if err != nil {
		return ev, err
	}
	if int64(len(raw)) > limit {
		return ev, errors.New("event too large")
	}
	return ev, json.Unmarshal(raw, &ev)
}

// failOpen is the answer for a broken hook: the generic warning, or the one
// that names the fix when the vault is locked. The error itself is dropped:
// it could carry text derived from the event.
func failOpen(eventName string, err error) *Output {
	msg := FailOpenWarning
	if w, ok := lockedWarning[eventName]; ok && errors.Is(err, ErrLocked) {
		msg = w
	}
	return &Output{
		SystemMessage: msg,
		Specific:      &Specific{HookEventName: eventName, AdditionalContext: msg},
	}
}
