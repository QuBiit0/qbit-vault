package hook

import (
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// BlockAdvice ends every block reason. It is fixed text: a reason never holds
// the message, a value or any part of one.
const BlockAdvice = "If you typed or pasted it, store it with 'qbit-vault set NAME' in your own terminal and refer to it by name. If it came from a background job or another agent's report, the command printed the value: run it through qbit-vault (secret_exec), which redacts its output."

// maxNamed is how many names a reason lists before "and N more".
const maxNamed = 5

// RunUserPrompt is `qbit-vault hook user-prompt`.
func RunUserPrompt(in io.Reader, out, _ io.Writer, src Source) int {
	return runEvent(in, out, userPromptSubmit, maxPostEvent, UserPrompt(src))
}

// shapes are high-precision patterns of well-known secret formats (PRD
// R-CAP-06), in the order they are checked. The label names the kind in the
// block reason, with its article. Generic high-entropy strings are
// deliberately not matched: the false positives would block ordinary prompts,
// and stored values are caught by value instead.
var shapes = []struct {
	re    *regexp.Regexp
	label string
}{
	{regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}`), "a GitHub token"},
	{regexp.MustCompile(`github_pat_[A-Za-z0-9_]{22,}`), "a GitHub fine-grained token"},
	{regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), "an AWS access key"},
	{regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`), "a Slack token"},
	{regexp.MustCompile(`\b[sr]k_live_[A-Za-z0-9]{16,}`), "a Stripe live key"},
	{regexp.MustCompile(`\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{32,}`), "an API key"},
	{regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`), "a private key"},
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), "a JWT"},
}

// redactedToken matches the [REDACTED:NAME] marks the redactor writes.
var redactedToken = regexp.MustCompile(`\[REDACTED:([^\]\s]+)\]`)

// UserPrompt blocks a prompt that carries a secret: the value of a stored
// secret (any encoding the redactor knows) or a well-known secret shape. The
// host cannot rewrite a prompt, only block it, and shows the reason to the
// user; suppressOriginalPrompt keeps the text out of the block message. The
// reason names the matching entries (or the shape's kind), never the text. A
// shape needs no vault, so it blocks even when the vault is locked.
func UserPrompt(src Source) Handler {
	return func(ev Event) (*Output, error) {
		if strings.TrimSpace(ev.Prompt) == "" {
			return nil, nil
		}
		for _, sh := range shapes {
			if sh.re.MatchString(ev.Prompt) {
				return block(shapeReason(sh.label)), nil
			}
		}
		red, err := src()
		if err != nil || red == nil {
			return nil, err
		}
		defer red.Wipe()
		out, n := red.Bytes([]byte(ev.Prompt))
		if out == nil {
			return nil, errRedact
		}
		if n > 0 {
			return block(storedReason(matchedNames(ev.Prompt, out))), nil
		}
		return nil, nil
	}
}

// matchedNames lists the stored entries whose value was redacted from in. The
// names come from the redacted text, so no value is read here. A name counts
// only when its token appears more often in out than in in: a token the
// message already carried is not a match.
func matchedNames(in string, out []byte) []string {
	before := map[string]int{}
	for _, m := range redactedToken.FindAllStringSubmatch(in, -1) {
		before[m[1]]++
	}
	after := map[string]int{}
	for _, m := range redactedToken.FindAllSubmatch(out, -1) {
		after[string(m[1])]++
	}
	var names []string
	for name, c := range after {
		if c > before[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func storedReason(names []string) string {
	var what string
	switch len(names) {
	case 0:
		what = "a stored secret"
	case 1:
		what = "the stored secret " + names[0]
	default:
		shown := names
		if len(names) > maxNamed {
			shown = names[:maxNamed]
		}
		what = "the stored secrets " + strings.Join(shown, ", ")
		if more := len(names) - len(shown); more > 0 {
			what += " and " + strconv.Itoa(more) + " more"
		}
	}
	return "This message contains the value of " + what + ", so qbit-vault blocked it. " + BlockAdvice
}

func shapeReason(label string) string {
	return "This message looks like it contains " + label + ", so qbit-vault blocked it. " + BlockAdvice
}

func block(reason string) *Output {
	return &Output{
		Decision: "block",
		Reason:   reason,
		Specific: &Specific{HookEventName: userPromptSubmit, SuppressOriginalPrompt: true},
	}
}
