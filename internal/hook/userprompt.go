package hook

import (
	"io"
	"regexp"
	"strings"
)

// Fixed block reasons. They never include the prompt: it holds the value.
const (
	BlockStoredReason = "This prompt contains the value of a stored secret, so qbit-vault blocked it. Store secrets with 'qbit-vault set NAME' in your own terminal and refer to them by name."
	BlockShapeReason  = "This prompt looks like it contains a secret, so qbit-vault blocked it. Store secrets with 'qbit-vault set NAME' in your own terminal and refer to them by name."
)

// RunUserPrompt is `qbit-vault hook user-prompt`.
func RunUserPrompt(in io.Reader, out, _ io.Writer, src Source) int {
	return runEvent(in, out, userPromptSubmit, maxPostEvent, UserPrompt(src))
}

// shapes are high-precision patterns of well-known secret formats (PRD
// R-CAP-06). Generic high-entropy strings are deliberately not matched: the
// false positives would block ordinary prompts, and stored values are caught
// by value instead.
var shapes = []*regexp.Regexp{
	regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}`),
	regexp.MustCompile(`github_pat_[A-Za-z0-9_]{22,}`),
	regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`),
	regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`),
	regexp.MustCompile(`\b[sr]k_live_[A-Za-z0-9]{16,}`),
	regexp.MustCompile(`\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{32,}`),
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),
}

// UserPrompt blocks a prompt that carries a secret: the value of a stored
// secret (any encoding the redactor knows) or a well-known secret shape. The
// host cannot rewrite a prompt, only block it, and shows the reason to the
// user; suppressOriginalPrompt keeps the text out of the block message. A
// shape needs no vault, so it blocks even when the vault is locked.
func UserPrompt(src Source) Handler {
	return func(ev Event) (*Output, error) {
		if strings.TrimSpace(ev.Prompt) == "" {
			return nil, nil
		}
		for _, re := range shapes {
			if re.MatchString(ev.Prompt) {
				return block(BlockShapeReason), nil
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
			return block(BlockStoredReason), nil
		}
		return nil, nil
	}
}

func block(reason string) *Output {
	return &Output{
		Decision: "block",
		Reason:   reason,
		Specific: &Specific{HookEventName: userPromptSubmit, SuppressOriginalPrompt: true},
	}
}
