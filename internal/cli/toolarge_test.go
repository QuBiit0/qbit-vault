package cli

import (
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/exitcode"
	"github.com/QuBiit0/qbit-vault/internal/prompt"
	"github.com/QuBiit0/qbit-vault/internal/prompt/prompttest"
)

// An oversized interactive value is refused with the same message as
// `set --stdin`, and nothing is written.
func TestInteractiveOversizeIsAUsageErrorAndWritesNothing(t *testing.T) {
	w := newWorld(t)
	before := w.snapshot()
	withBackend(t, answers(prompttest.Answer{Err: prompt.ErrTooLarge}))
	code, out, errs := w.run("", "set", "A_KEY", "--global")
	if code != exitcode.Usage || out != "" || errs != usageErr("value too large") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if w.snapshot() != before {
		t.Fatal("the vault changed")
	}
}
