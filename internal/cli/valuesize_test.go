package cli

import (
	"strings"
	"testing"
)

// The 64 KiB limit applies to the trimmed value: a value of exactly the limit
// followed by a newline (what `echo` sends) is stored.
func TestSetLimitAppliesAfterTrim(t *testing.T) {
	w := newWorld(t)
	w.outRepo()
	exact := "TESTSECRET_" + strings.Repeat("a", maxValueBytes-len("TESTSECRET_"))
	code, out, errs := w.run(exact+"\n", "set", "BIG_KEY", "--global", "--stdin")
	if code != 0 || errs != "" || out != "stored BIG_KEY (global)\n" {
		t.Fatalf("exact-limit value with newline: code=%d stdout=%q stderr-len=%d", code, out, len(errs))
	}
	code, _, errs = w.run(exact+"b", "set", "BIG_KEY2", "--global", "--stdin")
	if code != 2 || !strings.Contains(errs, "value too large") {
		t.Fatalf("over-limit value: code=%d", code)
	}
}
