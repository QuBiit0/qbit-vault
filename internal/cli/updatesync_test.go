package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/exitcode"
)

const updSyncText = "claude: registered\ncodex: registered\nCodex asks you to trust the new hooks: open /hooks in Codex and trust them\n"

const updDoneLine = "updated qbit-vault v1.0.0 -> v1.1.0; restart your agents so they load the new version\n"

func (w *updWorld) withVault() {
	w.t.Helper()
	os.MkdirAll(w.home, 0o700)
	os.WriteFile(filepath.Join(w.home, "state.json"), []byte("{}"), 0o600)
}

// What the sync run by update printed is shown after the "updated" line.
func TestUpdateShowsWhatSyncPrinted(t *testing.T) {
	w := newUpdWorld(t, "v1.0.0", "v1.1.0")
	w.withVault()
	w.syncText = updSyncText
	withBackend(t, answers(yes()))
	code, out, errs := w.run()
	if code != exitcode.OK || out != updDoneLine+updSyncText || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
}

// --json keeps its single object: the sync text is not mixed into it.
func TestUpdateJSONHasNoSyncText(t *testing.T) {
	w := newUpdWorld(t, "v1.0.0", "v1.1.0")
	w.withVault()
	w.syncText = updSyncText
	withBackend(t, answers(yes()))
	code, out, errs := w.run("--json")
	want := `{"ok":true,"current":"v1.0.0","latest":"v1.1.0","update_available":true,"updated":true}` + "\n"
	if code != exitcode.OK || out != want || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
}

// A failing sync keeps exit 0 and the stderr note; what it printed still shows.
func TestUpdateSyncFailureStillExitsZero(t *testing.T) {
	w := newUpdWorld(t, "v1.0.0", "v1.1.0")
	w.withVault()
	updateResync = func(_ context.Context, _ *globals, _ string, stdout, _ io.Writer) error {
		io.WriteString(stdout, "claude: registered\n")
		return fmt.Errorf("boom")
	}
	withBackend(t, answers(yes()))
	code, out, errs := w.run()
	if code != exitcode.OK || out != updDoneLine+"claude: registered\n" {
		t.Fatalf("code=%d out=%q", code, out)
	}
	if !strings.Contains(errs, "'qbit-vault sync' reported a problem") {
		t.Fatalf("err=%q", errs)
	}
}
