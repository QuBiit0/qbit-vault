package cli

import (
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/QuBiit0/gentle-vault/internal/grants"
	"github.com/QuBiit0/gentle-vault/internal/vault"
)

// failingDrop is a grants editor whose drops always fail, simulating a crash
// between the vault write and the grants write.
type failingDrop struct{}

func (failingDrop) DropRecord([]byte, string, string) ([]byte, int, error) {
	return nil, 0, errors.New("simulated drop failure")
}

func (failingDrop) DropNonOnce([]byte, string, string, string) ([]byte, int, error) {
	return nil, 0, errors.New("simulated drop failure")
}

func (failingDrop) DropLayer([]byte, string) ([]byte, int, error) {
	return nil, 0, errors.New("simulated drop failure")
}

// execCheck is what exec (slice 1.8) will do: resolve the record for cwd and
// evaluate the grants against its id.
func (w *world) execCheck(name, session string) error {
	w.t.Helper()
	g := &globals{getenv: envFrom(nil), home: w.home}
	s, err := g.openSession()
	if err != nil {
		w.t.Fatal(err)
	}
	defer s.close()
	cwd, _ := os.Getwd()
	rec, layer, err := s.v.Resolve(name, cwd)
	if err != nil {
		w.t.Fatal(err)
	}
	rec.Value.Wipe()
	var decision grants.Decision
	_, err = s.v.MutateGrants(func(body []byte, _ bool) ([]byte, error) {
		st, err := grants.Decode(body)
		if err != nil {
			return nil, err
		}
		decision, _ = grants.Check(st, name, layer.Key(), rec.ID, rec.Sensitive, session, cwd, clock())
		return nil, nil
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return decision.Err
}

func TestStaleGrantIsInertAfterAFailedDrop(t *testing.T) {
	pinClock(t)
	asTerminal(t, true)
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	w.mustRun("y\n", "--session", sessA, "grant", "A_KEY", "--scope", "session")
	if err := w.execCheck("A_KEY", sessA); err != nil {
		t.Fatalf("a fresh grant must allow its record: %v", err)
	}

	old := newGrantsEditor
	newGrantsEditor = func() vault.GrantsEditor { return failingDrop{} }
	code, _, _ := w.run("", "rm", "A_KEY", "--yes")
	newGrantsEditor = old
	if code == 0 {
		t.Fatal("rm must report the failed drop")
	}
	if got := w.grantsState(); got == `{"ok":true,"grants":[]}`+"\n" {
		t.Fatal("the simulated failure did not leave the stale grant behind")
	}

	// Same name, same layer, new record: the stale grant must not apply.
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	if err := w.execCheck("A_KEY", sessA); !errors.Is(err, grants.ErrGrantRequired) {
		t.Fatalf("stale grant authorized a re-created record: %v", err)
	}
	// describe shows only grants of the current record.
	if out := w.mustRun("", "--json", "describe", "A_KEY"); !contains(out, `"grants":[]`) {
		t.Fatalf("describe shows a stale grant: %s", out)
	}
}

func TestReplacedValueGetsANewRecordIDEvenIfDropFails(t *testing.T) {
	pinClock(t)
	asTerminal(t, true)
	w := newWorld(t)
	w.mustRun(fxVal+"1", "set", "A_KEY", "--global", "--stdin")
	w.mustRun("y\n", "--session", sessA, "grant", "A_KEY", "--scope", "session")
	old := newGrantsEditor
	newGrantsEditor = func() vault.GrantsEditor { return failingDrop{} }
	w.run(fxVal+"2", "set", "A_KEY", "--global", "--stdin")
	newGrantsEditor = old
	if err := w.execCheck("A_KEY", sessA); !errors.Is(err, grants.ErrGrantRequired) {
		t.Fatalf("a grant survived a value replacement: %v", err)
	}
}

func TestEditKeepsGrantsAndHumanOutputHidesIDs(t *testing.T) {
	pinClock(t)
	asTerminal(t, true)
	w := newWorld(t)
	w.mustRun(fxVal, "set", "A_KEY", "--global", "--stdin")
	w.mustRun("y\n", "--session", sessA, "grant", "A_KEY", "--scope", "session")
	w.mustRun("", "edit", "A_KEY", "--description", "d")
	if err := w.execCheck("A_KEY", sessA); err != nil {
		t.Fatalf("edit invalidated the grant: %v", err)
	}
	for _, args := range [][]string{{"describe", "A_KEY"}, {"grants"}, {"--json", "grants"}, {"--json", "describe", "A_KEY"}, {"list"}} {
		if out := w.mustRun("", args...); recordIDText.MatchString(out) {
			t.Fatalf("%v printed a record id: %q", args, out)
		}
	}
}

var recordIDText = regexp.MustCompile(`[0-9a-f]{32}`)

func contains(s, sub string) bool { return strings.Contains(s, sub) }
