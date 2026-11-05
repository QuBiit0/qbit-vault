package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/hosts/fake"
	"github.com/QuBiit0/qbit-vault/internal/keychain"
	"github.com/QuBiit0/qbit-vault/internal/prompt"
	"github.com/QuBiit0/qbit-vault/internal/prompt/prompttest"
	"github.com/QuBiit0/qbit-vault/internal/tui"
	"github.com/QuBiit0/qbit-vault/internal/vault"
)

// tuiOver is the TUI backend over the world's vault, as `qbit-vault tui` builds it.
func tuiOver(w *world) *tuiBackend {
	return &tuiBackend{g: &globals{getenv: envFrom(nil), home: w.home}}
}

// wipedEntries records the entries a listing handed to the hook after wiping
// them, so a test can look at their values.
func wipedEntries(t *testing.T) *[][]vault.Entry {
	t.Helper()
	var seen [][]vault.Entry
	old := tuiListed
	tuiListed = func(es []vault.Entry) { seen = append(seen, es) }
	t.Cleanup(func() { tuiListed = old })
	return &seen
}

// allZero reports whether every entry's value has been wiped: still as long as
// it was, but only zero bytes.
func allZero(es []vault.Entry) bool {
	for _, e := range es {
		b := e.Record.Value.Reveal()
		if len(b) == 0 {
			return false // an empty value would prove nothing
		}
		for _, c := range b {
			if c != 0 {
				return false
			}
		}
	}
	return len(es) > 0
}

func seed(w *world, name string, extra ...string) {
	w.t.Helper()
	args := append([]string{"set", name, "--stdin"}, extra...)
	w.mustRun(fxVal+"\n", args...)
}

// ---- F2: Status ----

func TestTUIStatusUnlockedVaultCountsSecretsAndWipesTheListing(t *testing.T) {
	w := newWorld(t)
	seed(w, "A_KEY", "--global")
	seed(w, "B_KEY", "--global")
	seen := wipedEntries(t)
	f := withBackend(t, answers())

	st, err := tuiOver(w).Status()
	if err != nil {
		t.Fatal(err)
	}
	want := tui.Status{State: tui.StateUnlocked, Home: w.home, KeyStore: "keychain", Secrets: 2}
	if st != want {
		t.Fatalf("status = %+v, want %+v", st, want)
	}
	if len(*seen) != 1 || len((*seen)[0]) != 2 || !allZero((*seen)[0]) {
		t.Fatalf("the listed entries were not wiped: %d listings", len(*seen))
	}
	if len(f.Calls) != 0 {
		t.Errorf("Status prompted: %+v", f.Calls)
	}
}

func TestTUIStatusLockedVaultNeverPromptsAndHidesTheCount(t *testing.T) {
	w := passphraseWorld(t)
	f := withBackend(t, answers(val(fxPass)))
	st, err := tuiOver(w).Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.State != tui.StateLocked || st.Secrets != -1 || st.KeyStore != "" || st.Home != w.home {
		t.Fatalf("status = %+v, want a locked vault with an unknown count", st)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("Status prompted for the passphrase: %+v", f.Calls)
	}
}

func TestTUIStatusCountsTheRegisteredHosts(t *testing.T) {
	w := newBareWorld(t)
	h := fakeHost(t, w)
	withHosts(t, h)
	w.mustRun("", "init")
	st, err := tuiOver(w).Status()
	if err != nil || st.Hosts != 1 {
		t.Fatalf("status = %+v, err = %v, want one host", st, err)
	}
}

func TestTUIStatusCountsWhatThePaneListsFromHere(t *testing.T) {
	w := newWorld(t)
	seed(w, "G_KEY", "--global")
	w.inRepo()
	seed(w, "P_KEY", "--project")
	b := tuiOver(w)
	st, _ := b.Status()
	list, err := b.Secrets()
	if err != nil || st.Secrets != 2 || len(list.Items) != 2 {
		t.Fatalf("in the repo: status %d, list %d, err %v, want 2 and 2", st.Secrets, len(list.Items), err)
	}
	w.outRepo()
	st, _ = b.Status()
	list, _ = b.Secrets()
	if st.Secrets != 1 || len(list.Items) != 1 {
		t.Fatalf("outside the repo: status %d, list %d, want 1 and 1", st.Secrets, len(list.Items))
	}
}

// ---- Secrets ----

func TestTUISecretsListsMetadataOnly(t *testing.T) {
	w := newWorld(t)
	w.mustRun(fxVal+"\n", "set", "GITHUB_TOKEN", "--global", "--stdin", "--description", "GitHub PAT", "--binaries", "gh,git", "--hosts", "api.github.com")
	w.inRepo()
	w.mustRun(fxVal+"\n", "set", "STRIPE_KEY", "--project", "--stdin", "--sensitive")
	seen := wipedEntries(t)

	list, err := tuiOver(w).Secrets()
	if err != nil {
		t.Fatal(err)
	}
	if list.Project != "shop-api" {
		t.Errorf("project = %q, want shop-api", list.Project)
	}
	if len(list.Items) != 2 {
		t.Fatalf("items = %+v", list.Items)
	}
	by := map[string]tui.Secret{}
	for _, s := range list.Items {
		by[s.Name] = s
	}
	g, p := by["GITHUB_TOKEN"], by["STRIPE_KEY"]
	if g.Layer != "global" || g.Project || g.Description != "GitHub PAT" || g.Sensitive || !reflect.DeepEqual(g.Binaries, []string{"gh", "git"}) || !reflect.DeepEqual(g.Hosts, []string{"api.github.com"}) || g.UpdatedAt == "" {
		t.Errorf("global secret = %+v", g)
	}
	if p.Layer != "shop-api" || !p.Project || !p.Sensitive {
		t.Errorf("project secret = %+v", p)
	}
	if strings.Contains(fmt.Sprintf("%+v", list), "TESTSECRET_") {
		t.Fatal("a value reached the TUI types")
	}
	if len(*seen) != 1 || !allZero((*seen)[0]) {
		t.Error("the listed entries were not wiped")
	}
	w.outRepo()
	if list, _ = tuiOver(w).Secrets(); list.Project != "" || len(list.Items) != 1 {
		t.Errorf("outside a repository: %+v", list)
	}
}

func TestTUISecretsFlagsOverridesAndOneLinesDescriptions(t *testing.T) {
	w := newWorld(t)
	seed(w, "K", "--global")
	w.inRepo()
	w.mustRun(fxVal+"\n", "set", "K", "--project", "--stdin", "--description", "line one\x1b[31m\nline two")
	list, err := tuiOver(w).Secrets()
	if err != nil || len(list.Items) != 1 {
		t.Fatalf("list = %+v, err = %v", list, err)
	}
	s := list.Items[0]
	if !s.Overrides || strings.ContainsAny(s.Description, "\n\x1b") {
		t.Errorf("secret = %+v, want an override with a one-line description", s)
	}
}

func TestTUISecretsOnALockedVaultIsErrLockedWithoutAPrompt(t *testing.T) {
	w := passphraseWorld(t)
	f := withBackend(t, answers(val(fxPass)))
	if _, err := tuiOver(w).Secrets(); !errors.Is(err, tui.ErrLocked) {
		t.Fatalf("err = %v, want tui.ErrLocked", err)
	}
	if _, err := tuiOver(w).Grants(); !errors.Is(err, tui.ErrLocked) {
		t.Fatalf("grants err = %v, want tui.ErrLocked", err)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("prompted: %+v", f.Calls)
	}
}

func TestTUIAddSecretCapturesTheValueThroughThePromptAndGrantsNothing(t *testing.T) {
	w := newWorld(t)
	f := withBackend(t, answers(val(fxVal)))
	act := tuiOver(w).AddSecret(tui.NewSecret{SecretRef: tui.SecretRef{Name: "NEW_KEY"}, Description: "for tests", Sensitive: true})
	if err := act.Run(); err != nil {
		t.Fatal(err)
	}
	if got := w.value("NEW_KEY"); got != fxVal {
		t.Fatal("the value typed in the prompt was not stored")
	}
	if len(f.Calls) != 1 || f.Calls[0].Kind != "secret" || f.Calls[0].Request.Name != "NEW_KEY" {
		t.Fatalf("prompt calls = %+v, want exactly one secret prompt", f.Calls)
	}
	if out := w.mustRun("", "describe", "NEW_KEY"); !strings.Contains(out, "for tests") || !strings.Contains(out, "sensitive:   yes") {
		t.Errorf("metadata not stored:\n%s", out)
	}
	if state := w.grantsState(); !strings.Contains(state, `"grants":[]`) {
		t.Errorf("adding a secret created a grant: %s", state)
	}
	if !w.auditHas(`"capture"`) {
		t.Error("the capture was not audited")
	}
}

func TestTUIAddSecretInTheProjectLayer(t *testing.T) {
	w := newWorld(t)
	w.inRepo()
	withBackend(t, answers(val(fxVal)))
	act := tuiOver(w).AddSecret(tui.NewSecret{SecretRef: tui.SecretRef{Name: "P_KEY", Project: true}})
	if err := act.Run(); err != nil {
		t.Fatal(err)
	}
	if out := w.mustRun("", "list", "--layer", "project"); !strings.Contains(out, "P_KEY") {
		t.Errorf("the secret is not in the project layer:\n%s", out)
	}
}

func TestTUIAddSecretKeepsTheMetadataOfAReplacedSecret(t *testing.T) {
	w := newWorld(t)
	w.mustRun(fxVal+"\n", "set", "OLD", "--global", "--stdin", "--description", "keep me", "--sensitive")
	withBackend(t, answers(val(fxVal+"_2")))
	if err := tuiOver(w).AddSecret(tui.NewSecret{SecretRef: tui.SecretRef{Name: "OLD"}}).Run(); err != nil {
		t.Fatal(err)
	}
	if out := w.mustRun("", "describe", "OLD", "--global"); !strings.Contains(out, "keep me") || !strings.Contains(out, "sensitive:   yes") {
		t.Errorf("a replace through the TUI wiped the metadata:\n%s", out)
	}
	if w.value("OLD") != fxVal+"_2" {
		t.Error("the value was not replaced")
	}
}

func TestTUIAddSecretFailuresAreShortSafeMessagesAndStoreNothing(t *testing.T) {
	cases := []struct {
		name   string
		fake   *fakePromptSetup
		secret tui.NewSecret
		want   string
	}{
		{"cancelled", scripted(cancel()), tui.NewSecret{SecretRef: tui.SecretRef{Name: "X"}}, "cancelled"},
		{"blank", scripted(val("   ")), tui.NewSecret{SecretRef: tui.SecretRef{Name: "X"}}, "empty value"},
		{"bad name", scripted(val(fxVal)), tui.NewSecret{SecretRef: tui.SecretRef{Name: "bad name!"}}, "name"},
		{"no prompt", unavailable(), tui.NewSecret{SecretRef: tui.SecretRef{Name: "X"}}, "terminal"},
		{"no project", scripted(val(fxVal)), tui.NewSecret{SecretRef: tui.SecretRef{Name: "X", Project: true}}, "repository"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t)
			c.fake.install(t)
			err := tuiOver(w).AddSecret(c.secret).Run()
			if err == nil {
				t.Fatal("no error")
			}
			if msg := err.Error(); !strings.Contains(strings.ToLower(msg), c.want) || strings.Contains(msg, "TESTSECRET_") || strings.Contains(msg, "\n") || len(msg) > 120 {
				t.Errorf("message = %q, want a short one-line text about %q", msg, c.want)
			}
			if out := w.mustRun("", "list", "--layer", "all"); !strings.Contains(out, "no secrets") {
				t.Errorf("a failed add stored something:\n%s", out)
			}
		})
	}
}

func TestTUIEditSecretUsesTheEditPath(t *testing.T) {
	w := newWorld(t)
	seed(w, "E_KEY", "--global")
	b := tuiOver(w)
	f := withBackend(t, answers())
	if err := b.EditSecret(tui.SecretEdit{SecretRef: tui.SecretRef{Name: "E_KEY"}, Description: "edited", Sensitive: true}); err != nil {
		t.Fatal(err)
	}
	out := w.mustRun("", "describe", "E_KEY", "--global")
	if !strings.Contains(out, "edited") || !strings.Contains(out, "sensitive:   yes") {
		t.Errorf("describe after edit:\n%s", out)
	}
	if !w.auditHas(`"edit"`) {
		t.Error("the edit was not audited")
	}
	if w.value("E_KEY") != fxVal {
		t.Error("editing metadata changed the value")
	}
	if len(f.Calls) != 0 {
		t.Errorf("an edit prompted: %+v", f.Calls)
	}
	if err := b.EditSecret(tui.SecretEdit{SecretRef: tui.SecretRef{Name: "MISSING"}, Description: "x"}); err == nil || !strings.Contains(err.Error(), "is not stored") {
		t.Errorf("editing a missing secret: err = %v", err)
	}
}

func TestTUIRemoveSecretUsesTheRemovePathWhichSnapshots(t *testing.T) {
	w := newWorld(t)
	seed(w, "R_KEY", "--global")
	seed(w, "KEEP", "--global")
	f := withBackend(t, answers())
	before, _ := vault.ListBackups(w.home)
	if err := tuiOver(w).RemoveSecret(tui.SecretRef{Name: "R_KEY"}); err != nil {
		t.Fatal(err)
	}
	out := w.mustRun("", "list", "--layer", "all")
	if strings.Contains(out, "R_KEY") || !strings.Contains(out, "KEEP") {
		t.Errorf("list after remove:\n%s", out)
	}
	if !w.auditHas(`"rm"`) {
		t.Error("the removal was not audited")
	}
	after, err := vault.ListBackups(w.home)
	if err != nil || len(after) == 0 || len(after) < len(before) {
		t.Errorf("no vault backup around the removal: before %d, after %d, err %v", len(before), len(after), err)
	}
	if len(f.Calls) != 0 {
		t.Errorf("the TUI already confirmed, but rm prompted again: %+v", f.Calls)
	}
	if err := tuiOver(w).RemoveSecret(tui.SecretRef{Name: "R_KEY"}); err == nil || !strings.Contains(err.Error(), "is not stored") {
		t.Errorf("removing it twice: err = %v", err)
	}
}

// ---- Grants ----

func grantFixture(t *testing.T) *world {
	t.Helper()
	pinClock(t)
	w := newWorld(t)
	seed(w, "A_KEY", "--global")
	seed(w, "B_KEY", "--global")
	w.inRepo()
	seed(w, "P_KEY", "--project")
	asTerminal(t, true)
	w.mustRun("y\n", "--session", sessA, "grant", "A_KEY", "--global", "--scope", "session")
	w.mustRun("y\n", "--session", sessA, "grant", "B_KEY", "--global", "--scope", "once")
	w.mustRun("y\n", "grant", "P_KEY", "--project", "--scope", "project")
	return w
}

func TestTUIGrantsListsActiveGrantsWithTimeLeft(t *testing.T) {
	w := grantFixture(t)
	f := withBackend(t, answers())
	gs, err := tuiOver(w).Grants()
	if err != nil || len(gs) != 3 {
		t.Fatalf("grants = %+v, err = %v", gs, err)
	}
	by := map[string]tui.Grant{}
	for _, g := range gs {
		by[g.Name] = g
	}
	a, b, p := by["A_KEY"], by["B_KEY"], by["P_KEY"]
	if a.Layer != "global" || a.Scope != "session" || a.Session != sessA || a.Left != "12h 0m" || a.Key == "" {
		t.Errorf("A_KEY grant = %+v", a)
	}
	if b.Scope != "once" || b.Left != "10m 0s" {
		t.Errorf("B_KEY grant = %+v", b)
	}
	if p.Layer != "project:shop-api" || p.Scope != "project" || p.Session != "" || p.Left != "no expiry" || p.Key == a.Key {
		t.Errorf("P_KEY grant = %+v", p)
	}
	if len(f.Calls) != 0 {
		t.Errorf("listing grants prompted: %+v", f.Calls)
	}
}

func TestTUIRevokeGrantRevokesOneSecretInOneLayerAndAudits(t *testing.T) {
	w := grantFixture(t)
	b := tuiOver(w)
	gs, _ := b.Grants()
	var target tui.Grant
	for _, g := range gs {
		if g.Name == "P_KEY" {
			target = g
		}
	}
	w.outRepo() // the project grant is revoked by its layer key, not by the working directory
	n, err := b.RevokeGrant(tui.GrantRef{Name: target.Name, Key: target.Key})
	if err != nil || n != 1 {
		t.Fatalf("revoked %d, err %v", n, err)
	}
	left, _ := b.Grants()
	if len(left) != 2 {
		t.Fatalf("grants after revoke = %+v", left)
	}
	for _, g := range left {
		if g.Name == "P_KEY" {
			t.Error("the grant is still active")
		}
	}
	if !w.auditHas(`"revoke"`) {
		t.Error("the revocation was not audited")
	}
	if n, err := b.RevokeGrant(tui.GrantRef{Name: "P_KEY", Key: target.Key}); err != nil || n != 0 {
		t.Errorf("revoking again: %d, %v", n, err)
	}
}

func TestTUIRevokeAllGrants(t *testing.T) {
	w := grantFixture(t)
	b := tuiOver(w)
	n, err := b.RevokeAllGrants()
	if err != nil || n != 3 {
		t.Fatalf("revoked %d, err %v", n, err)
	}
	if left, _ := b.Grants(); len(left) != 0 {
		t.Errorf("grants after revoke all = %+v", left)
	}
	if !w.auditHas("all revoked=3") {
		t.Error("the revoke-all was not audited")
	}
}

// ---- Setup ----

func TestTUISetupPlanListsHostsWithDetection(t *testing.T) {
	w := newBareWorld(t)
	present := fakeHost(t, w)
	absent := fake.New("absent", filepath.Join(filepath.Dir(w.home), "nothere"))
	withHosts(t, present, absent)
	plan, err := tuiOver(w).SetupPlan()
	if err != nil {
		t.Fatal(err)
	}
	if plan.Home != w.home || plan.Keychain == "" {
		t.Errorf("plan = %+v", plan)
	}
	want := []tui.HostChoice{
		{Name: "fake", Detected: true, Steps: []string{"mcp", "hooks"}},
		{Name: "absent", Detected: false, Steps: []string{"mcp", "hooks"}},
	}
	if !reflect.DeepEqual(plan.Hosts, want) {
		t.Errorf("hosts = %+v, want %+v", plan.Hosts, want)
	}
	if _, err := os.Stat(w.home); err == nil {
		t.Error("planning created the vault directory")
	}
}

func TestTUISetupWithTheKeychainRunsInitForTheChosenHosts(t *testing.T) {
	w := newBareWorld(t)
	chosen := fakeHost(t, w)
	other := fake.New("other", filepath.Join(filepath.Dir(w.home), "otherhost"))
	if err := os.MkdirAll(other.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	withHosts(t, chosen, other)
	f := withBackend(t, answers())
	if err := tuiOver(w).Setup(tui.SetupRequest{Hosts: []string{"fake"}}).Run(); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.ReadID(w.home); err != nil {
		t.Fatalf("no vault: %v", err)
	}
	if m, _ := keychain.ModeOf(w.home, keychain.Options{}); m == keychain.ModePassphrase {
		t.Error("keychain mode created a passphrase vault")
	}
	hs, _ := vault.ReadHosts(w.home)
	if _, ok := hs["fake"]; !ok || len(hs) != 1 {
		t.Errorf("registered hosts = %v, want only fake", hs)
	}
	if len(f.Calls) != 0 {
		t.Errorf("keychain setup prompted: %+v", f.Calls)
	}
	if !w.auditHas(`"init"`) {
		t.Error("init was not audited")
	}
	// Same code as the CLI: a second run is idempotent.
	if err := tuiOver(w).Setup(tui.SetupRequest{Hosts: []string{"fake"}}).Run(); err != nil {
		t.Errorf("second setup: %v", err)
	}
}

func TestTUISetupWithNoHostsRegistersNone(t *testing.T) {
	w := newBareWorld(t)
	withHosts(t, fakeHost(t, w))
	if err := tuiOver(w).Setup(tui.SetupRequest{}).Run(); err != nil {
		t.Fatal(err)
	}
	if hs, _ := vault.ReadHosts(w.home); len(hs) != 0 {
		t.Errorf("registered hosts = %v, want none", hs)
	}
	if _, err := vault.ReadID(w.home); err != nil {
		t.Errorf("no vault: %v", err)
	}
}

func TestTUISetupWithAPassphraseAsksThePromptBackendNotTheTUI(t *testing.T) {
	w := newBareWorld(t)
	withHosts(t)
	f := withBackend(t, answers(val(fxPass)))
	if err := tuiOver(w).Setup(tui.SetupRequest{Passphrase: true}).Run(); err != nil {
		t.Fatal(err)
	}
	if m, err := keychain.ModeOf(w.home, keychain.Options{}); err != nil || m != keychain.ModePassphrase {
		t.Fatalf("mode = %v, err = %v, want a passphrase vault", m, err)
	}
	if len(f.Calls) != 1 || f.Calls[0].Kind != "passphrase" || !f.Calls[0].Confirm {
		t.Fatalf("prompt calls = %+v, want one confirmed passphrase prompt", f.Calls)
	}
}

func TestTUISetupFailuresAreShortSafeMessages(t *testing.T) {
	t.Run("unknown host", func(t *testing.T) {
		w := newBareWorld(t)
		withHosts(t, fakeHost(t, w))
		err := tuiOver(w).Setup(tui.SetupRequest{Hosts: []string{"nope"}}).Run()
		if err == nil || !strings.Contains(err.Error(), "unknown agent") {
			t.Errorf("err = %v", err)
		}
		if _, serr := vault.ReadID(w.home); serr == nil {
			t.Error("a bad request created the vault")
		}
	})
	t.Run("passphrase prompt unavailable", func(t *testing.T) {
		w := newBareWorld(t)
		withHosts(t)
		withBackend(t, &prompttest.Fake{Unavailable: true})
		err := tuiOver(w).Setup(tui.SetupRequest{Passphrase: true}).Run()
		if err == nil || strings.Contains(err.Error(), "\n") {
			t.Errorf("err = %v", err)
		}
		if _, serr := vault.ReadID(w.home); serr == nil {
			t.Error("a failed passphrase setup left a vault")
		}
	})
}

// ---- Unlock ----

func TestTUIUnlockAsksThePassphraseThroughThePromptBackend(t *testing.T) {
	w := passphraseWorld(t)
	f := withBackend(t, answers(val(fxPass)))
	if err := tuiOver(w).Unlock().Run(); err != nil {
		t.Fatal(err)
	}
	if len(f.Calls) != 1 || f.Calls[0].Kind != "passphrase" {
		t.Fatalf("calls = %+v", f.Calls)
	}
	withBackend(t, answers(val("TESTSECRET_wrong")))
	err := tuiOver(w).Unlock().Run()
	if err == nil || strings.Contains(err.Error(), "TESTSECRET_") || !strings.Contains(err.Error(), "locked") {
		t.Errorf("wrong passphrase: err = %v", err)
	}
}

// The tui package cannot reach the grant machinery; the adapter must not
// expose a route to it either: its only grant entry points are the three reads
// and revokes of the Backend interface.
func TestTUIBackendAdapterImplementsExactlyTheBackendInterface(t *testing.T) {
	var _ tui.Backend = (*tuiBackend)(nil)
	typ := reflect.TypeOf(&tuiBackend{})
	for i := range typ.NumMethod() {
		n := strings.ToLower(typ.Method(i).Name)
		if strings.Contains(n, "grant") && n != "grants" && n != "revokegrant" && n != "revokeallgrants" {
			t.Errorf("tuiBackend.%s looks like a grant-creating method", typ.Method(i).Name)
		}
	}
}

// ---- helpers local to this file ----

// fakePromptSetup installs a prompt backend for one subtest.
type fakePromptSetup struct{ install func(*testing.T) }

func scripted(a ...prompttest.Answer) *fakePromptSetup {
	return &fakePromptSetup{install: func(t *testing.T) { withBackend(t, answers(a...)) }}
}

func unavailable() *fakePromptSetup {
	return &fakePromptSetup{install: func(t *testing.T) {
		old := newPrompt
		newPrompt = func(*globals) (prompt.Backend, error) { return nil, prompt.ErrNoTerminal }
		t.Cleanup(func() { newPrompt = old })
	}}
}

// Edit and remove run while the TUI owns the terminal, so they must never
// reach a passphrase prompt: a locked vault is an error, not a prompt.
func TestTUIEditAndRemoveOnALockedVaultFailWithoutPrompting(t *testing.T) {
	w := passphraseWorld(t)
	f := withBackend(t, answers(val(fxPass), val(fxPass)))
	b := tuiOver(w)
	if err := b.EditSecret(tui.SecretEdit{SecretRef: tui.SecretRef{Name: "A"}, Description: "x"}); !errors.Is(err, tui.ErrLocked) {
		t.Errorf("edit err = %v, want tui.ErrLocked", err)
	}
	if err := b.RemoveSecret(tui.SecretRef{Name: "A"}); !errors.Is(err, tui.ErrLocked) {
		t.Errorf("remove err = %v, want tui.ErrLocked", err)
	}
	if _, err := b.RevokeGrant(tui.GrantRef{Name: "A", Key: "global"}); !errors.Is(err, tui.ErrLocked) {
		t.Errorf("revoke err = %v, want tui.ErrLocked", err)
	}
	if _, err := b.RevokeAllGrants(); !errors.Is(err, tui.ErrLocked) {
		t.Errorf("revoke all err = %v, want tui.ErrLocked", err)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("a mutation prompted while the TUI was showing: %+v", f.Calls)
	}
}

func TestTUISetupPlanOfTheReleaseBuildNamesClaudeCodexAndPi(t *testing.T) {
	w := newBareWorld(t)
	old := hostRegistry
	hostRegistry = releaseHostRegistry
	t.Cleanup(func() { hostRegistry = old })
	plan, err := tuiOver(w).SetupPlan()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, h := range plan.Hosts {
		names = append(names, h.Name)
		if len(h.Steps) == 0 {
			t.Errorf("host %s lists no steps", h.Name)
		}
	}
	if !reflect.DeepEqual(names, []string{"claude-code", "codex", "pi"}) {
		t.Errorf("hosts = %v", names)
	}
}

// A name typed in the TUI is never parsed as a flag: "--help" must not turn
// the command into a help request that reports success, and "--stdin" must
// not switch the masked prompt for a read of the terminal.
func TestTUINamesThatLookLikeFlagsAreRejectedAsNames(t *testing.T) {
	for _, name := range []string{"--help", "-h", "--stdin", "--global"} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			seed(w, "KEEP", "--global")
			f := withBackend(t, answers(val(fxVal)))
			b := tuiOver(w)
			ref := tui.SecretRef{Name: name}
			for op, err := range map[string]error{
				"add":    b.AddSecret(tui.NewSecret{SecretRef: ref}).Run(),
				"edit":   b.EditSecret(tui.SecretEdit{SecretRef: ref, Description: "x"}),
				"remove": b.RemoveSecret(ref),
			} {
				if err == nil || !strings.Contains(strings.ToLower(err.Error()), "name") {
					t.Errorf("%s %q: err = %v, want an invalid-name error", op, name, err)
				}
			}
			if len(f.Calls) != 0 {
				t.Errorf("a flag-like name reached the prompt: %+v", f.Calls)
			}
			if out := w.mustRun("", "list", "--layer", "all"); !strings.Contains(out, "KEEP") || strings.Count(out, "\n") > 3 {
				t.Errorf("the vault changed:\n%s", out)
			}
		})
	}
}

// A description that starts with a dash is stored as text, not read as a flag.
func TestTUIDescriptionsThatLookLikeFlagsAreStoredAsText(t *testing.T) {
	w := newWorld(t)
	seed(w, "D_KEY", "--global")
	withBackend(t, answers())
	if err := tuiOver(w).EditSecret(tui.SecretEdit{SecretRef: tui.SecretRef{Name: "D_KEY"}, Description: "--sensitive"}); err != nil {
		t.Fatal(err)
	}
	out := w.mustRun("", "describe", "D_KEY", "--global")
	if !strings.Contains(out, "--sensitive") || strings.Contains(out, "sensitive:   yes") {
		t.Errorf("describe:\n%s", out)
	}
}
