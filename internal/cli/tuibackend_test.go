package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/QuBiit0/qbit-vault/internal/audit"
	"github.com/QuBiit0/qbit-vault/internal/exitcode"
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
// expose a route to it either: its only grant entry points are the read and
// the two revokes of the Backend interface. The pattern is the interface-level
// one (tui.TestBackendHasNoMethodThatCreatesOrApprovesAGrant), so a method
// named for approving, allowing, permitting or a token cannot slip in.
func TestTUIBackendAdapterImplementsExactlyTheBackendInterface(t *testing.T) {
	var _ tui.Backend = (*tuiBackend)(nil)
	allowed := map[string]bool{"Grants": true, "RevokeGrant": true, "RevokeAllGrants": true}
	suspicious := regexp.MustCompile(`(?i)grant|approve|allow|permit|authori|consent|token`)
	for _, typ := range []reflect.Type{reflect.TypeOf(&tuiBackend{}), reflect.TypeOf((*tui.Backend)(nil)).Elem()} {
		for i := range typ.NumMethod() {
			if name := typ.Method(i).Name; suspicious.MatchString(name) && !allowed[name] {
				t.Errorf("%s.%s looks like a grant-creating method", typ, name)
			}
		}
	}
	// The pattern must be able to fail: it matches names that approve or allow.
	for _, bad := range []string{"ApproveGrant", "AllowOnce", "PermitHost", "Authorize", "GiveConsent", "NewToken"} {
		if !suspicious.MatchString(bad) {
			t.Errorf("the pattern misses %s", bad)
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

// ---- T3 F3: commands that run while the TUI owns the terminal never prompt ----

// The window quiet() could not close: the vault opened without a prompt a
// moment ago, then the unlock cache expired, and the command asked for the
// passphrase over the screen. The no-prompt mode fails with ErrLocked instead.
func TestTUINoPromptModeFailsLockedInsteadOfAskingForThePassphrase(t *testing.T) {
	w := passphraseWorld(t)
	f := withBackend(t, answers(val(fxPass), val(fxPass), val(fxPass)))
	b := tuiOver(w)
	for name, args := range map[string][]string{
		"rm":     {"rm", "--global", "--yes", "--", "A_KEY"},
		"edit":   {"edit", "--global", "--description=x", "--sensitive=false", "--", "A_KEY"},
		"revoke": {"revoke", "--all"},
	} {
		err := b.g.runCommandNoPrompt(args...)
		if !errors.Is(err, tui.ErrLocked) {
			t.Errorf("%s: err = %v, want tui.ErrLocked", name, err)
		}
	}
	if len(f.Calls) != 0 {
		t.Fatalf("a no-prompt command prompted: %+v", f.Calls)
	}
	// The same command in the normal mode does ask: the mode is what changes it.
	_ = b.g.runCommand("rm", "--global", "--yes", "--", "A_KEY")
	if len(f.Calls) == 0 || f.Calls[0].Kind != "passphrase" {
		t.Fatalf("the control did not prompt, so the test proves nothing: %+v", f.Calls)
	}
}

func TestTUINoPromptModeStillRunsTheCommandOnAnOpenVault(t *testing.T) {
	w := newWorld(t)
	seed(w, "A_KEY", "--global")
	f := withBackend(t, answers())
	if err := tuiOver(w).g.runCommandNoPrompt("rm", "--global", "--yes", "--", "A_KEY"); err != nil {
		t.Fatal(err)
	}
	if out := w.mustRun("", "list", "--layer", "all"); strings.Contains(out, "A_KEY") {
		t.Errorf("the secret is still listed:\n%s", out)
	}
	if len(f.Calls) != 0 {
		t.Errorf("prompted: %+v", f.Calls)
	}
}

// The mutations of the TUI go through the no-prompt mode: with the quiet
// pre-check gone, a locked vault is still ErrLocked and nothing prompts.
func TestTUIMutationsUseTheNoPromptMode(t *testing.T) {
	w := passphraseWorld(t)
	f := withBackend(t, answers(val(fxPass), val(fxPass)))
	b := tuiOver(w)
	err := b.EditSecret(tui.SecretEdit{SecretRef: tui.SecretRef{Name: "A_KEY"}, KeepDescription: true})
	if !errors.Is(err, tui.ErrLocked) || len(f.Calls) != 0 {
		t.Errorf("edit: err = %v, calls = %+v", err, f.Calls)
	}
	if err := b.RemoveSecret(tui.SecretRef{Name: "A_KEY"}); !errors.Is(err, tui.ErrLocked) || len(f.Calls) != 0 {
		t.Errorf("remove: err = %v, calls = %+v", err, f.Calls)
	}
}

// ---- T3 F4: an unchanged description is kept as stored ----

func TestTUIEditKeepsAMultiLineDescriptionWhenToldToKeepIt(t *testing.T) {
	w := newWorld(t)
	w.mustRun(fxVal+"\n", "set", "M_KEY", "--global", "--stdin", "--description", "line one\nline two")
	withBackend(t, answers())
	b := tuiOver(w)
	if err := b.EditSecret(tui.SecretEdit{SecretRef: tui.SecretRef{Name: "M_KEY"}, KeepDescription: true, Sensitive: true}); err != nil {
		t.Fatal(err)
	}
	if got := storedDescription(t, w, "M_KEY"); got != "line one\nline two" {
		t.Fatalf("description = %q, want it untouched", got)
	}
	if out := w.mustRun("", "describe", "M_KEY", "--global"); !strings.Contains(out, "sensitive:   yes") {
		t.Errorf("the sensitive flag was not applied:\n%s", out)
	}
	if err := b.EditSecret(tui.SecretEdit{SecretRef: tui.SecretRef{Name: "M_KEY"}, Description: "new text"}); err != nil {
		t.Fatal(err)
	}
	if got := storedDescription(t, w, "M_KEY"); got != "new text" {
		t.Fatalf("description = %q, want the new text", got)
	}
	// An explicit empty description clears it.
	if err := b.EditSecret(tui.SecretEdit{SecretRef: tui.SecretRef{Name: "M_KEY"}}); err != nil {
		t.Fatal(err)
	}
	if got := storedDescription(t, w, "M_KEY"); got != "" {
		t.Fatalf("description = %q, want it cleared", got)
	}
}

// storedDescription reads a secret's description from the vault itself, not
// from the one-lined listing.
func storedDescription(t *testing.T, w *world, name string) string {
	t.Helper()
	s, err := (&globals{getenv: envFrom(nil), home: w.home}).openSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	cwd, _ := os.Getwd()
	es, err := s.v.List(cwd)
	if err != nil {
		t.Fatal(err)
	}
	defer wipeEntries(es)
	for _, e := range es {
		if e.Name == name {
			return e.Record.Description
		}
	}
	t.Fatalf("%s is not stored", name)
	return ""
}

// ---- T3: hosts ----

// hostWorld is a vault with one registered fake host.
func hostWorld(t *testing.T) (*world, *fake.Adapter) {
	t.Helper()
	w := newBareWorld(t)
	h := fakeHost(t, w)
	withHosts(t, h)
	w.mustRun("", "init")
	return w, h
}

// secondHost is a detected host that is not registered.
func secondHost(t *testing.T, w *world, name string) *fake.Adapter {
	t.Helper()
	dir := filepath.Join(filepath.Dir(w.home), name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return fake.New(name, dir)
}

func hostByName(t *testing.T, hs []tui.HostInfo, name string) tui.HostInfo {
	t.Helper()
	for _, h := range hs {
		if h.Name == name {
			return h
		}
	}
	t.Fatalf("host %s is not listed: %+v", name, hs)
	return tui.HostInfo{}
}

func TestTUIHostsListsEachStepWithItsFileAndStatus(t *testing.T) {
	w, h := hostWorld(t)
	hs, err := tuiOver(w).Hosts()
	if err != nil || len(hs) != 1 {
		t.Fatalf("hosts = %+v, err = %v", hs, err)
	}
	got := hs[0]
	if got.Name != "fake" || !got.Registered || !got.Detected || got.NoAdapter || len(got.Steps) != 2 {
		t.Fatalf("host = %+v", got)
	}
	for i, want := range []struct{ name, file string }{{"mcp", "config.json"}, {"hooks", "hooks.json"}} {
		s := got.Steps[i]
		if s.Name != want.name || s.Status != tui.StepOK || filepath.Base(s.File) != want.file || filepath.Base(filepath.Dir(s.File)) != filepath.Base(h.Dir) {
			t.Errorf("step %d = %+v, want %s %s in %s", i, s, want.name, tui.StepOK, h.Dir)
		}
	}
}

// The statuses are the ones doctor reports: drift is warn, per step.
func TestTUIHostsReportsDriftLikeDoctorDoes(t *testing.T) {
	w, h := hostWorld(t)
	if err := os.WriteFile(filepath.Join(h.Dir, "hooks.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := tuiOver(w)
	host := hostByName(t, mustHosts(t, b), "fake")
	if host.Steps[0].Status != tui.StepOK || host.Steps[1].Status != tui.StepDrift {
		t.Fatalf("steps = %+v, want mcp ok and hooks drift", host.Steps)
	}
	for _, c := range b.g.runDoctor().Checks {
		switch c.Name {
		case "host.fake.mcp":
			if c.Status != "ok" {
				t.Errorf("doctor says %s for mcp", c.Status)
			}
		case "host.fake.hooks":
			if c.Status != "warn" || !strings.Contains(c.Detail, "changed since registration") {
				t.Errorf("doctor says %s %q for hooks", c.Status, c.Detail)
			}
		}
	}
}

func mustHosts(t *testing.T, b *tuiBackend) []tui.HostInfo {
	t.Helper()
	hs, err := b.Hosts()
	if err != nil {
		t.Fatal(err)
	}
	return hs
}

func TestTUIHostsListsDetectedUnregisteredAndAdapterlessHosts(t *testing.T) {
	w, h := hostWorld(t)
	second := secondHost(t, w, "second")
	ghost := fake.New("ghost", filepath.Join(filepath.Dir(w.home), "nowhere"))
	withHosts(t, h, second, ghost)
	hs := mustHosts(t, tuiOver(w))
	if s := hostByName(t, hs, "second"); s.Registered || !s.Detected || len(s.Steps) != 2 || s.Steps[0].Status != tui.StepMissing || s.Steps[0].File != "" {
		t.Errorf("second = %+v, want detected, not registered, steps missing", s)
	}
	if g := hostByName(t, hs, "ghost"); g.Registered || g.Detected {
		t.Errorf("ghost = %+v, want not detected", g)
	}
	withHosts(t) // this build knows no host any more
	if g := hostByName(t, mustHosts(t, tuiOver(w)), "fake"); !g.NoAdapter || !g.Registered {
		t.Errorf("fake = %+v, want a registered host without an adapter", g)
	}
}

func TestTUIRepairHostsReappliesTheRegistrationLikeSync(t *testing.T) {
	w, h := hostWorld(t)
	second := secondHost(t, w, "second")
	withHosts(t, h, second)
	f := withBackend(t, answers())
	b := tuiOver(w)
	if err := os.WriteFile(filepath.Join(h.Dir, "hooks.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	sum, err := b.RepairHosts("fake")
	if err != nil || !strings.Contains(sum, "fake") || !strings.Contains(sum, "hooks") {
		t.Fatalf("summary = %q, err = %v", sum, err)
	}
	if st := hostByName(t, mustHosts(t, b), "fake").Steps[1].Status; st != tui.StepOK {
		t.Errorf("hooks is %s after the repair", st)
	}
	if _, err := vault.ReadHosts(w.home); err != nil {
		t.Fatal(err)
	}
	if hostByName(t, mustHosts(t, b), "second").Registered {
		t.Error("a repair registered a host that was only detected")
	}
	// Nothing to repair: said plainly, and nothing is rewritten.
	sum, err = b.RepairHosts("")
	if err != nil || !strings.Contains(sum, "up to date") {
		t.Errorf("summary = %q, err = %v", sum, err)
	}
	if len(f.Calls) != 0 {
		t.Errorf("a repair prompted: %+v", f.Calls)
	}
}

func TestTUIRepairHostsRefusesWhatIsNotRegistered(t *testing.T) {
	w, h := hostWorld(t)
	withHosts(t, h, secondHost(t, w, "second"))
	b := tuiOver(w)
	for _, name := range []string{"second", "nope"} {
		if _, err := b.RepairHosts(name); err == nil || !strings.Contains(err.Error(), "not registered") {
			t.Errorf("RepairHosts(%q) err = %v, want not registered", name, err)
		}
	}
	if recorded, _ := vault.ReadHosts(w.home); len(recorded) != 1 {
		t.Errorf("state.json records %d hosts, want only fake", len(recorded))
	}
}

func TestTUIUninstallHostRevertsOneHostAndKeepsTheVault(t *testing.T) {
	w, h := hostWorld(t)
	second := secondHost(t, w, "second")
	withHosts(t, h, second)
	w.mustRun("", "sync", "--agents", "second")
	seed(w, "KEEP_KEY", "--global")
	f := withBackend(t, answers())
	b := tuiOver(w)
	sum, err := b.UninstallHost("fake")
	if err != nil || !strings.Contains(sum, "fake") {
		t.Fatalf("summary = %q, err = %v", sum, err)
	}
	if _, err := os.Stat(filepath.Join(h.Dir, "config.json")); !os.IsNotExist(err) {
		t.Errorf("the config file we created is still there: %v", err)
	}
	recorded, _ := vault.ReadHosts(w.home)
	if _, still := recorded["fake"]; still || len(recorded) != 1 {
		t.Errorf("state.json records %v, want only second", recorded)
	}
	if w.value("KEEP_KEY") != fxVal {
		t.Error("uninstalling a host touched the vault")
	}
	if !w.auditHas(`"uninstall"`) {
		t.Error("the uninstall was not audited")
	}
	if len(f.Calls) != 0 {
		t.Errorf("an uninstall prompted: %+v", f.Calls)
	}
	for _, name := range []string{"fake", "nope", ""} {
		if _, err := b.UninstallHost(name); err == nil {
			t.Errorf("UninstallHost(%q) succeeded", name)
		}
	}
	if _, err := os.Stat(w.home); err != nil {
		t.Fatalf("the vault home is gone: %v", err)
	}
}

func TestTUIRegisterHostRegistersADetectedHostWithoutSecretsOrPrompts(t *testing.T) {
	w, h := hostWorld(t)
	second := secondHost(t, w, "second")
	ghost := fake.New("ghost", filepath.Join(filepath.Dir(w.home), "nowhere"))
	withHosts(t, h, second, ghost)
	f := withBackend(t, answers())
	b := tuiOver(w)
	sum, err := b.RegisterHost("second")
	if err != nil || !strings.Contains(sum, "second") {
		t.Fatalf("summary = %q, err = %v", sum, err)
	}
	if _, err := os.Stat(filepath.Join(second.Dir, "config.json")); err != nil {
		t.Errorf("the host config was not written: %v", err)
	}
	if s := hostByName(t, mustHosts(t, b), "second"); !s.Registered || s.Steps[0].Status != tui.StepOK {
		t.Errorf("second = %+v", s)
	}
	for name, want := range map[string]string{"second": "already registered", "ghost": "not found", "nope": "unknown host"} {
		if _, err := b.RegisterHost(name); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("RegisterHost(%q) err = %v, want %q", name, err, want)
		}
	}
	if len(f.Calls) != 0 {
		t.Errorf("registering prompted: %+v", f.Calls)
	}
}

// ---- T3: audit ----

func TestTUIAuditListsRecentRecordsWithNamesAndNoValues(t *testing.T) {
	w := newWorld(t)
	seed(w, "A_KEY", "--global")
	seed(w, "B_KEY", "--global")
	log, err := tuiOver(w).Audit()
	if err != nil {
		t.Fatal(err)
	}
	if log.Total < 3 || len(log.Entries) != log.Total {
		t.Fatalf("log = %+v, want every record (init and two captures)", log)
	}
	names := map[string]bool{}
	for _, e := range log.Entries {
		if e.Time == "" || e.Event == "" || e.By == "" {
			t.Errorf("incomplete entry %+v", e)
		}
		for _, n := range e.Names {
			names[n] = true
		}
	}
	if !names["A_KEY"] || !names["B_KEY"] {
		t.Errorf("names = %v", names)
	}
	noFixtures(t, "the audit listing", fmt.Sprintf("%+v", log))
	if log.Entries[0].Time > log.Entries[len(log.Entries)-1].Time {
		t.Error("the backend must return the oldest record first")
	}
}

func TestTUIAuditReturnsOnlyTheNewestRecordsButCountsAll(t *testing.T) {
	w := newWorld(t)
	for i := range defaultAuditTail + 10 {
		if err := audit.Append(w.home, audit.Record{Event: audit.EventWarning, Session: "cli", By: "user", Detail: fmt.Sprintf("n%d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	log, err := tuiOver(w).Audit()
	if err != nil || len(log.Entries) != defaultAuditTail || log.Total < defaultAuditTail+10 {
		t.Fatalf("entries = %d, total = %d, err = %v", len(log.Entries), log.Total, err)
	}
}

func TestTUIAuditOfAVaultWithoutALogIsEmpty(t *testing.T) {
	w := newBareWorld(t)
	if err := os.MkdirAll(w.home, 0o700); err != nil {
		t.Fatal(err)
	}
	log, err := tuiOver(w).Audit()
	if err != nil || len(log.Entries) != 0 || log.Total != 0 {
		t.Fatalf("log = %+v, err = %v", log, err)
	}
}

func TestTUIVerifyAuditReportsAnIntactChain(t *testing.T) {
	w := newWorld(t)
	seed(w, "A_KEY", "--global")
	v, err := tuiOver(w).VerifyAudit()
	if err != nil || !v.Valid || v.Records < 2 || v.Line != 0 {
		t.Fatalf("verdict = %+v, err = %v", v, err)
	}
}

func TestTUIVerifyAuditNamesTheFirstBrokenLine(t *testing.T) {
	w := newWorld(t)
	seed(w, "A_KEY", "--global")
	seed(w, "B_KEY", "--global")
	path := w.auditFile()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(string(raw), "\n")
	lines[1] = strings.Replace(lines[1], `"event":"`, `"event":"x`, 1)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "")), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := tuiOver(w).VerifyAudit()
	if err != nil || v.Valid || v.Line != 2 || v.Reason == "" {
		t.Fatalf("verdict = %+v, err = %v, want a break at line 2", v, err)
	}
	// It is the verdict `audit --verify` gives.
	code, out, _ := w.run("", "audit", "--verify", "--offline")
	if code == exitcode.OK || !strings.Contains(out, fmt.Sprintf("line %d", v.Line)) {
		t.Errorf("audit --verify: code=%d out=%q", code, out)
	}
}

// ---- T3: sync status ----

func TestTUISyncStatusOfAVaultThatDoesNotSync(t *testing.T) {
	w := newWorld(t)
	st, err := tuiOver(w).SyncStatus()
	if err != nil || st.Linked || st.Server != "" {
		t.Fatalf("status = %+v, err = %v", st, err)
	}
}

func linkedWorld(t *testing.T, w *world) {
	t.Helper()
	rem := &vault.Remote{
		Server: "https://vault.example", AccountID: "0123456789abcdef0123456789abcdef", Generation: 2, LastVersion: 9,
		PendingPush: true, LastPullAt: "2026-11-04T10:00:00Z",
		Summary: vault.RemoteSummary{At: "2026-11-04T10:00:00Z", Conflicts: 2, Devices: 3},
	}
	if err := vault.WriteRemote(w.home, rem); err != nil {
		t.Fatal(err)
	}
}

func TestTUISyncStatusOfALinkedVault(t *testing.T) {
	w := newWorld(t)
	linkedWorld(t, w)
	st, err := tuiOver(w).SyncStatus()
	if err != nil {
		t.Fatal(err)
	}
	// Unlocked: the conflicts are counted from the vault itself (none), not
	// taken from the summary of the last round.
	id, _ := vault.ReadDeviceID(w.home)
	want := tui.SyncStatus{Linked: true, Server: "https://vault.example", Device: short(id), LastRound: "2026-11-04T10:00:00Z", PendingPush: true, Conflicts: 0}
	if st != want {
		t.Fatalf("status = %+v, want %+v", st, want)
	}
}

func TestTUISyncStatusOfALockedVaultUsesTheLastRoundAndNeverPrompts(t *testing.T) {
	w := passphraseWorld(t)
	linkedWorld(t, w)
	f := withBackend(t, answers(val(fxPass)))
	st, err := tuiOver(w).SyncStatus()
	if err != nil || !st.Linked || !st.Cached || st.Conflicts != 2 {
		t.Fatalf("status = %+v, err = %v, want the cached count of the last round", st, err)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("prompted: %+v", f.Calls)
	}
	// Locked and no round yet: the count is unknown, not zero.
	rem, _ := vault.ReadRemote(w.home)
	rem.Summary = vault.RemoteSummary{}
	if err := vault.WriteRemote(w.home, rem); err != nil {
		t.Fatal(err)
	}
	if st, _ := tuiOver(w).SyncStatus(); st.Conflicts != -1 || st.Cached {
		t.Errorf("status = %+v, want unknown conflicts", st)
	}
}

func TestTUISyncStatusSaysWhenRemoteCallsAreOff(t *testing.T) {
	w := newWorld(t)
	linkedWorld(t, w)
	b := &tuiBackend{g: &globals{getenv: envFrom(map[string]string{envNoRemote: "1"}), home: w.home}}
	if st, err := b.SyncStatus(); err != nil || !st.Offline {
		t.Fatalf("status = %+v, err = %v, want offline", st, err)
	}
}

// ---- T3: doctor ----

func TestTUIDoctorIsTheDoctorReport(t *testing.T) {
	w, h := hostWorld(t)
	if err := os.WriteFile(filepath.Join(h.Dir, "hooks.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := tuiOver(w)
	rep, err := b.Doctor()
	if err != nil {
		t.Fatal(err)
	}
	want := b.g.runDoctor()
	if rep.OK != want.OK || len(rep.Checks) != len(want.Checks) || rep.OK {
		t.Fatalf("report = %+v, want the doctor's %+v (unhealthy)", rep, want)
	}
	for i, c := range rep.Checks {
		if c.Name != want.Checks[i].Name || c.Status != string(want.Checks[i].Status) || c.Detail != want.Checks[i].Detail {
			t.Errorf("check %d = %+v, want %+v", i, c, want.Checks[i])
		}
	}
}

// ---- T3 S7: no fixture through any adapter method or frame ----

// A vault that holds a TESTSECRET_ value, a grant, a host and an audit trail:
// nothing the adapter returns, and no frame of the real model over it, holds
// the value.
func TestTUIAdapterResultsNeverHoldAFixtureWhileTheVaultDoes(t *testing.T) {
	w := grantFixture(t)
	h := fakeHost(t, w)
	withHosts(t, h)
	w.mustRun("", "sync", "--agents", "fake")
	linkedWorld(t, w)
	b := tuiOver(w)
	var seen []string
	add := func(v any, err error) {
		seen = append(seen, fmt.Sprintf("%+v %v", v, err))
	}
	add(b.Status())
	add(b.SetupPlan())
	add(b.Secrets())
	add(b.Grants())
	add(b.Hosts())
	add(b.Audit())
	add(b.VerifyAudit())
	add(b.SyncStatus())
	add(b.Doctor())
	add(b.RepairHosts(""))
	add(b.RepairHosts("nope"))
	add(b.UninstallHost("nope"))
	add(b.RegisterHost("nope"))
	add(b.RevokeGrant(tui.GrantRef{Name: "A_KEY", Key: "global"}))
	if w.value("A_KEY") != fxVal {
		t.Fatal("the fixture is not in the vault: the test proves nothing")
	}
	for i, s := range seen {
		noFixtures(t, fmt.Sprintf("adapter result %d", i), s)
	}
}

func TestTUIFramesOverTheRealAdapterNeverHoldAFixture(t *testing.T) {
	w := grantFixture(t)
	withHosts(t, fakeHost(t, w))
	w.mustRun("", "sync", "--agents", "fake")
	linkedWorld(t, w)
	m := tui.New(tuiOver(w), tui.Options{Version: "t", Profile: tui.Profile{Color: true, TrueColor: true}})
	key := func(r rune) tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}} }
	var keys []tea.KeyMsg
	for r := rune('1'); r <= '7'; r++ {
		keys = append(keys, key(r), tea.KeyMsg{Type: tea.KeyTab}, tea.KeyMsg{Type: tea.KeyDown}, key('v'), key('r'), tea.KeyMsg{Type: tea.KeyEsc})
	}
	keys = append(keys, key('1'), key('a'))
	for _, r := range "SENTRY" {
		keys = append(keys, key(r))
	}
	keys = append(keys, tea.KeyMsg{Type: tea.KeyEsc}, key('d'), tea.KeyMsg{Type: tea.KeyEsc})
	// Stray typing where no field is open, as if a value were pasted: the
	// Update section ignores every key.
	keys = append(keys, key('7'))
	for _, r := range fxVal {
		keys = append(keys, key(r))
	}
	frames := []string{m.View()}
	for _, k := range keys {
		next, _ := m.Update(k) // commands (suspended prompts) are never run
		m = next.(tui.Model)
		frames = append(frames, m.View())
	}
	if w.value("A_KEY") != fxVal {
		t.Fatal("the fixture is not in the vault: the test proves nothing")
	}
	for i, f := range frames {
		noFixtures(t, fmt.Sprintf("frame %d", i), f)
	}
}
