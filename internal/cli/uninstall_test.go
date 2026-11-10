package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"

	"github.com/qbitdevz/qbit-vault/internal/exitcode"
	"github.com/qbitdevz/qbit-vault/internal/hook"
	"github.com/qbitdevz/qbit-vault/internal/hosts/fake"
	"github.com/qbitdevz/qbit-vault/internal/prompt/prompttest"
	"github.com/qbitdevz/qbit-vault/internal/refusal"
	"github.com/qbitdevz/qbit-vault/internal/vault"
)

const userConfig = "{\n  \"theme\": \"dark\"\n}\n"

// registeredOver registers the fake host over a config.json the user already
// had, and returns it.
func registeredOver(t *testing.T) (*world, *fake.Adapter) {
	t.Helper()
	w := newBareWorld(t)
	h := fakeHost(t, w)
	withHosts(t, h)
	if err := os.WriteFile(filepath.Join(h.Dir, "config.json"), []byte(userConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	w.mustRun("", "init")
	return w, h
}

func keychainHas(t *testing.T, w *world) bool {
	t.Helper()
	id, err := vault.ReadID(w.home)
	if err != nil {
		t.Fatal(err)
	}
	_, err = keyring.Get("qbit-vault", "master:"+id)
	return err == nil
}

func TestUninstallRestoresAnUntouchedConfigByteForByte(t *testing.T) {
	w, h := registeredOver(t)
	f := withBackend(t, answers(yes()))
	code, out, errs := w.run("", "--session", sessA, "uninstall")
	want := "host fake: hooks deleted, mcp restored\nvault kept at " + w.home + "\n"
	if code != exitcode.OK || errs != "" || out != want {
		t.Fatalf("code=%d out=%q want=%q err=%q", code, out, want, errs)
	}
	if len(f.Calls) != 1 || f.Calls[0].Kind != "confirm" {
		t.Fatalf("prompts: %+v", f.Calls)
	}
	if readFile(t, h.Dir, "config.json") != userConfig {
		t.Fatalf("config not restored byte for byte:\n%s", readFile(t, h.Dir, "config.json"))
	}
	if _, err := os.Stat(filepath.Join(h.Dir, "hooks.json")); !os.IsNotExist(err) {
		t.Fatal("a file we created is still there")
	}
	if hs, _ := vault.ReadHosts(w.home); len(hs) != 0 {
		t.Fatalf("hosts still recorded: %+v", hs)
	}
	if _, err := os.Stat(filepath.Join(w.home, "vault.enc")); err != nil || !keychainHas(t, w) {
		t.Fatal("uninstall touched the vault or its key")
	}
	if !w.auditHas(`"event":"uninstall"`) {
		t.Fatal("no uninstall audit record")
	}
	// Nothing left to revert: a second run says so and still asks first.
	withBackend(t, answers(yes()))
	if code, out, _ := w.run("", "--session", sessA, "uninstall"); code != exitcode.OK || out != "no hosts registered\nvault kept at "+w.home+"\n" {
		t.Fatalf("second run: code=%d out=%q", code, out)
	}
}

func TestUninstallKeepsAUserEditMadeAfterRegistration(t *testing.T) {
	w, h := registeredOver(t)
	cfg := filepath.Join(h.Dir, "config.json")
	edited := strings.Replace(readFile(t, cfg), "\"theme\": \"dark\"", "\"theme\": \"light\",\n  \"added\": true", 1)
	if err := os.WriteFile(cfg, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	withBackend(t, answers(yes()))
	code, out, errs := w.run("", "--session", sessA, "uninstall")
	if code != exitcode.OK || errs != "" || out != "host fake: hooks deleted, mcp stripped\nvault kept at "+w.home+"\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	got := readFile(t, cfg)
	if strings.Contains(got, "qbit-vault") || !strings.Contains(got, `"theme": "light"`) || !strings.Contains(got, `"added": true`) {
		t.Fatalf("user edit lost or our entry kept:\n%s", got)
	}
}

func TestUninstallFailedRevertKeepsTheHostInStateAndExitsOne(t *testing.T) {
	w := newBareWorld(t)
	bad := fakeHost(t, w)
	goodDir := filepath.Join(filepath.Dir(w.home), "goodhost")
	if err := os.MkdirAll(goodDir, 0o700); err != nil {
		t.Fatal(err)
	}
	good := fake.New("good", goodDir)
	withHosts(t, bad, good)
	w.mustRun("", "init")
	hooks := filepath.Join(bad.Dir, "hooks.json")
	if err := os.WriteFile(hooks, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	withBackend(t, answers(yes()))
	code, out, errs := w.run("", "--session", sessA, "uninstall")
	if code != exitcode.Failure || errs != "error: uninstall failed: fake (hooks)\n" ||
		out != "host fake: failed at hooks; kept in state.json\nhost good: hooks deleted, mcp deleted\nvault kept at "+w.home+"\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	hs, _ := vault.ReadHosts(w.home)
	if _, ok := hs["fake"]; !ok || len(hs) != 1 {
		t.Fatalf("hosts after a failed revert: %+v", hs)
	}
	if readFile(t, hooks) != "{not json" {
		t.Fatal("a file that could not be reverted was modified")
	}
	// The failure is typed in --json too.
	withBackend(t, answers(yes()))
	code, out, _ = w.run("", "--json", "uninstall")
	if code != exitcode.Failure || !strings.Contains(out, `"code":"host_revert_failed"`) {
		t.Fatalf("json: code=%d out=%q", code, out)
	}
}

func TestUninstallReportsAHostWithoutAnAdapterAndKeepsIt(t *testing.T) {
	w, h := registeredOver(t)
	withHosts(t)
	withBackend(t, answers(yes()))
	code, out, errs := w.run("", "--session", sessA, "uninstall")
	if code != exitcode.Failure || errs != "error: uninstall failed: fake (no adapter)\n" ||
		out != "host fake: no adapter in this build; kept in state.json\nvault kept at "+w.home+"\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if hs, _ := vault.ReadHosts(w.home); len(hs) != 1 {
		t.Fatalf("hosts: %+v", hs)
	}
	if !strings.Contains(readFile(t, h.Dir, "config.json"), "qbit-vault") {
		t.Fatal("a config was touched without its adapter")
	}
}

func TestUninstallCancelChangesNothing(t *testing.T) {
	for name, mk := range map[string]func() *prompttest.Fake{
		"no":     func() *prompttest.Fake { return answers(no()) },
		"cancel": func() *prompttest.Fake { return answers(cancel()) },
	} {
		t.Run(name, func(t *testing.T) {
			w, h := registeredOver(t)
			before := tree(t, w.home, h.Dir)
			withBackend(t, mk())
			code, out, errs := w.run("", "--session", sessA, "uninstall")
			if code != exitcode.Failure || out != "" || errs != msgCancelled {
				t.Fatalf("code=%d out=%q err=%q", code, out, errs)
			}
			if after := tree(t, w.home, h.Dir); after != before {
				t.Fatal("a cancelled uninstall changed something")
			}
		})
	}
}

func TestUninstallAndPurgeAreUserOnly(t *testing.T) {
	w, h := registeredOver(t) // default test backend: no terminal
	cfg, hooks := readFile(t, h.Dir, "config.json"), readFile(t, h.Dir, "hooks.json")
	w.wantRefusal(refusal.NotModelCallable, "", "--session", sessA, "uninstall")
	w.wantRefusal(refusal.NotModelCallable, "", "--session", sessA, "uninstall", "--purge")
	if readFile(t, h.Dir, "config.json") != cfg || readFile(t, h.Dir, "hooks.json") != hooks {
		t.Fatal("a refused uninstall reverted a config")
	}
	if hs, _ := vault.ReadHosts(w.home); len(hs) != 1 {
		t.Fatalf("hosts: %+v", hs)
	}
	if _, err := os.Stat(filepath.Join(w.home, "vault.enc")); err != nil {
		t.Fatal("a refused purge deleted the vault")
	}
	for _, c := range []string{"qbit-vault uninstall", "qbit-vault uninstall --purge", "qbit-vault --home /x uninstall --purge", "sudo qbit-vault uninstall"} {
		if !hook.Refuses(c) {
			t.Fatalf("the pre-bash hook lets %q through", c)
		}
	}
}

func TestUninstallWithoutAVault(t *testing.T) {
	w := newBareWorld(t)
	withBackend(t, answers())
	code, out, errs := w.run("", "--session", sessA, "uninstall")
	if code != exitcode.Failure || out != "" || errs != "error: no vault here; run 'qbit-vault init'\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
}

func TestUninstallJSON(t *testing.T) {
	w, _ := registeredOver(t)
	withBackend(t, answers(yes()))
	code, out, errs := w.run("", "--json", "uninstall")
	var body struct {
		OK     bool
		Home   string
		Purged bool
		Hosts  []struct {
			Name   string
			Status string
			Steps  []struct{ Name, Outcome string }
		}
	}
	if err := json.Unmarshal([]byte(out), &body); err != nil || code != exitcode.OK || errs != "" {
		t.Fatalf("code=%d out=%q err=%v", code, out, err)
	}
	if !body.OK || body.Purged || body.Home != w.home || len(body.Hosts) != 1 || body.Hosts[0].Status != "reverted" ||
		len(body.Hosts[0].Steps) != 2 || body.Hosts[0].Steps[1].Name != "mcp" || body.Hosts[0].Steps[1].Outcome != "restored" {
		t.Fatalf("body: %s", out)
	}
}

func TestUninstallRestoresARealAdapterConfigByteForByte(t *testing.T) {
	uh := isolateUserHome(t)
	w := newBareWorld(t)
	withHosts(t, claudeHost(uh))
	settings := "{\n  \"permissions\": {\"deny\": [\"Read(.env)\"]}\n}\n"
	if err := os.MkdirAll(filepath.Join(uh, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(uh, ".claude", "settings.json"), []byte(settings), 0o600); err != nil {
		t.Fatal(err)
	}
	w.mustRun("", "init", "--agents", "claude-code")
	if readFile(t, uh, ".claude", "settings.json") == settings {
		t.Fatal("init did not register anything")
	}
	withBackend(t, answers(yes()))
	code, out, errs := w.run("", "--session", sessA, "uninstall")
	if code != exitcode.OK || errs != "" || !strings.HasPrefix(out, "host claude-code: ") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if got := readFile(t, uh, ".claude", "settings.json"); got != settings {
		t.Fatalf("settings not restored:\n%s", got)
	}
	if _, err := os.Stat(filepath.Join(uh, ".claude.json")); !os.IsNotExist(err) {
		t.Fatalf("the file we created is still there: %v", err)
	}
}

// ---- --purge ----

func TestPurgeDeletesOnlyTheVaultHomeAndItsKeychainEntry(t *testing.T) {
	w, h := registeredOver(t)
	if !keychainHas(t, w) {
		t.Fatal("setup: no keychain entry")
	}
	f := withBackend(t, answers(val("purge")))
	code, out, errs := w.run("", "--session", sessA, "uninstall", "--purge")
	want := "host fake: hooks deleted, mcp restored\nvault purged: " + w.home + "\n"
	if code != exitcode.OK || errs != "" || out != want {
		t.Fatalf("code=%d out=%q want=%q err=%q", code, out, want, errs)
	}
	if len(f.Calls) != 1 || f.Calls[0].Kind != "secret" || !f.Calls[0].Request.Visible {
		t.Fatalf("purge must ask for the word once, visibly: %+v", f.Calls)
	}
	if _, err := os.Stat(w.home); !os.IsNotExist(err) {
		t.Fatalf("vault home still there: %v", err)
	}
	if readFile(t, h.Dir, "config.json") != userConfig {
		t.Fatal("host config not restored")
	}
	if _, err := os.Stat(filepath.Dir(w.home)); err != nil {
		t.Fatal("purge removed the parent of the vault home")
	}
	if _, err := os.Stat(h.Dir); err != nil {
		t.Fatal("purge removed a host directory")
	}
}

func TestPurgeDeletesTheKeychainEntry(t *testing.T) {
	w := newWorld(t)
	id, err := vault.ReadID(w.home)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keyring.Get("qbit-vault", "master:"+id); err != nil {
		t.Fatalf("setup: %v", err)
	}
	withBackend(t, answers(val("purge")))
	code, out, errs := w.run("", "--session", sessA, "uninstall", "--purge")
	if code != exitcode.OK || errs != "" || out != "no hosts registered\nvault purged: "+w.home+"\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if _, err := keyring.Get("qbit-vault", "master:"+id); err == nil {
		t.Fatal("the keychain entry survived the purge")
	}
	if _, err := os.Stat(w.home); !os.IsNotExist(err) {
		t.Fatal("vault home survived")
	}
}

func TestPurgeNeedsTheExactWord(t *testing.T) {
	cases := map[string]prompttest.Answer{
		"wrong word":      val("yes"),
		"wrong case":      val("Purge"),
		"word plus extra": val("purge now"),
		"empty":           val(""),
		"cancel":          cancel(),
		"a confirm only":  yes(),
	}
	for name, ans := range cases {
		t.Run(name, func(t *testing.T) {
			w, h := registeredOver(t)
			before := tree(t, w.home, h.Dir)
			withBackend(t, answers(ans))
			code, out, errs := w.run("", "--session", sessA, "uninstall", "--purge")
			if code != exitcode.Failure || out != "" || (errs != msgCancelled && errs != "error: the confirmation word did not match; nothing was changed\n") {
				t.Fatalf("code=%d out=%q err=%q", code, out, errs)
			}
			if after := tree(t, w.home, h.Dir); after != before {
				t.Fatal("a refused purge changed something")
			}
			if !keychainHas(t, w) {
				t.Fatal("a refused purge deleted the keychain entry")
			}
		})
	}
}

func TestPurgeDoesNotDeleteWhenAHostCouldNotBeReverted(t *testing.T) {
	w, h := registeredOver(t)
	if err := os.WriteFile(filepath.Join(h.Dir, "hooks.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	withBackend(t, answers(val("purge")))
	code, out, errs := w.run("", "--session", sessA, "uninstall", "--purge")
	if code != exitcode.Failure || errs != "error: uninstall failed: fake (hooks)\n" ||
		out != "host fake: failed at hooks; kept in state.json\nvault kept at "+w.home+" (not purged: a host was not reverted)\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if _, err := os.Stat(filepath.Join(w.home, "vault.enc")); err != nil || !keychainHas(t, w) {
		t.Fatal("the vault was deleted although a host stayed registered")
	}
}

func TestPurgeIsRefusedWhileTheVaultSyncs(t *testing.T) {
	w, h := registeredOver(t)
	if err := vault.WriteRemote(w.home, &vault.Remote{Server: "https://vault.example", AccountID: strings.Repeat("a", 32), Generation: 1}); err != nil {
		t.Fatal(err)
	}
	before := tree(t, w.home, h.Dir)
	f := withBackend(t, answers(val("purge")))
	code, out, errs := w.run("", "--session", sessA, "uninstall", "--purge")
	if code != exitcode.Failure || out != "" ||
		errs != "error: this vault syncs with https://vault.example; run 'qbit-vault remote logout' first, then purge\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("asked before refusing: %+v", f.Calls)
	}
	if tree(t, w.home, h.Dir) != before || !keychainHas(t, w) {
		t.Fatal("a refused purge changed something")
	}
	// A plain uninstall is fine: it never touches the server or the account.
	withBackend(t, answers(yes()))
	if code, _, errs := w.run("", "--session", sessA, "uninstall"); code != exitcode.OK {
		t.Fatalf("plain uninstall of a syncing vault: code=%d err=%q", code, errs)
	}
}

func TestPurgeTargetGuard(t *testing.T) {
	uh := t.TempDir()
	home := filepath.Join(uh, ".qbit-vault")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := safePurgeTarget(home, uh); err != nil {
		t.Fatalf("a normal vault home: %v", err)
	}
	for name, dir := range map[string]string{
		"user home":        uh,
		"parent of home":   filepath.Dir(uh),
		"filesystem root":  filepath.VolumeName(uh) + string(filepath.Separator),
		"relative":         "vault",
		"empty":            "",
		"dot":              ".",
		"missing":          filepath.Join(uh, "nope"),
		"a file":           filepath.Join(home, "state.json"),
		"home with a dots": home + string(filepath.Separator) + ".." + string(filepath.Separator) + ".qbit-vault2",
	} {
		if name == "a file" {
			_ = os.WriteFile(dir, []byte("x"), 0o600)
		}
		if err := safePurgeTarget(dir, uh); err == nil {
			t.Fatalf("%s accepted: %q", name, dir)
		}
	}
}

// --purge deletes a directory tree: it must hold nothing but what a vault
// keeps, so a --home pointed at a folder of the user's own files is refused.
func TestPurgeTargetMustLookLikeAVault(t *testing.T) {
	uh := t.TempDir()
	home := filepath.Join(uh, ".qbit-vault")
	for _, p := range []string{"vault.enc", "state.json", "grants.enc", "audit.jsonl", "audit.head", "key.enc", "vault.lock", "vault.enc.tmp.4242.0a1b", "audit.head.tmp-99"} {
		mustWrite(t, filepath.Join(home, p))
	}
	for _, d := range []string{"backups", "keys", "remote"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := safePurgeTarget(home, uh); err != nil {
		t.Fatalf("a vault home: %v", err)
	}
	mustWrite(t, filepath.Join(home, "thesis.docx"))
	if err := safePurgeTarget(home, uh); err == nil {
		t.Fatal("a directory holding a file that is not the vault's was accepted")
	}
	if err := os.Remove(filepath.Join(home, "thesis.docx")); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(home, "notes.txt.tmp.1.ab")) // a temp of a file that is not the vault's
	if err := safePurgeTarget(home, uh); err == nil {
		t.Fatal("a temp file of a foreign file was accepted")
	}
	if err := os.Remove(filepath.Join(home, "notes.txt.tmp.1.ab")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, "photos"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := safePurgeTarget(home, uh); err == nil {
		t.Fatal("a directory holding a folder that is not the vault's was accepted")
	}
}

// Windows paths are case-insensitive: the user home in other letter case is
// still the user home.
func TestPurgeTargetRefusesTheUserHomeInAnyCase(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("case-insensitive paths are a Windows rule")
	}
	uh := t.TempDir()
	if err := safePurgeTarget(strings.ToUpper(uh[:1])+strings.ToLower(uh[1:]), strings.ToLower(uh[:1])+strings.ToUpper(uh[1:])); err == nil {
		t.Fatal("the user home in another letter case was accepted")
	}
}

func mustWrite(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// End to end: a --purge whose vault home also holds the user's own files is
// refused before anything changes: no prompt, no host revert, the keychain
// entry kept. QBIT_VAULT_HOME takes the same route as --home.
func TestPurgeRefusesAHomeHoldingForeignFilesBeforeAnyChange(t *testing.T) {
	for _, viaEnv := range []bool{false, true} {
		w, h := registeredOver(t)
		mustWrite(t, filepath.Join(w.home, "thesis.docx"))
		before := tree(t, w.home, h.Dir)
		f := withBackend(t, answers(val("purge")))
		args := []string{"--session", sessA, "--json", "uninstall", "--purge"}
		var code int
		var out string
		if viaEnv {
			code, out, _ = w.runEnv(map[string]string{"QBIT_VAULT_HOME": w.home}, "", args...)
		} else {
			code, out, _ = w.run("", args...)
		}
		var e struct{ Error struct{ Code string } }
		_ = json.Unmarshal([]byte(out), &e)
		if code != exitcode.Failure || e.Error.Code != "unsafe_purge" {
			t.Fatalf("env=%v: code=%d out=%q", viaEnv, code, out)
		}
		if len(f.Calls) != 0 {
			t.Fatalf("env=%v: prompted before refusing: %+v", viaEnv, f.Calls)
		}
		if after := tree(t, w.home, h.Dir); after != before {
			t.Fatalf("env=%v: a refused purge changed something", viaEnv)
		}
		if !keychainHas(t, w) {
			t.Fatalf("env=%v: a refused purge deleted the keychain entry", viaEnv)
		}
	}
}

// A junction or symlink at the vault home is refused explicitly, not only
// because of how a Go version reports reparse points.
func TestPurgeTargetRefusesALinkedHome(t *testing.T) {
	uh := t.TempDir()
	real := filepath.Join(uh, "real-vault")
	mustWrite(t, filepath.Join(real, "state.json"))
	link := filepath.Join(uh, ".qbit-vault")
	made := false
	if runtime.GOOS == "windows" {
		made = exec.Command("cmd", "/c", "mklink", "/J", link, real).Run() == nil
	} else {
		made = os.Symlink(real, link) == nil
	}
	if !made {
		t.Skip("cannot create a link here")
	}
	if err := safePurgeTarget(link, uh); err == nil {
		t.Fatal("a linked vault home was accepted")
	}
	if !isLink(link) {
		t.Fatal("isLink does not see the link")
	}
}
