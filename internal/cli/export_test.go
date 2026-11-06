package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/exitcode"
	"github.com/QuBiit0/qbit-vault/internal/perm"
	"github.com/QuBiit0/qbit-vault/internal/prompt"
	"github.com/QuBiit0/qbit-vault/internal/prompt/prompttest"
	"github.com/QuBiit0/qbit-vault/internal/secret"
	"github.com/QuBiit0/qbit-vault/internal/vault"
)

// fxExport is the export passphrase of these tests (12 characters or more).
const fxExport = "TESTSECRET_export_passphrase_01"

const (
	msgExportKeep    = "keep the file and its passphrase in different places; anyone with both can read every secret\n"
	msgExportDamaged = "error: cannot open the export: wrong passphrase or damaged file\n"
)

// seedExport fills the vault with two global secrets (one of kind text and
// one sensitive) and one project secret, all with metadata.
func (w *world) seedExport() {
	w.t.Helper()
	w.mustRun("TESTSECRET_gh_value\n", "set", "GH_TOKEN", "--global", "--stdin", "--description", "GitHub token", "--binaries", "gh,git", "--hosts", "api.github.com")
	w.mustRun("TESTSECRET_npm_value\n", "set", "NPM_TOKEN", "--global", "--stdin", "--sensitive")
	w.inRepo()
	w.mustRun("TESTSECRET_db_value\n", "set", "DB_URL", "--project", "--stdin", "--description", "shop database", "--hosts", "db.internal")
	w.outRepo()
	g := &globals{getenv: envFrom(nil), home: w.home}
	s, err := g.openSession()
	if err != nil {
		w.t.Fatal(err)
	}
	defer s.close()
	err = s.v.Put(vault.Global(), "REGION", vault.Record{Value: secret.New("REGION", []byte("TESTSECRET_us-east-1")), Kind: "text", Description: "deploy region"})
	if err != nil {
		w.t.Fatal(err)
	}
}

// dump is every record of the vault, value and metadata included, one line
// each. It is for comparing two vaults in a test and is never printed.
func (w *world) dump() string {
	w.t.Helper()
	g := &globals{getenv: envFrom(nil), home: w.home}
	s, err := g.openSession()
	if err != nil {
		w.t.Fatal(err)
	}
	defer s.close()
	es, err := s.v.ListAll()
	if err != nil {
		w.t.Fatal(err)
	}
	var lines []string
	for _, e := range es {
		r := e.Record
		lines = append(lines, strings.Join([]string{
			e.Layer.Key(), e.Layer.Label, e.Name, string(r.Value.Reveal()), r.Kind, r.Description,
			map[bool]string{true: "sensitive", false: "plain"}[r.Sensitive],
			strings.Join(r.Binaries, ","), strings.Join(r.Hosts, ","), r.CreatedAt, r.UpdatedAt,
		}, "|"))
		r.Value.Wipe()
	}
	return strings.Join(lines, "\n")
}

// exportFile is a path for an export file in a fresh directory.
func exportFile(t *testing.T) string { return filepath.Join(t.TempDir(), "vault.qvx") }

// doExport runs `export` answering the passphrase prompt with pass.
func (w *world) doExport(file, pass string, extra ...string) (int, string, string) {
	w.t.Helper()
	withBackend(w.t, answers(val(pass)))
	return w.run("", append([]string{"export", file}, extra...)...)
}

func readBytes(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// holdsFixture reports whether data holds a fixture value in clear or in a
// base64 form (every byte alignment).
func holdsFixture(data []byte, values ...string) bool {
	for _, v := range values {
		if bytes.Contains(data, []byte(v)) {
			return true
		}
		for pad := 0; pad < 3; pad++ {
			enc := base64.StdEncoding.EncodeToString(append(bytes.Repeat([]byte{'x'}, pad), v...))
			// Drop the characters that depend on the neighbours.
			core := enc[4 : len(enc)-4]
			if bytes.Contains(data, []byte(core)) {
				return true
			}
		}
	}
	return bytes.Contains(data, []byte("TESTSECRET_"))
}

var exportValues = []string{"TESTSECRET_gh_value", "TESTSECRET_npm_value", "TESTSECRET_db_value", "TESTSECRET_us-east-1"}

// ---- S6: export ----

func TestExportWritesAnEncryptedFileAndSays(t *testing.T) {
	w := newWorld(t)
	w.seedExport()
	file := exportFile(t)
	f := withBackend(t, answers(val(fxExport)))
	code, out, errs := w.run("", "export", file)
	if code != exitcode.OK || out != "exported 4 secrets (global: 3, projects: 1) to "+file+"\n" || errs != msgExportKeep {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if len(f.Calls) != 1 || f.Calls[0].Kind != "passphrase" || !f.Calls[0].Confirm {
		t.Fatalf("calls=%+v, want one confirmed passphrase prompt", f.Calls)
	}
	data := readBytes(t, file)
	if holdsFixture(data, exportValues...) || bytes.Contains(data, []byte(fxExport)) {
		t.Fatal("the export file holds a fixture in clear")
	}
	if ok, why := perm.Check(file); !ok {
		t.Fatalf("export file is not owner-only: %s", why)
	}
	var head map[string]any
	if err := json.Unmarshal(data, &head); err != nil || head["format"] != "qbit-vault-export/1" {
		t.Fatalf("header: %v %v", head["format"], err)
	}
	kdf, _ := head["kdf"].(map[string]any)
	if kdf["alg"] != "argon2id" || kdf["salt"] == "" || head["nonce"] == "" || head["created_at"] == "" {
		t.Fatalf("header incomplete: %v", head)
	}
	entries, _ := os.ReadDir(filepath.Dir(file))
	if len(entries) != 1 {
		t.Fatalf("leftover files next to the export: %d entries", len(entries))
	}
	// Audited with the count only.
	if !w.auditHas(`"event":"export"`) || !w.auditHas(`"detail":"4 secrets"`) {
		t.Fatalf("audit: %s", w.auditText())
	}
	noFixtures(t, "export output", out+errs+w.auditText())
}

func TestExportJSON(t *testing.T) {
	w := newWorld(t)
	w.seedExport()
	file := exportFile(t)
	withBackend(t, answers(val(fxExport)))
	code, out, errs := w.run("", "--json", "export", file)
	fj, _ := json.Marshal(file)
	want := `{"ok":true,"file":` + string(fj) + `,"secrets":4,"layers":2}` + "\n"
	if code != exitcode.OK || out != want || errs != msgExportKeep {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	noFixtures(t, "export json", out+errs)
}

func TestExportRoundTripIntoAFreshVault(t *testing.T) {
	w := newWorld(t)
	w.seedExport()
	// A grant on the source: it must not travel.
	pinClock(t)
	asTerminal(t, true)
	w.mustRun("y\n", "--session", sessA, "grant", "GH_TOKEN", "--scope", "session")
	want := w.dump()
	file := exportFile(t)
	if code, out, errs := w.doExport(file, fxExport); code != exitcode.OK {
		t.Fatalf("export: code=%d out=%q err=%q", code, out, errs)
	}

	// The documented recovery path: a new machine, a vault that init just made.
	n := newBareWorld(t)
	n.mustRun("", "init")
	emptyGrants := n.grantsState()
	f := withBackend(t, answers(val(fxExport), yes()))
	code, out, errs := n.run("", "import", "--from-export", file)
	if code != exitcode.OK || out != "imported 4 secrets from the export\n" || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if len(f.Calls) != 2 || f.Calls[0].Kind != "passphrase" || f.Calls[0].Confirm || f.Calls[1].Q != "Import 4 secrets from the export?" {
		t.Fatalf("calls=%+v, want one single passphrase prompt and the short question", f.Calls)
	}
	if got := n.dump(); got != want {
		t.Fatal("the restored vault differs from the exported one (values or metadata)")
	}
	if !strings.Contains(want, "shop-api") || !strings.Contains(want, "|text|") || !strings.Contains(want, "sensitive") {
		t.Fatal("the fixture lost its project layer, kind or sensitive flag")
	}
	if n.grantsState() != emptyGrants {
		t.Fatal("a grant came along with the import")
	}
	if !n.auditHas(`"event":"capture"`) || !n.auditHas(`"reason":"import from export"`) {
		t.Fatalf("audit: %s", n.auditText())
	}
	noFixtures(t, "import output", out+errs+n.auditText())
}

func TestExportRefusesAnExistingFileUnlessForced(t *testing.T) {
	w := newWorld(t)
	w.seedExport()
	file := exportFile(t)
	if err := os.WriteFile(file, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := withBackend(t, answers(val(fxExport)))
	code, out, errs := w.run("", "export", file)
	if code != exitcode.Usage || out != "" || errs != usageErr(file+" exists; pass --force to overwrite") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if len(f.Calls) != 0 {
		t.Fatal("asked a question before refusing")
	}
	if string(readBytes(t, file)) != "precious" {
		t.Fatal("the existing file changed")
	}
	// --force replaces it, atomically, with a valid export.
	code, out, _ = w.run("", "export", file, "--force")
	if code != exitcode.OK || !strings.HasPrefix(out, "exported 4 secrets") {
		t.Fatalf("force: code=%d out=%q", code, out)
	}
	if bytes.Contains(readBytes(t, file), []byte("precious")) {
		t.Fatal("the file was not replaced")
	}
	if entries, _ := os.ReadDir(filepath.Dir(file)); len(entries) != 1 {
		t.Fatalf("temp file left behind: %d entries", len(entries))
	}
	n := newBareWorld(t)
	n.mustRun("", "init")
	withBackend(t, answers(val(fxExport)))
	n.mustRun("", "import", "--from-export", file, "--yes")
}

func TestExportPassphraseRulesWriteNothing(t *testing.T) {
	cases := []struct {
		name string
		ans  prompttest.Answer
		code int
		err  string
	}{
		{"11 characters", val("TESTSECRET_"), exitcode.Usage, usageErr("the export passphrase must be at least 12 characters")},
		{"blank", val("               "), exitcode.Usage, usageErr("the export passphrase must be at least 12 characters")},
		{"mismatch", prompttest.Answer{Err: prompt.ErrMismatch}, exitcode.Usage, usageErr("passphrases do not match")},
		{"cancelled", cancel(), exitcode.Failure, msgCancelled},
		{"timeout", prompttest.Answer{Err: prompt.ErrTimeout}, exitcode.Failure, "error: prompt timed out\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t)
			w.seedExport()
			before := w.snapshot()
			file := exportFile(t)
			withBackend(t, answers(c.ans))
			code, out, errs := w.run("", "export", file)
			if code != c.code || out != "" || errs != c.err {
				t.Fatalf("code=%d out=%q err=%q", code, out, errs)
			}
			if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("a file was written")
			}
			if entries, _ := os.ReadDir(filepath.Dir(file)); len(entries) != 0 {
				t.Fatal("something was left in the directory")
			}
			if w.snapshot() != before || w.auditHas(`"event":"export"`) {
				t.Fatal("a refused export changed the vault or was audited as done")
			}
		})
	}
}

func TestExportPassphraseTwelveCharactersIsEnough(t *testing.T) {
	w := newWorld(t)
	w.seedExport()
	file := exportFile(t)
	if code, out, errs := w.doExport(file, "123456789012"); code != exitcode.OK {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
}

func TestExportNeedsAPromptBackendAndAFileArgument(t *testing.T) {
	w := newWorld(t)
	w.seedExport()
	file := exportFile(t)
	asTerminal(t, false)
	code, out, errs := w.run("", "export", file)
	if code != exitcode.Usage || out != "" || !strings.Contains(errs, "no controlling terminal available") {
		t.Fatalf("no terminal: code=%d out=%q err=%q", code, out, errs)
	}
	if _, err := os.Stat(file); err == nil {
		t.Fatal("a file was written")
	}
	for _, args := range [][]string{{"export"}, {"export", file, "extra"}} {
		code, out, errs = w.run("", args...)
		if code != exitcode.Usage || out != "" {
			t.Errorf("%v: code=%d out=%q err=%q", args, code, out, errs)
		}
	}
}

func TestExportOfAnEmptyVaultIsRefused(t *testing.T) {
	w := newWorld(t)
	f := withBackend(t, answers(val(fxExport)))
	file := exportFile(t)
	code, out, errs := w.run("", "export", file)
	if code != exitcode.Usage || out != "" || errs != usageErr("the vault is empty; nothing to export") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if len(f.Calls) != 0 {
		t.Fatal("asked for a passphrase for nothing")
	}
}

func TestExportWorksInPassphraseModeAndWithoutANetwork(t *testing.T) {
	var calls atomic.Int64
	old := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("no network in this test")
	})
	t.Cleanup(func() { http.DefaultTransport = old })

	w := passphraseWorld(t)
	// Every command that opens the vault asks for its passphrase.
	withBackend(t, answers(val(fxPass), val(fxPass), val(fxPass)))
	w.mustRun("TESTSECRET_pp_value\n", "set", "PP_KEY", "--global", "--stdin")
	file := exportFile(t)
	f := withBackend(t, answers(val(fxPass), val(fxExport)))
	code, out, errs := w.run("", "export", file)
	if code != exitcode.OK || out != "exported 1 secret (global: 1, projects: 0) to "+file+"\n" || errs != msgExportKeep {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if len(f.Calls) != 2 || f.Calls[0].Confirm || !f.Calls[1].Confirm {
		t.Fatalf("calls=%+v, want the vault passphrase then the export passphrase twice", f.Calls)
	}
	n := newBareWorld(t)
	n.mustRun("", "init")
	withBackend(t, answers(val(fxExport)))
	n.mustRun("", "import", "--from-export", file, "--yes")
	if n.value("PP_KEY") != "TESTSECRET_pp_value" {
		t.Fatal("not restored")
	}
	if calls.Load() != 0 {
		t.Fatal("export or import made a network call")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// ---- S7: import --from-export ----

func TestImportFromExportRefusesAnUnopenableFile(t *testing.T) {
	src := newWorld(t)
	src.seedExport()
	good := exportFile(t)
	if code, _, errs := src.doExport(good, fxExport); code != exitcode.OK {
		t.Fatalf("export: %q", errs)
	}
	data := readBytes(t, good)

	flip := func(sub string) []byte {
		i := bytes.Index(data, []byte(sub))
		if i < 0 {
			t.Fatalf("no %q in the export", sub)
		}
		out := bytes.Clone(data)
		out[i+len(sub)+1] ^= 0x01
		return out
	}
	cases := []struct {
		name string
		pass string
		file []byte
	}{
		{"wrong passphrase", "TESTSECRET_not_the_one", data},
		{"flipped ciphertext byte", fxExport, flip(`"ct":"`)},
		{"flipped nonce byte", fxExport, flip(`"nonce":"`)},
		{"flipped salt byte", fxExport, flip(`"salt":"`)},
		{"changed created_at", fxExport, bytes.Replace(data, []byte(`"created_at":"2`), []byte(`"created_at":"3`), 1)},
		{"truncated", fxExport, data[:len(data)/2]},
		{"unknown format", fxExport, bytes.Replace(data, []byte("qbit-vault-export/1"), []byte("qbit-vault-export/9"), 1)},
		{"not an export", fxExport, []byte("{\"hello\":1}")},
		{"empty", fxExport, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t)
			w.mustRun("TESTSECRET_keep\n", "set", "KEEP_ME", "--global", "--stdin")
			before, bytesBefore := w.snapshot(), w.vaultBytes()
			file := exportFile(t)
			if err := os.WriteFile(file, c.file, 0o600); err != nil {
				t.Fatal(err)
			}
			withBackend(t, answers(val(c.pass)))
			code, out, errs := w.run("", "import", "--from-export", file, "--yes")
			if code != exitcode.Failure || out != "" || errs != msgExportDamaged {
				t.Fatalf("code=%d out=%q err=%q", code, out, errs)
			}
			if w.snapshot() != before || w.vaultBytes() != bytesBefore {
				t.Fatal("a refused import changed the vault")
			}
			noFixtures(t, "import error", errs)
		})
	}
}

func TestImportFromExportUnreadableFile(t *testing.T) {
	w := newWorld(t)
	before := w.vaultBytes()
	f := withBackend(t, answers(val(fxExport)))
	code, out, errs := w.run("", "import", "--from-export", filepath.Join(t.TempDir(), "missing.qvx"), "--yes")
	if code != exitcode.Usage || out != "" || errs != usageErr("cannot read the export file") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if len(f.Calls) != 0 || w.vaultBytes() != before {
		t.Fatal("asked or wrote for a file that cannot be read")
	}
}

func TestImportFromExportUsage(t *testing.T) {
	w := newWorld(t)
	file := exportFile(t)
	before := w.vaultBytes()
	cases := []struct {
		args []string
		msg  string
	}{
		{[]string{"import", "--from-export", file, "--from-env", "GH_TOKEN"}, "choose --from-env, --from-file or --from-export"},
		{[]string{"import", "--from-export", file, "--from-file", file}, "choose --from-env, --from-file or --from-export"},
		{[]string{"import", "--from-export", file, "--names", "A"}, "--names needs --from-file"},
		{[]string{"import", "--from-export", file, "--remove-source"}, "--remove-source needs --from-file"},
		{[]string{"import", "--from-export", file, "--global"}, "--global and --project do not apply to --from-export; every secret returns to its own layer"},
		{[]string{"import", "--from-export", file, "--project"}, "--global and --project do not apply to --from-export; every secret returns to its own layer"},
		{[]string{"import", "--yes"}, "choose --from-env, --from-file or --from-export"},
	}
	for _, c := range cases {
		code, out, errs := w.run("", c.args...)
		if code != exitcode.Usage || out != "" || errs != usageErr(c.msg) {
			t.Errorf("%v: code=%d out=%q err=%q", c.args[1:], code, out, errs)
		}
	}
	if w.vaultBytes() != before {
		t.Fatal("a refused import changed the vault")
	}
}

// exported builds a vault with the standard seed, exports it and returns the
// file.
func exported(t *testing.T) string {
	t.Helper()
	file, _ := exportedFrom(t)
	return file
}

// exportedFrom is exported plus the world it came from.
func exportedFrom(t *testing.T) (string, *world) {
	t.Helper()
	src := newWorld(t)
	src.seedExport()
	file := exportFile(t)
	if code, _, errs := src.doExport(file, fxExport); code != exitcode.OK {
		t.Fatalf("export: %q", errs)
	}
	return file, src
}

func TestImportFromExportMergesAndAsksAboutTheClashingNames(t *testing.T) {
	file := exported(t)
	pinClock(t)
	asTerminal(t, true)
	w := newWorld(t)
	// GH_TOKEN clashes (with a grant, an old description); ONLY_HERE does not
	// exist in the export and has a grant of its own.
	w.mustRun("TESTSECRET_old_gh\n", "set", "GH_TOKEN", "--global", "--stdin", "--description", "old description", "--binaries", "curl")
	w.mustRun("TESTSECRET_only_here\n", "set", "ONLY_HERE", "--global", "--stdin", "--description", "mine")
	w.mustRun("y\n", "--session", sessA, "grant", "GH_TOKEN", "--scope", "session")
	w.mustRun("y\n", "--session", sessA, "grant", "ONLY_HERE", "--scope", "session")
	onlyHereBefore := w.recordLine("ONLY_HERE")
	if err := w.execCheck("GH_TOKEN", sessA); err != nil {
		t.Fatalf("setup: %v", err)
	}

	f := withBackend(t, answers(val(fxExport), yes()))
	code, out, errs := w.run("", "import", "--from-export", file)
	if code != exitcode.OK || out != "imported 4 secrets from the export (replaced: GH_TOKEN)\n" || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if len(f.Calls) != 2 || f.Calls[1].Kind != "confirm" || f.Calls[1].Q != "Import 4 secrets from the export? These replace existing ones: GH_TOKEN" {
		t.Fatalf("calls=%+v", f.Calls)
	}
	// The replaced record is the export's, whole: nothing from the old one.
	if w.value("GH_TOKEN") != "TESTSECRET_gh_value" {
		t.Fatal("GH_TOKEN was not replaced")
	}
	gh := w.recordLine("GH_TOKEN")
	if strings.Contains(gh, "old description") || strings.Contains(gh, "curl") || !strings.Contains(gh, "GitHub token") || !strings.Contains(gh, "gh,git") {
		t.Fatalf("GH_TOKEN kept something of the old record: %s", gh)
	}
	// Its grant is gone, and the grants file says so.
	if err := w.execCheck("GH_TOKEN", sessA); err == nil {
		t.Fatal("the replaced record kept its grant")
	}
	// A secret that exists only here survives unchanged, grant still active.
	if got := w.recordLine("ONLY_HERE"); got != onlyHereBefore {
		t.Fatalf("ONLY_HERE changed: %q -> %q", onlyHereBefore, got)
	}
	if w.value("ONLY_HERE") != "TESTSECRET_only_here" {
		t.Fatal("ONLY_HERE lost its value")
	}
	if err := w.execCheck("ONLY_HERE", sessA); err != nil {
		t.Fatalf("ONLY_HERE lost its grant: %v", err)
	}
	if st := w.grantsState(); !strings.Contains(st, "ONLY_HERE") || strings.Contains(st, "GH_TOKEN") {
		t.Fatalf("grants after import: %s", st)
	}
	noFixtures(t, "import output", out+errs+w.auditText())
}

// recordLine is the dump line of one record name (all layers).
func (w *world) recordLine(name string) string {
	w.t.Helper()
	var out []string
	for _, l := range strings.Split(w.dump(), "\n") {
		if strings.Split(l, "|")[2] == name {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

func TestImportFromExportQuestionListsExactlyTheClashes(t *testing.T) {
	file, src := exportedFrom(t)
	w := newWorld(t)
	w.mustRun("TESTSECRET_a\n", "set", "NPM_TOKEN", "--global", "--stdin")
	w.mustRun("TESTSECRET_b\n", "set", "GH_TOKEN", "--global", "--stdin")
	w.mustRun("TESTSECRET_c\n", "set", "UNRELATED", "--global", "--stdin")
	w.inRepo()
	// Same name as an exported project secret, but another repository.
	w.mustRun("TESTSECRET_d\n", "set", "DB_URL", "--project", "--stdin")
	w.outRepo()
	before := w.dump()

	// A no is cancelled and writes nothing.
	f := withBackend(t, answers(val(fxExport), no()))
	code, out, errs := w.run("", "import", "--from-export", file)
	if code != exitcode.Failure || out != "" || errs != msgCancelled {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if want := "Import 4 secrets from the export? These replace existing ones: GH_TOKEN, NPM_TOKEN"; f.Calls[1].Q != want {
		t.Fatalf("question=%q", f.Calls[1].Q)
	}
	if w.dump() != before {
		t.Fatal("a declined import changed the vault")
	}

	// Nothing clashes: the short question.
	fresh := newBareWorld(t)
	fresh.mustRun("", "init")
	f = withBackend(t, answers(val(fxExport), yes()))
	fresh.mustRun("", "import", "--from-export", file)
	if f.Calls[1].Q != "Import 4 secrets from the export?" {
		t.Fatalf("question=%q", f.Calls[1].Q)
	}

	// Into the vault it came from, everything clashes, the project one too.
	f = withBackend(t, answers(val(fxExport), yes()))
	out = src.mustRun("", "import", "--from-export", file)
	want := "Import 4 secrets from the export? These replace existing ones: DB_URL (project shop-api), GH_TOKEN, NPM_TOKEN, REGION"
	if f.Calls[1].Q != want || out != "imported 4 secrets from the export (replaced: DB_URL (project shop-api), GH_TOKEN, NPM_TOKEN, REGION)\n" {
		t.Fatalf("question=%q out=%q", f.Calls[1].Q, out)
	}
}

func TestImportFromExportYesSkipsTheQuestionAndJSONShape(t *testing.T) {
	file := exported(t)
	w := newWorld(t)
	w.mustRun("TESTSECRET_a\n", "set", "NPM_TOKEN", "--global", "--stdin")
	f := withBackend(t, answers(val(fxExport)))
	code, out, errs := w.run("", "--json", "import", "--from-export", file, "--yes")
	if code != exitcode.OK || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if len(f.Calls) != 1 {
		t.Fatalf("calls=%+v, want the passphrase only", f.Calls)
	}
	var body struct {
		OK       bool   `json:"ok"`
		Source   string `json:"source"`
		Imported []struct {
			Name     string      `json:"name"`
			Layer    string      `json:"layer"`
			Project  *projectRef `json:"project"`
			Replaced bool        `json:"replaced"`
		} `json:"imported"`
		Skipped       int  `json:"skipped"`
		GrantsDropped int  `json:"grants_dropped"`
		SourceRemoved bool `json:"source_removed"`
	}
	if err := json.Unmarshal([]byte(out), &body); err != nil || !body.OK || body.Source != "export" || len(body.Imported) != 4 {
		t.Fatalf("body=%+v err=%v", body, err)
	}
	var replaced, project int
	for _, i := range body.Imported {
		if i.Replaced {
			replaced++
			if i.Name != "NPM_TOKEN" {
				t.Fatalf("replaced %s", i.Name)
			}
		}
		if i.Layer == "project" && i.Project != nil && i.Project.Label == "shop-api" {
			project++
		}
	}
	if replaced != 1 || project != 1 || body.SourceRemoved {
		t.Fatalf("body=%+v", body)
	}
	noFixtures(t, "import json", out)
}

func TestImportFromExportWithoutATerminalStillNeedsYes(t *testing.T) {
	file := exported(t)
	w := newWorld(t)
	w.mustRun("TESTSECRET_a\n", "set", "NPM_TOKEN", "--global", "--stdin")
	before := w.dump()
	// The passphrase was answered, the confirmation cannot be asked.
	withBackend(t, answers(val(fxExport), prompttest.Answer{Err: prompt.ErrNoTerminal}))
	code, out, errs := w.run("", "import", "--from-export", file)
	if code != exitcode.Usage || out != "" || errs != usageErr("confirmation required; pass --yes") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if w.dump() != before {
		t.Fatal("changed the vault")
	}
}

func TestImportFromExportIsOneAuditedWriteAndNamesOnly(t *testing.T) {
	file := exported(t)
	w := newWorld(t)
	backups := len(w.backupIDs())
	withBackend(t, answers(val(fxExport)))
	w.mustRun("", "import", "--from-export", file, "--yes")
	if got := len(w.backupIDs()) - backups; got != 1 {
		t.Fatalf("%d snapshots for one import", got)
	}
	var rec string
	for _, l := range strings.Split(w.auditText(), "\n") {
		if strings.Contains(l, `"reason":"import from export"`) {
			rec = l
		}
	}
	for _, n := range []string{"GH_TOKEN", "NPM_TOKEN", "DB_URL", "REGION"} {
		if !strings.Contains(rec, `"`+n+`"`) {
			t.Fatalf("audit record lacks %s: %s", n, rec)
		}
	}
	noFixtures(t, "audit", w.auditText())
}

// A project secret returns to the project with the same root, creating it
// when the vault has none and keeping the label of one it has.
func TestImportFromExportProjectLayerIsMatchedByRoot(t *testing.T) {
	file := exported(t)
	w := newWorld(t)
	withBackend(t, answers(val(fxExport)))
	w.mustRun("", "import", "--from-export", file, "--yes")
	if !strings.Contains(w.dump(), "project:") {
		t.Fatal("no project layer was created")
	}
	// Importing again replaces in place: still one project, same label.
	withBackend(t, answers(val(fxExport)))
	w.mustRun("", "import", "--from-export", file, "--yes")
	if n := strings.Count(w.dump(), "|DB_URL|"); n != 1 {
		t.Fatalf("DB_URL is in %d layers", n)
	}
}

// The values must not leave through the export or import paths in any
// captured channel (docs/TESTING.md § Leak battery).
func TestExportImportLeakBattery(t *testing.T) {
	w := newWorld(t)
	w.seedExport()
	file := exportFile(t)
	var seen strings.Builder
	grab := func(code int, out, errs string) {
		seen.WriteString(out)
		seen.WriteString(errs)
	}
	grab(w.doExport(file, fxExport))
	grab(w.doExport(file, fxExport)) // refused: exists
	grab(w.doExport(file, fxExport, "--force", "--json"))
	grab(w.doExport(exportFile(t), "short"))
	n := newBareWorld(t)
	n.mustRun("", "init")
	withBackend(t, answers(val("TESTSECRET_wrong_passphrase_1")))
	grab(n.run("", "import", "--from-export", file, "--yes"))
	withBackend(t, answers(val(fxExport)))
	grab(n.run("", "--json", "import", "--from-export", file, "--yes"))
	withBackend(t, answers(val(fxExport)))
	grab(n.run("", "import", "--from-export", file, "--yes"))

	noFixtures(t, "captured output", seen.String())
	if strings.Contains(seen.String(), fxExport) {
		t.Fatal("the export passphrase was printed")
	}
	noFixtures(t, "audit log", w.auditText()+n.auditText())
	// Nothing but the export file and sealed vault files hold a value.
	if holdsFixture(readBytes(t, file), exportValues...) {
		t.Fatal("export file holds a value in clear")
	}
	for _, home := range []string{w.home, n.home} {
		_ = filepath.WalkDir(home, func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() && holdsFixture(readBytes(t, p), exportValues...) {
				t.Errorf("a value in clear under the vault home: %s", filepath.Base(p))
			}
			return nil
		})
	}
}
