package cli

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/exitcode"
	"github.com/qbitdevz/qbit-vault/internal/minisign/minisigntest"
)

const (
	updOld = "OLD-BINARY-BYTES"
	updNew = "NEW-BINARY-BYTES"
)

// updWorld is a fake releases API with its assets, a temp copy of the binary
// to update, a vault home that does not exist and a recording re-registration.
type updWorld struct {
	t         *testing.T
	srv       *httptest.Server
	hits      atomic.Int32 // asset downloads
	latest    string
	assets    map[string][]byte
	checksums string
	sig       []byte // checksums.txt.minisig; nil means the release has none
	dir       string
	target    string
	home      string
	env       map[string]string
	resyncs   []string
	syncText  string // what the fake sync prints on stdout
}

func newUpdWorld(t *testing.T, current, latest string) *updWorld {
	t.Helper()
	w := &updWorld{t: t, latest: latest, assets: map[string][]byte{}}
	oldV, oldT, oldOS, oldArch, oldR, oldK := Version, updateTarget, updateGOOS, updateGOARCH, updateResync, updateKey
	t.Cleanup(func() {
		Version, updateTarget, updateGOOS, updateGOARCH, updateResync, updateKey = oldV, oldT, oldOS, oldArch, oldR, oldK
	})
	Version, updateGOOS, updateGOARCH = current, "linux", "amd64"
	updateKey = updSigner.Pub

	mux := http.NewServeMux()
	mux.HandleFunc("/api", func(rw http.ResponseWriter, r *http.Request) {
		fmt.Fprint(rw, w.releaseJSON())
	})
	mux.HandleFunc("/dl/", func(rw http.ResponseWriter, r *http.Request) {
		w.hits.Add(1)
		name := strings.TrimPrefix(r.URL.Path, "/dl/")
		if name == "checksums.txt" {
			fmt.Fprint(rw, w.checksums)
			return
		}
		if name == "checksums.txt.minisig" && w.sig != nil {
			rw.Write(w.sig)
			return
		}
		b, ok := w.assets[name]
		if !ok {
			http.NotFound(rw, r)
			return
		}
		rw.Write(b)
	})
	w.srv = httptest.NewServer(mux)
	t.Cleanup(w.srv.Close)

	w.dir = t.TempDir()
	w.target = filepath.Join(w.dir, "qbit-vault")
	if err := os.WriteFile(w.target, []byte(updOld), 0o700); err != nil {
		t.Fatal(err)
	}
	updateTarget = func() (string, error) { return w.target, nil }
	updateResync = func(_ context.Context, _ *globals, target string, stdout, _ io.Writer) error {
		w.resyncs = append(w.resyncs, target)
		io.WriteString(stdout, w.syncText)
		return nil
	}
	w.home = filepath.Join(t.TempDir(), "no-vault-here")
	w.env = map[string]string{"QBIT_VAULT_HOME": w.home, "QBIT_VAULT_RELEASES_API": w.srv.URL + "/api"}
	w.setArchive("qbit-vault_linux_amd64.tar.gz", updTarGz(t, "qbit-vault", updNew))
	return w
}

func (w *updWorld) releaseJSON() string {
	type asset struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	}
	var as []asset
	for n := range w.assets {
		as = append(as, asset{n, w.srv.URL + "/dl/" + n})
	}
	as = append(as, asset{"checksums.txt", w.srv.URL + "/dl/checksums.txt"})
	if w.sig != nil {
		as = append(as, asset{"checksums.txt.minisig", w.srv.URL + "/dl/checksums.txt.minisig"})
	}
	b, _ := json.Marshal(map[string]any{"tag_name": w.latest, "draft": false, "prerelease": false,
		"published_at": "2026-02-01T00:00:00Z", "html_url": w.srv.URL + "/notes", "assets": as})
	return string(b)
}

// updSigner stands in for the release key: the binary under test is pointed
// at its throwaway public key through the updateKey seam, so these tests keep
// working whichever release key is pinned.
var updSigner = minisigntest.New(1)

func (w *updWorld) signChecksums() {
	w.sig = updSigner.Sign([]byte(w.checksums), "timestamp:1 file:checksums.txt version:"+w.latest)
}

func updSum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func (w *updWorld) setArchive(name string, data []byte) {
	w.assets[name] = data
	w.checksums = updSum(data) + "  " + name + "\n" + strings.Repeat("0", 64) + "  other.zip\n"
	w.signChecksums()
}

func updTarGz(t *testing.T, name, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range [][2]string{{"README.md", "r"}, {name, body}} {
		tw.WriteHeader(&tar.Header{Name: e[0], Mode: 0o644, Size: int64(len(e[1])), Typeflag: tar.TypeReg})
		tw.Write([]byte(e[1]))
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func updZip(name, body string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range [][2]string{{"LICENSE", "l"}, {name, body}} {
		f, _ := zw.Create(e[0])
		f.Write([]byte(e[1]))
	}
	zw.Close()
	return buf.Bytes()
}

func (w *updWorld) run(args ...string) (int, string, string) {
	w.t.Helper()
	return run(w.t, w.env, append([]string{"update"}, args...)...)
}

func (w *updWorld) binary() string {
	b, err := os.ReadFile(w.target)
	if err != nil {
		w.t.Fatal(err)
	}
	return string(b)
}

// onlyBinary fails when anything but the binary is in its directory.
func (w *updWorld) onlyBinary() {
	w.t.Helper()
	es, _ := os.ReadDir(w.dir)
	for _, e := range es {
		if e.Name() != filepath.Base(w.target) {
			w.t.Errorf("leftover next to the binary: %s", e.Name())
		}
	}
}

func (w *updWorld) noVault() {
	w.t.Helper()
	if _, err := os.Stat(w.home); !os.IsNotExist(err) {
		w.t.Fatalf("the vault home was created or opened: %v", err)
	}
}

func TestUpdateUpToDate(t *testing.T) {
	w := newUpdWorld(t, "v1.1.0", "v1.1.0")
	f := withBackend(t, answers())
	code, out, errs := w.run()
	if code != exitcode.OK || out != "qbit-vault v1.1.0 is up to date\n" || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if w.hits.Load() != 0 || len(f.Calls) != 0 || w.binary() != updOld || len(w.resyncs) != 0 {
		t.Fatal("up to date must download, ask and change nothing")
	}
	w.noVault()
}

func TestUpdateNewerConfirmed(t *testing.T) {
	w := newUpdWorld(t, "v1.0.0", "v1.1.0")
	f := withBackend(t, answers(yes()))
	code, out, errs := w.run()
	want := "updated qbit-vault v1.0.0 -> v1.1.0; restart your agents so they load the new version\n"
	if code != exitcode.OK || out != want || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if len(f.Calls) != 1 || f.Calls[0].Kind != "confirm" || f.Calls[0].Q != "Update QBit Vault v1.0.0 to v1.1.0?" {
		t.Fatalf("prompt calls: %+v", f.Calls)
	}
	if w.binary() != updNew {
		t.Fatal("binary not replaced")
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(w.target); st.Mode().Perm() != 0o755 {
			t.Fatalf("mode %v", st.Mode())
		}
	}
	w.onlyBinary()
	w.noVault()
}

func TestUpdateDeclined(t *testing.T) {
	w := newUpdWorld(t, "v1.0.0", "v1.1.0")
	withBackend(t, answers(no()))
	code, out, errs := w.run()
	if code != exitcode.Failure || out != "" || errs != msgCancelled {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if w.hits.Load() != 0 || w.binary() != updOld || len(w.resyncs) != 0 {
		t.Fatal("a decline must change nothing")
	}
	w.onlyBinary()
	w.noVault()
}

func TestUpdateNoPromptBackend(t *testing.T) {
	w := newUpdWorld(t, "v1.0.0", "v1.1.0")
	code, out, errs := w.run() // TestMain installs a seam with no terminal
	if code != exitcode.Refusal || out != "" || errs != "error: this operation is not available to the model\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if w.hits.Load() != 0 || w.binary() != updOld {
		t.Fatal("no prompt backend must change nothing")
	}
	w.noVault()
}

func TestUpdateStopsOnBadDownload(t *testing.T) {
	for name, mutate := range map[string]func(w *updWorld){
		"checksum mismatch": func(w *updWorld) {
			w.checksums = strings.Repeat("b", 64) + "  qbit-vault_linux_amd64.tar.gz\n"
		},
		"missing line": func(w *updWorld) { w.checksums = strings.Repeat("b", 64) + "  other.tar.gz\n" },
		"no binary in the archive": func(w *updWorld) {
			w.setArchive("qbit-vault_linux_amd64.tar.gz", updTarGz(t, "something-else", "x"))
		},
		"archive 404": func(w *updWorld) {
			// listed in the release, gone from the host
			w.assets["qbit-vault_linux_amd64.tar.gz"] = nil
			delete(w.assets, "qbit-vault_linux_amd64.tar.gz")
		},
	} {
		t.Run(name, func(t *testing.T) {
			w := newUpdWorld(t, "v1.0.0", "v1.1.0")
			mutate(w)
			if name == "archive 404" {
				// keep the asset in the listing but not in the store
				w.srv.Config.Handler = http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/api" {
						fmt.Fprintf(rw, `{"tag_name":"v1.1.0","published_at":"2026-02-01T00:00:00Z","assets":[{"name":"qbit-vault_linux_amd64.tar.gz","browser_download_url":"%s/dl/qbit-vault_linux_amd64.tar.gz"},{"name":"checksums.txt","browser_download_url":"%s/dl/checksums.txt"}]}`, w.srv.URL, w.srv.URL)
						return
					}
					http.NotFound(rw, r)
				})
			}
			withBackend(t, answers(yes()))
			code, out, errs := w.run()
			if code != exitcode.Failure || out != "" || !strings.HasPrefix(errs, "error: ") {
				t.Fatalf("code=%d out=%q err=%q", code, out, errs)
			}
			if w.binary() != updOld || len(w.resyncs) != 0 {
				t.Fatal("the installed binary must stay byte-identical")
			}
			w.onlyBinary()
			w.noVault()
		})
	}
}

const updNotSigned = "error: the release v1.1.0 is not signed with the QBit Vault release key; nothing was changed\n"

func TestUpdateSignedReleaseUpdates(t *testing.T) {
	w := newUpdWorld(t, "v1.0.0", "v1.1.0")
	withBackend(t, answers(yes()))
	code, _, errs := w.run()
	if code != exitcode.OK || errs != "" || w.binary() != updNew {
		t.Fatalf("code=%d err=%q binary=%q", code, errs, w.binary())
	}
	w.onlyBinary()
}

// A release without a valid signature is refused with one message, however it
// is wrong, and the SHA-256 alone never lets it through.
func TestUpdateRefusesWithoutValidSignature(t *testing.T) {
	other := minisigntest.New(2)
	for name, mutate := range map[string]func(w *updWorld){
		"no minisig": func(w *updWorld) { w.sig = nil },
		"signed by another key": func(w *updWorld) {
			w.sig = other.Sign([]byte(w.checksums), "timestamp:1 file:checksums.txt version:v1.1.0")
		},
		"checksums changed after signing": func(w *updWorld) {
			// The archive still matches its line, so the SHA-256 check passes.
			w.checksums += strings.Repeat("1", 64) + "  extra.zip\n"
		},
		"malformed signature": func(w *updWorld) { w.sig = []byte("not a signature\n") },
		"empty signature":     func(w *updWorld) { w.sig = []byte{} },
		"tampered signature": func(w *updWorld) {
			w.sig = bytes.Replace(w.sig, []byte("trusted comment: timestamp:1"), []byte("trusted comment: timestamp:2"), 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			w := newUpdWorld(t, "v1.0.0", "v1.1.0")
			mutate(w)
			withBackend(t, answers(yes()))
			code, out, errs := w.run()
			if code != exitcode.Failure || out != "" || errs != updNotSigned {
				t.Fatalf("code=%d out=%q err=%q", code, out, errs)
			}
			if w.binary() != updOld || len(w.resyncs) != 0 {
				t.Fatal("the installed binary must stay byte-identical")
			}
			w.onlyBinary()
			w.noVault()
		})
	}
}

// With no test key injected the binary trusts only its pinned key.
func TestUpdateDefaultKeyIsThePinnedOne(t *testing.T) {
	w := newUpdWorld(t, "v1.0.0", "v1.1.0")
	updateKey = nil
	w.sig = minisigntest.New(3).Sign([]byte(w.checksums), "timestamp:1 file:checksums.txt version:v1.1.0")
	withBackend(t, answers(yes()))
	code, _, errs := w.run()
	if code != exitcode.Failure || errs != updNotSigned || w.binary() != updOld {
		t.Fatalf("code=%d err=%q", code, errs)
	}
}

func TestUpdateCheckNeedsNoSignature(t *testing.T) {
	w := newUpdWorld(t, "v1.0.0", "v1.1.0")
	w.sig = nil
	code, out, errs := w.run("--check")
	if code != exitcode.OK || out != "update available: v1.0.0 -> v1.1.0\n" || errs != "" || w.hits.Load() != 0 {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
}

func TestUpdateNonReleaseBuild(t *testing.T) {
	for _, v := range []string{"dev", "v1.0.0+dirty", "v0.0.0-20260101000000-abcdef123456", ""} {
		w := newUpdWorld(t, v, "v1.1.0")
		f := withBackend(t, answers(yes()))
		code, out, errs := w.run()
		want := "error: " + msgNotRelease + "\n" + helpHint
		if code != exitcode.Usage || out != "" || errs != want {
			t.Fatalf("%q: code=%d out=%q err=%q", v, code, out, errs)
		}
		if w.hits.Load() != 0 || len(f.Calls) != 0 || w.binary() != updOld {
			t.Fatalf("%q: a non-release build must not update", v)
		}
	}
}

func TestUpdateCheckWorksOnNonReleaseBuild(t *testing.T) {
	w := newUpdWorld(t, "dev", "v1.1.0")
	code, out, errs := w.run("--check")
	if code != exitcode.OK || out != "update available: dev -> v1.1.0\n" || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
}

func TestUpdateCheckText(t *testing.T) {
	w := newUpdWorld(t, "v1.0.0", "v1.1.0")
	f := withBackend(t, answers())
	code, out, errs := w.run("--check")
	if code != exitcode.OK || out != "update available: v1.0.0 -> v1.1.0\n" || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	w.latest = "v1.0.0"
	code, out, errs = w.run("--check")
	if code != exitcode.OK || out != "qbit-vault v1.0.0 is up to date\n" || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if w.hits.Load() != 0 || len(f.Calls) != 0 || w.binary() != updOld {
		t.Fatal("--check must not ask, download or change anything")
	}
	w.noVault()
}

func TestUpdateCheckJSON(t *testing.T) {
	w := newUpdWorld(t, "v1.0.0", "v1.1.0")
	code, out, errs := w.run("--check", "--json")
	want := `{"ok":true,"current":"v1.0.0","latest":"v1.1.0","update_available":true}` + "\n"
	if code != exitcode.OK || out != want || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	w.latest = "v1.0.0"
	code, out, errs = w.run("--check", "--json")
	want = `{"ok":true,"current":"v1.0.0","latest":"v1.0.0","update_available":false}` + "\n"
	if code != exitcode.OK || out != want || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
}

func TestUpdateJSONAfterUpdate(t *testing.T) {
	w := newUpdWorld(t, "v1.0.0", "v1.1.0")
	withBackend(t, answers(yes()))
	code, out, errs := w.run("--json")
	want := `{"ok":true,"current":"v1.0.0","latest":"v1.1.0","update_available":true,"updated":true}` + "\n"
	if code != exitcode.OK || out != want || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if w.binary() != updNew {
		t.Fatal("binary not replaced")
	}
}

func TestUpdateUpToDateJSON(t *testing.T) {
	w := newUpdWorld(t, "v1.1.0", "v1.1.0")
	code, out, _ := w.run("--json")
	want := `{"ok":true,"current":"v1.1.0","latest":"v1.1.0","update_available":false}` + "\n"
	if code != exitcode.OK || out != want {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

func TestUpdateUnwritableDirectory(t *testing.T) {
	w := newUpdWorld(t, "v1.0.0", "v1.1.0")
	gone := filepath.Join(w.dir, "gone", "qbit-vault")
	updateTarget = func() (string, error) { return gone, nil }
	f := withBackend(t, answers(yes()))
	code, out, errs := w.run()
	want := "error: cannot replace " + gone + ": re-run the install command\n"
	if code != exitcode.Failure || out != "" || errs != want {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if w.hits.Load() != 0 || len(f.Calls) != 0 {
		t.Fatal("the message must come before any download or prompt")
	}
}

func TestUpdateReRegistersHosts(t *testing.T) {
	w := newUpdWorld(t, "v1.0.0", "v1.1.0")
	if err := os.MkdirAll(w.home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(w.home, "state.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	withBackend(t, answers(yes(), yes()))
	if code, _, errs := w.run(); code != exitcode.OK {
		t.Fatalf("code=%d err=%q", code, errs)
	}
	if len(w.resyncs) != 1 || w.resyncs[0] != w.target {
		t.Fatalf("re-registration calls: %v", w.resyncs)
	}
	// QBIT_VAULT_NO_SYNC=1 skips it, as in the installers.
	w.latest = "v1.2.0"
	w.env["QBIT_VAULT_NO_SYNC"] = "1"
	if code, _, errs := w.run(); code != exitcode.OK {
		t.Fatalf("code=%d err=%q", code, errs)
	}
	if len(w.resyncs) != 1 {
		t.Fatalf("QBIT_VAULT_NO_SYNC=1 still re-registered: %v", w.resyncs)
	}
	// The files of the vault home are left as they were.
	if b, _ := os.ReadFile(filepath.Join(w.home, "state.json")); string(b) != "{}" {
		t.Fatal("state.json was touched")
	}
	es, _ := os.ReadDir(w.home)
	if len(es) != 1 {
		t.Fatalf("files appeared in the vault home: %v", es)
	}
}

func TestUpdateResyncFailureKeepsTheUpdate(t *testing.T) {
	w := newUpdWorld(t, "v1.0.0", "v1.1.0")
	os.MkdirAll(w.home, 0o700)
	os.WriteFile(filepath.Join(w.home, "state.json"), []byte("{}"), 0o600)
	updateResync = func(context.Context, *globals, string, io.Writer, io.Writer) error { return fmt.Errorf("boom") }
	withBackend(t, answers(yes()))
	code, out, errs := w.run()
	if code != exitcode.OK || !strings.HasPrefix(out, "updated qbit-vault v1.0.0 -> v1.1.0;") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if !strings.Contains(errs, "qbit-vault sync") || w.binary() != updNew {
		t.Fatalf("the binary stays updated and the user is told to run sync: %q", errs)
	}
}

func TestUpdateWindowsAsideAndCleanup(t *testing.T) {
	w := newUpdWorld(t, "v1.0.0", "v1.1.0")
	updateGOOS = "windows"
	w.target = filepath.Join(w.dir, "qbit-vault.exe")
	os.WriteFile(w.target, []byte(updOld), 0o700)
	os.Remove(filepath.Join(w.dir, "qbit-vault"))
	w.setArchive("qbit-vault_windows_amd64.zip", updZip("qbit-vault.exe", updNew))
	stale := w.target + ".old-cafebabe"
	os.WriteFile(stale, []byte("ancient"), 0o700)
	withBackend(t, answers(yes(), yes()))

	if code, _, errs := w.run(); code != exitcode.OK {
		t.Fatalf("code=%d err=%q", code, errs)
	}
	if w.binary() != updNew {
		t.Fatal("binary not replaced")
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("an older .old-* copy survived the next run")
	}
	olds, _ := filepath.Glob(w.target + ".old-*")
	if len(olds) != 1 {
		t.Fatalf("want exactly one aside copy, got %v", olds)
	}
	if b, _ := os.ReadFile(olds[0]); string(b) != updOld {
		t.Fatal("the aside copy is not the old binary")
	}

	// The next update run removes the copy this one left.
	w.latest = "v1.2.0"
	Version = "v1.1.0"
	if code, _, errs := w.run(); code != exitcode.OK {
		t.Fatalf("code=%d err=%q", code, errs)
	}
	if _, err := os.Stat(olds[0]); !os.IsNotExist(err) {
		t.Fatal("the previous aside copy was not cleaned")
	}
	if left, _ := filepath.Glob(w.target + ".old-*"); len(left) != 1 {
		t.Fatalf("aside copies: %v", left)
	}
}

func TestUpdateRefusesPlainHTTPAPI(t *testing.T) {
	w := newUpdWorld(t, "v1.0.0", "v1.1.0")
	w.env["QBIT_VAULT_RELEASES_API"] = "http://example.invalid/releases"
	f := withBackend(t, answers(yes()))
	code, out, errs := w.run("--check")
	if code != exitcode.Failure || out != "" || !strings.HasPrefix(errs, "error: ") || len(f.Calls) != 0 {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
}

func TestUpdateDefaultAPI(t *testing.T) {
	if got := updateAPI(func(string) string { return "" }); got != "https://api.github.com/repos/qbitdevz/qbit-vault/releases/latest" {
		t.Fatal(got)
	}
	if got := updateAPI(func(string) string { return "https://x.test/r" }); got != "https://x.test/r" {
		t.Fatal(got)
	}
}

func TestUpdateRejectsArguments(t *testing.T) {
	code, _, errs := run(t, nil, "update", "now")
	if code != exitcode.Usage || !strings.Contains(errs, "unexpected arguments") {
		t.Fatalf("code=%d err=%q", code, errs)
	}
}
