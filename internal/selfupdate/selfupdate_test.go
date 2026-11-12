package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/minisign/minisigntest"
)

func TestIsRelease(t *testing.T) {
	for v, want := range map[string]bool{
		"v1.0.0": true, "1.2.3": true, "v1.1.0-beta.2": true,
		"dev": false, "": false, "(devel)": false, "v1.0.0+dirty": false,
		"v0.0.0-20240101000000-abcdef123456":   false,
		"v1.0.1-0.20240101000000-abcdef123456": false,
		"v1.0":                                 false, "vx.y.z": false,
	} {
		if got := IsRelease(v); got != want {
			t.Errorf("IsRelease(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		cur, lat string
		want     bool
	}{
		{"v1.0.0", "v1.1.0", true},
		{"v1.0.0", "v1.0.0", false},
		{"v1.1.0", "v1.0.0", false},
		{"v1.9.0", "v1.10.0", true},
		{"v1.1.0-beta.1", "v1.1.0", true},
		{"v1.1.0", "v1.1.0-beta.1", false},
		{"v1.1.0-beta.9", "v1.1.0-beta.10", true},
		{"v1.1.0-alpha", "v1.1.0-beta", true},
		{"1.0.0", "v1.0.1", true},
	} {
		got, err := Newer(c.cur, c.lat)
		if err != nil || got != c.want {
			t.Errorf("Newer(%q,%q) = %v,%v want %v", c.cur, c.lat, got, err, c.want)
		}
	}
	if _, err := Newer("dev", "v1.0.0"); err == nil {
		t.Error("Newer on a non-release current must fail")
	}
	if _, err := Newer("v1.0.0", "nightly"); err == nil {
		t.Error("Newer on a non-release latest must fail")
	}
}

func TestNames(t *testing.T) {
	if got := ArchiveName("linux", "amd64"); got != "qbit-vault_linux_amd64.tar.gz" {
		t.Fatal(got)
	}
	if got := ArchiveName("windows", "arm64"); got != "qbit-vault_windows_arm64.zip" {
		t.Fatal(got)
	}
	if BinaryName("windows") != "qbit-vault.exe" || BinaryName("darwin") != "qbit-vault" {
		t.Fatal("binary names")
	}
}

// fakeRelease serves a releases API and its assets on loopback.
type fakeRelease struct {
	srv       *httptest.Server
	hits      atomic.Int32 // asset downloads
	ua        atomic.Value
	assets    map[string][]byte
	checksums string
	sign      func(sums string) []byte // the checksums.txt.minisig served
	apiBody   func(base string) string
}

func newFake(t *testing.T) *fakeRelease {
	t.Helper()
	f := &fakeRelease{assets: map[string][]byte{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		f.ua.Store(r.Header.Get("User-Agent"))
		fmt.Fprint(w, f.apiBody(f.srv.URL))
	})
	// Release assets redirect to a blob host, like GitHub's.
	mux.HandleFunc("/dl/", func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		http.Redirect(w, r, "/blob/"+strings.TrimPrefix(r.URL.Path, "/dl/"), http.StatusFound)
	})
	mux.HandleFunc("/blob/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/blob/")
		if name == "checksums.txt" {
			fmt.Fprint(w, f.checksums)
			return
		}
		if name == "checksums.txt.minisig" {
			if f.sign == nil {
				http.NotFound(w, r)
				return
			}
			w.Write(f.sign(f.checksums))
			return
		}
		b, ok := f.assets[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	f.sign = func(sums string) []byte {
		return testSigner.Sign([]byte(sums), "timestamp:1 file:checksums.txt version:v1.1.0")
	}
	f.apiBody = func(base string) string {
		return releaseJSON(base, "v1.1.0", false, false, "2026-01-02T00:00:00Z", "qbit-vault_linux_amd64.tar.gz", "qbit-vault_windows_amd64.zip", "checksums.txt", "checksums.txt.minisig")
	}
	return f
}

func releaseJSON(base, tag string, draft, pre bool, published string, names ...string) string {
	type asset struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	}
	var as []asset
	for _, n := range names {
		as = append(as, asset{n, base + "/dl/" + n})
	}
	b, _ := json.Marshal(map[string]any{"tag_name": tag, "draft": draft, "prerelease": pre, "published_at": published, "html_url": base + "/notes/" + tag, "assets": as})
	return string(b)
}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func tarGz(t *testing.T, name string, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range []struct {
		n string
		b []byte
	}{{"README.md", []byte("readme")}, {name, body}} {
		tw.WriteHeader(&tar.Header{Name: e.n, Mode: 0o644, Size: int64(len(e.b)), Typeflag: tar.TypeReg})
		tw.Write(e.b)
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func zipOf(t *testing.T, name string, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range []struct {
		n string
		b []byte
	}{{"LICENSE", []byte("l")}, {name, body}} {
		w, _ := zw.Create(e.n)
		w.Write(e.b)
	}
	zw.Close()
	return buf.Bytes()
}

// testSigner is a throwaway release key; clients under test trust it through
// Client.Key, so these tests do not depend on which key the binary pins.
var testSigner = minisigntest.New(1)

func (f *fakeRelease) client() *Client {
	c := NewClient("v1.0.0", f.srv.URL+"/api")
	c.Key = testSigner.Pub
	return c
}

func (f *fakeRelease) setLinux(t *testing.T, binary []byte) {
	a := tarGz(t, "qbit-vault", binary)
	f.assets["qbit-vault_linux_amd64.tar.gz"] = a
	f.checksums = sum(a) + "  qbit-vault_linux_amd64.tar.gz\n" + strings.Repeat("0", 64) + "  other.zip\n"
}

func empty(t *testing.T, dir string) {
	t.Helper()
	es, _ := os.ReadDir(dir)
	for _, e := range es {
		t.Errorf("leftover in %s: %s", dir, e.Name())
	}
}

func TestLatestObject(t *testing.T) {
	f := newFake(t)
	rel, err := f.client().Latest(context.Background())
	if err != nil || rel.Tag != "v1.1.0" || rel.URL != f.srv.URL+"/notes/v1.1.0" || rel.Assets["checksums.txt"] != f.srv.URL+"/dl/checksums.txt" {
		t.Fatalf("%+v %v", rel, err)
	}
	if ua := f.ua.Load(); ua != "qbit-vault/v1.0.0" {
		t.Fatalf("User-Agent = %v", ua)
	}
}

func TestLatestListPicksNewestPublishedStable(t *testing.T) {
	f := newFake(t)
	f.apiBody = func(base string) string {
		return "[" + strings.Join([]string{
			releaseJSON(base, "v2.0.0-beta.1", false, true, "2026-05-01T00:00:00Z"),
			releaseJSON(base, "v1.5.0", true, false, "2026-06-01T00:00:00Z"),
			releaseJSON(base, "v1.2.0", false, false, "2026-03-01T00:00:00Z"),
			releaseJSON(base, "v1.1.0", false, false, "2026-01-01T00:00:00Z"),
		}, ",") + "]"
	}
	rel, err := f.client().Latest(context.Background())
	if err != nil || rel.Tag != "v1.2.0" {
		t.Fatalf("%+v %v", rel, err)
	}
}

func TestLatestNeverDraftOrPrerelease(t *testing.T) {
	for _, body := range []func(string) string{
		func(b string) string { return releaseJSON(b, "v1.1.0", true, false, "2026-01-01T00:00:00Z") },
		func(b string) string { return releaseJSON(b, "v1.1.0", false, true, "2026-01-01T00:00:00Z") },
		func(b string) string { return "[]" },
		func(b string) string { return "not json" },
		func(b string) string { return releaseJSON(b, "nightly", false, false, "2026-01-01T00:00:00Z") },
	} {
		f := newFake(t)
		f.apiBody = body
		if rel, err := f.client().Latest(context.Background()); err == nil {
			t.Errorf("picked %+v", rel)
		}
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (r roundTrip) RoundTrip(q *http.Request) (*http.Response, error) { return r(q) }

func TestHTTPSOnlyExceptLoopback(t *testing.T) {
	var hits atomic.Int32
	c := NewClient("v1.0.0", "http://example.invalid/api")
	c.HTTP = &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
		hits.Add(1)
		return nil, fmt.Errorf("network")
	})}
	if _, err := c.Latest(context.Background()); err == nil || hits.Load() != 0 {
		t.Fatalf("plain http to a remote host: err=%v hits=%d", err, hits.Load())
	}
	// A release whose assets are plain http on a remote host is refused too.
	f := newFake(t)
	f.apiBody = func(string) string {
		return `{"tag_name":"v1.1.0","published_at":"2026-01-01T00:00:00Z","assets":[{"name":"checksums.txt","browser_download_url":"http://example.invalid/c"},{"name":"qbit-vault_linux_amd64.tar.gz","browser_download_url":"http://example.invalid/a"}]}`
	}
	rel, err := f.client().Latest(context.Background())
	if err != nil {
		return // refusing at lookup is fine
	}
	cl := f.client()
	cl.HTTP = c.HTTP
	if _, err := cl.Download(context.Background(), rel, "linux", "amd64", t.TempDir()); err == nil || hits.Load() != 0 {
		t.Fatalf("downloaded from a plain http remote host: %v", err)
	}
}

func TestDownloadTarGz(t *testing.T) {
	f := newFake(t)
	f.setLinux(t, []byte("NEWBINARY"))
	rel, _ := f.client().Latest(context.Background())
	dir := t.TempDir()
	p, err := f.client().Download(context.Background(), rel, "linux", "amd64", dir)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(p) != dir {
		t.Fatalf("temp file %s not in %s", p, dir)
	}
	if b, _ := os.ReadFile(p); string(b) != "NEWBINARY" {
		t.Fatalf("content %q", b)
	}
	if f.hits.Load() != 3 {
		t.Fatalf("hits=%d, want archive+checksums+signature", f.hits.Load())
	}
}

const notSignedMsg = "the release v1.1.0 is not signed with the QBit Vault release key; nothing was changed"

func TestDownloadSignatureRefusals(t *testing.T) {
	other := minisigntest.New(2)
	for name, mutate := range map[string]func(f *fakeRelease){
		"not listed": func(f *fakeRelease) {
			f.apiBody = func(b string) string {
				return releaseJSON(b, "v1.1.0", false, false, "2026-01-02T00:00:00Z", "qbit-vault_linux_amd64.tar.gz", "checksums.txt")
			}
		},
		"listed but gone": func(f *fakeRelease) { f.sign = nil },
		"another key": func(f *fakeRelease) {
			f.sign = func(s string) []byte { return other.Sign([]byte(s), "timestamp:1") }
		},
		"signs other checksums": func(f *fakeRelease) {
			// checksums.txt still lists the archive with its real SHA-256.
			f.sign = func(s string) []byte { return testSigner.Sign([]byte(s+"tampered"), "timestamp:1") }
		},
		"malformed": func(f *fakeRelease) { f.sign = func(string) []byte { return []byte("garbage\n") } },
		"empty":     func(f *fakeRelease) { f.sign = func(string) []byte { return nil } },
		"oversized": func(f *fakeRelease) {
			f.sign = func(s string) []byte {
				return append(testSigner.Sign([]byte(s), "timestamp:1"), bytes.Repeat([]byte("x"), maxSignature)...)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			f.setLinux(t, []byte("NEWBINARY"))
			mutate(f)
			rel, _ := f.client().Latest(context.Background())
			dir := t.TempDir()
			p, err := f.client().Download(context.Background(), rel, "linux", "amd64", dir)
			if err == nil || p != "" {
				t.Fatalf("accepted: %q", p)
			}
			if err.Error() != notSignedMsg || !errors.Is(err, ErrNotSigned) {
				t.Fatalf("error %q", err)
			}
			empty(t, dir)
		})
	}
}

func TestDownloadSignatureCheckedAfterChecksum(t *testing.T) {
	f := newFake(t)
	f.setLinux(t, []byte("NEWBINARY"))
	f.checksums = strings.Repeat("a", 64) + "  qbit-vault_linux_amd64.tar.gz\n"
	rel, _ := f.client().Latest(context.Background())
	_, err := f.client().Download(context.Background(), rel, "linux", "amd64", t.TempDir())
	if err == nil || errors.Is(err, ErrNotSigned) {
		t.Fatalf("a checksum mismatch must be reported as such: %v", err)
	}
}

// The default client trusts the key pinned in the binary, not the test key.
func TestDownloadDefaultKeyIsThePinnedOne(t *testing.T) {
	f := newFake(t)
	f.setLinux(t, []byte("NEWBINARY"))
	rel, _ := f.client().Latest(context.Background())
	_, err := NewClient("v1.0.0", f.srv.URL+"/api").Download(context.Background(), rel, "linux", "amd64", t.TempDir())
	if !errors.Is(err, ErrNotSigned) {
		t.Fatalf("a signature by a throwaway key was accepted: %v", err)
	}
}

func TestDownloadZip(t *testing.T) {
	f := newFake(t)
	a := zipOf(t, "qbit-vault.exe", []byte("WINBIN"))
	f.assets["qbit-vault_windows_amd64.zip"] = a
	f.checksums = sum(a) + "  qbit-vault_windows_amd64.zip\n"
	rel, _ := f.client().Latest(context.Background())
	p, err := f.client().Download(context.Background(), rel, "windows", "amd64", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "WINBIN" {
		t.Fatalf("content %q", b)
	}
}

func TestDownloadRefusals(t *testing.T) {
	good := tarGz(t, "qbit-vault", []byte("NEW"))
	for name, mutate := range map[string]func(f *fakeRelease){
		"mismatch": func(f *fakeRelease) {
			f.checksums = strings.Repeat("a", 64) + "  qbit-vault_linux_amd64.tar.gz\n"
		},
		"missing line":    func(f *fakeRelease) { f.checksums = strings.Repeat("a", 64) + "  other.tar.gz\n" },
		"empty checksums": func(f *fakeRelease) { f.checksums = "" },
		"no binary in archive": func(f *fakeRelease) {
			a := tarGz(t, "other-file", []byte("x"))
			f.assets["qbit-vault_linux_amd64.tar.gz"] = a
			f.checksums = sum(a) + "  qbit-vault_linux_amd64.tar.gz\n"
		},
		"not an archive": func(f *fakeRelease) {
			a := []byte("garbage")
			f.assets["qbit-vault_linux_amd64.tar.gz"] = a
			f.checksums = sum(a) + "  qbit-vault_linux_amd64.tar.gz\n"
		},
		"asset 404": func(f *fakeRelease) { delete(f.assets, "qbit-vault_linux_amd64.tar.gz") },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			f.assets["qbit-vault_linux_amd64.tar.gz"] = good
			f.checksums = sum(good) + "  qbit-vault_linux_amd64.tar.gz\n"
			mutate(f)
			rel, _ := f.client().Latest(context.Background())
			dir := t.TempDir()
			if p, err := f.client().Download(context.Background(), rel, "linux", "amd64", dir); err == nil {
				t.Fatalf("accepted: %s", p)
			}
			empty(t, dir)
		})
	}
}

func TestDownloadMissingAsset(t *testing.T) {
	f := newFake(t)
	f.apiBody = func(b string) string {
		return releaseJSON(b, "v1.1.0", false, false, "2026-01-01T00:00:00Z", "checksums.txt")
	}
	rel, _ := f.client().Latest(context.Background())
	if _, err := f.client().Download(context.Background(), rel, "linux", "amd64", t.TempDir()); err == nil {
		t.Fatal("no archive for this platform must fail")
	}
	if f.hits.Load() != 0 {
		t.Fatal("nothing should be downloaded")
	}
}

func TestDownloadSizeCaps(t *testing.T) {
	f := newFake(t)
	f.setLinux(t, bytes.Repeat([]byte("A"), 4096))
	rel, _ := f.client().Latest(context.Background())
	c := f.client()
	c.MaxArchive = 100
	dir := t.TempDir()
	if _, err := c.Download(context.Background(), rel, "linux", "amd64", dir); err == nil {
		t.Fatal("archive over the cap accepted")
	}
	empty(t, dir)
	c = f.client()
	c.MaxChecksums = 10
	if _, err := c.Download(context.Background(), rel, "linux", "amd64", dir); err == nil {
		t.Fatal("checksums over the cap accepted")
	}
	empty(t, dir)
}

func TestReplacePosix(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "qbit-vault")
	os.WriteFile(target, []byte("OLD"), 0o600)
	nf := filepath.Join(dir, ".new")
	os.WriteFile(nf, []byte("NEW"), 0o600)
	if err := Replace(target, nf, "linux"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); string(b) != "NEW" {
		t.Fatalf("content %q", b)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(target); st.Mode().Perm() != 0o755 {
			t.Fatalf("mode %v", st.Mode())
		}
	}
	if _, err := os.Stat(nf); !os.IsNotExist(err) {
		t.Fatal("temp file left")
	}
}

func TestReplaceWindowsMovesOldAside(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "qbit-vault.exe")
	os.WriteFile(target, []byte("OLD"), 0o755)
	nf := filepath.Join(dir, ".new")
	os.WriteFile(nf, []byte("NEW"), 0o755)
	if err := Replace(target, nf, "windows"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); string(b) != "NEW" {
		t.Fatalf("content %q", b)
	}
	olds, _ := filepath.Glob(target + ".old-*")
	if len(olds) != 1 || len(strings.TrimPrefix(filepath.Base(olds[0]), "qbit-vault.exe.old-")) != 8 {
		t.Fatalf("aside copies: %v", olds)
	}
	if b, _ := os.ReadFile(olds[0]); string(b) != "OLD" {
		t.Fatal("aside copy lost the old content")
	}
	CleanOld(target)
	if olds, _ = filepath.Glob(target + ".old*"); len(olds) != 0 {
		t.Fatalf("not cleaned: %v", olds)
	}
	if b, _ := os.ReadFile(target); string(b) != "NEW" {
		t.Fatal("cleanup touched the binary")
	}
}

func TestReplaceWindowsRestoresOnFailure(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "qbit-vault.exe")
	os.WriteFile(target, []byte("OLD"), 0o755)
	if err := Replace(target, filepath.Join(dir, "missing"), "windows"); err == nil {
		t.Fatal("expected failure")
	}
	if b, _ := os.ReadFile(target); string(b) != "OLD" {
		t.Fatalf("old binary not put back: %q", b)
	}
	if olds, _ := filepath.Glob(target + ".old*"); len(olds) != 0 {
		t.Fatalf("aside copy left: %v", olds)
	}
}

func TestCanReplace(t *testing.T) {
	dir := t.TempDir()
	if err := CanReplace(dir); err != nil {
		t.Fatal(err)
	}
	empty(t, dir)
	if err := CanReplace(filepath.Join(dir, "nope")); err == nil {
		t.Fatal("a missing directory is not replaceable")
	}
}

func TestDownloadSyncsTempFileBeforeClose(t *testing.T) {
	var synced []string
	prev := syncFile
	syncFile = func(f *os.File) error { synced = append(synced, f.Name()); return prev(f) }
	t.Cleanup(func() { syncFile = prev })
	f := newFake(t)
	f.setLinux(t, []byte("NEWBINARY"))
	rel, _ := f.client().Latest(context.Background())
	p, err := f.client().Download(context.Background(), rel, "linux", "amd64", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(synced) != 1 || synced[0] != p {
		t.Fatalf("synced %v, want [%s]", synced, p)
	}
}

func TestDownloadSyncFailureLeavesNothing(t *testing.T) {
	prev := syncFile
	syncFile = func(*os.File) error { return errors.New("disk full") }
	t.Cleanup(func() { syncFile = prev })
	f := newFake(t)
	f.setLinux(t, []byte("NEWBINARY"))
	rel, _ := f.client().Latest(context.Background())
	dir := t.TempDir()
	if _, err := f.client().Download(context.Background(), rel, "linux", "amd64", dir); err == nil {
		t.Fatal("want an error when the new binary cannot be synced")
	}
	if es, _ := os.ReadDir(dir); len(es) != 0 {
		t.Fatalf("temp file left: %v", es)
	}
}

func TestReplacePosixSyncsDirectoryAfterRename(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "qbit-vault")
	os.WriteFile(target, []byte("OLD"), 0o600)
	nf := filepath.Join(dir, ".new")
	os.WriteFile(nf, []byte("NEW"), 0o600)
	var got string
	var seen []byte
	prev := syncDir
	syncDir = func(d string) error { got = d; seen, _ = os.ReadFile(target); return nil }
	t.Cleanup(func() { syncDir = prev })
	if err := Replace(target, nf, "linux"); err != nil {
		t.Fatal(err)
	}
	if got != dir || string(seen) != "NEW" {
		t.Fatalf("syncDir(%q) saw %q, want the directory after the rename", got, seen)
	}
}

// A .minisig that cannot be fetched is not "not signed": the user is told the
// download failed, with a fixed short reason, and nothing is installed.
func TestDownloadSignatureFetchFailures(t *testing.T) {
	for name, tc := range map[string]struct {
		serve  func(w http.ResponseWriter, r *http.Request)
		reason string
	}{
		"server error": {func(w http.ResponseWriter, r *http.Request) { http.Error(w, "boom", 500) }, "server answered 500"},
		"forbidden":    {func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 403) }, "server answered 403"},
		"connection dropped": {func(w http.ResponseWriter, r *http.Request) {
			c, _, _ := w.(http.Hijacker).Hijack()
			c.Close()
		}, "request failed"},
		"interrupted": {func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "500")
			w.Write([]byte("short"))
		}, "download interrupted"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			f.setLinux(t, []byte("NEWBINARY"))
			base := f.srv.Config.Handler
			f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/blob/checksums.txt.minisig" {
					tc.serve(w, r)
					return
				}
				base.ServeHTTP(w, r)
			})
			rel, _ := f.client().Latest(context.Background())
			dir := t.TempDir()
			p, err := f.client().Download(context.Background(), rel, "linux", "amd64", dir)
			if err == nil || p != "" {
				t.Fatalf("accepted: %q", p)
			}
			want := "could not download the signature of the release v1.1.0: " + tc.reason + "; nothing was changed"
			if err.Error() != want {
				t.Fatalf("error %q, want %q", err, want)
			}
			if errors.Is(err, ErrNotSigned) {
				t.Fatal("a fetch failure must not look like an unsigned release")
			}
			if strings.Contains(err.Error(), f.srv.URL) {
				t.Fatal("the URL leaked into the message")
			}
			empty(t, dir)
		})
	}
}
