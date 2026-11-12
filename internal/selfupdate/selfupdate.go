// Package selfupdate brings an installed qbit-vault to the latest release
// (docs/CLI.md `update`, docs/INSTALL.md § Self-update). It looks up the
// release the way the installers do, downloads the archive for this OS and
// architecture, verifies its SHA-256 against checksums.txt and swaps the
// binary. It never touches the vault and never reads a secret.
package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/qbitdevz/qbit-vault/internal/minisign"
)

// Default limits: the archive of a release is a few megabytes.
const (
	defaultMaxArchive   = 200 << 20
	defaultMaxChecksums = 1 << 20
	maxBinary           = 400 << 20
	maxSignature        = 16 << 10
	maxAPIBody          = 8 << 20
	apiTimeout          = 20 * time.Second
	downloadTimeout     = 10 * time.Minute
	maxRedirects        = 5
)

// Release is the release the lookup picked.
type Release struct {
	Tag    string
	URL    string            // release notes page
	Assets map[string]string // asset name -> download URL
}

// Client talks to the releases API and the asset hosts, over HTTPS only (plain
// HTTP only for a loopback host, for tests).
type Client struct {
	HTTP         *http.Client
	UserAgent    string
	API          string
	MaxArchive   int64
	MaxChecksums int64
	// Key verifies checksums.txt.minisig. Nil means the release key pinned in
	// the binary; only tests set it, with a throwaway key.
	Key *minisign.PublicKey
}

// NewClient returns a client for api (the releases API URL) that identifies
// itself as qbit-vault/<version>.
func NewClient(version, api string) *Client {
	return &Client{
		HTTP: &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return errors.New("too many redirects")
			}
			return allowedURL(req.URL)
		}},
		UserAgent:    "qbit-vault/" + version,
		API:          api,
		MaxArchive:   defaultMaxArchive,
		MaxChecksums: defaultMaxChecksums,
	}
}

// allowedURL accepts https, and http only for a loopback host.
func allowedURL(u *url.URL) error {
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return errors.New("only https URLs are allowed")
}

var semverRE = regexp.MustCompile(`^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$`)

// pseudoRE matches the tail of a Go pseudo-version.
var pseudoRE = regexp.MustCompile(`(^|\.)\d{14}-[0-9a-f]{12}$`)

type version struct {
	major, minor, patch int
	pre                 []string
}

func parse(v string) (version, bool) {
	m := semverRE.FindStringSubmatch(v)
	if m == nil {
		return version{}, false
	}
	if m[4] != "" && pseudoRE.MatchString(m[4]) {
		return version{}, false
	}
	var out version
	for i, p := range []*int{&out.major, &out.minor, &out.patch} {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return version{}, false
		}
		*p = n
	}
	if m[4] != "" {
		out.pre = strings.Split(m[4], ".")
	}
	return out, true
}

// IsRelease reports whether v names a published release: a plain semantic
// version, not a dev build, a dirty build or a pseudo-version.
func IsRelease(v string) bool {
	_, ok := parse(v)
	return ok
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func cmpPre(a, b []string) int {
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) == 0:
		return 1 // a release is newer than its pre-releases
	case len(b) == 0:
		return -1
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		an, aerr := strconv.Atoi(a[i])
		bn, berr := strconv.Atoi(b[i])
		var c int
		switch {
		case aerr == nil && berr == nil:
			c = cmpInt(an, bn)
		case aerr == nil:
			c = -1 // numeric identifiers sort before the others
		case berr == nil:
			c = 1
		default:
			c = strings.Compare(a[i], b[i])
		}
		if c != 0 {
			return c
		}
	}
	return cmpInt(len(a), len(b))
}

// Newer reports whether latest is a newer release than current.
func Newer(current, latest string) (bool, error) {
	c, ok := parse(current)
	if !ok {
		return false, errors.New("the running version is not a release")
	}
	l, ok := parse(latest)
	if !ok {
		return false, errors.New("the latest release has no semantic version")
	}
	for _, d := range []int{cmpInt(l.major, c.major), cmpInt(l.minor, c.minor), cmpInt(l.patch, c.patch), cmpPre(l.pre, c.pre)} {
		if d != 0 {
			return d > 0, nil
		}
	}
	return false, nil
}

// ArchiveName is the release asset for an OS and architecture, the name the
// installers download.
func ArchiveName(goos, goarch string) string {
	if goos == "windows" {
		return "qbit-vault_" + goos + "_" + goarch + ".zip"
	}
	return "qbit-vault_" + goos + "_" + goarch + ".tar.gz"
}

// BinaryName is the executable inside the archive.
func BinaryName(goos string) string {
	if goos == "windows" {
		return "qbit-vault.exe"
	}
	return "qbit-vault"
}

type apiRelease struct {
	Tag         string `json:"tag_name"`
	Draft       bool   `json:"draft"`
	Prerelease  bool   `json:"prerelease"`
	PublishedAt string `json:"published_at"`
	HTMLURL     string `json:"html_url"`
	Assets      []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

func (r apiRelease) usable() bool {
	return !r.Draft && !r.Prerelease && r.PublishedAt != "" && IsRelease(r.Tag)
}

func (r apiRelease) release() Release {
	out := Release{Tag: r.Tag, URL: r.HTMLURL, Assets: map[string]string{}}
	for _, a := range r.Assets {
		out.Assets[a.Name] = a.URL
	}
	return out
}

var errTooLarge = errors.New("response is larger than allowed")

// statusError is a non-200 answer; a 404 is told apart from the other
// failures (a release without a signature file vs a download that failed).
type statusError int

func (e statusError) Error() string { return fmt.Sprintf("server answered %d", int(e)) }

func (c *Client) get(ctx context.Context, raw string, limit int64, accept string) ([]byte, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("invalid URL")
	}
	if err := allowedURL(u); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, errors.New("invalid URL")
	}
	req.Header.Set("User-Agent", c.UserAgent)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		// The URL error text can carry the whole URL; say only what failed.
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, errors.New("timed out")
		}
		return nil, errors.New("request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, statusError(resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, errors.New("download interrupted")
	}
	if int64(len(b)) > limit {
		return nil, errTooLarge
	}
	return b, nil
}

// Latest picks the release the installers would: the API answers either one
// release (/releases/latest) or a list, from which the newest published
// non-draft, non-prerelease is taken. A prerelease is never chosen.
func (c *Client) Latest(ctx context.Context) (Release, error) {
	ctx, cancel := context.WithTimeout(ctx, apiTimeout)
	defer cancel()
	body, err := c.get(ctx, c.API, maxAPIBody, "application/vnd.github+json")
	if err != nil {
		return Release{}, fmt.Errorf("could not query the releases: %w", err)
	}
	var list []apiRelease
	if bytes.HasPrefix(bytes.TrimSpace(body), []byte("[")) {
		if json.Unmarshal(body, &list) != nil {
			return Release{}, errors.New("the releases answer is not valid")
		}
	} else {
		var one apiRelease
		if json.Unmarshal(body, &one) != nil {
			return Release{}, errors.New("the releases answer is not valid")
		}
		list = []apiRelease{one}
	}
	var best *apiRelease
	var bestAt time.Time
	for i := range list {
		r := &list[i]
		if !r.usable() {
			continue
		}
		at, err := time.Parse(time.RFC3339, r.PublishedAt)
		if err != nil {
			continue
		}
		if best == nil || at.After(bestAt) {
			best, bestAt = r, at
		}
	}
	if best == nil {
		return Release{}, errors.New("no release found")
	}
	return best.release(), nil
}

// ErrNotSigned matches (errors.Is) the Download error of a release whose
// checksums.txt has no valid signature from the pinned key.
var ErrNotSigned = errors.New("not signed with the QBit Vault release key")

type notSignedError struct{ tag string }

func (e notSignedError) Error() string {
	return "the release " + e.tag + " is not signed with the QBit Vault release key; nothing was changed"
}

func (notSignedError) Is(target error) bool { return target == ErrNotSigned }

func notSigned(tag string) error { return notSignedError{tag} }

// sigFetchError is a signature file that could not be downloaded: the
// release may well be signed, so this is not ErrNotSigned. Nothing is
// installed and there is no fallback to the SHA-256 alone.
type sigFetchError struct{ tag, reason string }

func (e sigFetchError) Error() string {
	return "could not download the signature of the release " + e.tag + ": " + e.reason + "; nothing was changed"
}

// verifySignature checks checksums.txt.minisig of rel against sums with the
// pinned key. A missing, oversized or invalid signature is the "not signed"
// refusal; one that could not be downloaded says so.
func (c *Client) verifySignature(ctx context.Context, rel Release, sums []byte) error {
	key := c.Key
	if key == nil {
		var err error
		if key, err = minisign.ReleaseKey(); err != nil {
			return notSigned(rel.Tag)
		}
	}
	sigURL, ok := rel.Assets["checksums.txt.minisig"]
	if !ok {
		return notSigned(rel.Tag)
	}
	sig, err := c.get(ctx, sigURL, maxSignature, "")
	if err != nil {
		if se, ok := err.(statusError); ok && se == http.StatusNotFound {
			return notSigned(rel.Tag)
		}
		if errors.Is(err, errTooLarge) {
			return notSigned(rel.Tag)
		}
		return sigFetchError{rel.Tag, err.Error()}
	}
	if _, err := minisign.Verify(key, sums, sig); err != nil {
		return notSigned(rel.Tag)
	}
	return nil
}

// Download fetches and verifies the archive of rel and writes the binary to a
// new temp file in dir. The caller owns the returned path; on any error
// nothing is left behind.
func (c *Client) Download(ctx context.Context, rel Release, goos, goarch, dir string) (string, error) {
	archive := ArchiveName(goos, goarch)
	archiveURL, ok := rel.Assets[archive]
	if !ok {
		return "", fmt.Errorf("release %s has no %s", rel.Tag, archive)
	}
	sumsURL, ok := rel.Assets["checksums.txt"]
	if !ok {
		return "", fmt.Errorf("release %s has no checksums.txt", rel.Tag)
	}
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()
	maxA, maxC := c.MaxArchive, c.MaxChecksums
	if maxA <= 0 {
		maxA = defaultMaxArchive
	}
	if maxC <= 0 {
		maxC = defaultMaxChecksums
	}
	data, err := c.get(ctx, archiveURL, maxA, "")
	if err != nil {
		return "", fmt.Errorf("could not download %s: %w", archive, err)
	}
	sums, err := c.get(ctx, sumsURL, maxC, "")
	if err != nil {
		return "", fmt.Errorf("could not download checksums.txt: %w", err)
	}
	want := checksumFor(string(sums), archive)
	if want == "" {
		return "", fmt.Errorf("%s is not listed in checksums.txt", archive)
	}
	got := sha256.Sum256(data)
	if !strings.EqualFold(want, hex.EncodeToString(got[:])) {
		return "", fmt.Errorf("checksum mismatch for %s: nothing was installed", archive)
	}
	if err := c.verifySignature(ctx, rel, sums); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(dir, ".qbit-vault.update-*")
	if err != nil {
		return "", errors.New("could not create a temp file next to the binary")
	}
	name := tmp.Name()
	if err := extract(data, archive, BinaryName(goos), tmp); err != nil {
		tmp.Close()
		os.Remove(name)
		return "", err
	}
	// Flush to disk before the swap: a power loss must not leave a truncated
	// binary behind the renamed name.
	if err := syncFile(tmp); err != nil {
		tmp.Close()
		os.Remove(name)
		return "", errors.New("could not write the new binary")
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return "", errors.New("could not write the new binary")
	}
	return name, nil
}

// checksumFor reads the sha256sum-format line of name: "<hex>  <name>".
func checksumFor(sums, name string) string {
	for _, line := range strings.Split(sums, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name && len(f[0]) == 64 {
			return f[0]
		}
	}
	return ""
}

var errNoBinary = errors.New("the archive has no qbit-vault binary")

// extract copies the entry called bin out of an in-memory archive.
func extract(data []byte, archive, bin string, dst io.Writer) error {
	if strings.HasSuffix(archive, ".zip") {
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return errors.New("the archive is not valid")
		}
		for _, f := range zr.File {
			if path.Base(f.Name) != bin || f.FileInfo().IsDir() {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				return errors.New("the archive is not valid")
			}
			defer rc.Close()
			return copyBinary(dst, rc)
		}
		return errNoBinary
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return errors.New("the archive is not valid")
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return errNoBinary
		}
		if err != nil {
			return errors.New("the archive is not valid")
		}
		if h.Typeflag == tar.TypeReg && path.Base(h.Name) == bin {
			return copyBinary(dst, tr)
		}
	}
}

func copyBinary(dst io.Writer, src io.Reader) error {
	n, err := io.Copy(dst, io.LimitReader(src, maxBinary+1))
	switch {
	case err != nil:
		return errors.New("the archive is not valid")
	case n > maxBinary:
		return errors.New("the binary in the archive is larger than allowed")
	case n == 0:
		return errNoBinary
	}
	return nil
}

// Seams for the tests: flushing the new binary and the directory entry.
var (
	syncFile = func(f *os.File) error { return f.Sync() }
	syncDir  = func(dir string) error {
		d, err := os.Open(dir)
		if err != nil {
			return err
		}
		defer d.Close()
		return d.Sync()
	}
)

// CanReplace reports whether a file can be created in dir, which is what a
// swap needs. It leaves nothing behind.
func CanReplace(dir string) error {
	f, err := os.CreateTemp(dir, ".qbit-vault.probe-*")
	if err != nil {
		return err
	}
	name := f.Name()
	f.Close()
	return os.Remove(name)
}

// Replace swaps newFile in as target and consumes newFile. POSIX renames it
// over the target. Windows cannot overwrite a running executable but can
// rename it: the old binary moves to <target>.old-<8 hex> (CleanOld removes
// it on a later run) and goes back if the new one cannot be moved in.
func Replace(target, newFile, goos string) error {
	if goos != "windows" {
		if err := os.Chmod(newFile, 0o755); err != nil {
			return err
		}
		if err := os.Rename(newFile, target); err != nil {
			return err
		}
		// Best effort: the swap is done, this only makes the new directory
		// entry durable.
		_ = syncDir(filepath.Dir(target))
		return nil
	}
	var id [4]byte
	if _, err := rand.Read(id[:]); err != nil {
		return err
	}
	old := target + ".old-" + hex.EncodeToString(id[:])
	if err := os.Rename(target, old); err != nil {
		return err
	}
	if err := os.Rename(newFile, target); err != nil {
		os.Rename(old, target)
		return err
	}
	return nil
}

// CleanOld removes the aside copies a Windows upgrade left next to target.
// Failures are ignored: one may still be running.
func CleanOld(target string) {
	dir, base := filepath.Split(target)
	es, _ := os.ReadDir(filepath.Clean(dir))
	for _, e := range es {
		if strings.HasPrefix(e.Name(), base+".old") {
			os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}
