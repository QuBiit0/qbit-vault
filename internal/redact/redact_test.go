package redact

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/secret"
)

// Fixtures use the TESTSECRET_ prefix so a leak in CI output is greppable.
// Failure messages never print fixtures, inputs or outputs: only labels,
// offsets and lengths.
const (
	fixture  = "TESTSECRET_redact_value_0123456789"
	fixtureB = "TESTSECRET_redact_other_9876543210"
)

const token = "[REDACTED:API_KEY]"

func sec(name, value string) secret.Secret { return secret.New(name, []byte(value)) }

func mustNew(t testing.TB, values ...secret.Secret) *Redactor {
	t.Helper()
	r, err := New(values)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

type form struct {
	label string
	text  string
}

// forms lists independent encodings of v, built with the standard library
// rather than this package's encoders.
func forms(v string) []form {
	jsonStd, _ := json.Marshal(v)
	var noHTML bytes.Buffer
	enc := json.NewEncoder(&noHTML)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	fs := []form{
		{"raw", v},
		{"base64 std padded", base64.StdEncoding.EncodeToString([]byte(v))},
		{"base64 std unpadded", base64.RawStdEncoding.EncodeToString([]byte(v))},
		{"base64 url padded", base64.URLEncoding.EncodeToString([]byte(v))},
		{"base64 url unpadded", base64.RawURLEncoding.EncodeToString([]byte(v))},
		{"percent query", url.QueryEscape(v)},
		{"percent query lower", lowerPercent(url.QueryEscape(v))},
		{"percent path", url.PathEscape(v)},
		{"percent path lower", lowerPercent(url.PathEscape(v))},
		{"json", string(jsonStd[1 : len(jsonStd)-1])},
		{"json no html", strings.TrimSuffix(noHTML.String(), "\n")[1 : len(strings.TrimSuffix(noHTML.String(), "\n"))-1]},
	}
	return fs
}

// basicBlobs returns base64 blobs embedding v after every prefix length 0..8
// (all three alignments) in std and URL-safe encodings, padded and not.
func basicBlobs(v string) []form {
	var out []form
	encs := map[string]*base64.Encoding{
		"std": base64.StdEncoding, "std raw": base64.RawStdEncoding,
		"url": base64.URLEncoding, "url raw": base64.RawURLEncoding,
	}
	for name, enc := range encs {
		for pre := 0; pre <= 8; pre++ {
			for post := 0; post < 3; post++ {
				in := strings.Repeat("u", pre) + v + strings.Repeat("p", post)
				out = append(out, form{fmt.Sprintf("blob %s pre=%d post=%d", name, pre, post), enc.EncodeToString([]byte(in))})
			}
		}
	}
	return out
}

func TestEveryEncodingIsReplaced(t *testing.T) {
	r := mustNew(t, sec("API_KEY", fixture))
	for _, f := range forms(fixture) {
		t.Run(f.label, func(t *testing.T) {
			out, n := r.Bytes([]byte("pre " + f.text + " post"))
			if string(out) != "pre "+token+" post" || n != 1 {
				t.Fatalf("not replaced exactly once: n=%d outlen=%d", n, len(out))
			}
		})
	}
}

func TestBasicAuthAlignments(t *testing.T) {
	r := mustNew(t, sec("API_KEY", fixture))
	for _, f := range basicBlobs(fixture) {
		t.Run(f.label, func(t *testing.T) {
			in := "Authorization: Basic " + f.text + "\r\n"
			out, n := r.Bytes([]byte(in))
			if n != 1 || !strings.Contains(string(out), token) {
				t.Fatalf("blob not redacted: n=%d", n)
			}
			// The characters that depend only on the value are gone: what is
			// left of the blob is at most the unstable edges.
			if len(out)-len(token) > len(in)-len(fixture)*8/6+4 {
				t.Fatalf("too much of the blob survived: out=%d in=%d", len(out), len(in))
			}
		})
	}
}

func TestBasicAuthHeaderRealistic(t *testing.T) {
	r := mustNew(t, sec("API_KEY", fixture))
	hdr := "Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("user:"+fixture))
	out, n := r.Bytes([]byte(hdr))
	if n != 1 || !strings.HasPrefix(string(out), "Authorization: Basic ") {
		t.Fatalf("basic auth header: n=%d", n)
	}
	// Nothing of the encoded credential beyond the unstable head and tail.
	if len(out) > len("Authorization: Basic ")+len(token)+8 {
		t.Fatalf("basic auth header kept %d bytes", len(out))
	}
}

func TestShortValueNoInnerBase64(t *testing.T) {
	// L2 applies to values of at least 8 bytes only.
	r := mustNew(t, sec("SHORT", "abcdefg"))
	blob := base64.StdEncoding.EncodeToString([]byte("xxabcdefgxx"))
	if out, n := r.Bytes([]byte(blob)); n != 0 || string(out) != blob {
		t.Fatalf("short value must not match inside a blob: n=%d", n)
	}
}

func TestQuotedValue(t *testing.T) {
	for _, q := range []string{`"`, `'`} {
		inner := "TESTSECRET_quoted_value_42"
		r := mustNew(t, sec("API_KEY", q+inner+q))
		for name, in := range map[string]string{
			"with quotes":     "k=" + q + inner + q,
			"quotes stripped": "k=" + inner,
		} {
			out, n := r.Bytes([]byte(in))
			if n != 1 || !strings.HasPrefix(string(out), "k=") || !strings.Contains(string(out), token) {
				t.Fatalf("%s (%s): n=%d", name, q, n)
			}
			if strings.Contains(string(out), inner) {
				t.Fatalf("%s (%s): inner value survived", name, q)
			}
		}
	}
	// Mismatched quotes are not stripped.
	r := mustNew(t, sec("API_KEY", `"TESTSECRET_mismatch_value_1'`))
	if _, n := r.Bytes([]byte("TESTSECRET_mismatch_value_1")); n != 0 {
		t.Fatal("mismatched quotes must not produce a stripped pattern")
	}
}

func TestChunkBoundaryAtEveryOffset(t *testing.T) {
	r := mustNew(t, sec("API_KEY", fixture))
	all := append(forms(fixture), basicBlobs(fixture)...)
	for _, f := range all {
		in := []byte("xx " + f.text + " yy")
		want, wantN := r.Bytes(in)
		for cut := 0; cut <= len(in); cut++ {
			var dst bytes.Buffer
			w := r.Writer(&dst)
			mustWrite(t, w, in[:cut])
			mustWrite(t, w, in[cut:])
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(dst.Bytes(), want) || w.Count() != wantN {
				t.Fatalf("%s: split at %d differs from whole-buffer result", f.label, cut)
			}
		}
	}
}

func TestOneByteWrites(t *testing.T) {
	r := mustNew(t, sec("API_KEY", fixture))
	all := append(forms(fixture), basicBlobs(fixture)...)
	for _, f := range all {
		in := []byte("a " + f.text + " b " + f.text)
		want, wantN := r.Bytes(in)
		var dst bytes.Buffer
		w := r.Writer(&dst)
		for i := range in {
			mustWrite(t, w, in[i:i+1])
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(dst.Bytes(), want) || w.Count() != wantN || wantN < 2 {
			t.Fatalf("%s: one-byte writes differ (n=%d want=%d)", f.label, w.Count(), wantN)
		}
	}
}

func mustWrite(t testing.TB, w io.Writer, p []byte) {
	t.Helper()
	if n, err := w.Write(p); err != nil || n != len(p) {
		t.Fatalf("write: n=%d err=%v", n, err)
	}
}

func TestOverlappingValuesLongestWins(t *testing.T) {
	long := "TESTSECRET_overlap_abc_and_a_longer_tail"
	short := "TESTSECRET_overlap_abc"
	r := mustNew(t, sec("SHORT_ONE", short), sec("LONG_ONE", long))
	out, n := r.Bytes([]byte("a " + long + " b"))
	if string(out) != "a [REDACTED:LONG_ONE] b" || n != 1 {
		t.Fatalf("longest did not win: n=%d", n)
	}
	out, n = r.Bytes([]byte("a " + short + " b"))
	if string(out) != "a [REDACTED:SHORT_ONE] b" || n != 1 {
		t.Fatalf("short value alone: n=%d", n)
	}

	// Same result through the stream, split at every offset.
	in := []byte("a " + long + " b " + short)
	want, _ := r.Bytes(in)
	for cut := 0; cut <= len(in); cut++ {
		var dst bytes.Buffer
		w := r.Writer(&dst)
		mustWrite(t, w, in[:cut])
		mustWrite(t, w, in[cut:])
		_ = w.Close()
		if !bytes.Equal(dst.Bytes(), want) {
			t.Fatalf("overlap: split at %d differs", cut)
		}
	}
}

func TestOverlapLongerStartsEarlier(t *testing.T) {
	inner := "TESTSECRET_inner_value_77"
	outer := "PREFIX_" + inner + "_SUFFIX"
	r := mustNew(t, sec("INNER", inner), sec("OUTER", outer))
	out, n := r.Bytes([]byte("[" + outer + "]"))
	if string(out) != "[[REDACTED:OUTER]]" || n != 1 {
		t.Fatalf("outer must win when it starts earlier: n=%d", n)
	}
}

func TestAdjacentOccurrences(t *testing.T) {
	r := mustNew(t, sec("API_KEY", fixture))
	out, n := r.Bytes([]byte(fixture + fixture + "-" + fixture))
	if string(out) != token+token+"-"+token || n != 3 {
		t.Fatalf("adjacent: n=%d", n)
	}
}

func TestSharedPrefixValues(t *testing.T) {
	r := mustNew(t, sec("ONE", "TESTSECRET_shared_prefix_one"), sec("TWO", "TESTSECRET_shared_prefix_two"))
	out, n := r.Bytes([]byte("TESTSECRET_shared_prefix_two TESTSECRET_shared_prefix_one TESTSECRET_shared_prefix_"))
	if string(out) != "[REDACTED:TWO] [REDACTED:ONE] TESTSECRET_shared_prefix_" || n != 2 {
		t.Fatalf("shared prefix: n=%d", n)
	}
}

func TestIdenticalValuesFirstNameWins(t *testing.T) {
	r := mustNew(t, sec("FIRST", fixture), sec("SECOND", fixture))
	out, _ := r.Bytes([]byte(fixture))
	if string(out) != "[REDACTED:FIRST]" {
		t.Fatal("first registration should win")
	}
}

func TestShortValueWarnsAndIsStillRedacted(t *testing.T) {
	r := mustNew(t, sec("PIN", "ab1"), sec("SEVEN", "1234567"), sec("EIGHT", "12345678x"), sec("API_KEY", fixture))
	if got := strings.Join(r.Warnings(), ","); got != "PIN,SEVEN" {
		t.Fatalf("warnings = %q", got)
	}
	out, n := r.Bytes([]byte("pin=ab1 seven=1234567"))
	if string(out) != "pin=[REDACTED:PIN] seven=[REDACTED:SEVEN]" || n != 2 {
		t.Fatalf("short values: n=%d", n)
	}
	// A single byte is still redacted.
	r = mustNew(t, sec("ONE_BYTE", "Q"))
	if out, n := r.Bytes([]byte("aQb")); string(out) != "a[REDACTED:ONE_BYTE]b" || n != 1 {
		t.Fatalf("one-byte value: n=%d", n)
	}
	if got := r.Warnings(); len(got) != 1 || got[0] != "ONE_BYTE" {
		t.Fatalf("warnings = %v", got)
	}
}

func TestNoFalsePositives(t *testing.T) {
	r := mustNew(t, sec("API_KEY", fixture), sec("OTHER", fixtureB))
	text := "TESTSECRET_ is just a marker; redact_value_0123456789 alone; dGVzdA== and %41%42 and {\"a\":1}\n" +
		strings.Repeat("lorem ipsum dolor sit amet ", 50)
	out, n := r.Bytes([]byte(text))
	if n != 0 || string(out) != text {
		t.Fatalf("unrelated text changed: n=%d", n)
	}
	if got := r.Warnings(); len(got) != 0 {
		t.Fatalf("unexpected warnings %v", got)
	}
}

func TestEmptyValuesIsPassthrough(t *testing.T) {
	for name, vals := range map[string][]secret.Secret{
		"nil":         nil,
		"empty value": {secret.New("API_KEY", nil)},
		"zero secret": {{}},
		"empty bytes": {secret.New("API_KEY", []byte{})},
		"mixed empty": {sec("API_KEY", ""), {}},
	} {
		t.Run(name, func(t *testing.T) {
			r := mustNew(t, vals...)
			in := []byte("anything at all, including TESTSECRET_x")
			out, n := r.Bytes(in)
			if n != 0 || !bytes.Equal(out, in) {
				t.Fatal("not a passthrough")
			}
			var dst bytes.Buffer
			w := r.Writer(&dst)
			mustWrite(t, w, in)
			if err := w.Close(); err != nil || !bytes.Equal(dst.Bytes(), in) || w.Count() != 0 {
				t.Fatal("stream not a passthrough")
			}
		})
	}
}

func TestInvalidNameIsRejectedWithoutLeaking(t *testing.T) {
	for _, name := range []string{"", "lower", "1ABC", "A-B", strings.Repeat("A", 65)} {
		_, err := New([]secret.Secret{sec(name, fixture)})
		if !errors.Is(err, ErrInvalidName) {
			t.Fatalf("name %q: err = %v", name, err)
		}
		if strings.Contains(err.Error(), fixture) {
			t.Fatal("error leaked the value")
		}
	}
}

func TestWriterCountAndClose(t *testing.T) {
	r := mustNew(t, sec("API_KEY", fixture))
	var dst bytes.Buffer
	w := r.Writer(&dst)
	mustWrite(t, w, []byte("a "+fixture+" b "+fixture[:10]))
	if strings.HasSuffix(dst.String(), fixture[:10]) {
		t.Fatal("held-back tail was emitted before Close")
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if w.Count() != 1 {
		t.Fatalf("count = %d", w.Count())
	}
	if got := dst.String(); got != "a "+token+" b "+fixture[:10] {
		t.Fatalf("Close did not flush the remainder (len %d)", len(got))
	}
	if err := w.Close(); err != nil {
		t.Fatalf("second Close = %v", err)
	}
	if _, err := w.Write([]byte("x")); !errors.Is(err, ErrClosed) {
		t.Fatalf("write after Close = %v", err)
	}
}

func TestWriterDoesNotCloseDestination(t *testing.T) {
	r := mustNew(t, sec("API_KEY", fixture))
	c := &closeSpy{}
	w := r.Writer(c)
	mustWrite(t, w, []byte("hello"))
	if err := w.Close(); err != nil || c.closed {
		t.Fatalf("Close err=%v closedDst=%v", err, c.closed)
	}
	if c.buf.String() != "hello" {
		t.Fatal("remainder not flushed")
	}
}

type closeSpy struct {
	buf    bytes.Buffer
	closed bool
}

func (c *closeSpy) Write(p []byte) (int, error) { return c.buf.Write(p) }
func (c *closeSpy) Close() error                { c.closed = true; return nil }

var errDst = errors.New("destination failed")

type failWriter struct{ after, writes int }

func (f *failWriter) Write(p []byte) (int, error) {
	f.writes++
	if f.writes > f.after {
		return 0, errDst
	}
	return len(p), nil
}

func TestDestinationErrorPropagates(t *testing.T) {
	r := mustNew(t, sec("API_KEY", fixture))
	fw := &failWriter{after: 1}
	w := r.Writer(fw)
	long := bytes.Repeat([]byte("0123456789abcdef"), 16)
	mustWrite(t, w, long)
	if _, err := w.Write(long); !errors.Is(err, errDst) {
		t.Fatalf("expected destination error, got %v", err)
	}
	if _, err := w.Write(long); !errors.Is(err, errDst) {
		t.Fatalf("write after error = %v", err)
	}
	if err := w.Close(); !errors.Is(err, errDst) {
		t.Fatalf("Close after error = %v", err)
	}
	if fw.writes != 2 {
		t.Fatalf("destination written %d times after failing", fw.writes)
	}
}

func TestDestinationErrorOnClose(t *testing.T) {
	r := mustNew(t, sec("API_KEY", fixture))
	w := r.Writer(&failWriter{})
	if _, err := w.Write([]byte("short")); err != nil {
		t.Fatalf("held-back write must not touch the destination: %v", err)
	}
	if err := w.Close(); !errors.Is(err, errDst) {
		t.Fatalf("Close = %v", err)
	}
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) / 2, nil }

func TestShortDestinationWrite(t *testing.T) {
	r := mustNew(t, sec("API_KEY", fixture))
	w := r.Writer(shortWriter{})
	if _, err := w.Write(bytes.Repeat([]byte("z"), 500)); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write = %v", err)
	}
}

func TestNeverPrinted(t *testing.T) {
	r := mustNew(t, sec("API_KEY", fixture))
	w := r.Writer(io.Discard)
	mustWrite(t, w, []byte("pending "+fixture[:12]))
	type holder struct{ R *Redactor }
	var leaks []string
	for _, f := range forms(fixture) {
		leaks = append(leaks, f.text)
	}
	leaks = append(leaks, fixture[:12])
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
		for _, arg := range []any{r, *r, w, *w, holder{r}, &holder{r}, []*Redactor{r}} {
			out := fmt.Sprintf(verb, arg)
			for _, l := range leaks {
				if strings.Contains(out, l) {
					t.Fatalf("verb %s printed pattern bytes", verb)
				}
			}
		}
	}
	if s := r.String(); strings.Contains(s, "TESTSECRET") {
		t.Fatal("String leaked")
	}
}

func TestWipeFailsClosed(t *testing.T) {
	r := mustNew(t, sec("API_KEY", fixture))
	var dst bytes.Buffer
	w := r.Writer(&dst)
	r.Wipe()
	if out, n := r.Bytes([]byte(fixture)); out != nil || n != 0 {
		t.Fatal("wiped Bytes must fail closed")
	}
	if _, err := w.Write([]byte(fixture)); !errors.Is(err, ErrWiped) {
		t.Fatalf("write after Wipe = %v", err)
	}
	if dst.Len() != 0 {
		t.Fatal("wiped writer emitted bytes")
	}
	r.Wipe() // idempotent
	var nilR *Redactor
	nilR.Wipe()
	if out, _ := nilR.Bytes([]byte("x")); out != nil {
		t.Fatal("nil Redactor must fail closed")
	}
}

func TestWipeClearsPatternBytes(t *testing.T) {
	r := mustNew(t, sec("API_KEY", fixture))
	pats := append([]pattern(nil), r.s.pats...)
	r.Wipe()
	for _, p := range pats {
		for _, c := range p.b {
			if c != 0 {
				t.Fatal("pattern bytes survived Wipe")
			}
		}
	}
}

func TestPatternsAreDerivedFromTheValue(t *testing.T) {
	// Guards the construction rules: nothing shorter than 4 bytes except the
	// raw value, no duplicates.
	r := mustNew(t, sec("API_KEY", fixture), sec("PIN", "ab1"))
	seen := map[string]bool{}
	for _, p := range r.s.pats {
		if len(p.b) < minPattern && string(p.b) != "ab1" {
			t.Fatalf("derived pattern shorter than %d bytes", minPattern)
		}
		if seen[string(p.b)] {
			t.Fatal("duplicate pattern")
		}
		seen[string(p.b)] = true
	}
}

// FuzzRedactStream checks that, whatever the value, the surrounding bytes and
// the chunking, the stream output equals the whole-buffer output and never
// contains the value in a modeled encoding.
//
// Encodings are checked only when at least minPattern bytes long: shorter
// derived patterns are dropped on purpose because they would match
// constantly. The value embedded inside a larger base64 blob is covered by
// the L2 inner-substring patterns only for values of at least ShortLen bytes
// (odd/tasks/redact.md L2), so this target embeds whole-value encodings and
// asserts on those; blob embedding is covered by TestBasicAuthAlignments.
func FuzzRedactStream(f *testing.F) {
	f.Add([]byte(fixture), []byte("pre "), []byte(" post"), []byte{3, 1, 7}, uint8(0))
	f.Add([]byte("a"), []byte("aaa"), []byte("a"), []byte{1}, uint8(1))
	f.Add([]byte("p@ss w/rd<&>\"\\"), []byte("x"), []byte("y"), []byte{2, 2}, uint8(5))
	f.Add([]byte("é😀\xff\x00\n"), []byte{}, []byte{}, []byte{1, 5}, uint8(9))
	f.Add([]byte("ab"), []byte("[REDACTED:"), []byte("]"), []byte{4}, uint8(2))
	f.Fuzz(func(t *testing.T, value, pre, post, cuts []byte, pick uint8) {
		if len(value) == 0 {
			t.Skip()
		}
		r, err := New([]secret.Secret{secret.New("API_KEY", value)})
		if err != nil {
			t.Fatal(err)
		}
		v := string(value)
		fs := fuzzForms(v)
		embedded := fs[int(pick)%len(fs)]
		input := []byte(string(pre) + embedded + string(post) + v)

		want, wantN := r.Bytes(input)

		var dst bytes.Buffer
		w := r.Writer(&dst)
		rest := input
		for i := 0; len(rest) > 0; i++ {
			size := len(rest)
			if len(cuts) > 0 {
				size = int(cuts[i%len(cuts)])%17 + 1
			}
			if size > len(rest) {
				size = len(rest)
			}
			mustWrite(t, w, rest[:size])
			rest = rest[size:]
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(dst.Bytes(), want) || w.Count() != wantN {
			t.Fatal("stream output differs from whole-buffer output")
		}

		// Split on the token so bytes of the token itself cannot count as
		// a leak of a short value.
		for _, seg := range strings.Split(dst.String(), token) {
			for _, f := range fs {
				if f != v && len(f) < minPattern {
					continue
				}
				if strings.Contains(seg, f) {
					t.Fatalf("a modeled encoding of the value survived (len %d)", len(f))
				}
			}
		}
	})
}

func fuzzForms(v string) []string {
	var out []string
	for _, f := range forms(v) {
		out = append(out, f.text)
		if f.label == "json" {
			out = append(out, strings.ReplaceAll(f.text, "/", `\/`))
		}
	}
	if strings.Contains(v, "\n") && !strings.Contains(v, "\r\n") {
		out = append(out, strings.ReplaceAll(v, "\n", "\r\n"))
	}
	return out
}
