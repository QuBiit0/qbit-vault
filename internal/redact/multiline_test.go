package redact

import (
	"bytes"
	"strings"
	"testing"
)

// pemLike is a multi-line fixture: long lines, one short line ("}").
var pemLines = []string{
	"-----BEGIN TESTSECRET_KEY-----",
	"TESTSECRET_line_one_MIIEvQIBADANBgkqhkiG9w0B",
	"TESTSECRET_line_two_AQEFAASCBKcwggSjAgEAAoIB",
	"}",
	"-----END TESTSECRET_KEY-----",
}

func pemValue(sep string) string { return strings.Join(pemLines, sep) }

func TestMultilineWholeValueTranslatesLineEndings(t *testing.T) {
	cases := map[string]struct{ stored, printed string }{
		"LF value printed CRLF": {pemValue("\n"), pemValue("\r\n")},
		"CRLF value printed LF": {pemValue("\r\n"), pemValue("\n")},
		"LF value printed LF":   {pemValue("\n"), pemValue("\n")},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r := mustNew(t, sec("API_KEY", c.stored))
			out, n := r.Bytes([]byte("before\n" + c.printed + "\nafter"))
			if string(out) != "before\n"+token+"\nafter" || n != 1 {
				t.Fatalf("whole value not replaced as one unit: n=%d", n)
			}
		})
	}
}

func TestMultilineSingleLineAlone(t *testing.T) {
	r := mustNew(t, sec("API_KEY", pemValue("\n")))
	out, n := r.Bytes([]byte("log: " + pemLines[1] + "\n"))
	if string(out) != "log: "+token+"\n" || n != 1 {
		t.Fatalf("middle line alone not redacted: n=%d", n)
	}
	// Trailing CR / indentation around a line does not defeat it.
	out, n = r.Bytes([]byte("  " + pemLines[2] + "\r\n"))
	if string(out) != "  "+token+"\r\n" || n != 1 {
		t.Fatalf("line with CR not redacted: n=%d", n)
	}
}

func TestMultilineInterleavedWithOtherOutput(t *testing.T) {
	r := mustNew(t, sec("API_KEY", pemValue("\n")))
	var b strings.Builder
	for _, l := range pemLines {
		b.WriteString("INFO ")
		b.WriteString(l)
		b.WriteString("\nnoise between lines\n")
	}
	out, n := r.Bytes([]byte(b.String()))
	for _, l := range pemLines {
		if len(strings.TrimSpace(l)) >= 16 && strings.Contains(string(out), l) {
			t.Fatalf("a long line survived (len %d)", len(l))
		}
	}
	if n != 4 {
		t.Fatalf("expected 4 long lines replaced, got %d", n)
	}
	if !strings.Contains(string(out), "INFO }\n") {
		t.Fatal("short line must be left alone")
	}
}

func TestMultilineShortLinesAreNotPatterns(t *testing.T) {
	r := mustNew(t, sec("API_KEY", pemValue("\n")))
	in := []byte("} } }\n-----\nshort line\n123456789012345 (15 bytes above)")
	if out, n := r.Bytes(in); n != 0 || !bytes.Equal(out, in) {
		t.Fatalf("short lines must not match: n=%d", n)
	}
	// Threshold is on the trimmed length: 15 trimmed bytes padded with spaces.
	r = mustNew(t, sec("API_KEY", "  123456789012345  \nTESTSECRET_other_line_long_enough"))
	if _, n := r.Bytes([]byte("123456789012345")); n != 0 {
		t.Fatal("15-byte trimmed line must not be a pattern")
	}
	r = mustNew(t, sec("API_KEY", "  1234567890123456  \nTESTSECRET_other_line_long_enough"))
	if _, n := r.Bytes([]byte("x 1234567890123456 x")); n != 1 {
		t.Fatal("16-byte trimmed line must be a pattern")
	}
}

func TestMultilineChunkedStream(t *testing.T) {
	r := mustNew(t, sec("API_KEY", pemValue("\n")))
	in := []byte("a\n" + pemValue("\r\n") + "\nb " + pemLines[1])
	want, wantN := r.Bytes(in)
	for cut := 0; cut <= len(in); cut++ {
		var dst bytes.Buffer
		w := r.Writer(&dst)
		mustWrite(t, w, in[:cut])
		mustWrite(t, w, in[cut:])
		_ = w.Close()
		if !bytes.Equal(dst.Bytes(), want) || w.Count() != wantN {
			t.Fatalf("split at %d differs", cut)
		}
	}
}
