package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixtureMarker is assembled at runtime so that this package's own test output
// and sources never contain the raw fixture prefix.
var fixtureMarker = "TESTSECRET" + "_"

func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func runMain(args ...string) (code int, stdout, stderr string) {
	var out, errb bytes.Buffer
	code = run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestDetectsEncodings(t *testing.T) {
	cases := map[string][]byte{
		"raw":             []byte("log line " + fixtureMarker + "abc"),
		"percent-encoded": []byte("q=" + "TESTSECRET" + "%5F" + "abc"),
		"json-escaped":    []byte(`{"v":"` + "TESTSECRET" + `\u005f` + `abc"}`),
	}
	for pad := 0; pad < 3; pad++ {
		raw := append(bytes.Repeat([]byte{'x'}, pad), []byte(fixtureMarker+"suffix-value")...)
		cases["base64-std pad "+string(rune('0'+pad))] = []byte(base64.StdEncoding.EncodeToString(raw))
		cases["base64-url pad "+string(rune('0'+pad))] = []byte(base64.URLEncoding.EncodeToString(raw))
		// Embedded in unrelated surrounding base64 text.
		cases["base64-std embedded pad "+string(rune('0'+pad))] = []byte("AAAA" + base64.StdEncoding.EncodeToString(raw) + "BBBB")
	}
	// Alignments with a different surrounding byte, to prove the match does
	// not depend on neighbouring bytes.
	for _, prefix := range []string{"a", "ab", "abc", "\x00", "\xff\xfe"} {
		raw := []byte(prefix + fixtureMarker + "\xff\xff")
		cases["base64-std prefix "+prefix] = []byte(base64.StdEncoding.EncodeToString(raw))
		cases["base64-url prefix "+prefix] = []byte(base64.URLEncoding.EncodeToString(raw))
	}

	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			p := writeFile(t, dir, "out.log", data)
			code, out, errs := runMain(p)
			if code != 1 {
				t.Fatalf("exit = %d, want 1", code)
			}
			if !strings.HasPrefix(out, p+":") || errs != "" {
				t.Fatalf("unexpected report shape (len %d, stderr len %d)", len(out), len(errs))
			}
			if strings.Contains(out, fixtureMarker) {
				t.Fatal("report echoes the fixture")
			}
		})
	}
}

func TestReportsOffsetAndEncoding(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "out.log", []byte("0123456789"+fixtureMarker+"x"))
	_, out, _ := runMain(p)
	if want := p + ":10: raw\n"; out != want {
		t.Fatalf("report = %q", out)
	}
}

func TestCleanInput(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.log", []byte("PASS\nok  github.com/qbitdevz/qbit-vault 0.1s\n"))
	writeFile(t, dir, "sub/b.log", []byte("TESTSECRET without underscore, and a 40 byte base64 free text"))
	code, out, errs := runMain(dir)
	if code != 0 || out != "" || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
}

func TestRecursion(t *testing.T) {
	dir := t.TempDir()
	deep := writeFile(t, dir, "a/b/c/deep.log", []byte(fixtureMarker+"v"))
	writeFile(t, dir, "clean.log", []byte("nothing"))
	code, out, _ := runMain(dir)
	if code != 1 || !strings.HasPrefix(out, deep+":0: ") {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

func TestMultipleHitsAndPaths(t *testing.T) {
	dir := t.TempDir()
	a := writeFile(t, dir, "a.log", []byte(fixtureMarker+" "+fixtureMarker))
	b := writeFile(t, dir, "b.log", []byte("clean"))
	code, out, _ := runMain(a, b)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if code != 1 || len(lines) != 2 {
		t.Fatalf("code=%d lines=%d", code, len(lines))
	}
}

func TestUsageAndMissingPath(t *testing.T) {
	if code, _, errs := runMain(); code != 2 || errs == "" {
		t.Fatalf("no args: code=%d", code)
	}
	missing := filepath.Join(t.TempDir(), "nope")
	if code, _, errs := runMain(missing); code != 2 || errs == "" {
		t.Fatalf("missing path: code=%d", code)
	}
}
