// Command leakgrep scans files for the TESTSECRET_ fixture marker in the
// encodings a leak could take (docs/TESTING.md § Leak battery).
//
// Usage: leakgrep PATH...
//
// Exit codes: 0 clean, 1 at least one hit, 2 usage or I/O error. A hit is
// reported as "path:byte-offset: encoding"; the surrounding bytes are never
// printed, so the report itself cannot leak.
package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// The marker is split so this source file does not contain the raw fixture
// prefix itself.
const marker = "TESTSECRET" + "_"

type pattern struct {
	label  string
	needle []byte
}

// patterns returns every needle to search for.
func patterns() []pattern {
	ps := []pattern{
		{"raw", []byte(marker)},
		{"percent-encoded", []byte("TESTSECRET" + "%5F")},
		{"percent-encoded", []byte("TESTSECRET" + "%5f")},
		{"json-escaped", []byte("TESTSECRET" + `\u005f`)},
		{"json-escaped", []byte("TESTSECRET" + `\u005F`)},
	}
	for pad := 0; pad < 3; pad++ {
		raw := append(bytes.Repeat([]byte{0}, pad), marker...)
		for _, e := range []struct {
			label string
			enc   *base64.Encoding
		}{
			{"base64-std", base64.RawStdEncoding},
			{"base64-url", base64.RawURLEncoding},
		} {
			ps = append(ps, pattern{fmt.Sprintf("%s (alignment %d)", e.label, pad), stableBase64(e.enc, raw, pad)})
		}
	}
	return ps
}

// stableBase64 returns the characters of enc(raw) that depend only on the
// marker bytes (those after the first pad bytes), so they appear verbatim
// wherever the marker is embedded at that alignment, whatever its neighbours.
func stableBase64(enc *base64.Encoding, raw []byte, pad int) []byte {
	full := []byte(enc.EncodeToString(raw))
	startBit, endBit := 8*pad, 8*len(raw)
	var out []byte
	for i := range full {
		if 6*i >= startBit && 6*i+6 <= endBit {
			out = append(out, full[i])
		}
	}
	return out
}

// scanBytes writes one line per occurrence of any pattern in data.
func scanBytes(path string, data []byte, ps []pattern, w io.Writer) int {
	hits := 0
	for _, p := range ps {
		for off := 0; ; {
			i := bytes.Index(data[off:], p.needle)
			if i < 0 {
				break
			}
			fmt.Fprintf(w, "%s:%d: %s\n", path, off+i, p.label)
			hits++
			off += i + 1
		}
	}
	return hits
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: leakgrep PATH...")
		return 2
	}
	ps := patterns()
	hits := 0
	for _, root := range args {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			hits += scanBytes(path, data, ps, stdout)
			return nil
		})
		if err != nil {
			fmt.Fprintf(stderr, "leakgrep: %v\n", err)
			return 2
		}
	}
	if hits > 0 {
		return 1
	}
	return 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
