// Command leakscan looks for fixture values, secret names, project paths and
// device labels in files, in the encodings a leak could take (docs/TESTING.md
// § Tier 2 item 7, R-SYNC-02).
//
// Usage: leakscan -needles FILE PATH...
//
// FILE has one needle per line as "label<TAB>text". A hit is reported as
// "path:offset: label (encoding)"; neither the needle nor the surrounding
// bytes are printed, so the report cannot leak. Exit codes: 0 clean, 1 a hit,
// 2 usage or I/O error. Test tooling only.
package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const minNeedle = 8

type pattern struct {
	label, enc string
	needle     []byte
}

// forms returns the byte strings a needle can show up as.
func forms(label, text string) []pattern {
	var ps []pattern
	add := func(enc string, b []byte) {
		if len(b) >= minNeedle {
			ps = append(ps, pattern{label, enc, b})
		}
	}
	add("raw", []byte(text))
	if q := url.QueryEscape(text); q != text {
		add("percent", []byte(q))
	}
	if q := url.PathEscape(text); q != text {
		add("percent", []byte(q))
	}
	if j, err := json.Marshal(text); err == nil {
		if s := string(j[1 : len(j)-1]); s != text {
			add("json", []byte(s))
		}
	}
	for pad := range 3 {
		raw := append(bytes.Repeat([]byte{0}, pad), text...)
		for _, e := range []struct {
			name string
			enc  *base64.Encoding
		}{{"base64", base64.RawStdEncoding}, {"base64url", base64.RawURLEncoding}} {
			add(fmt.Sprintf("%s@%d", e.name, pad), stable(e.enc, raw, pad))
		}
	}
	return ps
}

// stable keeps the base64 characters that depend only on the needle bytes.
func stable(enc *base64.Encoding, raw []byte, pad int) []byte {
	full := []byte(enc.EncodeToString(raw))
	var out []byte
	for i := range full {
		if 6*i >= 8*pad && 6*i+6 <= 8*len(raw) {
			out = append(out, full[i])
		}
	}
	return out
}

func main() {
	needles := flag.String("needles", "", "file of label<TAB>text needles")
	flag.Parse()
	if *needles == "" || flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: leakscan -needles FILE PATH...")
		os.Exit(2)
	}
	f, err := os.Open(*needles)
	if err != nil {
		fmt.Fprintln(os.Stderr, "leakscan: cannot read the needles file")
		os.Exit(2)
	}
	var ps []pattern
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		label, text, ok := strings.Cut(strings.TrimRight(sc.Text(), "\r"), "\t")
		if !ok || len(text) < minNeedle {
			fmt.Fprintf(os.Stderr, "leakscan: needle %q is missing or shorter than %d bytes\n", label, minNeedle)
			os.Exit(2)
		}
		ps = append(ps, forms(label, text)...)
	}
	f.Close()

	hits, files := 0, 0
	for _, root := range flag.Args() {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			files++
			for _, p := range ps {
				for off := 0; ; {
					i := bytes.Index(data[off:], p.needle)
					if i < 0 {
						break
					}
					fmt.Printf("%s:%d: %s (%s)\n", path, off+i, p.label, p.enc)
					hits++
					off += i + 1
				}
			}
			return nil
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "leakscan: cannot read", root)
			os.Exit(2)
		}
	}
	fmt.Printf("leakscan: %d files, %d hits\n", files, hits)
	if hits > 0 {
		os.Exit(1)
	}
}
