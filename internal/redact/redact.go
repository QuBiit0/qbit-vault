// Package redact replaces secret values, and their common encodings, with
// [REDACTED:NAME] in byte buffers and streams (docs/PRD.md § 5.5).
//
// The package is pure: it imports neither the vault nor the audit log. Short
// values are reported through Warnings so the caller can audit them.
//
// Matching is leftmost-longest: scanning left to right, at the first
// position where any pattern matches, the longest matching pattern wins.
// Candidates are looked up by first byte, so the cost is roughly one table
// lookup per input byte plus a prefix compare per candidate. With 16 secrets
// (about 20 patterns each) a first byte has a handful of candidates, so this
// stays linear in the input; see BenchmarkRedact.
//
// Modeled encodings per value: raw; the value with matching surrounding
// quotes stripped; base64 (standard and URL-safe, padded and unpadded);
// percent-encoding (query, path and strict flavors, upper and lower hex);
// JSON string bodies (with and without HTML escaping, with and without
// ASCII-only escaping, upper and lower hex); UTF-16LE and UTF-16BE (PowerShell
// 5.1 redirection, no BOM needed); and, for values of at least 8
// bytes, the stable inner base64 substring at each of the three byte
// alignments, so a value embedded in a larger base64 blob (HTTP Basic
// credentials) is still found.
package redact

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"regexp"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/QuBiit0/qbit-vault/internal/secret"
)

// ShortLen is the length below which a value is reported by Warnings.
const ShortLen = 8

// minPattern is the shortest derived pattern kept; shorter ones would match
// constantly. The raw value itself is always kept.
const minPattern = 4

// minLine is the shortest trimmed line of a multi-line value kept as its own
// pattern.
const minLine = 16

var (
	// ErrInvalidName is returned by New for a secret whose name is not valid.
	ErrInvalidName = errors.New("redact: invalid secret name")
	// ErrWiped is returned when a wiped Redactor is used.
	ErrWiped = errors.New("redact: redactor wiped")
	// ErrClosed is returned by writes to a closed StreamWriter.
	ErrClosed = errors.New("redact: writer closed")
)

// nameRE mirrors the vault's secret name rule. It is duplicated on purpose:
// this package must not import the vault.
var nameRE = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

type pattern struct {
	b   []byte
	tok int // index into state.toks
}

type state struct {
	pats     []pattern
	toks     [][]byte
	first    [256][]int // pattern indices by first byte, longest first
	maxLen   int
	warnings []string
	wiped    bool
}

// Redactor replaces the registered secrets in buffers and streams. It holds
// the secret bytes and their encodings; call Wipe when the grant ends. It is
// safe for concurrent use only if no Wipe races with a use.
type Redactor struct {
	s *state
}

// New builds a Redactor for values. Empty values are skipped. A non-empty
// value with an invalid name is an error that mentions the name only.
func New(values []secret.Secret) (*Redactor, error) {
	s := &state{}
	for _, sec := range values {
		if sec.Len() == 0 {
			continue
		}
		name := sec.Name()
		if !nameRE.MatchString(name) {
			s.wipe()
			return nil, fmt.Errorf("%w: %q", ErrInvalidName, name)
		}
		v := sec.Reveal()
		s.addSecret(name, v)
		clear(v)
		if len(v) < ShortLen && !contains(s.warnings, name) {
			s.warnings = append(s.warnings, name)
		}
	}
	s.index()
	return &Redactor{s: s}, nil
}

func contains(list []string, x string) bool {
	for _, y := range list {
		if y == x {
			return true
		}
	}
	return false
}

// add registers b (taking ownership) unless it is too short or a duplicate.
// The first registration of identical bytes wins.
func (s *state) add(b []byte, tok int, exempt bool) {
	if len(b) == 0 || (len(b) < minPattern && !exempt) {
		clear(b)
		return
	}
	for _, p := range s.pats {
		if bytes.Equal(p.b, b) {
			clear(b)
			return
		}
	}
	s.pats = append(s.pats, pattern{b: b, tok: tok})
}

func (s *state) addSecret(name string, v []byte) {
	tok := len(s.toks)
	s.toks = append(s.toks, []byte("[REDACTED:"+name+"]"))

	bases := [][]byte{append([]byte(nil), v...)}
	s.add(append([]byte(nil), v...), tok, true)
	if n := len(v); n >= 2 && (v[0] == '"' || v[0] == '\'') && v[n-1] == v[0] {
		bases = append(bases, append([]byte(nil), v[1:n-1]...))
		s.add(append([]byte(nil), v[1:n-1]...), tok, false)
	}
	if bytes.IndexByte(v, '\n') >= 0 {
		// Same value with the other line-ending convention.
		var alt []byte
		if bytes.Contains(v, []byte("\r\n")) {
			alt = bytes.ReplaceAll(v, []byte("\r\n"), []byte("\n"))
		} else {
			alt = bytes.ReplaceAll(v, []byte("\n"), []byte("\r\n"))
		}
		s.add(append([]byte(nil), alt...), tok, false)
		bases = append(bases, alt)
		// Each long line on its own: the value printed line by line or
		// re-wrapped. The 16-byte threshold keeps lines like "}" out.
		for _, line := range bytes.Split(v, []byte("\n")) {
			if line = bytes.TrimSpace(line); len(line) >= minLine {
				s.add(append([]byte(nil), line...), tok, false)
			}
		}
	}
	for _, b := range bases {
		s.addEncodings(b, tok)
		clear(b)
	}

	if len(v) >= ShortLen {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
			for align := 0; align < 3; align++ {
				s.add(innerBase64(enc, v, align), tok, false)
			}
		}
	}
}

func (s *state) addEncodings(b []byte, tok int) {
	// Windows PowerShell 5.1 writes redirected text as UTF-16LE; BE is its twin.
	// A BOM before the value is not needed to match.
	for _, be := range []bool{false, true} {
		s.add(utf16Form(b, be), tok, false)
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
		s.add(b64(enc, b), tok, false)
		s.add(b64(enc.WithPadding(base64.NoPadding), b), tok, false)
	}
	for _, mode := range []pctMode{pctQuery, pctPath, pctStrict, pctPython, pctJS} {
		for _, lower := range []bool{false, true} {
			s.add(percent(b, mode, lower), tok, false)
		}
	}
	// Encoders disagree on invalid UTF-8 next to literal non-ASCII text: Go
	// 1.26 escapes the replacement character, Go 1.27 writes it as is, so a
	// value with an invalid byte also gets the escaped form of the literal one.
	invalid := []bool{false}
	if !utf8.Valid(b) {
		invalid = append(invalid, true)
	}
	for _, html := range []bool{false, true} {
		for _, ascii := range []bool{false, true} {
			for _, upper := range []bool{false, true} {
				for _, inv := range invalid {
					if ascii && inv {
						continue // the ASCII form already escapes it
					}
					j := jsonEscapeInvalid(b, html, ascii, upper, inv)
					if bytes.IndexByte(j, '/') >= 0 {
						s.add(escapeSlashes(j), tok, false)
					}
					s.add(j, tok, false)
				}
			}
		}
	}
}

// index builds the first-byte table, longest candidates first.
func (s *state) index() {
	for i, p := range s.pats {
		if len(p.b) > s.maxLen {
			s.maxLen = len(p.b)
		}
		c := p.b[0]
		list := append(s.first[c], i)
		// Insertion sort by length, descending; lists are tiny.
		for j := len(list) - 1; j > 0 && len(s.pats[list[j]].b) > len(s.pats[list[j-1]].b); j-- {
			list[j], list[j-1] = list[j-1], list[j]
		}
		s.first[c] = list
	}
}

func (s *state) wipe() {
	for _, p := range s.pats {
		clear(p.b)
	}
	s.pats = nil
	s.first = [256][]int{}
	s.maxLen = 0
	s.wiped = true
}

// scan redacts buf. Unless final, it stops at the first position where a
// longer pattern could still complete beyond the end of buf, and reports how
// many bytes were consumed; the caller keeps buf[consumed:] for the next
// call. It appends the redacted output to out and returns the replacement
// count.
func (s *state) scan(buf []byte, final bool, out []byte) (res []byte, consumed, n int) {
	i, run := 0, 0
	for i < len(buf) {
		if !final && i+s.maxLen > len(buf) {
			break
		}
		cands := s.first[buf[i]]
		hit := -1
		for _, pi := range cands {
			if bytes.HasPrefix(buf[i:], s.pats[pi].b) {
				hit = pi
				break
			}
		}
		if hit < 0 {
			i++
			continue
		}
		out = append(out, buf[run:i]...)
		out = append(out, s.toks[s.pats[hit].tok]...)
		i += len(s.pats[hit].b)
		run = i
		n++
	}
	out = append(out, buf[run:i]...)
	return out, i, n
}

// Warnings returns the names of values shorter than ShortLen bytes. They are
// still redacted, but short secrets cause false positives (R-RED-03); the
// caller audits the warning.
func (r *Redactor) Warnings() []string {
	if r == nil || r.s == nil {
		return nil
	}
	return append([]string(nil), r.s.warnings...)
}

// Bytes redacts a whole buffer and returns a new slice plus the number of
// replacements. A wiped Redactor fails closed: it returns nil, 0.
func (r *Redactor) Bytes(in []byte) (out []byte, n int) {
	if r == nil || r.s == nil || r.s.wiped {
		return nil, 0
	}
	out, _, n = r.s.scan(in, true, make([]byte, 0, len(in)))
	return out, n
}

// Wipe zeroes every pattern. Uses after Wipe fail closed.
func (r *Redactor) Wipe() {
	if r != nil && r.s != nil {
		r.s.wipe()
	}
}

// String implements fmt.Stringer; it never prints patterns.
func (r *Redactor) String() string { return r.describe() }

// GoString implements fmt.GoStringer.
func (r *Redactor) GoString() string { return r.describe() }

// Format implements fmt.Formatter for every verb.
func (r Redactor) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, r.describe()) }

func (r Redactor) describe() string {
	if r.s == nil {
		return "redact.Redactor{}"
	}
	return fmt.Sprintf("redact.Redactor{patterns: %d}", len(r.s.pats))
}

// StreamWriter redacts everything written to it and forwards the result to
// the destination. It holds back up to maxPatternLen-1 bytes between writes
// so a pattern split across writes is still found, and never emits bytes
// that could be the start of a pattern still completing. Close flushes the
// remainder. Not safe for concurrent use.
type StreamWriter struct {
	r     *Redactor
	dst   io.Writer
	buf   []byte
	out   []byte
	count int
	err   error
}

// Writer returns a StreamWriter that forwards redacted bytes to dst.
func (r *Redactor) Writer(dst io.Writer) *StreamWriter {
	return &StreamWriter{r: r, dst: dst}
}

// Count returns the number of replacements made so far.
func (w *StreamWriter) Count() int { return w.count }

// Write redacts p. It reports len(p) on success; after any error, all
// further writes fail with that error.
func (w *StreamWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	s := w.state()
	if s == nil {
		w.fail(ErrWiped)
		return 0, w.err
	}
	w.buf = append(w.buf, p...)
	var consumed, n int
	w.out, consumed, n = s.scan(w.buf, false, w.out[:0])
	w.count += n
	rest := copy(w.buf, w.buf[consumed:])
	clear(w.buf[rest:])
	w.buf = w.buf[:rest]
	if err := w.emit(); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close flushes the held-back bytes, redacted, and wipes the internal
// buffers. It does not close the destination. Closing twice is a no-op.
func (w *StreamWriter) Close() error {
	if errors.Is(w.err, ErrClosed) {
		return nil
	}
	var flushErr error
	if w.err == nil {
		if s := w.state(); s == nil {
			flushErr = ErrWiped
		} else {
			var n int
			w.out, _, n = s.scan(w.buf, true, w.out[:0])
			w.count += n
			flushErr = w.emit()
		}
	} else {
		flushErr = w.err
	}
	w.release()
	w.err = ErrClosed
	return flushErr
}

func (w *StreamWriter) state() *state {
	if w.r == nil || w.r.s == nil || w.r.s.wiped {
		return nil
	}
	return w.r.s
}

// emit writes the pending output to dst.
func (w *StreamWriter) emit() error {
	if len(w.out) == 0 {
		return nil
	}
	n, err := w.dst.Write(w.out)
	if err == nil && n < len(w.out) {
		err = io.ErrShortWrite
	}
	if err != nil {
		w.fail(err)
		return err
	}
	return nil
}

func (w *StreamWriter) fail(err error) {
	w.err = err
	w.release()
}

func (w *StreamWriter) release() {
	clear(w.buf)
	clear(w.out)
	w.buf, w.out = nil, nil
}

// Format implements fmt.Formatter; the writer holds unredacted bytes and must
// never print them.
func (w StreamWriter) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "redact.StreamWriter{}")
}

// utf16Form is b read as UTF-8 and written as UTF-16 code units (invalid
// bytes become U+FFFD, as every encoder does).
func utf16Form(b []byte, bigEndian bool) []byte {
	units := utf16.Encode([]rune(string(b)))
	out := make([]byte, 0, 2*len(units))
	for _, u := range units {
		if bigEndian {
			out = append(out, byte(u>>8), byte(u))
		} else {
			out = append(out, byte(u), byte(u>>8))
		}
	}
	return out
}
