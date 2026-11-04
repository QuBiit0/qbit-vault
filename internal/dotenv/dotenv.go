// Package dotenv parses .env files for `gentle-vault import --from-file`
// (docs/CLI.md). Values never appear in errors: a problem is reported by line
// number only.
package dotenv

import (
	"bytes"
	"fmt"
	"regexp"
)

// Entry is one variable. Value is a fresh buffer the caller wipes (Wipe).
type Entry struct {
	Name  string
	Value []byte
	Line  int
}

// LineError is a syntax problem at a line. It never carries file content.
type LineError struct {
	Line int
	What string
}

func (e *LineError) Error() string { return fmt.Sprintf("line %d: %s", e.Line, e.What) }

var nameRE = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

// Parse reads KEY=VALUE lines: blank lines and `#` comments are ignored, an
// `export ` prefix is allowed, single quotes are literal, double quotes take
// the escapes \n \r \t \" \\ and both may span lines; an unquoted value ends
// at the line end or at a ` #` comment and is trimmed. A line without `=`,
// with a name that is not a valid secret name, or with an empty value is
// skipped and counted. When a name repeats, the last value wins and the name
// keeps its first position. Surrounding whitespace of every value is trimmed
// (the same rule as `set`).
func Parse(data []byte) (entries []Entry, skipped int, err error) {
	index := map[string]int{}
	line, pos := 1, 0
	for pos < len(data) {
		start, eol := pos, lineEnd(data, pos)
		i := skipBlank(data, start, eol)
		if i == eol || data[i] == '#' {
			pos, line = eol+1, line+1
			continue
		}
		if hasExport(data[i:eol]) {
			i = skipBlank(data, i+len("export"), eol)
		}
		eq := bytes.IndexByte(data[i:eol], '=')
		if eq < 0 {
			skipped++
			pos, line = eol+1, line+1
			continue
		}
		key := string(bytes.TrimSpace(data[i : i+eq]))
		j := skipBlank(data, i+eq+1, eol)
		var val []byte
		at := line
		if j < eol && (data[j] == '"' || data[j] == '\'') {
			var next, lines int
			val, next, lines, err = quoted(data, j, line)
			if err != nil {
				Wipe(entries)
				return nil, 0, err
			}
			line += lines
			end := lineEnd(data, next)
			if tail := bytes.TrimSpace(data[next:end]); len(tail) > 0 && tail[0] != '#' {
				clear(val)
				Wipe(entries)
				return nil, 0, &LineError{Line: line, What: "text after the closing quote"}
			}
			pos, line = end+1, line+1
		} else {
			raw := data[j:eol]
			if k := commentStart(raw); k >= 0 {
				raw = raw[:k]
			}
			val = bytes.Clone(raw)
			pos, line = eol+1, line+1
		}
		trimmed := bytes.TrimSpace(val)
		if !nameRE.MatchString(key) || len(trimmed) == 0 {
			clear(val)
			skipped++
			continue
		}
		v := bytes.Clone(trimmed)
		clear(val)
		if k, dup := index[key]; dup {
			clear(entries[k].Value)
			entries[k].Value, entries[k].Line = v, at
			continue
		}
		index[key] = len(entries)
		entries = append(entries, Entry{Name: key, Value: v, Line: at})
	}
	return entries, skipped, nil
}

// Wipe clears every value.
func Wipe(es []Entry) {
	for i := range es {
		clear(es[i].Value)
	}
}

// lineEnd returns the index of the '\n' ending the line at pos, or len(data).
func lineEnd(data []byte, pos int) int {
	if k := bytes.IndexByte(data[pos:], '\n'); k >= 0 {
		return pos + k
	}
	return len(data)
}

func skipBlank(data []byte, i, end int) int {
	for i < end && (data[i] == ' ' || data[i] == '\t' || data[i] == '\r') {
		i++
	}
	return i
}

func hasExport(b []byte) bool {
	return len(b) > len("export ") && bytes.HasPrefix(b, []byte("export")) && (b[6] == ' ' || b[6] == '\t')
}

// commentStart finds an inline comment: a '#' preceded by a space or tab.
func commentStart(b []byte) int {
	for k := 1; k < len(b); k++ {
		if b[k] == '#' && (b[k-1] == ' ' || b[k-1] == '\t') {
			return k
		}
	}
	return -1
}

// quoted reads the quoted value opening at data[j]. It returns the value, the
// index just past the closing quote and how many line breaks it crossed. A
// CR before a line break is dropped, so CRLF files read like LF ones.
func quoted(data []byte, j, line int) ([]byte, int, int, error) {
	q := data[j]
	var val []byte
	lines := 0
	for k := j + 1; ; {
		if k >= len(data) {
			clear(val)
			return nil, 0, 0, &LineError{Line: line, What: "unterminated quote"}
		}
		c := data[k]
		switch {
		case c == q:
			return val, k + 1, lines, nil
		case c == '\r' && k+1 < len(data) && data[k+1] == '\n':
			k++
		case c == '\n':
			lines++
			val = append(val, '\n')
			k++
		case q == '"' && c == '\\' && k+1 < len(data):
			switch n := data[k+1]; n {
			case 'n':
				val = append(val, '\n')
			case 'r':
				val = append(val, '\r')
			case 't':
				val = append(val, '\t')
			case '"', '\\':
				val = append(val, n)
			default:
				val = append(val, '\\', n)
			}
			k += 2
		default:
			val = append(val, c)
			k++
		}
	}
}
