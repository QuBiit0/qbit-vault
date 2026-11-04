package filemerge

import (
	"bytes"
	"strconv"
	"strings"
)

// MergeTOML adds or replaces our table (and its subtables) in doc and returns
// the new bytes. table is the dotted name of our table, for example
// "mcp_servers.qbit-vault"; block is its full text: the header
// "[mcp_servers.qbit-vault]", its keys and any subtable such as
// "[mcp_servers.qbit-vault.env]". Every byte outside our table stays
// identical, comments included.
//
//   - Missing file or table: the block is appended after a blank line.
//   - Existing table: the first run of our headers is replaced in place; any
//     other run of them (subtables placed elsewhere) is removed. Blank lines
//     and comments that follow our table belong to what follows and stay.
//   - The block is rewritten with the file's line endings (CRLF or LF); when
//     our table is the last thing in a file without a trailing newline, the
//     replacement has none either.
//
// Input it cannot edit safely is refused with ErrAmbiguous and nothing is
// written: our table or a subtable defined twice, an array of tables, or an
// inline/dotted definition of the table (qbit-vault = {...} under
// [mcp_servers], mcp_servers.qbit-vault.x = 1, mcp_servers = {...}). An
// unterminated string or array is ErrInvalidTOML. A block that is not made
// only of our headers is ErrInvalidEdit.
func MergeTOML(doc []byte, table, block string) ([]byte, error) {
	own, err := parseTableName(table)
	if err != nil {
		return nil, err
	}
	if err := checkBlock(own, block); err != nil {
		return nil, err
	}
	sc, err := scanTOML(doc, own)
	if err != nil {
		return nil, err
	}
	eol := detectEOL(doc)
	text := normalizeEOL(block, eol)
	if !strings.HasSuffix(text, eol) {
		text += eol
	}
	if len(sc.regions) == 0 {
		out := append([]byte{}, doc...)
		if len(out) > 0 {
			if !bytes.HasSuffix(out, []byte("\n")) {
				out = append(out, eol...)
			}
			out = append(out, eol...)
		}
		return append(out, text...), nil
	}
	first := sc.regions[0]
	if !bytes.HasSuffix(doc[first.start:first.end], []byte("\n")) {
		text = strings.TrimSuffix(text, eol)
	}
	// Later runs go first so the offsets of the first one stay valid.
	out := doc
	for i := len(sc.regions) - 1; i >= 1; i-- {
		out = cutRegion(out, sc.regions[i])
	}
	return splice(out, first.start, first.end, []byte(text)), nil
}

// UnmergeTOML removes our table and its subtables and returns the new bytes;
// an absent table is a no-op. The blank lines after the removed table go with
// it; when it was the last thing in the file, the single blank line that
// separated it from the previous content goes too (the one MergeTOML adds).
// Same refusals as MergeTOML.
func UnmergeTOML(doc []byte, table string) ([]byte, error) {
	own, err := parseTableName(table)
	if err != nil {
		return nil, err
	}
	sc, err := scanTOML(doc, own)
	if err != nil {
		return nil, err
	}
	out := doc
	// Last region first: earlier offsets stay valid.
	for i := len(sc.regions) - 1; i >= 0; i-- {
		r := sc.regions[i]
		out = cutRegion(out, r)
	}
	return out, nil
}

// region is a run of our headers and their key/value lines, [start,end).
type region struct{ start, end int }

// cutRegion removes r plus the blank lines after it; at the end of the file
// it also removes one blank line before it.
func cutRegion(doc []byte, r region) []byte {
	end := r.end
	for end < len(doc) {
		nl := bytes.IndexByte(doc[end:], '\n')
		var line []byte
		next := len(doc)
		if nl >= 0 {
			line, next = doc[end:end+nl], end+nl+1
		} else {
			line = doc[end:]
		}
		if len(bytes.TrimSpace(line)) != 0 {
			break
		}
		end = next
	}
	start := r.start
	if end == len(doc) && start > 0 {
		prev := bytes.LastIndexByte(doc[:start-1], '\n') + 1
		if len(bytes.TrimSpace(doc[prev:start])) == 0 {
			start = prev
		}
	}
	return splice(doc, start, end, nil)
}

func detectEOL(doc []byte) string {
	if i := bytes.IndexByte(doc, '\n'); i > 0 && doc[i-1] == '\r' {
		return "\r\n"
	}
	return "\n"
}

func normalizeEOL(s, eol string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	if eol == "\n" {
		return s
	}
	return strings.ReplaceAll(s, "\n", eol)
}

func parseTableName(name string) ([]string, error) {
	parts, rest, ok := parseKey(name)
	if !ok || strings.TrimSpace(rest) != "" || len(parts) == 0 {
		return nil, ErrInvalidEdit
	}
	return parts, nil
}

// checkBlock verifies the block holds only headers of our table or its
// subtables, with no key before the first header and no duplicates.
func checkBlock(own []string, block string) error {
	sc, err := scanTOML([]byte(block), own)
	if err != nil || sc.headers == 0 || sc.foreign || sc.leading {
		return ErrInvalidEdit
	}
	return nil
}

// ---- scanner ------------------------------------------------------------

type scanResult struct {
	regions []region
	headers int  // number of table headers seen
	foreign bool // a header outside our table, or a key outside our region
	leading bool // key/value or text before the first header
}

type lineKind int

const (
	kBlank lineKind = iota // blank or comment-only
	kHeader
	kKV
	kCont // continuation of a multi-line value
)

func isOwned(path, own []string) bool {
	if len(path) < len(own) {
		return false
	}
	for i := range own {
		if path[i] != own[i] {
			return false
		}
	}
	return true
}

func isProperPrefix(path, own []string) bool {
	if len(path) >= len(own) {
		return false
	}
	for i := range path {
		if path[i] != own[i] {
			return false
		}
	}
	return true
}

// scanTOML walks doc statement by statement, tracking multi-line strings and
// brackets so a "[" inside them is never taken for a header. It records the
// runs of owned headers and refuses ambiguous definitions.
func scanTOML(doc []byte, own []string) (*scanResult, error) {
	res := &scanResult{}
	var table []string
	seen := map[string]bool{}
	inOwned := false
	var cur *region
	lastContent := 0 // end offset of the last non-blank line in the current region

	closeRegion := func() {
		if cur != nil {
			cur.end = lastContent
			res.regions = append(res.regions, *cur)
			cur = nil
		}
	}
	st := &valueState{}
	pos := 0
	first := true
	for pos < len(doc) {
		nl := bytes.IndexByte(doc[pos:], '\n')
		next := len(doc)
		if nl >= 0 {
			next = pos + nl + 1
		}
		line := string(bytes.TrimRight(doc[pos:next], "\r\n"))
		if first && strings.HasPrefix(line, "\ufeff") {
			line = line[3:]
		}
		first = false

		kind := kCont
		if !st.active() {
			trimmed := strings.TrimLeft(line, " \t")
			switch {
			case trimmed == "" || strings.HasPrefix(trimmed, "#"):
				kind = kBlank
			case strings.HasPrefix(trimmed, "["):
				kind = kHeader
				path, array, ok := parseHeader(trimmed)
				if !ok {
					return nil, ErrInvalidTOML
				}
				res.headers++
				table = path
				owned := isOwned(path, own)
				if owned {
					if array {
						return nil, ErrAmbiguous
					}
					key := strings.Join(path, "\x00")
					if seen[key] {
						return nil, ErrAmbiguous
					}
					seen[key] = true
				} else {
					res.foreign = true
				}
				if owned && !inOwned {
					cur = &region{start: pos}
				}
				if !owned && inOwned {
					closeRegion()
				}
				inOwned = owned
			default:
				kind = kKV
				if res.headers == 0 {
					res.leading = true
				}
				keys, rest, ok := parseKey(trimmed)
				if !ok || !strings.HasPrefix(strings.TrimLeft(rest, " \t"), "=") {
					return nil, ErrInvalidTOML
				}
				if !inOwned {
					full := append(append([]string{}, table...), keys...)
					if isOwned(full, own) || isProperPrefix(full, own) {
						return nil, ErrAmbiguous
					}
				}
				rest = strings.TrimLeft(rest, " \t")[1:]
				if err := st.feed(rest); err != nil {
					return nil, err
				}
			}
		} else {
			if err := st.feed(line); err != nil {
				return nil, err
			}
		}
		if kind != kBlank && inOwned {
			lastContent = next
		}
		pos = next
	}
	if st.active() {
		return nil, ErrInvalidTOML
	}
	closeRegion()
	return res, nil
}

// valueState tracks an unfinished value across lines.
type valueState struct {
	ml    string // `"""` or `'''` while inside a multi-line string
	depth int
}

func (s *valueState) active() bool { return s.ml != "" || s.depth > 0 }

// feed scans the rest of a line, updating string and bracket state.
func (s *valueState) feed(line string) error {
	i := 0
	for i < len(line) {
		if s.ml != "" {
			j := i
			for j < len(line) {
				if s.ml == `"""` && line[j] == '\\' {
					j += 2
					continue
				}
				if strings.HasPrefix(line[j:], s.ml) {
					break
				}
				j++
			}
			if j >= len(line) {
				return nil // continues on the next line
			}
			i = j + 3
			for i < len(line) && line[i] == s.ml[0] {
				i++
			}
			s.ml = ""
			continue
		}
		switch c := line[i]; c {
		case '#':
			return nil
		case '[', '{':
			s.depth++
			i++
		case ']', '}':
			s.depth--
			i++
		case '"', '\'':
			if strings.HasPrefix(line[i:], strings.Repeat(string(c), 3)) {
				s.ml = strings.Repeat(string(c), 3)
				i += 3
				continue
			}
			j := i + 1
			for j < len(line) && line[j] != c {
				if c == '"' && line[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(line) {
				return ErrInvalidTOML
			}
			i = j + 1
		default:
			i++
		}
	}
	return nil
}

// parseHeader parses "[a.b]" or "[[a.b]]" followed by an optional comment.
func parseHeader(s string) (path []string, array, ok bool) {
	s = s[1:]
	if strings.HasPrefix(s, "[") {
		array, s = true, s[1:]
	}
	path, rest, ok := parseKey(s)
	if !ok {
		return nil, false, false
	}
	rest = strings.TrimLeft(rest, " \t")
	want := "]"
	if array {
		want = "]]"
	}
	if !strings.HasPrefix(rest, want) {
		return nil, false, false
	}
	rest = strings.TrimLeft(rest[len(want):], " \t")
	if rest != "" && !strings.HasPrefix(rest, "#") {
		return nil, false, false
	}
	return path, array, true
}

// parseKey parses a dotted key (bare, "basic" or 'literal' parts) and returns
// the remaining text.
func parseKey(s string) (parts []string, rest string, ok bool) {
	for {
		s = strings.TrimLeft(s, " \t")
		if s == "" {
			return nil, "", false
		}
		var part string
		switch s[0] {
		case '"':
			j := 1
			for j < len(s) && s[j] != '"' {
				if s[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(s) {
				return nil, "", false
			}
			if u, err := strconv.Unquote(s[:j+1]); err == nil {
				part = u
			} else {
				part = s[1:j]
			}
			s = s[j+1:]
		case '\'':
			j := strings.IndexByte(s[1:], '\'')
			if j < 0 {
				return nil, "", false
			}
			part, s = s[1:1+j], s[j+2:]
		default:
			j := 0
			for j < len(s) && (s[j] == '-' || s[j] == '_' || s[j] >= '0' && s[j] <= '9' || s[j]|0x20 >= 'a' && s[j]|0x20 <= 'z') {
				j++
			}
			if j == 0 {
				return nil, "", false
			}
			part, s = s[:j], s[j:]
		}
		parts = append(parts, part)
		t := strings.TrimLeft(s, " \t")
		if strings.HasPrefix(t, ".") {
			s = t[1:]
			continue
		}
		return parts, s, true
	}
}
