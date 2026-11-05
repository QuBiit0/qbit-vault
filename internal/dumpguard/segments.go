package dumpguard

import "strings"

// maxDepth bounds the nesting of subshells and `sh -c` scripts that Segments
// follows; deeper text is kept as one flat segment.
const maxDepth = 8

// Segment is one simple command: its shell words after quote removal and
// their single-space join.
type Segment struct {
	Words []string
	Text  string

	// script marks `sh -c '...'` and `eval ...`: the script's own segments
	// are listed separately, so this one is a transparent wrapper.
	script bool
}

// Segments splits cmd into simple commands. It splits on | || |& && ; & and
// newlines outside quotes (honoring backslash escapes), adds the contents of
// $(...), backticks, parenthesized groups and `sh -c` / `eval` scripts as
// further segments, drops comments and output redirections, and strips
// leading shell keywords (`if`, `then`, `{`, `!`, ...). Unterminated quotes
// and groups are closed at the end of the text.
func Segments(cmd string) []Segment { return segments(cmd, 0) }

var keywords = map[string]bool{
	"{": true, "}": true, "!": true, "if": true, "then": true, "elif": true, "else": true,
	"fi": true, "do": true, "done": true, "while": true, "until": true, "esac": true,
}

func segments(s string, depth int) []Segment {
	var (
		out, sub []Segment
		words    []string
		cur      strings.Builder
		inWord   bool
		quoted   bool
		skipNext bool
	)
	flushWord := func() {
		if !inWord {
			return
		}
		w := cur.String()
		cur.Reset()
		wasQuoted := quoted
		inWord, quoted = false, false
		if skipNext {
			skipNext = false
			return
		}
		if !wasQuoted {
			if isRedir, takesNext := redirect(w); isRedir {
				skipNext = takesNext
				return
			}
		}
		words = append(words, w)
	}
	flushSeg := func() {
		flushWord()
		skipNext = false
		for len(words) > 0 && keywords[words[0]] {
			words = words[1:]
		}
		if len(words) == 0 {
			words = nil
			return
		}
		seg := Segment{Words: words, Text: strings.Join(words, " ")}
		if script, ok := scriptOf(words); ok {
			seg.script = true
			if depth < maxDepth {
				sub = append(sub, segments(script, depth+1)...)
			} else {
				sub = append(sub, flat(script))
			}
		}
		out = append(out, seg)
		words = nil
	}
	// group writes the original text of a $(...) or `...` group into the
	// word and queues its contents as segments.
	group := func(start, end int, inner string) {
		cur.WriteString(s[start:end])
		inWord = true
		if depth < maxDepth {
			sub = append(sub, segments(inner, depth+1)...)
		} else {
			sub = append(sub, flat(inner))
		}
	}

	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '\\':
			switch {
			case i+1 >= len(s):
				cur.WriteByte(c)
				inWord = true
				i++
			case s[i+1] == '\n':
				i += 2
			case s[i+1] == '\r' && i+2 < len(s) && s[i+2] == '\n':
				i += 3
			default:
				cur.WriteByte(s[i+1])
				inWord, quoted = true, true
				i += 2
			}
		case c == '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				cur.WriteString(s[i+1:])
				i = len(s)
			} else {
				cur.WriteString(s[i+1 : i+1+j])
				i += j + 2
			}
			inWord, quoted = true, true
		case c == '"':
			i++
			for i < len(s) && s[i] != '"' {
				switch {
				case s[i] == '\\' && i+1 < len(s):
					switch s[i+1] {
					case '"', '\\', '$', '`':
						cur.WriteByte(s[i+1])
						i += 2
					case '\n':
						i += 2
					default:
						cur.WriteByte('\\')
						i++
					}
				case s[i] == '$' && i+1 < len(s) && s[i+1] == '(':
					inner, end := matchParen(s, i+1)
					group(i, end, inner)
					i = end
				case s[i] == '`':
					inner, end := matchTick(s, i)
					group(i, end, inner)
					i = end
				default:
					cur.WriteByte(s[i])
					i++
				}
			}
			i++ // closing quote
			inWord, quoted = true, true
		case c == '$' && i+1 < len(s) && s[i+1] == '(':
			inner, end := matchParen(s, i+1)
			group(i, end, inner)
			i = end
		case c == '`':
			inner, end := matchTick(s, i)
			group(i, end, inner)
			i = end
		case c == '#' && !inWord:
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case c == ' ' || c == '\t' || c == '\r':
			flushWord()
			i++
		case c == '\n' || c == ';':
			flushSeg()
			i++
		case c == '|':
			flushSeg()
			i++
			if i < len(s) && (s[i] == '|' || s[i] == '&') {
				i++
			}
		case c == '&':
			next := byte(0)
			if i+1 < len(s) {
				next = s[i+1]
			}
			switch {
			case next == '&':
				flushSeg()
				i += 2
			case next == '>' || (inWord && i > 0 && (s[i-1] == '>' || s[i-1] == '<')):
				cur.WriteByte(c) // &> and >&N are redirections
				inWord = true
				i++
			default:
				flushSeg()
				i++
			}
		case c == '(' || c == ')':
			flushSeg()
			i++
		default:
			cur.WriteByte(c)
			inWord = true
			i++
		}
	}
	flushSeg()
	return append(out, sub...)
}

// flat is the segment of text too deeply nested to follow.
func flat(s string) Segment {
	w := strings.Fields(s)
	return Segment{Words: w, Text: strings.Join(w, " ")}
}

// redirect reports whether an unquoted word is an output redirection
// (`>f`, `2>&1`, `&>f`, `>>`) and whether it takes the next word as its
// target. Input redirections and here-strings are kept.
func redirect(w string) (isRedir, takesNext bool) {
	r := w
	if strings.HasPrefix(r, "&>") {
		r = r[1:]
	} else {
		r = strings.TrimLeft(r, "0123456789")
	}
	if !strings.HasPrefix(r, ">") {
		return false, false
	}
	r = r[1:]
	if strings.HasPrefix(r, ">") || strings.HasPrefix(r, "|") {
		r = r[1:]
	}
	if strings.HasPrefix(r, "&") {
		return true, false
	}
	return true, r == ""
}

// matchParen returns the text inside the group whose "(" is s[open] and the
// index just after its ")". Quotes inside are skipped.
func matchParen(s string, open int) (inner string, end int) {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '\'':
			if j := strings.IndexByte(s[i+1:], '\''); j >= 0 {
				i += j + 1
			} else {
				i = len(s)
			}
		case '"':
			for i++; i < len(s) && s[i] != '"'; i++ {
				if s[i] == '\\' {
					i++
				}
			}
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return s[open+1 : i], i + 1
			}
		}
	}
	return s[min(open+1, len(s)):], len(s)
}

// matchTick returns the text inside the backticks opening at s[open] and the
// index just after the closing one.
func matchTick(s string, open int) (inner string, end int) {
	for i := open + 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '`':
			return strings.ReplaceAll(s[open+1:i], "\\`", "`"), i + 1
		}
	}
	return s[open+1:], len(s)
}
