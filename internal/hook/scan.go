package hook

import "strings"

// placeholder stands in a word for text the scanner cannot know, such as
// the output of `$( )` or a `${…}` expansion.
const placeholder = "\x01"

// scan splits a shell command line into simple commands, each a list of
// words with quoting and escapes removed. It splits on newlines, `;`, `&`,
// `|` (so `&&`, `||` and `|&` too), and descends into `( )`, `$( )` and
// backticks, including inside double quotes. It is deliberately small, not a
// shell: ok is false when the line cannot be tokenised with confidence
// (unbalanced quotes or substitutions, here-documents), and the caller
// decides what that means.
func scan(src string) (cmds [][]string, ok bool) {
	p := &scanner{s: src}
	if !p.list(0) {
		return nil, false
	}
	return p.cmds, true
}

type scanner struct {
	s    string
	i    int
	cmds [][]string
}

func (p *scanner) peek(off int) byte {
	if p.i+off < len(p.s) {
		return p.s[p.i+off]
	}
	return 0
}

// list reads simple commands up to the closing term (0 means end of input).
func (p *scanner) list(term byte) bool {
	var (
		cur    []string
		word   strings.Builder
		inWord bool
	)
	flushWord := func() {
		if inWord {
			cur = append(cur, word.String())
			word.Reset()
			inWord = false
		}
	}
	flushCmd := func() {
		flushWord()
		if len(cur) > 0 {
			p.cmds = append(p.cmds, cur)
			cur = nil
		}
	}
	put := func(s string) {
		word.WriteString(s)
		inWord = true
	}
	for p.i < len(p.s) {
		c := p.s[p.i]
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			flushWord()
			p.i++
		case c == '\n' || c == ';' || c == '&' || c == '|':
			flushCmd()
			p.i++
		case c == '(':
			flushCmd()
			p.i++
			if !p.list(')') {
				return false
			}
		case c == ')':
			if term != ')' {
				return false
			}
			flushCmd()
			p.i++
			return true
		case c == '`':
			p.i++
			if term == '`' {
				flushCmd()
				return true
			}
			if !p.list('`') {
				return false
			}
			put(placeholder)
		case c == '$' && p.peek(1) == '(':
			p.i += 2
			if !p.list(')') {
				return false
			}
			put(placeholder)
		case c == '$' && p.peek(1) == '{':
			end := strings.IndexByte(p.s[p.i:], '}')
			if end < 0 {
				return false
			}
			p.i += end + 1
			put(placeholder)
		case c == '\\':
			switch next := p.peek(1); next {
			case 0:
				p.i++
			case '\n':
				p.i += 2
			default:
				// Only a shell-special character is escaped; any other
				// backslash is literal so Windows paths keep their shape.
				if !strings.ContainsRune(" \t\"'$`\\;&|()<>#*?[]{}!~", rune(next)) {
					put("\\")
				}
				put(string(next))
				p.i += 2
			}
		case c == '\'':
			end := strings.IndexByte(p.s[p.i+1:], '\'')
			if end < 0 {
				return false
			}
			put(p.s[p.i+1 : p.i+1+end])
			p.i += end + 2
		case c == '"':
			p.i++
			s, ok := p.double()
			if !ok {
				return false
			}
			put(s)
		case c == '#' && !inWord:
			for p.i < len(p.s) && p.s[p.i] != '\n' {
				p.i++
			}
		case c == '<' && p.peek(1) == '<' && p.peek(2) != '<':
			return false // here-document: the body would be misread as commands
		default:
			put(string(c))
			p.i++
		}
	}
	if term != 0 {
		return false
	}
	flushCmd()
	return true
}

// double reads the inside of a double-quoted string after its opening quote.
func (p *scanner) double() (string, bool) {
	var b strings.Builder
	for p.i < len(p.s) {
		c := p.s[p.i]
		switch {
		case c == '"':
			p.i++
			return b.String(), true
		case c == '\\' && p.i+1 < len(p.s):
			if n := p.s[p.i+1]; n != '\n' {
				b.WriteByte(n)
			}
			p.i += 2
		case c == '`':
			p.i++
			if !p.list('`') {
				return "", false
			}
			b.WriteString(placeholder)
		case c == '$' && p.peek(1) == '(':
			p.i += 2
			if !p.list(')') {
				return "", false
			}
			b.WriteString(placeholder)
		default:
			b.WriteByte(c)
			p.i++
		}
	}
	return "", false
}
