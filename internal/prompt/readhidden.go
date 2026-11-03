package prompt

import (
	"io"
	"unicode/utf8"
)

// Escape sequence states of readHidden.
const (
	escNone = iota
	escStart
	escCSI
	escSS3
)

// readHidden reads one line from a raw terminal r. Enter ends it; Backspace
// removes the last rune; Ctrl-C, or Ctrl-D on an empty line, is ErrCancelled;
// escape sequences (arrow keys, bracketed-paste markers) and other control
// bytes are dropped. The bytes are never echoed to w, which only gets the
// line break. The input is kept as bytes and bounded by maxInput.
//
// Input that arrives together with Enter (a multi-line paste) is refused with
// ErrTrailingInput and the value is wiped. On every path flush runs before
// returning, so whatever is still queued on the terminal is dropped instead
// of being read, run and recorded in history by the next program.
func readHidden(r io.Reader, w io.Writer, flush func()) ([]byte, error) {
	var (
		buf   []byte
		esc   = escNone
		chunk = make([]byte, 4096)
	)
	defer clear(chunk)
	defer flush()
	fail := func(err error) ([]byte, error) {
		clear(buf)
		_, _ = io.WriteString(w, "\r\n")
		return nil, err
	}
	for {
		n, err := r.Read(chunk)
		for i := 0; i < n; i++ {
			b := chunk[i]
			switch esc {
			case escStart:
				switch b {
				case '[':
					esc = escCSI
					continue
				case 'O':
					esc = escSS3
					continue
				}
				esc = escNone // not a sequence: handle b as a normal byte
			case escCSI:
				if b >= 0x40 && b <= 0x7e {
					esc = escNone
				}
				continue
			case escSS3:
				esc = escNone
				continue
			}
			switch {
			case b == '\r' || b == '\n':
				rest := chunk[i+1 : n]
				if b == '\r' && len(rest) > 0 && rest[0] == '\n' {
					rest = rest[1:] // CRLF is one line ending
				}
				if len(rest) > 0 {
					return fail(ErrTrailingInput)
				}
				_, _ = io.WriteString(w, "\r\n")
				return buf, nil
			case b == 0x03:
				return fail(ErrCancelled)
			case b == 0x04:
				if len(buf) == 0 {
					return fail(ErrCancelled)
				}
			case b == 0x7f || b == 0x08:
				for len(buf) > 0 {
					last := buf[len(buf)-1]
					buf = buf[:len(buf)-1]
					if utf8.RuneStart(last) {
						break
					}
				}
			case b == 0x1b:
				esc = escStart
			case b < 0x20:
			case len(buf) < maxInput:
				buf = append(buf, b)
			}
		}
		if err != nil {
			if err == io.EOF && len(buf) > 0 {
				_, _ = io.WriteString(w, "\r\n")
				return buf, nil
			}
			return fail(err)
		}
	}
}
