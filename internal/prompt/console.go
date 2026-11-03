package prompt

import (
	"io"
	"os"
	"runtime"
	"unicode/utf8"

	"golang.org/x/term"
)

// maxInput bounds one line read from the terminal: a 64 KiB value plus the
// whitespace around it, and one byte so the caller can tell it was cut.
const maxInput = 64*1024 + 4096 + 1

// console is the controlling terminal: /dev/tty on POSIX, CONIN$ and CONOUT$
// on Windows. It never touches the process stdin, stdout or stderr, so a pipe
// the caller controls cannot answer (L3).
type console struct {
	in, out *os.File
}

// openConsole opens the controlling terminal, or reports ErrUnavailable.
func openConsole() (Terminal, error) {
	inName, outName := "/dev/tty", "/dev/tty"
	if runtime.GOOS == "windows" {
		inName, outName = "CONIN$", "CONOUT$"
	}
	in, err := os.OpenFile(inName, os.O_RDWR, 0)
	if err != nil {
		return nil, ErrNoTerminal
	}
	out := in
	if outName != inName {
		if out, err = os.OpenFile(outName, os.O_RDWR, 0); err != nil {
			in.Close()
			return nil, ErrNoTerminal
		}
	}
	if !term.IsTerminal(int(in.Fd())) {
		if out != in {
			out.Close()
		}
		in.Close()
		return nil, ErrNoTerminal
	}
	return &console{in: in, out: out}, nil
}

func (c *console) Write(p []byte) (int, error) { return c.out.Write(p) }

func (c *console) Close() error {
	err := c.in.Close()
	if c.out != c.in {
		if e := c.out.Close(); err == nil {
			err = e
		}
	}
	return err
}

func (c *console) ReadLine() ([]byte, error) { return readLine(c.in) }

// ReadHidden puts the terminal in raw mode (no echo, no line editing, Ctrl-C
// delivered as a byte so it cancels instead of killing the process mid-read)
// and restores it on every path. Nothing is echoed, not even a mask: the
// length of a secret is not shown either.
func (c *console) ReadHidden() ([]byte, error) {
	fd := int(c.in.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		return nil, ErrNoTerminal
	}
	defer func() { _ = term.Restore(fd, state) }()
	return readHidden(c.in, c.out)
}

// readByte reads exactly one byte, so nothing past the answer is consumed.
func readByte(r io.Reader) (byte, error) {
	var one [1]byte
	for {
		n, err := r.Read(one[:])
		if n == 1 {
			return one[0], nil
		}
		if err != nil {
			return 0, err
		}
	}
}

// readLine reads up to the next LF, dropping the LF and a CR before it. At
// the end of input it returns what it has, or io.EOF when that is nothing.
// Bytes past maxInput are dropped.
func readLine(r io.Reader) ([]byte, error) {
	var buf []byte
	for {
		b, err := readByte(r)
		if err != nil {
			if err == io.EOF && len(buf) > 0 {
				return buf, nil
			}
			clear(buf)
			return nil, err
		}
		if b == '\n' {
			if n := len(buf); n > 0 && buf[n-1] == '\r' {
				buf = buf[:n-1]
			}
			return buf, nil
		}
		if len(buf) < maxInput {
			buf = append(buf, b)
		}
	}
}

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
func readHidden(r io.Reader, w io.Writer) ([]byte, error) {
	var (
		buf []byte
		esc = escNone
	)
	fail := func(err error) ([]byte, error) {
		clear(buf)
		_, _ = io.WriteString(w, "\r\n")
		return nil, err
	}
	for {
		b, err := readByte(r)
		if err != nil {
			if err == io.EOF && len(buf) > 0 {
				break
			}
			return fail(err)
		}
		switch esc {
		case escStart:
			switch {
			case b == '[':
				esc = escCSI
				continue
			case b == 'O':
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
				if !utf8.RuneStart(last) {
					continue
				}
				break
			}
		case b == 0x1b:
			esc = escStart
		case b < 0x20:
		case len(buf) < maxInput:
			buf = append(buf, b)
		}
	}
	_, _ = io.WriteString(w, "\r\n")
	return buf, nil
}
