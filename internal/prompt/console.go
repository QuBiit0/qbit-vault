package prompt

import (
	"context"
	"io"
	"os"
	"runtime"

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

func (c *console) ReadLine(ctx context.Context) ([]byte, error) {
	return untilDone(ctx, func() ([]byte, error) { return readLine(c.in) })
}

// untilDone runs read and returns its result, or ctx.Err() if ctx ends first.
// A blocked console read cannot be interrupted, so it is left behind; the
// process is about to exit with the timeout.
func untilDone(ctx context.Context, read func() ([]byte, error)) ([]byte, error) {
	type result struct {
		b   []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		b, err := read()
		ch <- result{b, err}
	}()
	select {
	case r := <-ch:
		return r.b, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// ReadHidden puts the terminal in raw mode (no echo, no line editing, Ctrl-C
// delivered as a byte so it cancels instead of killing the process mid-read)
// and restores it on every path. Nothing is echoed, not even a mask: the
// length of a secret is not shown either.
func (c *console) ReadHidden(ctx context.Context) ([]byte, error) {
	fd := int(c.in.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		return nil, ErrNoTerminal
	}
	defer func() { _ = term.Restore(fd, state) }()
	b, err := untilDone(ctx, func() ([]byte, error) {
		return readHidden(c.in, c.out, func() { flushInput(c.in) })
	})
	if err != nil && ctx.Err() != nil {
		// Timed out with the reader still blocked: drop what it could not
		// take and leave the hidden prompt line.
		flushInput(c.in)
		_, _ = io.WriteString(c.out, "\r\n")
	}
	return b, err
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
