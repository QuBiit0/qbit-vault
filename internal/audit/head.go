package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/QuBiit0/qbit-vault/internal/perm"
)

// maxTail bounds how far back from the end Append looks for the last line. A
// longer last line is treated as malformed.
const maxTail = 64 * 1024

// head is the content of audit.head: the truncation anchor (L3). Hash is the
// hash field of the record with that seq; Line is the SHA-256 of that record's
// raw line, which is the prev the next record needs.
type head struct {
	Seq  uint64 `json:"seq"`
	Hash string `json:"hash"`
	Line string `json:"line"`
}

// tailState returns the seq and prev for the next record, and whether a
// newline must precede it (the file ends without one).
func tailState(f *os.File, home string) (seq uint64, prev string, sep bool, err error) {
	info, err := f.Stat()
	if err != nil {
		return 0, "", false, errors.New("audit: cannot read the log")
	}
	size := info.Size()
	if size == 0 {
		// An empty log after a head with records is a deleted or emptied
		// log: continue the chain from the head, never restart at genesis.
		if h, ok := readHead(home); ok && h.Seq > 0 {
			return h.Seq + 1, h.Line, false, nil
		}
		return 1, Genesis, false, nil
	}
	n := min(size, maxTail)
	buf := make([]byte, n)
	if _, err := f.ReadAt(buf, size-n); err != nil && !errors.Is(err, io.EOF) {
		return 0, "", false, errors.New("audit: cannot read the log")
	}
	sep = buf[len(buf)-1] != '\n'
	body := bytes.TrimSuffix(buf, []byte("\n"))
	i := bytes.LastIndexByte(body, '\n')
	if i < 0 && n < size {
		// The last line is longer than the window: treat it as malformed.
		return fallbackSeq(f, home), sum(body), sep, nil
	}
	raw := body[i+1:]
	var last Record
	if !sep && json.Unmarshal(raw, &last) == nil && last.Seq > 0 {
		// The head is ahead of the log: its tail was removed. Continue from
		// the head, not from the surviving last line, so the gap stays
		// visible to verify instead of being healed by this append.
		if h, ok := readHead(home); ok && h.Seq > last.Seq {
			return h.Seq + 1, h.Line, false, nil
		}
		return last.Seq + 1, sum(raw), false, nil
	}
	return fallbackSeq(f, home), sum(raw), sep, nil
}

// fallbackSeq is the next seq when the last line cannot be trusted: the
// head's seq, else the number of lines in the log, plus one.
func fallbackSeq(f *os.File, home string) uint64 {
	if h, ok := readHead(home); ok {
		return h.Seq + 1
	}
	var lines uint64
	buf := make([]byte, 32*1024)
	lastByte := byte('\n')
	for off := int64(0); ; {
		n, err := f.ReadAt(buf, off)
		lines += uint64(bytes.Count(buf[:n], []byte("\n")))
		if n > 0 {
			lastByte = buf[n-1]
		}
		off += int64(n)
		if err != nil {
			break
		}
	}
	if lastByte != '\n' {
		lines++
	}
	return lines + 1
}

func readHead(home string) (head, bool) {
	b, err := os.ReadFile(filepath.Join(home, headFile))
	if err != nil {
		return head{}, false
	}
	var h head
	// A head missing any field is unreadable, which verify reports as
	// head_mismatch.
	if json.Unmarshal(b, &h) != nil || h.Hash == "" || h.Line == "" {
		return head{}, false
	}
	return h, true
}

// writeHead replaces audit.head atomically: owner-only temp file, fsync,
// rename.
func writeHead(home string, h head) error {
	errWrite := errors.New("audit: cannot write the head")
	data, _ := json.Marshal(h)
	data = append(data, '\n')
	tmp, err := os.CreateTemp(home, headFile+".tmp-*")
	if err != nil {
		return errWrite
	}
	name := tmp.Name()
	fail := func() error {
		_ = tmp.Close()
		_ = os.Remove(name)
		return errWrite
	}
	if perm.EnsureFile(name) != nil {
		return fail()
	}
	if _, err := tmp.Write(data); err != nil {
		return fail()
	}
	if err := tmp.Sync(); err != nil {
		return fail()
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return errWrite
	}
	target := filepath.Join(home, headFile)
	for range 50 {
		if os.Rename(name, target) == nil {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = os.Remove(name)
	return errors.New("audit: cannot replace the head")
}
