package audit

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// AnchorMismatch is the reason when a line that a remote anchor vouches for
// has been rewritten (docs/REMOTE_SYNC.md § 8).
const AnchorMismatch = "anchor_mismatch"

// AnchorPoint is what a remote anchor says about the log: the SHA-256 (as
// the log writes it) of the raw line at Seq.
type AnchorPoint struct {
	Seq  uint64
	Line string
}

// ReadHead returns the seq and raw-line hash audit.head holds; ok is false
// when there is no readable head.
func ReadHead(home string) (seq uint64, line string, ok bool) {
	h, ok := readHead(home)
	return h.Seq, h.Line, ok
}

// CheckAnchors compares the log under home with the anchors a server kept.
// Every anchor whose seq is inside the log must match the raw line at that
// seq (AnchorMismatch at that line); a log with fewer records than the
// highest anchored seq is Truncated. Call it after Verify: it relies on line
// n holding seq n, which a valid chain guarantees. The error is for I/O
// failures.
func CheckAnchors(home string, pts []AnchorPoint) (*Problem, error) {
	if len(pts) == 0 {
		return nil, nil
	}
	want := map[uint64]string{}
	var top uint64
	for _, p := range pts {
		if p.Seq == 0 {
			continue
		}
		want[p.Seq] = p.Line
		top = max(top, p.Seq)
	}
	release, err := lock(home)
	switch {
	case errors.Is(err, os.ErrNotExist):
		release = func() {}
	case err != nil:
		return nil, errors.New("audit: cannot take the audit lock")
	}
	defer release()
	var r io.Reader = bytes.NewReader(nil)
	if f, err := os.Open(filepath.Join(home, logFile)); err == nil {
		defer f.Close()
		r = f
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("audit: cannot read the log")
	}
	br := bufio.NewReader(r)
	var n uint64
	for {
		raw, err := br.ReadBytes('\n')
		if len(raw) > 0 {
			n++
			if sum, ok := want[n]; ok && sum != sumOfLine(raw) {
				return &Problem{Line: int(n), Seq: n, Reason: AnchorMismatch}, nil
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return nil, errors.New("audit: cannot read the log")
			}
			break
		}
	}
	if n < top {
		return &Problem{Line: int(max(n, 1)), Seq: top, Reason: Truncated}, nil
	}
	return nil, nil
}

// sumOfLine is the hash of a raw line without its newline.
func sumOfLine(raw []byte) string { return sum(bytes.TrimSuffix(raw, []byte("\n"))) }
