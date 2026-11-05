package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Reasons a chain can be broken.
const (
	BadJSON      = "bad_json"
	BadHash      = "bad_hash"
	BadPrev      = "bad_prev"
	BadSeq       = "bad_seq"
	PartialLine  = "partial_line"
	Truncated    = "truncated"
	HeadMismatch = "head_mismatch"
)

// Problem locates the first broken link. Line is 1-based (0 when the whole
// log is gone); Seq is the seq the record at that position should have had.
type Problem struct {
	Line   int    `json:"line"`
	Seq    uint64 `json:"seq"`
	Reason string `json:"reason"`
}

// Result is the outcome of Verify. Records counts the records that verified
// before the first problem (all of them when Valid).
type Result struct {
	Valid   bool
	Records int
	Problem *Problem
}

// Verify walks the whole chain under home: every line must be valid JSON in
// canonical form with a matching hash, prev must be the hash of the previous
// raw line, seq must count up from 1 and the last line must end with a
// newline. It then compares the end of the log with audit.head. A missing log
// and a missing head are valid with 0 records. The error is for I/O
// failures, not for a broken chain.
func Verify(home string) (Result, error) {
	release, err := lock(home)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return Result{Valid: true}, nil
	case err != nil:
		return Result{}, errors.New("audit: cannot take the audit lock")
	}
	defer release()
	return verifyLog(filepath.Join(home, logFile), filepath.Join(home, headFile))
}

// verifyLog is Verify without the lock, on explicit paths (the fuzz target).
func verifyLog(logPath, headPath string) (Result, error) {
	var (
		h       *head
		badHead bool
	)
	switch b, err := os.ReadFile(headPath); {
	case err == nil:
		h = new(head)
		if json.Unmarshal(b, h) != nil || h.Seq == 0 {
			h, badHead = nil, true
		}
	case !errors.Is(err, os.ErrNotExist):
		return Result{}, errors.New("audit: cannot read the head")
	}
	var r io.Reader = strings.NewReader("")
	if f, err := os.Open(logPath); err == nil {
		defer f.Close()
		r = f
	} else if !errors.Is(err, os.ErrNotExist) {
		return Result{}, errors.New("audit: cannot read the log")
	}
	return verifyReader(r, h, badHead)
}

// verifyReader walks the lines of r and then checks the head. badHead means
// the head file exists but is unusable; it is reported after the walk, so a
// break in the log itself wins.
func verifyReader(r io.Reader, h *head, badHead bool) (Result, error) {
	br := bufio.NewReader(r)
	var (
		res      Result
		prev     = Genesis
		expect   = uint64(1)
		line     int
		headHash string
		headLine string
		headSeen bool
	)
	fail := func(reason string) (Result, error) {
		res.Problem = &Problem{Line: line, Seq: expect, Reason: reason}
		return res, nil
	}
	for {
		raw, err := br.ReadBytes('\n')
		if len(raw) == 0 && err != nil {
			if !errors.Is(err, io.EOF) {
				return Result{}, errors.New("audit: cannot read the log")
			}
			break
		}
		line++
		if err != nil { // no trailing newline
			if !errors.Is(err, io.EOF) {
				return Result{}, errors.New("audit: cannot read the log")
			}
			return fail(PartialLine)
		}
		body := raw[:len(raw)-1]
		var rec Record
		if len(body) == 0 || body[0] != '{' || json.Unmarshal(body, &rec) != nil {
			return fail(BadJSON)
		}
		want := recordHash(rec)
		canon := rec
		canon.Hash = want
		if enc, _ := json.Marshal(canon); rec.Hash != want || !bytes.Equal(enc, body) {
			return fail(BadHash)
		}
		if line == 1 && rec.Seq != 1 {
			// The log starts after genesis: its head was cut off.
			return fail(Truncated)
		}
		if rec.Prev != prev {
			return fail(BadPrev)
		}
		if rec.Seq != expect {
			return fail(BadSeq)
		}
		if h != nil && rec.Seq == h.Seq {
			headSeen, headHash, headLine = true, rec.Hash, sum(body)
		}
		prev = sum(body)
		expect++
		res.Records++
	}
	switch {
	case badHead:
		return fail(HeadMismatch)
	case h != nil && uint64(res.Records) < h.Seq:
		expect = h.Seq
		line = max(line, 1)
		return fail(Truncated)
	case h != nil && (!headSeen || headHash != h.Hash || headLine != h.Line):
		expect = h.Seq
		return fail(HeadMismatch)
	}
	res.Valid = true
	return res, nil
}

// Filter narrows Read. Zero fields match everything.
type Filter struct {
	Tail  int       // keep only the newest Tail records after filtering (<=0: all)
	Since time.Time // records at or after this instant
	Name  string    // records naming this secret
	Event string    // records of this event
}

// Read returns the records under home that match f, oldest first. Lines that
// do not parse are skipped (Verify is what reports them). A missing log is
// an empty result.
func Read(home string, f Filter) ([]Record, error) {
	release, err := lock(home)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, nil
	case err != nil:
		return nil, errors.New("audit: cannot take the audit lock")
	}
	defer release()
	file, err := os.Open(filepath.Join(home, logFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("audit: cannot read the log")
	}
	defer file.Close()
	var out []Record
	br := bufio.NewReader(file)
	for {
		raw, err := br.ReadBytes('\n')
		if len(raw) > 0 {
			var rec Record
			if json.Unmarshal(bytes.TrimSuffix(raw, []byte("\n")), &rec) == nil && matches(rec, f) {
				out = append(out, rec)
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return nil, errors.New("audit: cannot read the log")
			}
			break
		}
	}
	if f.Tail > 0 && len(out) > f.Tail {
		out = out[len(out)-f.Tail:]
	}
	return out, nil
}

func matches(r Record, f Filter) bool {
	if f.Event != "" && r.Event != f.Event {
		return false
	}
	if f.Name != "" {
		found := false
		for _, n := range r.Names {
			if n == f.Name {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if !f.Since.IsZero() {
		ts, err := time.Parse(time.RFC3339Nano, r.TS)
		if err != nil || ts.Before(f.Since) {
			return false
		}
	}
	return true
}
