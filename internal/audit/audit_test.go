package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qbitdevz/qbit-vault/internal/perm"
)

func capture(name string) Record {
	return Record{Event: EventCapture, Session: "cli", Names: []string{name}, Layer: "global", By: "user"}
}

func appendN(t *testing.T, home string, n int) {
	t.Helper()
	for i := 1; i <= n; i++ {
		if err := Append(home, capture(fmt.Sprintf("KEY_%d", i))); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
}

func logPath(home string) string  { return filepath.Join(home, logFile) }
func headPath(home string) string { return filepath.Join(home, headFile) }

func readLines(t *testing.T, home string) []string {
	t.Helper()
	b, err := os.ReadFile(logPath(home))
	if err != nil {
		t.Fatal(err)
	}
	s := strings.TrimSuffix(string(b), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func writeLines(t *testing.T, home string, lines []string) {
	t.Helper()
	data := ""
	if len(lines) > 0 {
		data = strings.Join(lines, "\n") + "\n"
	}
	if err := os.WriteFile(logPath(home), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func wantProblem(t *testing.T, home string, line int, reason string) Result {
	t.Helper()
	res, err := Verify(home)
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid || res.Problem == nil {
		t.Fatalf("chain reported valid, want %s at line %d", reason, line)
	}
	if res.Problem.Reason != reason || res.Problem.Line != line {
		t.Fatalf("problem = %+v, want %s at line %d", *res.Problem, reason, line)
	}
	return res
}

func TestChainOfAppendsVerifies(t *testing.T) {
	home := t.TempDir()
	appendN(t, home, 25)
	res, err := Verify(home)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid || res.Records != 25 || res.Problem != nil {
		t.Fatalf("result = %+v", res)
	}
	lines := readLines(t, home)
	prev := Genesis
	for i, l := range lines {
		var r Record
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			t.Fatal(err)
		}
		if r.Seq != uint64(i+1) || r.Prev != prev {
			t.Fatalf("line %d: seq=%d prev ok=%v", i+1, r.Seq, r.Prev == prev)
		}
		if r.Hash != recordHash(r) {
			t.Fatalf("line %d: hash mismatch", i+1)
		}
		prev = sum([]byte(l))
	}
	var h head
	b, _ := os.ReadFile(headPath(home))
	if err := json.Unmarshal(b, &h); err != nil || h.Seq != 25 {
		t.Fatalf("head = %+v, %v", h, err)
	}
}

func TestFieldOrderIsFixed(t *testing.T) {
	home := t.TempDir()
	code := 3
	ms := int64(12)
	r := Record{
		Event: EventExec, Session: "cli", Host: &Host{Name: "h", Version: "1"}, Names: []string{"A_KEY"},
		Layer: "global", By: "user", Reason: "r", Cwd: "/c", Refusal: "x", Scope: "once", ExpiresAt: "t",
		Command: "cmd", ExitCode: &code, DurationMS: &ms, Redactions: 2, Outcome: "ok", Detail: "d",
	}
	if err := Append(home, r); err != nil {
		t.Fatal(err)
	}
	line := readLines(t, home)[0]
	keys := []string{"ts", "seq", "prev", "event", "session", "host", "names", "layer", "by", "reason", "cwd",
		"refusal", "scope", "expires_at", "command", "exit_code", "duration_ms", "redactions", "outcome", "detail", "hash"}
	at := -1
	for _, k := range keys {
		i := strings.Index(line, `"`+k+`":`)
		if i <= at {
			t.Fatalf("key %s out of order or missing", k)
		}
		at = i
	}
}

func TestEmptyAndMissingLogAreValid(t *testing.T) {
	for name, home := range map[string]string{
		"empty":   t.TempDir(),
		"missing": filepath.Join(t.TempDir(), "absent"),
	} {
		res, err := Verify(home)
		if err != nil || !res.Valid || res.Records != 0 {
			t.Errorf("%s: result = %+v, err = %v", name, res, err)
		}
		recs, err := Read(home, Filter{})
		if err != nil || len(recs) != 0 {
			t.Errorf("%s: Read = %v, %v", name, recs, err)
		}
	}
}

func TestAppendNeedsHome(t *testing.T) {
	err := Append(filepath.Join(t.TempDir(), "absent"), capture("A_KEY"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v, want ErrNotExist", err)
	}
	if strings.Contains(err.Error(), "absent") {
		t.Fatalf("error leaks the path: %q", err)
	}
}

func TestEditedMiddleLineIsBadHash(t *testing.T) {
	home := t.TempDir()
	appendN(t, home, 6)
	lines := readLines(t, home)
	lines[2] = strings.Replace(lines[2], "KEY_3", "KEY_X", 1)
	writeLines(t, home, lines)
	res := wantProblem(t, home, 3, BadHash)
	if res.Problem.Seq != 3 || res.Records != 2 {
		t.Fatalf("result = %+v", res)
	}
}

func TestEditedLineWithRecomputedHashIsCaughtByNextPrev(t *testing.T) {
	home := t.TempDir()
	appendN(t, home, 5)
	lines := readLines(t, home)
	var r Record
	_ = json.Unmarshal([]byte(lines[2]), &r)
	r.Names = []string{"OTHER"}
	r.Hash = recordHash(r)
	b, _ := json.Marshal(r)
	lines[2] = string(b)
	writeLines(t, home, lines)
	wantProblem(t, home, 4, BadPrev)
}

func TestNonCanonicalLineIsBadHash(t *testing.T) {
	home := t.TempDir()
	appendN(t, home, 3)
	lines := readLines(t, home)
	lines[1] = strings.Replace(lines[1], `"hash":`, `"extra":1,"hash":`, 1)
	writeLines(t, home, lines)
	wantProblem(t, home, 2, BadHash)
}

func TestDeletedMiddleLineIsBadPrev(t *testing.T) {
	home := t.TempDir()
	appendN(t, home, 6)
	lines := readLines(t, home)
	writeLines(t, home, append(lines[:2:2], lines[3:]...))
	wantProblem(t, home, 3, BadPrev)
}

func TestReorderedLines(t *testing.T) {
	home := t.TempDir()
	appendN(t, home, 6)
	lines := readLines(t, home)
	lines[1], lines[2] = lines[2], lines[1]
	writeLines(t, home, lines)
	wantProblem(t, home, 2, BadPrev)
}

func TestBadSeq(t *testing.T) {
	home := t.TempDir()
	appendN(t, home, 3)
	lines := readLines(t, home)
	var r Record
	_ = json.Unmarshal([]byte(lines[1]), &r)
	r.Seq = 7
	r.Hash = recordHash(r)
	b, _ := json.Marshal(r)
	lines[1] = string(b)
	// Keep the chain consistent so only seq is wrong.
	var r3 Record
	_ = json.Unmarshal([]byte(lines[2]), &r3)
	r3.Prev = sum(b)
	r3.Seq = 8
	r3.Hash = recordHash(r3)
	b3, _ := json.Marshal(r3)
	lines[2] = string(b3)
	writeLines(t, home, lines)
	wantProblem(t, home, 2, BadSeq)
}

func TestBadJSONLine(t *testing.T) {
	home := t.TempDir()
	appendN(t, home, 3)
	lines := readLines(t, home)
	lines[1] = "not json"
	writeLines(t, home, lines)
	wantProblem(t, home, 2, BadJSON)
}

func TestLastLineTruncatedMidwayIsPartial(t *testing.T) {
	home := t.TempDir()
	appendN(t, home, 4)
	b, _ := os.ReadFile(logPath(home))
	if err := os.WriteFile(logPath(home), b[:len(b)-40], 0o600); err != nil {
		t.Fatal(err)
	}
	wantProblem(t, home, 4, PartialLine)
}

func TestLastWholeLineRemovedIsTruncated(t *testing.T) {
	home := t.TempDir()
	appendN(t, home, 5)
	lines := readLines(t, home)
	writeLines(t, home, lines[:4])
	res := wantProblem(t, home, 4, Truncated)
	if res.Problem.Seq != 5 {
		t.Fatalf("problem = %+v", *res.Problem)
	}
}

func TestLogDeletedWithHeadIsTruncated(t *testing.T) {
	home := t.TempDir()
	appendN(t, home, 3)
	if err := os.Remove(logPath(home)); err != nil {
		t.Fatal(err)
	}
	wantProblem(t, home, 1, Truncated)
	// An emptied log is the same.
	if err := os.WriteFile(logPath(home), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	wantProblem(t, home, 1, Truncated)
}

func TestDeletedLogThenAppendDoesNotRestartAtGenesis(t *testing.T) {
	for name, wipe := range map[string]func(string) error{
		"deleted": os.Remove,
		"emptied": func(p string) error { return os.WriteFile(p, nil, 0o600) },
	} {
		home := t.TempDir()
		appendN(t, home, 3)
		lines := readLines(t, home)
		if err := wipe(logPath(home)); err != nil {
			t.Fatal(err)
		}
		appendN(t, home, 1)
		got := readLines(t, home)
		if len(got) != 1 {
			t.Fatalf("%s: %d lines", name, len(got))
		}
		var r Record
		if err := json.Unmarshal([]byte(got[0]), &r); err != nil {
			t.Fatal(err)
		}
		if r.Seq != 4 || r.Prev != sum([]byte(lines[2])) || r.Prev == Genesis {
			t.Fatalf("%s: seq=%d, prev continues the chain=%v", name, r.Seq, r.Prev == sum([]byte(lines[2])))
		}
		wantProblem(t, home, 1, Truncated)
	}
}

func TestHeadWithoutLineHashIsMismatch(t *testing.T) {
	home := t.TempDir()
	appendN(t, home, 2)
	var r Record
	_ = json.Unmarshal([]byte(readLines(t, home)[1]), &r)
	hb, _ := json.Marshal(map[string]any{"seq": 2, "hash": r.Hash})
	if err := os.WriteFile(headPath(home), hb, 0o600); err != nil {
		t.Fatal(err)
	}
	wantProblem(t, home, 2, HeadMismatch)
}

func TestHeadEdited(t *testing.T) {
	home := t.TempDir()
	appendN(t, home, 4)
	good, _ := os.ReadFile(headPath(home))

	for name, edit := range map[string]string{
		"wrong hash": strings.Replace(string(good), `"sha256:`, `"sha256:0`, 1),
		"garbage":    "not json",
		"zero seq":   `{"seq":0,"hash":"x"}`,
	} {
		if err := os.WriteFile(headPath(home), []byte(edit), 0o600); err != nil {
			t.Fatal(err)
		}
		res, _ := Verify(home)
		if res.Valid || res.Problem == nil || res.Problem.Reason != HeadMismatch {
			t.Errorf("%s: result = %+v", name, res)
		}
	}
	// A head ahead of the log is a truncation.
	if err := os.WriteFile(headPath(home), []byte(`{"seq":9,"hash":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	wantProblem(t, home, 4, Truncated)
}

func TestHeadBehindByACrashIsValid(t *testing.T) {
	home := t.TempDir()
	appendN(t, home, 4)
	lines := readLines(t, home)
	var r Record
	_ = json.Unmarshal([]byte(lines[2]), &r)
	hb, _ := json.Marshal(head{Seq: 3, Hash: r.Hash, Line: sum([]byte(lines[2]))})
	if err := os.WriteFile(headPath(home), hb, 0o600); err != nil {
		t.Fatal(err)
	}
	if res, err := Verify(home); err != nil || !res.Valid || res.Records != 4 {
		t.Fatalf("result = %+v, %v", res, err)
	}
	// Appending catches the head up.
	appendN(t, home, 1)
	if res, _ := Verify(home); !res.Valid || res.Records != 5 {
		t.Fatalf("result = %+v", res)
	}
}

// A head is never more than one record behind the log, so a missing head next
// to two or more records was deleted; with a single record it is a crash
// between the log write and the head write.
func TestMissingHeadWithRecordsIsMismatch(t *testing.T) {
	home := t.TempDir()
	appendN(t, home, 3)
	if err := os.Remove(headPath(home)); err != nil {
		t.Fatal(err)
	}
	res := wantProblem(t, home, 3, HeadMismatch)
	if res.Records != 3 || res.Problem.Seq != 4 {
		t.Fatalf("result = %+v, problem = %+v", res, res.Problem)
	}
}

func TestMissingHeadWithOneRecordIsValid(t *testing.T) {
	home := t.TempDir()
	appendN(t, home, 1)
	if err := os.Remove(headPath(home)); err != nil {
		t.Fatal(err)
	}
	if res, _ := Verify(home); !res.Valid || res.Records != 1 {
		t.Fatalf("result = %+v", res)
	}
	// The next audited write puts the head back.
	appendN(t, home, 1)
	if res, _ := Verify(home); !res.Valid || res.Records != 2 {
		t.Fatalf("result = %+v", res)
	}
	if _, _, ok := ReadHead(home); !ok {
		t.Fatal("no head after the next append")
	}
}

func TestAppendAfterMalformedLastLine(t *testing.T) {
	home := t.TempDir()
	appendN(t, home, 3)
	f, err := os.OpenFile(logPath(home), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`{"ts":"half`)
	_ = f.Close()

	// With a readable head, seq continues from the head.
	appendN(t, home, 1)
	lines := readLines(t, home)
	if len(lines) != 5 {
		t.Fatalf("%d lines, want 5 (the partial line stays its own line)", len(lines))
	}
	var r Record
	_ = json.Unmarshal([]byte(lines[4]), &r)
	if r.Seq != 4 || r.Prev != sum([]byte(lines[3])) {
		t.Fatalf("seq = %d, prev ok = %v", r.Seq, r.Prev == sum([]byte(lines[3])))
	}
	wantProblem(t, home, 4, BadJSON)

	// Without a head, seq is the number of lines plus one.
	f, err = os.OpenFile(logPath(home), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("garbage")
	_ = f.Close()
	if err := os.Remove(headPath(home)); err != nil {
		t.Fatal(err)
	}
	appendN(t, home, 1)
	lines = readLines(t, home)
	if len(lines) != 7 {
		t.Fatalf("%d lines, want 7", len(lines))
	}
	_ = json.Unmarshal([]byte(lines[6]), &r)
	if r.Seq != 7 {
		t.Fatalf("seq = %d, want 7 (6 lines + 1)", r.Seq)
	}
}

func TestAppendAfterOverlongLastLine(t *testing.T) {
	home := t.TempDir()
	appendN(t, home, 2)
	f, _ := os.OpenFile(logPath(home), os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.Write(append(bytes.Repeat([]byte("x"), maxTail+10), '\n'))
	_ = f.Close()
	appendN(t, home, 1)
	wantProblem(t, home, 3, BadJSON)
}

func TestConcurrentGoroutinesKeepOneChain(t *testing.T) {
	home := t.TempDir()
	const workers, each = 8, 10
	// 8 writers contending for one lock is far beyond real use; under a
	// loaded machine one goroutine can wait past the default timeout. The
	// test checks chain integrity, not lock latency.
	old := lockOpts
	lockOpts.Timeout = time.Minute
	t.Cleanup(func() { lockOpts = old })
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				if err := Append(home, capture(fmt.Sprintf("W%d_%d", w, i))); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	checkChain(t, home, workers*each)
}

func checkChain(t *testing.T, home string, want int) {
	t.Helper()
	res, err := Verify(home)
	if err != nil || !res.Valid || res.Records != want {
		t.Fatalf("result = %+v, err = %v, want %d valid records", res, err, want)
	}
	seen := map[uint64]bool{}
	recs, _ := Read(home, Filter{})
	for _, r := range recs {
		if seen[r.Seq] {
			t.Fatalf("duplicate seq %d", r.Seq)
		}
		seen[r.Seq] = true
	}
	if len(seen) != want {
		t.Fatalf("%d distinct seqs, want %d", len(seen), want)
	}
}

const helperEnv = "QBIT_VAULT_AUDIT_TEST_HOME"

// TestHelperAppend is the child side of TestTwoProcessesKeepOneChain.
func TestHelperAppend(t *testing.T) {
	home := os.Getenv(helperEnv)
	if home == "" {
		t.Skip("helper process only")
	}
	tag := os.Getenv(helperEnv + "_TAG")
	for i := range 15 {
		if err := Append(home, capture(fmt.Sprintf("%s_%d", tag, i))); err != nil {
			t.Fatalf("child append: %v", err)
		}
	}
}

func TestTwoProcessesKeepOneChain(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns processes")
	}
	home := t.TempDir()
	var cmds []*exec.Cmd
	var outs []*bytes.Buffer
	for _, tag := range []string{"PA", "PB"} {
		c := exec.Command(os.Args[0], "-test.run=^TestHelperAppend$")
		c.Env = append(os.Environ(), helperEnv+"="+home, helperEnv+"_TAG="+tag)
		var out bytes.Buffer
		c.Stdout, c.Stderr = &out, &out
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		cmds, outs = append(cmds, c), append(outs, &out)
	}
	for i, c := range cmds {
		if err := c.Wait(); err != nil {
			t.Fatalf("child %d failed (%d output bytes)", i, outs[i].Len())
		}
	}
	checkChain(t, home, 30)
}

func TestInvalidNameIsNeverWrittenRaw(t *testing.T) {
	home := t.TempDir()
	bad := "TESTSECRET_not a name/\"{}"
	r := capture("GOOD_NAME")
	r.Names = []string{bad, "GOOD_NAME", "lower"}
	if err := Append(home, r); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(logPath(home))
	for _, frag := range []string{"TESTSECRET_", "not a name", "lower"} {
		if bytes.Contains(b, []byte(frag)) {
			t.Fatal("an invalid name reached the log")
		}
	}
	recs, _ := Read(home, Filter{})
	if len(recs) != 1 || len(recs[0].Names) != 1 || recs[0].Names[0] != "GOOD_NAME" || recs[0].Detail != "invalid name" {
		t.Fatalf("records = %+v", recs)
	}
	// An existing detail is kept.
	r.Detail = "replaced"
	_ = Append(home, r)
	recs, _ = Read(home, Filter{Tail: 1})
	if recs[0].Detail != "replaced; invalid name" {
		t.Fatalf("detail = %q", recs[0].Detail)
	}
}

func TestUnknownEvent(t *testing.T) {
	home := t.TempDir()
	for _, e := range []string{"", "nope", "CAPTURE"} {
		if err := Append(home, Record{Event: e, Session: "cli"}); !errors.Is(err, ErrUnknownEvent) {
			t.Errorf("event %q: err = %v", e, err)
		}
	}
	if _, err := os.Stat(logPath(home)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused record created the log")
	}
	for _, e := range events {
		if !ValidEvent(e) {
			t.Errorf("%s not valid", e)
		}
	}
	if !ValidEvent(EventPrompt) || !ValidEvent(EventLink) {
		t.Error("prompt or link is not valid")
	}
	if !ValidEvent(EventRemote) || EventRemote != "remote" {
		t.Error("remote is not valid")
	}
	if !ValidEvent(EventExport) || EventExport != "export" {
		t.Error("export is not valid")
	}
	if len(events) != 19 {
		t.Fatalf("%d events, want 19", len(events))
	}
}

func TestFilesAreOwnerOnly(t *testing.T) {
	home := t.TempDir()
	appendN(t, home, 2)
	for _, p := range []string{logPath(home), headPath(home)} {
		if ok, detail := perm.Check(p); !ok {
			t.Errorf("%s not owner-only: %s", filepath.Base(p), detail)
		}
	}
	entries, _ := os.ReadDir(home)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") || e.Name() == lockName {
			t.Errorf("leftover %s", e.Name())
		}
	}
}

func TestReadFilters(t *testing.T) {
	home := t.TempDir()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tick := t0
	prev := now
	now = func() time.Time { tick = tick.Add(time.Hour); return tick }
	t.Cleanup(func() { now = prev })

	for _, r := range []Record{
		{Event: EventInit, Session: "cli"},
		capture("A_KEY"),
		{Event: EventRm, Session: "cli", Names: []string{"A_KEY"}},
		capture("B_KEY"),
		{Event: EventRefusal, Session: "cli", Refusal: "unknown_secret", Names: []string{"B_KEY"}},
	} {
		if err := Append(home, r); err != nil {
			t.Fatal(err)
		}
	}
	seqs := func(f Filter) string {
		recs, err := Read(home, f)
		if err != nil {
			t.Fatal(err)
		}
		var b strings.Builder
		for _, r := range recs {
			fmt.Fprintf(&b, "%d", r.Seq)
		}
		return b.String()
	}
	for name, tc := range map[string]struct {
		f    Filter
		want string
	}{
		"all, oldest first":      {Filter{}, "12345"},
		"tail":                   {Filter{Tail: 2}, "45"},
		"tail larger than log":   {Filter{Tail: 99}, "12345"},
		"name":                   {Filter{Name: "A_KEY"}, "23"},
		"event":                  {Filter{Event: EventCapture}, "24"},
		"since":                  {Filter{Since: t0.Add(3*time.Hour + time.Minute)}, "45"},
		"since at the boundary":  {Filter{Since: t0.Add(3 * time.Hour)}, "345"},
		"tail after filter":      {Filter{Name: "B_KEY", Tail: 1}, "5"},
		"name and event":         {Filter{Name: "B_KEY", Event: EventCapture}, "4"},
		"no match":               {Filter{Name: "C_KEY"}, ""},
		"unknown name is no hit": {Filter{Name: "nope"}, ""},
	} {
		if got := seqs(tc.f); got != tc.want {
			t.Errorf("%s: got %q, want %q", name, got, tc.want)
		}
	}
}

func TestReadSkipsMalformedLines(t *testing.T) {
	home := t.TempDir()
	appendN(t, home, 3)
	lines := readLines(t, home)
	lines[1] = "garbage"
	writeLines(t, home, lines)
	recs, err := Read(home, Filter{})
	if err != nil || len(recs) != 2 {
		t.Fatalf("records = %d, err = %v", len(recs), err)
	}
}

func FuzzVerify(f *testing.F) {
	dir := f.TempDir()
	lp, hp := filepath.Join(dir, logFile), filepath.Join(dir, headFile)

	home := f.TempDir()
	for i := 1; i <= 3; i++ {
		_ = Append(home, capture(fmt.Sprintf("KEY_%d", i)))
	}
	goodLog, _ := os.ReadFile(logPath(home))
	goodHead, _ := os.ReadFile(headPath(home))
	f.Add(goodLog, goodHead)
	f.Add(goodLog[:len(goodLog)/2], goodHead)
	f.Add([]byte("{}\n"), []byte("{}"))
	f.Add([]byte("\n\n\x00"), []byte(""))
	f.Add([]byte(`{"seq":1}`), []byte(`{"seq":1,"hash":""}`))

	f.Fuzz(func(t *testing.T, log, hd []byte) {
		if err := os.WriteFile(lp, log, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(hp, hd, 0o600); err != nil {
			t.Fatal(err)
		}
		res, err := verifyLog(lp, hp)
		if err != nil {
			t.Fatal("I/O error on a readable file")
		}
		if res.Valid == (res.Problem != nil) {
			t.Fatal("result is both valid and broken, or neither")
		}
	})
}

// Removing the tail of the log and then appending must not heal the
// truncation: the next record continues from the head, so the gap stays
// visible to verify.
func TestTailTruncationNotHealedByAppend(t *testing.T) {
	home := t.TempDir()
	appendN(t, home, 5)
	lines := readLines(t, home)
	kept := strings.Join(lines[:3], "\n") + "\n"
	if err := os.WriteFile(logPath(home), []byte(kept), 0o600); err != nil {
		t.Fatal(err)
	}
	appendN(t, home, 1)
	res, err := Verify(home)
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid {
		t.Fatalf("tail truncation healed by the next append")
	}
}
