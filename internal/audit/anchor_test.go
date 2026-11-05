package audit

import (
	"os"
	"testing"
)

// The remote anchors (REMOTE_SYNC § 8): the head of the log, uploaded now
// and then, must still match the raw line at its seq.

func anchorOf(t *testing.T, home string) AnchorPoint {
	t.Helper()
	seq, line, ok := ReadHead(home)
	if !ok {
		t.Fatal("no readable head")
	}
	return AnchorPoint{Seq: seq, Line: line}
}

func TestReadHeadReportsTheLastRecord(t *testing.T) {
	home := t.TempDir()
	if _, _, ok := ReadHead(home); ok {
		t.Fatal("a head without a log")
	}
	appendN(t, home, 3)
	seq, line, ok := ReadHead(home)
	lines := readLines(t, home)
	if !ok || seq != 3 || line != sum([]byte(lines[2])) {
		t.Fatalf("head = %d %q %v", seq, line, ok)
	}
}

func TestCheckAnchorsPassesWhileTheLogIsTheOneAnchored(t *testing.T) {
	home := t.TempDir()
	appendN(t, home, 2)
	first := anchorOf(t, home)
	appendN(t, home, 3) // the log grows past the anchor
	last := anchorOf(t, home)
	p, err := CheckAnchors(home, []AnchorPoint{first, last})
	if err != nil || p != nil {
		t.Fatalf("problem = %+v err = %v", p, err)
	}
	if p, err := CheckAnchors(home, nil); err != nil || p != nil {
		t.Fatalf("no anchors: %+v %v", p, err)
	}
}

func TestCheckAnchorsFindsARewrittenLine(t *testing.T) {
	home := t.TempDir()
	appendN(t, home, 4)
	pts := []AnchorPoint{{Seq: 2, Line: sum([]byte(readLines(t, home)[1]))}, anchorOf(t, home)}
	// A rewrite that keeps the chain valid: a new log with other records.
	for _, f := range []string{logPath(home), headPath(home)} {
		if err := os.Remove(f); err != nil {
			t.Fatal(err)
		}
	}
	for i := 1; i <= 4; i++ {
		if err := Append(home, capture("OTHER")); err != nil {
			t.Fatal(err)
		}
	}
	if res, err := Verify(home); err != nil || !res.Valid {
		t.Fatalf("the forged log must verify on its own: %+v %v", res, err)
	}
	p, err := CheckAnchors(home, pts)
	if err != nil || p == nil || p.Reason != AnchorMismatch || p.Line != 2 || p.Seq != 2 {
		t.Fatalf("problem = %+v err = %v", p, err)
	}
}

func TestCheckAnchorsFindsATruncatedLog(t *testing.T) {
	home := t.TempDir()
	appendN(t, home, 5)
	pt := anchorOf(t, home)
	for _, f := range []string{logPath(home), headPath(home)} {
		if err := os.Remove(f); err != nil {
			t.Fatal(err)
		}
	}
	appendN(t, home, 2)
	p, err := CheckAnchors(home, []AnchorPoint{pt})
	if err != nil || p == nil || p.Reason != Truncated || p.Seq != 5 {
		t.Fatalf("problem = %+v err = %v", p, err)
	}
	// No log at all is shorter than any anchor.
	_ = os.Remove(logPath(home))
	if p, err := CheckAnchors(home, []AnchorPoint{pt}); err != nil || p == nil || p.Reason != Truncated {
		t.Fatalf("missing log: %+v %v", p, err)
	}
}
