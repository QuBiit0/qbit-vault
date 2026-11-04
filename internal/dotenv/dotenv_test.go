package dotenv

import (
	"errors"
	"strings"
	"testing"
)

func parse(t *testing.T, in string) (map[string]string, []string, int) {
	t.Helper()
	es, skipped, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	m := map[string]string{}
	var order []string
	for _, e := range es {
		m[e.Name] = string(e.Value)
		order = append(order, e.Name)
	}
	return m, order, skipped
}

func TestParseForms(t *testing.T) {
	in := strings.Join([]string{
		"# comment",
		"",
		"PLAIN=TESTSECRET_plain",
		"  SPACED  =   TESTSECRET_spaced   ",
		"export EXPORTED=TESTSECRET_exported",
		"COMMENTED=TESTSECRET_value # trailing comment",
		"HASH_IN=TESTSECRET_a#b",
		"SINGLE='TESTSECRET_ $literal \\n # kept'",
		`DOUBLE="TESTSECRET_line1\nline2 \"q\" \\ \t"`,
		"MULTI=\"-----BEGIN KEY-----",
		"TESTSECRET_body",
		"-----END KEY-----\"",
		"SQMULTI='a",
		"b'",
		"CRLF=TESTSECRET_crlf\r",
		"QUOTED_COMMENT=\"TESTSECRET_q\" # after",
	}, "\n")
	m, _, skipped := parse(t, in)
	want := map[string]string{
		"PLAIN":          "TESTSECRET_plain",
		"SPACED":         "TESTSECRET_spaced",
		"EXPORTED":       "TESTSECRET_exported",
		"COMMENTED":      "TESTSECRET_value",
		"HASH_IN":        "TESTSECRET_a#b",
		"SINGLE":         "TESTSECRET_ $literal \\n # kept",
		"DOUBLE":         "TESTSECRET_line1\nline2 \"q\" \\", // the trailing " \t" is trimmed, as by set
		"MULTI":          "-----BEGIN KEY-----\nTESTSECRET_body\n-----END KEY-----",
		"SQMULTI":        "a\nb",
		"CRLF":           "TESTSECRET_crlf",
		"QUOTED_COMMENT": "TESTSECRET_q",
	}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("%s = %q, want %q", k, m[k], v)
		}
	}
	if len(m) != len(want) || skipped != 0 {
		t.Fatalf("got %d entries, skipped %d", len(m), skipped)
	}
}

func TestParseSkipsInvalidNamesAndEmptyValues(t *testing.T) {
	in := "lower=TESTSECRET_x\n1BAD=y\nNO_EQUALS\nEMPTY=\nBLANK=   \nOK=TESTSECRET_ok\n=nothing\n"
	m, _, skipped := parse(t, in)
	if len(m) != 1 || m["OK"] != "TESTSECRET_ok" || skipped != 6 {
		t.Fatalf("m=%v skipped=%d", m, skipped)
	}
}

func TestParseLastDuplicateWinsInFirstOrder(t *testing.T) {
	m, order, _ := parse(t, "A=1\nB=2\nA=3\n")
	if m["A"] != "3" || strings.Join(order, ",") != "A,B" {
		t.Fatalf("m=%v order=%v", m, order)
	}
}

func TestParseUnterminatedQuoteNamesLineOnly(t *testing.T) {
	for _, in := range []string{"A=ok\nB=\"TESTSECRET_never_closed\nC=x\n", "A='TESTSECRET_open"} {
		_, _, err := Parse([]byte(in))
		var le *LineError
		if !errors.As(err, &le) {
			t.Fatalf("err=%v", err)
		}
		if strings.Contains(err.Error(), "TESTSECRET_") {
			t.Fatal("error echoes the value")
		}
	}
	_, _, err := Parse([]byte("A=ok\nB=\"TESTSECRET_never_closed\n"))
	if err.Error() != "line 2: unterminated quote" {
		t.Fatalf("err=%q", err)
	}
}

func TestParseRejectsTrailingGarbageAfterQuote(t *testing.T) {
	_, _, err := Parse([]byte("A=\"x\"TESTSECRET_garbage\n"))
	if err == nil || err.Error() != "line 1: text after the closing quote" {
		t.Fatalf("err=%v", err)
	}
}

func TestWipe(t *testing.T) {
	es, _, _ := Parse([]byte("A=TESTSECRET_wipe\n"))
	v := es[0].Value
	Wipe(es)
	for _, b := range v {
		if b != 0 {
			t.Fatal("value not wiped")
		}
	}
}

// FuzzParse: arbitrary input never panics and an error never carries content.
func FuzzParse(f *testing.F) {
	for _, s := range []string{"A=1", "A=\"x\ny\"", "A='", "export B=2 # c", "\r\n=\n\"", "A=\"\\"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		es, _, err := Parse(in)
		if err != nil {
			var le *LineError
			if !errors.As(err, &le) || le.What == "" || le.Line < 1 {
				t.Fatalf("untyped error %v", err)
			}
			return
		}
		for _, e := range es {
			if !nameRE.MatchString(e.Name) || len(e.Value) == 0 {
				t.Fatalf("bad entry %q", e.Name)
			}
		}
	})
}
