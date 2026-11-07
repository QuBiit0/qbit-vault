package redact

import (
	"bytes"
	"testing"
	"unicode/utf16"
)

// utf16Bytes encodes s as UTF-16 in the given byte order, independently of
// this package's encoder.
func utf16Bytes(s string, bigEndian bool) []byte {
	var b []byte
	for _, u := range utf16.Encode([]rune(s)) {
		if bigEndian {
			b = append(b, byte(u>>8), byte(u))
		} else {
			b = append(b, byte(u), byte(u>>8))
		}
	}
	return b
}

// A-F4: PowerShell 5.1 writes UTF-16LE; the value must not survive in it.
func TestUTF16FormsAreReplaced(t *testing.T) {
	values := []string{fixture, "TESTSECRET_é😀_utf16_0123", "abcd"}
	for _, v := range values {
		r := mustNew(t, sec("API_KEY", v))
		for _, be := range []bool{false, true} {
			enc := utf16Bytes(v, be)
			bom := []byte{0xFF, 0xFE}
			if be {
				bom = []byte{0xFE, 0xFF}
			}
			for name, in := range map[string][]byte{
				"bare":     append(append([]byte("pre "), enc...), []byte(" post")...),
				"with BOM": append(append(append([]byte(nil), bom...), enc...), []byte("tail")...),
			} {
				out, n := r.Bytes(in)
				if bytes.Contains(out, enc) || n != 1 || !bytes.Contains(out, []byte(token)) {
					t.Errorf("%q be=%v %s: n=%d outlen=%d", "value", be, name, n, len(out))
				}
			}
		}
	}
}

func TestUTF16ChunkedStream(t *testing.T) {
	r := mustNew(t, sec("API_KEY", fixture))
	enc := utf16Bytes(fixture, false)
	input := append(append([]byte{0xFF, 0xFE}, enc...), utf16Bytes(" ok", false)...)
	for size := 1; size <= 9; size++ {
		var dst bytes.Buffer
		w := r.Writer(&dst)
		for rest := input; len(rest) > 0; {
			k := min(size, len(rest))
			if _, err := w.Write(rest[:k]); err != nil {
				t.Fatal(err)
			}
			rest = rest[k:]
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(dst.Bytes(), enc) {
			t.Fatalf("chunk size %d: UTF-16 value survived", size)
		}
	}
}

func TestUTF16NoFalsePositives(t *testing.T) {
	r := mustNew(t, sec("API_KEY", fixture))
	in := utf16Bytes("TESTSECRET_redact_value_other", false)
	if out, n := r.Bytes(in); n != 0 || !bytes.Equal(out, in) {
		t.Fatalf("n=%d changed=%v", n, !bytes.Equal(out, in))
	}
}
