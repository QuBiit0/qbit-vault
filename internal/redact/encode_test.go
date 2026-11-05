package redact

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"net/url"
	"strings"
	"testing"
)

// randBytes returns n bytes biased toward the interesting cases for the
// encoders: ASCII specials, controls, multi-byte runes and invalid UTF-8.
func randBytes(rng *rand.Rand, n int) []byte {
	alphabet := []string{
		"a", "Z", "0", " ", "-", "_", ".", "~", "$", "&", "+", "=", ":", "@", "/", ";", ",", "?",
		"<", ">", "\"", "\\", "\n", "\r", "\t", "\b", "\f", "\x00", "\x1f", "\x7f",
		"é", "€", "😀", "\u2028", "\u2029", "\xff", "\xc3",
	}
	var b []byte
	for len(b) < n {
		b = append(b, alphabet[rng.Intn(len(alphabet))]...)
	}
	return b
}

func TestPercentMatchesNetURL(t *testing.T) {
	check := func(v []byte) {
		t.Helper()
		if got, want := string(percent(v, pctQuery, false)), url.QueryEscape(string(v)); got != want {
			t.Fatalf("query mismatch for input of len %d", len(v))
		}
		if got, want := string(percent(v, pctPath, false)), url.PathEscape(string(v)); got != want {
			t.Fatalf("path mismatch for input of len %d", len(v))
		}
		if got, want := string(percent(v, pctQuery, true)), lowerPercent(url.QueryEscape(string(v))); got != want {
			t.Fatalf("lower query mismatch for input of len %d", len(v))
		}
	}
	for c := 0; c < 256; c++ {
		check([]byte{byte(c)})
	}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 500; i++ {
		check(randBytes(rng, 1+rng.Intn(40)))
	}
}

func TestPercentStrictEscapesEverythingButUnreserved(t *testing.T) {
	got := string(percent([]byte("a b$&+=:@~-._"), pctStrict, false))
	if want := "a%20b%24%26%2B%3D%3A%40~-._"; got != want {
		t.Fatalf("strict percent mismatch: got %q", got)
	}
}

func TestJSONEscapeMatchesEncodingJSON(t *testing.T) {
	std := func(v []byte, html bool) []byte {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(html)
		if err := enc.Encode(string(v)); err != nil {
			t.Fatal(err)
		}
		out := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
		return out[1 : len(out)-1]
	}
	rng := rand.New(rand.NewSource(2))
	inputs := [][]byte{}
	for c := 0; c < 256; c++ {
		inputs = append(inputs, []byte{byte(c)})
	}
	for i := 0; i < 500; i++ {
		inputs = append(inputs, randBytes(rng, 1+rng.Intn(40)))
	}
	for _, v := range inputs {
		for _, html := range []bool{false, true} {
			// Go 1.27 writes the replacement character for an invalid byte
			// literally, Go 1.26 as an escape: the one this Go produces must be
			// one of the two forms the redactor registers.
			want := std(v, html)
			if !bytes.Equal(jsonEscapeInvalid(v, html, false, false, false), want) &&
				!bytes.Equal(jsonEscapeInvalid(v, html, false, false, true), want) {
				t.Fatalf("json mismatch (html=%v) for input of len %d", html, len(v))
			}
		}
	}
}

func TestJSONEscapeASCIIVariants(t *testing.T) {
	v := []byte("é😀\x01")
	if got, want := string(jsonEscape(v, false, true, false)), `\u00e9\ud83d\ude00\u0001`; got != want {
		t.Fatalf("ascii lower: got %q", got)
	}
	if got, want := string(jsonEscape(v, false, true, true)), `\u00E9\uD83D\uDE00\u0001`; got != want {
		t.Fatalf("ascii upper: got %q", got)
	}
}

func TestInnerBase64IsStableUnderEmbedding(t *testing.T) {
	v := []byte("a-value-of-some-length")
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
		for align := 0; align < 3; align++ {
			inner := innerBase64(enc, v, align)
			if len(inner) < 8 {
				t.Fatalf("align %d: inner too short (%d)", align, len(inner))
			}
			for _, pre := range []string{"", "x", "xy", "xyz", "user:"} {
				if len(pre)%3 != align {
					continue
				}
				for _, post := range []string{"", "!", "!!", "tail"} {
					blob := enc.EncodeToString([]byte(pre + string(v) + post))
					if !strings.Contains(blob, string(inner)) {
						t.Fatalf("align %d: inner missing from blob (pre %d, post %d)", align, len(pre), len(post))
					}
				}
			}
		}
	}
}

// lowerPercent lowercases the hex digits of every %XX sequence.
func lowerPercent(s string) string {
	b := []byte(s)
	for i := 0; i+2 < len(b); i++ {
		if b[i] == '%' {
			b[i+1] |= 0x20
			b[i+2] |= 0x20
			i += 2
		}
	}
	return string(b)
}
