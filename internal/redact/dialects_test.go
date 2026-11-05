package redact

import "testing"

// Expected strings are written out by hand, not produced by this package.
const dialectValue = "TESTSECRET_a/b c!*'()~$:@x_01"

func TestPercentDialects(t *testing.T) {
	cases := map[string]string{
		// Python urllib.parse.quote(v) (safe="/"): unreserved plus "/".
		"python upper": "TESTSECRET_a/b%20c%21%2A%27%28%29~%24%3A%40x_01",
		"python lower": "TESTSECRET_a/b%20c%21%2a%27%28%29~%24%3a%40x_01",
		// JavaScript encodeURIComponent: unreserved plus !*'().
		"js upper": "TESTSECRET_a%2Fb%20c!*'()~%24%3A%40x_01",
		"js lower": "TESTSECRET_a%2fb%20c!*'()~%24%3a%40x_01",
	}
	r := mustNew(t, sec("API_KEY", dialectValue))
	for name, enc := range cases {
		t.Run(name, func(t *testing.T) {
			out, n := r.Bytes([]byte("q=" + enc + "&z=1"))
			if string(out) != "q="+token+"&z=1" || n != 1 {
				t.Fatalf("dialect not redacted: n=%d", n)
			}
		})
	}
}

func TestJSONSlashEscapeVariant(t *testing.T) {
	r := mustNew(t, sec("API_KEY", dialectValue))
	for name, enc := range map[string]string{
		"slash escaped": `TESTSECRET_a\/b c!*'()~$:@x_01`,
		"slash plain":   `TESTSECRET_a/b c!*'()~$:@x_01`,
	} {
		t.Run(name, func(t *testing.T) {
			out, n := r.Bytes([]byte(`{"k":"` + enc + `"}`))
			if string(out) != `{"k":"`+token+`"}` || n != 1 {
				t.Fatalf("json form not redacted: n=%d", n)
			}
		})
	}
	// Slash escaping composes with the other JSON options.
	r = mustNew(t, sec("API_KEY", "TESTSECRET_a/b<c>é_end"))
	out, n := r.Bytes([]byte(`x TESTSECRET_a\/b\u003cc\u003e\u00e9_end y`))
	if string(out) != "x "+token+" y" || n != 1 {
		t.Fatalf("slash + html + ascii escapes: n=%d", n)
	}
}
