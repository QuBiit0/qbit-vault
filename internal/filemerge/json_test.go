package filemerge

import (
	"errors"
	"testing"
)

var mcpEdit = JSONEdit{
	Path:  []string{"mcpServers", "qbit-vault"},
	Value: []byte(`{"command":"qbit-vault","args":["mcp"]}`),
}

var hookEdit = JSONEdit{
	Path:   []string{"hooks", "PreToolUse"},
	Marker: "qbit-vault hook pre-bash",
	Value:  []byte(`{"matcher":"Bash","hooks":[{"type":"command","command":"qbit-vault hook pre-bash"}]}`),
}

var denyEdit = JSONEdit{
	Path:   []string{"permissions", "deny"},
	Marker: `Read(C:\Users\Ana\.qbit-vault/**)`,
	Value:  []byte(`"Read(C:\\Users\\Ana\\.qbit-vault/**)"`),
}

func TestMergeJSONGolden(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		edits []JSONEdit
		want  string
	}{
		{
			name:  "empty file creates pretty doc",
			in:    "",
			edits: []JSONEdit{mcpEdit},
			want: `{
  "mcpServers": {
    "qbit-vault": {
      "command": "qbit-vault",
      "args": [
        "mcp"
      ]
    }
  }
}
`,
		},
		{
			name:  "append member keeps order and user layout",
			in:    "{\n    \"theme\":   \"dark\",\n    \"model\" : \"x\"\n}\n",
			edits: []JSONEdit{{Path: []string{"k"}, Value: []byte(`1`)}},
			want:  "{\n    \"theme\":   \"dark\",\n    \"model\" : \"x\",\n    \"k\" : 1\n}\n",
		},
		{
			name:  "nested into existing object, sibling untouched",
			in:    "{\n\t\"mcpServers\": {\n\t\t\"other\": {\"command\": \"x\"}\n\t}\n}",
			edits: []JSONEdit{{Path: []string{"mcpServers", "qbit-vault"}, Value: []byte(`{"command":"q"}`)}},
			want:  "{\n\t\"mcpServers\": {\n\t\t\"other\": {\"command\": \"x\"},\n\t\t\"qbit-vault\": {\n\t\t\t\"command\": \"q\"\n\t\t}\n\t}\n}",
		},
		{
			name:  "replace existing value in place",
			in:    `{"a":1,"mcpServers":{"qbit-vault":{"command":"old"},"z":2},"b":3}`,
			edits: []JSONEdit{{Path: []string{"mcpServers", "qbit-vault"}, Value: []byte(`{"command":"new"}`)}},
			want:  `{"a":1,"mcpServers":{"qbit-vault":{"command":"new"},"z":2},"b":3}`,
		},
		{
			name:  "semantically equal value leaves bytes alone",
			in:    "{\"mcpServers\": {\"qbit-vault\":   {\"command\": \"q\"}}}\n",
			edits: []JSONEdit{{Path: []string{"mcpServers", "qbit-vault"}, Value: []byte(`{"command":"q"}`)}},
			want:  "{\"mcpServers\": {\"qbit-vault\":   {\"command\": \"q\"}}}\n",
		},
		{
			name:  "empty object root",
			in:    "{}\n",
			edits: []JSONEdit{{Path: []string{"a"}, Value: []byte(`true`)}},
			want:  "{\n  \"a\": true\n}\n",
		},
		{
			name:  "compact one-line file stays compact",
			in:    `{"a":1}`,
			edits: []JSONEdit{{Path: []string{"b"}, Value: []byte(`{"c":[1,2]}`)}},
			want:  `{"a":1,"b":{"c":[1,2]}}`,
		},
		{
			name:  "array: user entry plus ours appended",
			in:    "{\n  \"hooks\": {\n    \"PreToolUse\": [\n      {\"matcher\": \"Edit\", \"hooks\": []}\n    ]\n  }\n}\n",
			edits: []JSONEdit{hookEdit},
			want:  "{\n  \"hooks\": {\n    \"PreToolUse\": [\n      {\"matcher\": \"Edit\", \"hooks\": []},\n      {\n        \"matcher\": \"Bash\",\n        \"hooks\": [\n          {\n            \"type\": \"command\",\n            \"command\": \"qbit-vault hook pre-bash\"\n          }\n        ]\n      }\n    ]\n  }\n}\n",
		},
		{
			name:  "array: our entry replaced, user entries kept",
			in:    `{"hooks":{"PreToolUse":[{"matcher":"A"},{"matcher":"Bash","hooks":[{"command":"qbit-vault hook pre-bash --old"}]},{"matcher":"B"}]}}`,
			edits: []JSONEdit{hookEdit},
			want:  `{"hooks":{"PreToolUse":[{"matcher":"A"},{"matcher":"Bash","hooks":[{"type":"command","command":"qbit-vault hook pre-bash"}]},{"matcher":"B"}]}}`,
		},
		{
			name:  "array: duplicate owned entries collapse to one",
			in:    `{"hooks":{"PreToolUse":[{"c":"qbit-vault hook pre-bash"},{"u":1},{"c":"qbit-vault hook pre-bash"}]}}`,
			edits: []JSONEdit{hookEdit},
			want:  `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"qbit-vault hook pre-bash"}]},{"u":1}]}}`,
		},
		{
			name:  "string array entry matched by decoded value (windows backslashes)",
			in:    `{"permissions":{"deny":["Bash(rm -rf /)"]}}`,
			edits: []JSONEdit{denyEdit},
			want:  `{"permissions":{"deny":["Bash(rm -rf /)","Read(C:\\Users\\Ana\\.qbit-vault/**)"]}}`,
		},
		{
			name:  "string array entry already present is untouched",
			in:    "{\"permissions\":{\"deny\":[\n  \"Read(C:\\\\Users\\\\Ana\\\\.qbit-vault/**)\"\n]}}\n",
			edits: []JSONEdit{denyEdit},
			want:  "{\"permissions\":{\"deny\":[\n  \"Read(C:\\\\Users\\\\Ana\\\\.qbit-vault/**)\"\n]}}\n",
		},
		{
			name:  "missing array created inside existing object",
			in:    "{\n  \"permissions\": {\n    \"allow\": []\n  }\n}\n",
			edits: []JSONEdit{denyEdit},
			want:  "{\n  \"permissions\": {\n    \"allow\": [],\n    \"deny\": [\n      \"Read(C:\\\\Users\\\\Ana\\\\.qbit-vault/**)\"\n    ]\n  }\n}\n",
		},
		{
			name:  "CRLF file keeps CRLF",
			in:    "{\r\n  \"a\": 1\r\n}\r\n",
			edits: []JSONEdit{{Path: []string{"b"}, Value: []byte(`{"c":1}`)}},
			want:  "{\r\n  \"a\": 1,\r\n  \"b\": {\r\n    \"c\": 1\r\n  }\r\n}\r\n",
		},
		{
			name:  "string values with braces and escapes do not confuse the scanner",
			in:    `{"a":"} , { \" ]","b":[1,"]"]}`,
			edits: []JSONEdit{{Path: []string{"c"}, Value: []byte(`0`)}},
			want:  `{"a":"} , { \" ]","b":[1,"]"],"c":0}`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := MergeJSON([]byte(c.in), c.edits)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != c.want {
				t.Fatalf("got:\n%q\nwant:\n%q", got, c.want)
			}
			again, err := MergeJSON(got, c.edits)
			if err != nil || string(again) != string(got) {
				t.Fatalf("not idempotent: %v\n%q\n%q", err, again, got)
			}
		})
	}
}

func TestMergeJSONMultipleEditsIdempotent(t *testing.T) {
	in := "{\n  \"model\": \"x\",\n  \"hooks\": {\"PostToolUse\": []}\n}\n"
	edits := []JSONEdit{mcpEdit, hookEdit, denyEdit}
	a, err := MergeJSON([]byte(in), edits)
	if err != nil {
		t.Fatal(err)
	}
	b, err := MergeJSON(a, edits)
	if err != nil || string(a) != string(b) {
		t.Fatalf("not idempotent: %v", err)
	}
	if got, err := UnmergeJSON(a, edits, false); err != nil {
		t.Fatal(err)
	} else if _, err := MergeJSON(got, edits); err != nil {
		t.Fatal(err)
	}
}

func TestMergeJSONRefusals(t *testing.T) {
	cases := []struct {
		name string
		in   string
		edit JSONEdit
		want error
	}{
		{"invalid json", `{"a": }`, mcpEdit, ErrInvalidJSON},
		{"trailing garbage", `{"a":1} x`, mcpEdit, ErrInvalidJSON},
		{"comments are not JSON", "{\n// c\n\"a\":1}", mcpEdit, ErrInvalidJSON},
		{"BOM", "\xef\xbb\xbf{}", mcpEdit, ErrInvalidJSON},
		{"root is array", `[1]`, mcpEdit, ErrJSONShape},
		{"path element is a string", `{"mcpServers":"x"}`, mcpEdit, ErrJSONShape},
		{"array path is an object", `{"hooks":{"PreToolUse":{}}}`, hookEdit, ErrJSONShape},
		{"duplicate key on path", `{"mcpServers":{},"mcpServers":{}}`, mcpEdit, ErrAmbiguous},
		{"empty path", `{}`, JSONEdit{Value: []byte(`1`)}, ErrInvalidEdit},
		{"invalid value", `{}`, JSONEdit{Path: []string{"a"}, Value: []byte(`{`)}, ErrInvalidEdit},
		{"entry without marker in value", `{}`, JSONEdit{Path: []string{"a"}, Marker: "zzz", Value: []byte(`"x"`)}, ErrInvalidEdit},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := MergeJSON([]byte(c.in), []JSONEdit{c.edit}); !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
}

func TestUnmergeJSONGolden(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		edits []JSONEdit
		prune bool
		want  string
	}{
		{
			name:  "last member removed with its comma",
			in:    "{\n  \"a\": 1,\n  \"mcpServers\": {\n    \"qbit-vault\": {\"command\": \"q\"}\n  },\n  \"b\": 2\n}\n",
			edits: []JSONEdit{mcpEdit},
			want:  "{\n  \"a\": 1,\n  \"mcpServers\": {},\n  \"b\": 2\n}\n",
		},
		{
			name:  "first of several members",
			in:    `{"mcpServers":{"qbit-vault":{"c":1},"other":{"c":2}}}`,
			edits: []JSONEdit{mcpEdit},
			want:  `{"mcpServers":{"other":{"c":2}}}`,
		},
		{
			name:  "last of several members",
			in:    "{\n  \"mcpServers\": {\n    \"other\": {},\n    \"qbit-vault\": {\"c\": 1}\n  }\n}\n",
			edits: []JSONEdit{mcpEdit},
			want:  "{\n  \"mcpServers\": {\n    \"other\": {}\n  }\n}\n",
		},
		{
			name:  "absent key is a no-op",
			in:    "{ \"a\" : 1 }\n",
			edits: []JSONEdit{mcpEdit, hookEdit},
			want:  "{ \"a\" : 1 }\n",
		},
		{
			name:  "array entries removed, user entries stay",
			in:    `{"hooks":{"PreToolUse":[{"matcher":"A"},{"c":"qbit-vault hook pre-bash"}]}}`,
			edits: []JSONEdit{hookEdit},
			want:  `{"hooks":{"PreToolUse":[{"matcher":"A"}]}}`,
		},
		{
			name:  "only array entry left empty without prune",
			in:    `{"hooks":{"PreToolUse":[{"c":"qbit-vault hook pre-bash"}]},"a":1}`,
			edits: []JSONEdit{hookEdit},
			want:  `{"hooks":{"PreToolUse":[]},"a":1}`,
		},
		{
			name:  "prune removes emptied parents but not the root",
			in:    `{"hooks":{"PreToolUse":[{"c":"qbit-vault hook pre-bash"}]},"a":1}`,
			edits: []JSONEdit{hookEdit},
			prune: true,
			want:  `{"a":1}`,
		},
		{
			name:  "prune keeps parents that still hold user keys",
			in:    `{"mcpServers":{"qbit-vault":{},"o":{}}}`,
			edits: []JSONEdit{mcpEdit},
			prune: true,
			want:  `{"mcpServers":{"o":{}}}`,
		},
		{
			name:  "prune to empty root",
			in:    "{\n  \"mcpServers\": {\n    \"qbit-vault\": {}\n  }\n}\n",
			edits: []JSONEdit{mcpEdit},
			prune: true,
			want:  "{}\n",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := UnmergeJSON([]byte(c.in), c.edits, c.prune)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != c.want {
				t.Fatalf("got:\n%q\nwant:\n%q", got, c.want)
			}
		})
	}
}

func TestMergeThenUnmergeRestoresExistingFile(t *testing.T) {
	ins := []string{
		"{\n  \"a\": 1,\n  \"mcpServers\": {\n    \"other\": {\"command\": \"x\"}\n  }\n}\n",
		`{"mcpServers":{"other":{}},"b":2}`,
		"{\n    \"mcpServers\" :  {\"o\":1}\n}",
	}
	for _, in := range ins {
		merged, err := MergeJSON([]byte(in), []JSONEdit{mcpEdit})
		if err != nil {
			t.Fatal(err)
		}
		back, err := UnmergeJSON(merged, []JSONEdit{mcpEdit}, false)
		if err != nil {
			t.Fatal(err)
		}
		if string(back) != in {
			t.Fatalf("roundtrip:\n%q\n%q", back, in)
		}
	}
}

func TestUnmergeJSONRefusesInvalid(t *testing.T) {
	if _, err := UnmergeJSON([]byte(`{"a":`), []JSONEdit{mcpEdit}, false); !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("err = %v", err)
	}
}
