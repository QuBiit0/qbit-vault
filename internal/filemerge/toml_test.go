package filemerge

import (
	"errors"
	"strings"
	"testing"
)

const tomlOwn = "mcp_servers.qbit-vault"

const tomlBlock = "[mcp_servers.qbit-vault]\ncommand = \"qbit-vault\"\nargs = [\"mcp\"]\n"

const tomlBlockEnv = tomlBlock + "\n[mcp_servers.qbit-vault.env]\nQBIT_VAULT_PROMPT = \"tty\"\n"

func TestMergeTOMLGolden(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		block string
		want  string
	}{
		{
			name:  "missing file",
			in:    "",
			block: tomlBlock,
			want:  tomlBlock,
		},
		{
			name:  "append after user content with comments",
			in:    "# my codex config\nmodel = \"o3\"  # trailing\n\n[mcp_servers.other]\ncommand = \"x\"\n",
			block: tomlBlock,
			want:  "# my codex config\nmodel = \"o3\"  # trailing\n\n[mcp_servers.other]\ncommand = \"x\"\n\n" + tomlBlock,
		},
		{
			name:  "no trailing newline",
			in:    "model = \"o3\"",
			block: tomlBlock,
			want:  "model = \"o3\"\n\n" + tomlBlock,
		},
		{
			name:  "CRLF file gets CRLF block",
			in:    "model = \"o3\"\r\n\r\n[a]\r\nx = 1\r\n",
			block: tomlBlock,
			want:  "model = \"o3\"\r\n\r\n[a]\r\nx = 1\r\n\r\n[mcp_servers.qbit-vault]\r\ncommand = \"qbit-vault\"\r\nargs = [\"mcp\"]\r\n",
		},
		{
			name:  "our table first: replaced in place, rest identical",
			in:    "[mcp_servers.qbit-vault]\ncommand = \"old\"\n\n# keep me\n[other]\nx = 1\n",
			block: tomlBlock,
			want:  tomlBlock + "\n# keep me\n[other]\nx = 1\n",
		},
		{
			name:  "our table in the middle",
			in:    "a = 1\n\n[mcp_servers.qbit-vault]\ncommand = \"old\"\nextra = true\n\n# about b\n[b]\ny = 2\n",
			block: tomlBlock,
			want:  "a = 1\n\n" + tomlBlock + "\n# about b\n[b]\ny = 2\n",
		},
		{
			name:  "our table last, no trailing newline",
			in:    "a = 1\n\n[mcp_servers.qbit-vault]\ncommand = \"old\"",
			block: tomlBlock,
			want:  "a = 1\n\n[mcp_servers.qbit-vault]\ncommand = \"qbit-vault\"\nargs = [\"mcp\"]",
		},
		{
			name:  "subtables are replaced together",
			in:    "[mcp_servers.qbit-vault]\ncommand = \"old\"\n[mcp_servers.qbit-vault.env]\nOLD = \"1\"\n\n[z]\nq = 1\n",
			block: tomlBlockEnv,
			want:  tomlBlockEnv + "\n[z]\nq = 1\n",
		},
		{
			name:  "non-contiguous owned tables collapse into one place",
			in:    "[mcp_servers.qbit-vault]\na = 1\n\n[other]\nb = 2\n\n[mcp_servers.qbit-vault.env]\nc = 3\n",
			block: tomlBlockEnv,
			want:  tomlBlockEnv + "\n[other]\nb = 2\n",
		},
		{
			name:  "similarly named tables are not ours",
			in:    "[mcp_servers.qbit-vault-dev]\ncommand = \"d\"\n\n[mcp_servers.qbit]\nx = 1\n",
			block: tomlBlock,
			want:  "[mcp_servers.qbit-vault-dev]\ncommand = \"d\"\n\n[mcp_servers.qbit]\nx = 1\n\n" + tomlBlock,
		},
		{
			name:  "quoted key spelling of our table is ours",
			in:    "[mcp_servers.\"qbit-vault\"]\ncommand = \"old\"\n",
			block: tomlBlock,
			want:  tomlBlock,
		},
		{
			name:  "multi-line strings and arrays that look like headers",
			in:    "doc = \"\"\"\n[mcp_servers.qbit-vault]\n\"\"\"\nlist = [\n  [1, 2],\n  [3],\n]\n",
			block: tomlBlock,
			want:  "doc = \"\"\"\n[mcp_servers.qbit-vault]\n\"\"\"\nlist = [\n  [1, 2],\n  [3],\n]\n\n" + tomlBlock,
		},
		{
			name:  "parent table without ours is fine",
			in:    "[mcp_servers]\nstartup = 5\n\n[mcp_servers.x]\nc = 1\n",
			block: tomlBlock,
			want:  "[mcp_servers]\nstartup = 5\n\n[mcp_servers.x]\nc = 1\n\n" + tomlBlock,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := MergeTOML([]byte(c.in), tomlOwn, c.block)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != c.want {
				t.Fatalf("got:\n%q\nwant:\n%q", got, c.want)
			}
			again, err := MergeTOML(got, tomlOwn, c.block)
			if err != nil || string(again) != string(got) {
				t.Fatalf("not idempotent: %v\n%q\n%q", err, again, got)
			}
		})
	}
}

func TestMergeTOMLRefusals(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want error
	}{
		{"table defined twice", "[mcp_servers.qbit-vault]\na=1\n[x]\n[mcp_servers.qbit-vault]\nb=2\n", ErrAmbiguous},
		{"subtable defined twice", "[mcp_servers.qbit-vault.env]\na=1\n[mcp_servers.qbit-vault.env]\n", ErrAmbiguous},
		{"array of tables", "[[mcp_servers.qbit-vault]]\na=1\n", ErrAmbiguous},
		{"inline table under parent header", "[mcp_servers]\nqbit-vault = { command = \"x\" }\n", ErrAmbiguous},
		{"quoted inline under parent header", "[mcp_servers]\n\"qbit-vault\" = { command = \"x\" }\n", ErrAmbiguous},
		{"dotted key under parent header", "[mcp_servers]\nqbit-vault.command = \"x\"\n", ErrAmbiguous},
		{"dotted key at root", "mcp_servers.qbit-vault.command = \"x\"\n", ErrAmbiguous},
		{"inline parent at root", "mcp_servers = { qbit-vault = { command = \"x\" } }\n", ErrAmbiguous},
		{"unterminated multi-line string", "a = \"\"\"\nnever closed\n", ErrInvalidTOML},
		{"unterminated array", "a = [\n1,\n", ErrInvalidTOML},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, op := range []string{"merge", "remove"} {
				var err error
				if op == "merge" {
					_, err = MergeTOML([]byte(c.in), tomlOwn, tomlBlock)
				} else {
					_, err = UnmergeTOML([]byte(c.in), tomlOwn)
				}
				if !errors.Is(err, c.want) {
					t.Fatalf("%s: err = %v, want %v", op, err, c.want)
				}
				if strings.Contains(err.Error(), "command") {
					t.Fatalf("error leaks file text: %v", err)
				}
			}
		})
	}
}

func TestMergeTOMLRejectsBadBlock(t *testing.T) {
	bad := []string{
		"",
		"command = \"x\"\n",
		"[other]\nx = 1\n",
		tomlBlock + "[other]\nx = 1\n",
		tomlBlock + tomlBlock,
		"[[mcp_servers.qbit-vault]]\n",
	}
	for _, b := range bad {
		if _, err := MergeTOML(nil, tomlOwn, b); !errors.Is(err, ErrInvalidEdit) {
			t.Errorf("block %q: err = %v", b, err)
		}
	}
	if _, err := MergeTOML(nil, "", tomlBlock); !errors.Is(err, ErrInvalidEdit) {
		t.Errorf("empty table name: %v", err)
	}
}

func TestUnmergeTOMLGolden(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"absent is a no-op", "a = 1\n[b]\nc = 2\n", "a = 1\n[b]\nc = 2\n"},
		{"empty", "", ""},
		{
			name: "first table, comment before next kept",
			in:   tomlBlock + "\n# about other\n[other]\nx = 1\n",
			want: "# about other\n[other]\nx = 1\n",
		},
		{
			name: "middle table with subtable",
			in:   "a = 1\n\n" + tomlBlockEnv + "\n[b]\ny = 2\n",
			want: "a = 1\n\n[b]\ny = 2\n",
		},
		{
			name: "last table drops the separator we added",
			in:   "a = 1\n\n" + tomlBlock,
			want: "a = 1\n",
		},
		{
			name: "last table, CRLF",
			in:   "a = 1\r\n\r\n[mcp_servers.qbit-vault]\r\ncommand = \"q\"\r\n",
			want: "a = 1\r\n",
		},
		{
			name: "only our table leaves an empty file",
			in:   tomlBlockEnv,
			want: "",
		},
		{
			name: "neighbours with similar names stay",
			in:   "[mcp_servers.qbit-vault-dev]\nc = 1\n\n" + tomlBlock,
			want: "[mcp_servers.qbit-vault-dev]\nc = 1\n",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := UnmergeTOML([]byte(c.in), tomlOwn)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != c.want {
				t.Fatalf("got:\n%q\nwant:\n%q", got, c.want)
			}
		})
	}
}

func TestMergeThenUnmergeTOMLRoundTrip(t *testing.T) {
	ins := []string{
		"model = \"o3\"\n",
		"# c\n[a]\nx = 1\n\n[b]\ny = 2\n",
		"a = 1\r\n[b]\r\nc = 2\r\n",
		"",
	}
	for _, in := range ins {
		m, err := MergeTOML([]byte(in), tomlOwn, tomlBlockEnv)
		if err != nil {
			t.Fatal(err)
		}
		back, err := UnmergeTOML(m, tomlOwn)
		if err != nil {
			t.Fatal(err)
		}
		if string(back) != in {
			t.Fatalf("roundtrip of %q gave %q", in, back)
		}
	}
}
