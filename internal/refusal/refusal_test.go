package refusal

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/exitcode"
)

// The enum must be exactly the types listed in CONTRACT.md § Refusals.
func TestTypesMatchContract(t *testing.T) {
	data, err := os.ReadFile("../../contracts/secrets-broker/v1/CONTRACT.md")
	if err != nil {
		t.Fatal(err)
	}
	sec := string(data)
	i := strings.Index(sec, "\n## Refusals")
	if i < 0 {
		t.Fatal("CONTRACT.md has no Refusals section")
	}
	sec = sec[i+1:]
	if j := strings.Index(sec[3:], "\n## "); j >= 0 {
		sec = sec[:j+3]
	}
	row := regexp.MustCompile("(?m)^\\| `([a-z_]+)` \\|")
	var want []string
	for _, m := range row.FindAllStringSubmatch(sec, -1) {
		if m[1] != "type" { // the table header
			want = append(want, m[1])
		}
	}
	var got []string
	for _, ty := range Types() {
		got = append(got, string(ty))
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("types\n got %v\nwant %v", got, want)
	}
}

func TestExitCodes(t *testing.T) {
	for _, ty := range Types() {
		want := exitcode.Refusal
		switch ty {
		case VaultLocked:
			want = exitcode.Locked
		case VaultCorrupt:
			want = exitcode.Corrupt
		}
		if got := New(ty, "").ExitCode(); got != want {
			t.Errorf("%s: exit %d, want %d", ty, got, want)
		}
	}
}

func TestJSONShape(t *testing.T) {
	b, err := json.Marshal(New(UnknownSecret, "GITHUB_TOKEN").Envelope())
	if err != nil {
		t.Fatal(err)
	}
	want := `{"ok":false,"refusal":{"type":"unknown_secret","name":"GITHUB_TOKEN","message":"GITHUB_TOKEN is not stored","retryable":true}}`
	if string(b) != want {
		t.Fatalf("got  %s\nwant %s", b, want)
	}
	b, _ = json.Marshal(New(InvalidName, "").Envelope())
	want = `{"ok":false,"refusal":{"type":"invalid_name","name":null,"message":"invalid secret name","retryable":false}}`
	if string(b) != want {
		t.Fatalf("got  %s\nwant %s", b, want)
	}
}

func TestOverrides(t *testing.T) {
	r := New(Internal, "").WithMessage("vault is busy").WithRetryable(true)
	if r.Message != "vault is busy" || !r.Retryable || r.Type != Internal || r.Name != nil {
		t.Fatalf("unexpected refusal %+v", r)
	}
	if r.Error() != "vault is busy" {
		t.Fatalf("Error() = %q", r.Error())
	}
}

func TestDefaultsAreFixedStrings(t *testing.T) {
	for _, ty := range Types() {
		r := New(ty, "NAME_X")
		if r.Message == "" || !r.Valid() {
			t.Errorf("%s: empty message or invalid", ty)
		}
		if strings.Contains(New(ty, "").Message, "NAME_X") {
			t.Errorf("%s: nameless message mentions a name", ty)
		}
	}
	if (Refusal{Type: "bogus"}).Valid() {
		t.Fatal("unknown type reported valid")
	}
}

func TestPartialIsOptionalAndOnlyOnRequest(t *testing.T) {
	b, err := json.Marshal(New(Timeout, "").Envelope())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "partial") {
		t.Fatalf("no partial output was attached: %s", b)
	}
	r := New(Timeout, "").WithPartial("out text", "err text")
	b, err = json.Marshal(r.Envelope())
	if err != nil {
		t.Fatal(err)
	}
	want := `{"ok":false,"refusal":{"type":"timeout","name":null,"message":"the command timed out","retryable":true,"partial":{"stdout":"out text","stderr":"err text"}}}`
	if string(b) != want {
		t.Fatalf("got  %s\nwant %s", b, want)
	}
}
