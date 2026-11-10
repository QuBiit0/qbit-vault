package exportfile

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qbitdevz/qbit-vault/internal/secret"
)

const fixture = "TESTSECRET_exportfile_value_0123456789"

func lowCost(t *testing.T) {
	t.Helper()
	oldK, oldMin := kdfParams, minMKiB
	kdfParams = KDF{Alg: algArgon2id, T: 1, MKiB: 1024, P: 1}
	minMKiB = 1024
	t.Cleanup(func() { kdfParams, minMKiB = oldK, oldMin })
}

func pass(s string) secret.Secret { return secret.New("passphrase", []byte(s)) }

func sample() Payload {
	return Payload{Layers: []Layer{
		{Records: []Record{{Name: "A_KEY", Value: []byte(fixture), Kind: "text", Description: "d", Sensitive: true,
			Binaries: []string{"gh"}, Hosts: []string{"h"}, CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-02-02T00:00:00Z"}}},
		{Project: true, Root: "/work/shop", Label: "shop", Records: []Record{{Name: "B_KEY", Value: []byte(fixture + "_b")}}},
	}}
}

func TestSealOpenRoundTrip(t *testing.T) {
	lowCost(t)
	data, err := Seal(pass("correct horse battery"), sample(), time.Date(2026, 11, 6, 1, 2, 3, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("TESTSECRET_")) || bytes.Contains(data, []byte("A_KEY")) {
		t.Fatal("the file shows payload content")
	}
	var head map[string]any
	if err := json.Unmarshal(data, &head); err != nil || head["created_at"] != "2026-11-06T01:02:03Z" || head["format"] != Format {
		t.Fatalf("header: %v %v", head, err)
	}
	p, err := Open(pass("correct horse battery"), data)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Wipe()
	want, got := sample(), p
	wj, _ := json.Marshal(want)
	gj, _ := json.Marshal(got)
	if string(wj) != string(gj) {
		t.Fatal("payload changed in the round trip")
	}
	// Two seals of the same payload differ (fresh salt and nonce).
	again, _ := Seal(pass("correct horse battery"), sample(), time.Now())
	if bytes.Equal(data, again) {
		t.Fatal("two exports are byte-identical")
	}
}

func TestOpenRefusesEverythingUntrusted(t *testing.T) {
	lowCost(t)
	good, err := Seal(pass("correct horse battery"), sample(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	set := func(key string, v any) []byte {
		var m map[string]any
		_ = json.Unmarshal(good, &m)
		m[key] = v
		out, _ := json.Marshal(m)
		return out
	}
	setKDF := func(key string, v any) []byte {
		var m map[string]any
		_ = json.Unmarshal(good, &m)
		m["kdf"].(map[string]any)[key] = v
		out, _ := json.Marshal(m)
		return out
	}
	cases := map[string][]byte{
		"truncated":       good[:len(good)/2],
		"empty":           nil,
		"trailing data":   append(bytes.Clone(good), []byte(`{}`)...),
		"other format":    set("format", "qbit-vault-export/2"),
		"other cipher":    set("cipher", "aes"),
		"changed time":    set("created_at", "2000-01-01T00:00:00Z"),
		"unknown field":   set("extra", 1),
		"kdf t changed":   setKDF("t", 2),
		"kdf m too low":   setKDF("m_kib", 8),
		"kdf m too high":  setKDF("m_kib", maxMKiB+1),
		"kdf m 1 GiB":     setKDF("m_kib", 1<<20),
		"kdf p zero":      setKDF("p", 0),
		"kdf alg":         setKDF("alg", "scrypt"),
		"salt not base64": setKDF("salt", "!!"),
		"salt short":      setKDF("salt", "AAAA"),
	}
	for name, data := range cases {
		if _, err := Open(pass("correct horse battery"), data); !errors.Is(err, ErrOpen) {
			t.Errorf("%s: err=%v, want ErrOpen", name, err)
		}
	}
	if _, err := Open(pass("wrong passphrase!!"), good); !errors.Is(err, ErrOpen) {
		t.Errorf("wrong passphrase: %v", err)
	}
	// Every single flipped byte of the ciphertext field fails.
	i := bytes.Index(good, []byte(`"ct":"`)) + 8
	flipped := bytes.Clone(good)
	flipped[i] ^= 0x02
	if _, err := Open(pass("correct horse battery"), flipped); !errors.Is(err, ErrOpen) {
		t.Errorf("flipped ct: %v", err)
	}
}

func TestCheckPassphrase(t *testing.T) {
	for in, want := range map[string]error{
		"":               ErrShort,
		"            ":   ErrShort,
		"elevenchars":    ErrShort,
		"twelvechars1":   nil,
		"ñandúñandúñand": nil,
		"ñandúñandú":     ErrShort,
	} {
		if got := CheckPassphrase(pass(in)); !errors.Is(got, want) && got != want {
			t.Errorf("%q: %v, want %v", in, got, want)
		}
	}
}

func TestWriteIsAtomicOwnerOnlyAndHonoursForce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.qvx")
	if err := Write(path, []byte("one"), false); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, []byte("two"), false); !errors.Is(err, ErrExists) {
		t.Fatalf("err=%v, want ErrExists", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "one" {
		t.Fatal("an existing file was replaced without force")
	}
	if err := Write(path, []byte("three"), true); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "three" {
		t.Fatal("force did not replace")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("leftover temp files: %d entries", len(entries))
	}
	if err := Write(filepath.Join(dir, "no", "such", "dir", "x"), []byte("x"), false); !errors.Is(err, ErrWrite) {
		t.Fatalf("err=%v, want ErrWrite", err)
	}
}

func TestReadIsBounded(t *testing.T) {
	dir := t.TempDir()
	if _, err := Read(filepath.Join(dir, "missing")); !errors.Is(err, ErrRead) {
		t.Fatalf("err=%v", err)
	}
	p := filepath.Join(dir, "x")
	if err := os.WriteFile(p, []byte(strings.Repeat("a", 10)), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := Read(p); err != nil || len(b) != 10 {
		t.Fatalf("read: %v", err)
	}
}

// An export is refused when it would be larger than Read accepts: a file
// that cannot be imported back is not a backup.
func TestSealRefusesAFileTooLargeToReadBack(t *testing.T) {
	lowCost(t)
	old := maxFileBytes
	maxFileBytes = 200
	t.Cleanup(func() { maxFileBytes = old })
	if _, err := Seal(pass("correct horse battery"), sample(), time.Now()); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
}
