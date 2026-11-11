package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qbitdevz/qbit-vault/internal/minisign"
)

type result struct {
	code        int
	out, errOut string
}

func runCLI(t *testing.T, env map[string]string, args ...string) result {
	t.Helper()
	var out, errOut bytes.Buffer
	e := &environment{
		getenv: func(k string) string { return env[k] },
		rand:   rand.Reader,
		now:    func() time.Time { return time.Unix(1700000000, 0) },
		stdout: &out,
		stderr: &errOut,
	}
	return result{run(e, args), out.String(), errOut.String()}
}

// genKey writes the public key to dir and returns its path and the seed it printed.
func genKey(t *testing.T, dir string) (pubPath, seed string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	pubPath = filepath.Join(dir, "release-key.pub")
	r := runCLI(t, nil, "keygen", "--pub", pubPath)
	if r.code != 0 || r.errOut != "" {
		t.Fatalf("keygen: %d %q", r.code, r.errOut)
	}
	return pubPath, strings.TrimSpace(r.out)
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestKeygenThenSignVerifies(t *testing.T) {
	dir := t.TempDir()
	pubPath, seed := genKey(t, dir)
	file := writeFile(t, dir, "checksums.txt", "abc  a.tar.gz\n")
	r := runCLI(t, map[string]string{"QBIT_VAULT_SIGNING_KEY": seed}, "sign", file, "--version", "v1.4.0")
	if r.code != 0 {
		t.Fatalf("sign: %d %q", r.code, r.errOut)
	}
	pubText, _ := os.ReadFile(pubPath)
	pub, err := minisign.ParsePublicKey(pubText)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := os.ReadFile(file + ".minisig")
	if err != nil {
		t.Fatal(err)
	}
	msg, _ := os.ReadFile(file)
	trusted, err := minisign.Verify(pub, msg, sig)
	if err != nil {
		t.Fatal(err)
	}
	if trusted != "timestamp:1700000000 file:checksums.txt version:v1.4.0" {
		t.Fatalf("trusted = %q", trusted)
	}
	if !strings.HasPrefix(string(pubText), "untrusted comment: minisign public key "+pub.ID()+"\n") {
		t.Fatalf("pub = %q", pubText)
	}
}

func TestSignNeverPrintsTheSeed(t *testing.T) {
	dir := t.TempDir()
	_, seed := genKey(t, dir)
	file := writeFile(t, dir, "f", "x")
	r := runCLI(t, map[string]string{"QBIT_VAULT_SIGNING_KEY": seed}, "sign", file, "--version", "v1")
	if r.code != 0 {
		t.Fatalf("sign: %d %q", r.code, r.errOut)
	}
	for _, s := range []string{r.out, r.errOut} {
		if strings.Contains(s, seed) {
			t.Fatalf("seed leaked: %q", s)
		}
	}
	sig, _ := os.ReadFile(file + ".minisig")
	if strings.Contains(string(sig), seed) {
		t.Fatal("seed in signature file")
	}
}

func TestSignRefusesBadKey(t *testing.T) {
	dir := t.TempDir()
	file := writeFile(t, dir, "f", "x")
	short := base64.StdEncoding.EncodeToString(make([]byte, 39))
	cases := map[string]struct {
		env  map[string]string
		want string
	}{
		"missing":    {nil, "QBIT_VAULT_SIGNING_KEY is not set"},
		"empty":      {map[string]string{"QBIT_VAULT_SIGNING_KEY": ""}, "QBIT_VAULT_SIGNING_KEY is not set"},
		"not base64": {map[string]string{"QBIT_VAULT_SIGNING_KEY": "TESTSECRET_nope!"}, "QBIT_VAULT_SIGNING_KEY is malformed"},
		"short":      {map[string]string{"QBIT_VAULT_SIGNING_KEY": short}, "QBIT_VAULT_SIGNING_KEY is malformed"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r := runCLI(t, c.env, "sign", file, "--version", "v1")
			if r.code == 0 || strings.TrimSpace(r.errOut) != "release-sign: "+c.want || r.out != "" {
				t.Fatalf("got %d out=%q err=%q", r.code, r.out, r.errOut)
			}
			if strings.Contains(r.errOut+r.out, "TESTSECRET_") || strings.Contains(r.errOut, short) {
				t.Fatal("key material in output")
			}
			if _, err := os.Stat(file + ".minisig"); err == nil {
				t.Fatal("signature written despite refusal")
			}
		})
	}
}

func TestSignArguments(t *testing.T) {
	dir := t.TempDir()
	_, seed := genKey(t, dir)
	env := map[string]string{"QBIT_VAULT_SIGNING_KEY": seed}
	file := writeFile(t, dir, "f", "x")
	for name, args := range map[string][]string{
		"no file":        {"sign", "--version", "v1"},
		"no version":     {"sign", file},
		"empty version":  {"sign", file, "--version", ""},
		"newline in tag": {"sign", file, "--version", "v1\nx"},
		"extra arg":      {"sign", file, "other", "--version", "v1"},
		"missing file":   {"sign", filepath.Join(dir, "nope"), "--version", "v1"},
		"unknown":        {"verify"},
		"none":           {},
	} {
		t.Run(name, func(t *testing.T) {
			r := runCLI(t, env, args...)
			if r.code == 0 || r.errOut == "" || strings.Contains(r.errOut+r.out, seed) {
				t.Fatalf("got %d out=%q err=%q", r.code, r.out, r.errOut)
			}
		})
	}
}

func TestKeygenRefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	pubPath, _ := genKey(t, dir)
	before, _ := os.ReadFile(pubPath)
	r := runCLI(t, nil, "keygen", "--pub", pubPath)
	after, _ := os.ReadFile(pubPath)
	if r.code == 0 || r.out != "" || !bytes.Equal(before, after) {
		t.Fatalf("got %d out=%q", r.code, r.out)
	}
}

func TestKeygenIsRandomAndIgnoresEnvironment(t *testing.T) {
	d := t.TempDir()
	_, a := genKey(t, filepath.Join(d, "a"))
	_, b := genKey(t, filepath.Join(d, "b"))
	if a == b || a == "" {
		t.Fatal("seeds must differ")
	}
}

// TestRealMinisignVerifiesOurSignature runs only where `minisign` is installed.
func TestRealMinisignVerifiesOurSignature(t *testing.T) {
	bin, err := exec.LookPath("minisign")
	if err != nil {
		t.Skip("minisign is not on PATH")
	}
	dir := t.TempDir()
	pubPath, seed := genKey(t, dir)
	file := writeFile(t, dir, "checksums.txt", "abc  a.tar.gz\n")
	if r := runCLI(t, map[string]string{"QBIT_VAULT_SIGNING_KEY": seed}, "sign", file, "--version", "v1.4.0"); r.code != 0 {
		t.Fatal(r.errOut)
	}
	out, err := exec.Command(bin, "-V", "-p", pubPath, "-m", file, "-x", file+".minisig").CombinedOutput()
	if err != nil {
		t.Fatalf("minisign -V: %v\n%s", err, out)
	}
}
