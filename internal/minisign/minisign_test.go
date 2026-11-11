package minisign

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/blake2b"
)

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fixture(t *testing.T) (*PublicKey, []byte, []byte) {
	t.Helper()
	pub, err := ParsePublicKey(readTestdata(t, "test-minisign.pub"))
	if err != nil {
		t.Fatal(err)
	}
	return pub, readTestdata(t, "fixture.txt"), readTestdata(t, "fixture.txt.minisig")
}

// makeSig builds a signature file the way a signer would, with a local key.
func makeSig(t *testing.T, alg string, id [8]byte, msg []byte, trusted string) (*PublicKey, []byte) {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	pubKey := priv.Public().(ed25519.PublicKey)
	body := append([]byte(alg), id[:]...)
	signed := msg
	if alg == "ED" {
		h := blake2b.Sum512(msg)
		signed = h[:]
	}
	sig := ed25519.Sign(priv, signed)
	body = append(body, sig...)
	global := ed25519.Sign(priv, append(append([]byte{}, sig...), trusted...))
	pubText := "untrusted comment: minisign public key X\n" +
		base64.StdEncoding.EncodeToString(append(append([]byte("Ed"), id[:]...), pubKey...)) + "\n"
	pub, err := ParsePublicKey([]byte(pubText))
	if err != nil {
		t.Fatal(err)
	}
	file := "untrusted comment: signature\n" + base64.StdEncoding.EncodeToString(body) + "\n" +
		"trusted comment: " + trusted + "\n" + base64.StdEncoding.EncodeToString(global) + "\n"
	return pub, []byte(file)
}

func wantErr(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
	}
}

func TestVerifyRealMinisignFixture(t *testing.T) {
	pub, msg, sig := fixture(t)
	trusted, err := Verify(pub, msg, sig)
	if err != nil {
		t.Fatal(err)
	}
	if trusted != "timestamp:1700000000 file:fixture.txt version:v0.0.0-test" {
		t.Fatalf("trusted comment = %q", trusted)
	}
	if pub.ID() != "BEEE762E58A69B2B" {
		t.Fatalf("id = %s", pub.ID())
	}
}

func TestVerifyLocalSignature(t *testing.T) {
	id := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	pub, sig := makeSig(t, "ED", id, []byte("hello"), "file:x")
	if trusted, err := Verify(pub, []byte("hello"), sig); err != nil || trusted != "file:x" {
		t.Fatalf("got %q, %v", trusted, err)
	}
}

func TestVerifyTamperedMessage(t *testing.T) {
	pub, msg, sig := fixture(t)
	_, err := Verify(pub, append([]byte("x"), msg...), sig)
	wantErr(t, err, "signature does not match")
}

func TestVerifyTamperedTrustedComment(t *testing.T) {
	pub, msg, sig := fixture(t)
	bad := bytes.Replace(sig, []byte("version:v0.0.0-test"), []byte("version:v9.9.9-test"), 1)
	_, err := Verify(pub, msg, bad)
	wantErr(t, err, "signature does not match")
}

func TestVerifyTamperedSignatureBytes(t *testing.T) {
	pub, msg, sig := fixture(t)
	lines := strings.Split(string(sig), "\n")
	raw, _ := base64.StdEncoding.DecodeString(lines[1])
	raw[20] ^= 1
	lines[1] = base64.StdEncoding.EncodeToString(raw)
	_, err := Verify(pub, msg, []byte(strings.Join(lines, "\n")))
	wantErr(t, err, "signature does not match")
}

func TestVerifyWrongKeyID(t *testing.T) {
	_, msg, sig := fixture(t)
	other, _ := makeSig(t, "ED", [8]byte{9, 9, 9, 9, 9, 9, 9, 9}, msg, "t")
	_, err := Verify(other, msg, sig)
	wantErr(t, err, "signature made with another key")
}

func TestVerifyWrongKeySameID(t *testing.T) {
	// Same key id, different key material: the signature cannot match.
	_, msg, sig := fixture(t)
	pub, _ := makeSig(t, "ED", [8]byte{0x2b, 0x9b, 0xa6, 0x58, 0x2e, 0x76, 0xee, 0xbe}, msg, "t")
	_, err := Verify(pub, msg, sig)
	wantErr(t, err, "signature does not match")
}

func TestVerifyRefusesLegacyAlgorithm(t *testing.T) {
	id := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	pub, sig := makeSig(t, "Ed", id, []byte("hello"), "t")
	_, err := Verify(pub, []byte("hello"), sig)
	wantErr(t, err, "malformed signature")
}

func TestVerifyMalformedFiles(t *testing.T) {
	pub, msg, sig := fixture(t)
	lines := strings.Split(strings.TrimSuffix(string(sig), "\n"), "\n")
	join := func(l ...string) []byte { return []byte(strings.Join(l, "\n") + "\n") }
	cases := map[string][]byte{
		"empty":            nil,
		"three lines":      join(lines[:3]...),
		"trailing line":    join(append(append([]string{}, lines...), "extra")...),
		"trailing blank":   append(append([]byte{}, sig...), '\n'),
		"crlf":             []byte(strings.ReplaceAll(string(sig), "\n", "\r\n")),
		"bad comment 1":    join("comment", lines[1], lines[2], lines[3]),
		"bad comment 3":    join(lines[0], lines[1], "comment: x", lines[3]),
		"bad base64":       join(lines[0], "!!!!", lines[2], lines[3]),
		"short body":       join(lines[0], lines[1][:40], lines[2], lines[3]),
		"bad global":       join(lines[0], lines[1], lines[2], "AAAA"),
		"empty untrusted":  join("", lines[1], lines[2], lines[3]),
		"trusted no space": join(lines[0], lines[1], "trusted comment:x", lines[3]),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Verify(pub, msg, in)
			wantErr(t, err, "malformed signature")
		})
	}
}

func TestVerifyErrorsNeverCarryContent(t *testing.T) {
	pub, _, sig := fixture(t)
	secretish := []byte("TESTSECRET_content")
	_, err := Verify(pub, secretish, sig)
	if err == nil || strings.Contains(err.Error(), "TESTSECRET_") {
		t.Fatalf("error = %v", err)
	}
	_, err = Verify(pub, secretish, []byte("TESTSECRET_garbage"))
	if err == nil || strings.Contains(err.Error(), "TESTSECRET_") {
		t.Fatalf("error = %v", err)
	}
}

func TestParsePublicKey(t *testing.T) {
	good := string(readTestdata(t, "test-minisign.pub"))
	lines := strings.Split(strings.TrimSuffix(good, "\n"), "\n")
	if _, err := ParsePublicKey([]byte(good)); err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePublicKey([]byte(strings.TrimSuffix(good, "\n"))); err != nil {
		t.Fatalf("no trailing newline: %v", err)
	}
	legacy := base64.StdEncoding.EncodeToString(append([]byte("ED"), make([]byte, 40)...))
	cases := map[string]string{
		"empty":         "",
		"one line":      lines[0] + "\n",
		"extra line":    good + "extra\n",
		"bad comment":   "comment\n" + lines[1] + "\n",
		"bad base64":    lines[0] + "\n!!!\n",
		"short key":     lines[0] + "\n" + lines[1][:20] + "\n",
		"wrong alg":     lines[0] + "\n" + legacy + "\n",
		"crlf":          strings.ReplaceAll(good, "\n", "\r\n"),
		"blank trailer": good + "\n",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParsePublicKey([]byte(in))
			wantErr(t, err, "malformed public key")
		})
	}
}

func TestReleaseKeyMatchesDefaults(t *testing.T) {
	want, err := os.ReadFile(filepath.Join("..", "..", "defaults", "release-key.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != releaseKeyText {
		t.Fatal("internal/minisign/release-key.pub differs from defaults/release-key.pub; copy it over")
	}
	if _, err := ReleaseKey(); err != nil {
		t.Fatal(err)
	}
}

// TestReleaseKeyIsNotTheTestKey keeps a test key out of a release: the release
// workflow sets QBIT_VAULT_RELEASE_CHECK=1.
func TestReleaseKeyIsNotTheTestKey(t *testing.T) {
	if os.Getenv("QBIT_VAULT_RELEASE_CHECK") != "1" {
		t.Skip("set QBIT_VAULT_RELEASE_CHECK=1 to check the pinned key (release workflow)")
	}
	pinned, err := ReleaseKey()
	if err != nil {
		t.Fatal(err)
	}
	test, err := ParsePublicKey(readTestdata(t, "test-minisign.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if pinned.ID() == test.ID() {
		t.Fatalf("defaults/release-key.pub still holds the test key %s", test.ID())
	}
}
