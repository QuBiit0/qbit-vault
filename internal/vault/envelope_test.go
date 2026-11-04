package vault

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/secret"
)

const (
	fixtureValue = "TESTSECRET_envelope_value_0123456789"
	fixtureName  = "TESTSECRET_NAME"
)

func testKey(b byte) secret.Secret {
	return secret.New("master", bytes.Repeat([]byte{b}, 32))
}

func testAAD(writes uint64) AAD {
	return AAD{Format: FormatVault, Cipher: CipherName, CreatedAt: "2026-11-03T00:00:00Z", Writes: writes}
}

func mustSeal(t *testing.T, key secret.Secret, aad AAD, pt []byte) []byte {
	t.Helper()
	out, err := seal(key, aad, pt)
	if err != nil {
		t.Fatalf("seal failed: %v", err)
	}
	return out
}

// mutate decodes a sealed envelope into a generic map, applies fn and re-encodes it.
func mutate(t *testing.T, sealed []byte, fn func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(sealed, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	fn(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return out
}

func TestSealOpenRoundTrip(t *testing.T) {
	key := testKey(1)
	pt := []byte(fixtureValue)
	sealed := mustSeal(t, key, testAAD(7), pt)

	got, aad, err := open(key, sealed)
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("plaintext mismatch (len %d, want %d)", len(got), len(pt))
	}
	if aad != testAAD(7) {
		t.Fatalf("aad = %+v", aad)
	}
	if bytes.Contains(sealed, pt) {
		t.Fatal("sealed envelope contains plaintext")
	}
}

func TestEnvelopeShape(t *testing.T) {
	sealed := mustSeal(t, testKey(1), testAAD(3), []byte("x"))
	var m map[string]json.RawMessage
	if err := json.Unmarshal(sealed, &m); err != nil {
		t.Fatal(err)
	}
	if len(m) != 5 {
		t.Fatalf("unexpected key count %d", len(m))
	}
	for k, want := range map[string]string{
		"format": `"qbit-vault/1"`,
		"cipher": `"xchacha20poly1305"`,
		"aad":    `{"format":"qbit-vault/1","cipher":"xchacha20poly1305","created_at":"2026-11-03T00:00:00Z","writes":3}`,
	} {
		if string(m[k]) != want {
			t.Fatalf("%s = %s, want %s", k, m[k], want)
		}
	}
	var nonce string
	if err := json.Unmarshal(m["nonce"], &nonce); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil || len(raw) != 24 {
		t.Fatalf("nonce: err=%v len=%d", err, len(raw))
	}
}

func TestSealFreshNoncePerWrite(t *testing.T) {
	key := testKey(1)
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		var m struct {
			Nonce string `json:"nonce"`
		}
		if err := json.Unmarshal(mustSeal(t, key, testAAD(1), []byte("same")), &m); err != nil {
			t.Fatal(err)
		}
		if seen[m.Nonce] {
			t.Fatal("nonce reused")
		}
		seen[m.Nonce] = true
	}
}

func TestSealRejectsBadKeyLength(t *testing.T) {
	if _, err := seal(secret.New("k", []byte("short")), testAAD(1), []byte("x")); err == nil {
		t.Fatal("expected error for short key")
	}
	if _, _, err := open(secret.New("k", []byte("short")), []byte("{}")); err == nil {
		t.Fatal("expected error for short key on open")
	}
}

func TestOpenRefusals(t *testing.T) {
	key := testKey(1)
	good := mustSeal(t, key, testAAD(5), []byte(fixtureValue))

	flipB64 := func(field string) func(map[string]any) {
		return func(m map[string]any) {
			raw, _ := base64.StdEncoding.DecodeString(m[field].(string))
			raw[0] ^= 0x01
			m[field] = base64.StdEncoding.EncodeToString(raw)
		}
	}
	tests := []struct {
		name string
		key  secret.Secret
		data []byte
	}{
		{"wrong key", testKey(2), good},
		{"tampered ct", key, mutate(t, good, flipB64("ct"))},
		{"tampered nonce", key, mutate(t, good, flipB64("nonce"))},
		{"tampered aad writes", key, mutate(t, good, func(m map[string]any) { m["aad"].(map[string]any)["writes"] = 1 })},
		{"tampered aad created_at", key, mutate(t, good, func(m map[string]any) { m["aad"].(map[string]any)["created_at"] = "2000-01-01T00:00:00Z" })},
		{"wrong format", key, mutate(t, good, func(m map[string]any) { m["format"] = "qbit-vault/2" })},
		{"tampered aad cipher", key, mutate(t, good, func(m map[string]any) { m["aad"].(map[string]any)["cipher"] = "aes" })},
		{"tampered aad format", key, mutate(t, good, func(m map[string]any) { m["aad"].(map[string]any)["format"] = "qbit-vault/2" })},
		{"unknown top-level kdf", key, mutate(t, good, func(m map[string]any) { m["kdf"] = nil })},
		{"unknown top-level field", key, mutate(t, good, func(m map[string]any) { m["extra"] = 1 })},
		{"wrong cipher", key, mutate(t, good, func(m map[string]any) { m["cipher"] = "aes" })},
		{"bad base64 ct", key, mutate(t, good, func(m map[string]any) { m["ct"] = "!!!" })},
		{"bad base64 nonce", key, mutate(t, good, func(m map[string]any) { m["nonce"] = "!!!" })},
		{"short nonce", key, mutate(t, good, func(m map[string]any) { m["nonce"] = base64.StdEncoding.EncodeToString([]byte("short")) })},
		{"empty ct", key, mutate(t, good, func(m map[string]any) { m["ct"] = "" })},
		{"not json", key, []byte("not json")},
		{"empty", key, nil},
		{"json array", key, []byte("[]")},
		{"trailing garbage", key, append(append([]byte{}, good...), []byte("x")...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pt, _, err := open(tt.key, tt.data)
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("err = %v, want ErrCorrupt", err)
			}
			if pt != nil {
				t.Fatal("plaintext returned with error")
			}
			if bytes.Contains([]byte(err.Error()), []byte(fixtureValue)) {
				t.Fatal("error leaks plaintext")
			}
		})
	}
}

func FuzzEnvelope(f *testing.F) {
	key := testKey(9)
	want := []byte(fixtureValue)
	sealed, err := seal(key, testAAD(2), want)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(sealed)
	f.Add([]byte("{}"))
	f.Add([]byte(""))
	f.Add(bytes.Replace(sealed, []byte(`"writes":2`), []byte(`"writes":3`), 1))
	f.Fuzz(func(t *testing.T, data []byte) {
		pt, _, err := open(key, data)
		if err != nil {
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("error is not ErrCorrupt: %v", err)
			}
			return
		}
		// Without the key the only plaintext that can ever come out is the original.
		if !bytes.Equal(pt, want) {
			t.Fatal("corrupted envelope decrypted to different plaintext")
		}
	})
}
