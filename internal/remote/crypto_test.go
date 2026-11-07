package remote

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/secret"
)

func key(b byte) secret.Secret { return secret.New("k", bytes.Repeat([]byte{b}, 32)) }

func reveal(s secret.Secret) string { b := s.Reveal(); defer clear(b); return string(b) }

func TestSubkeysAreDistinctAndStable(t *testing.T) {
	mk := key(1)
	a, b := Subkeys(mk), Subkeys(mk)
	if reveal(a.Vault) != reveal(b.Vault) || reveal(a.Anchor) != reveal(b.Anchor) || reveal(a.Pairing) != reveal(b.Pairing) {
		t.Fatal("derivation is not deterministic")
	}
	set := map[string]bool{reveal(a.Vault): true, reveal(a.Anchor): true, reveal(a.Pairing): true, reveal(mk): true}
	if len(set) != 4 {
		t.Fatal("subkeys collide with each other or the master key")
	}
	// A fixed vector pins the derivation (salt and info strings).
	if got := hexOf(a.Vault)[:16]; got != vaultKeyVector {
		t.Fatalf("remote vault key of 0x01*32 = %s..., want %s...", got, vaultKeyVector)
	}
	if reveal(Subkeys(key(2)).Vault) == reveal(a.Vault) {
		t.Fatal("different master keys gave one subkey")
	}
}

func TestDeviceKeysFromSecret(t *testing.T) {
	d1, d2 := DeviceFromSecret(key(7)), DeviceFromSecret(key(7))
	if !bytes.Equal(d1.SignPub, d2.SignPub) || !bytes.Equal(d1.BoxPub, d2.BoxPub) || len(d1.SignPub) != 32 || len(d1.BoxPub) != 32 {
		t.Fatal("device keys not deterministic")
	}
	if bytes.Equal(DeviceFromSecret(key(8)).SignPub, d1.SignPub) {
		t.Fatal("different secrets, same key")
	}
}

func TestRecoveryKeyFormatAndParse(t *testing.T) {
	rk, text, err := NewRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(text, "QVR1-") || len(text) != len("QVR1-")+8*4+7 {
		t.Fatalf("format %q", text)
	}
	back, err := ParseRecoveryKey(strings.ToLower(strings.ReplaceAll(text, "-", " ")))
	if err != nil || reveal(back) != reveal(rk) {
		t.Fatalf("round trip: %v", err)
	}
	// Crockford: I and L read as 1, O as 0; the prefix is optional.
	confusable := strings.NewReplacer("1", "I", "0", "O").Replace(strings.TrimPrefix(text, "QVR1-"))
	if back, err := ParseRecoveryKey(confusable); err != nil || reveal(back) != reveal(rk) {
		t.Fatalf("confusables: %v", err)
	}
	for _, bad := range []string{"", "QVR1-TOO-SHORT", text + "XX", strings.Replace(text, "QVR1-", "QVR1-U", 1)} {
		if _, err := ParseRecoveryKey(bad); !errors.Is(err, ErrBadRecoveryKey) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	r := RecoveryFromKey(rk)
	if len(r.LookupID) != 16 || r.AuthSecret.Len() != 32 || r.Wrap.Len() != 32 || reveal(r.AuthSecret) == reveal(r.Wrap) {
		t.Fatal("recovery derivation")
	}
}

func TestPairingAndConfirmationCodes(t *testing.T) {
	d := DeviceFromSecret(key(3))
	code := PairingCode(d.SignPub, d.BoxPub)
	if len(code) != 19 || strings.Count(code, "-") != 3 || code != PairingCode(d.SignPub, d.BoxPub) {
		t.Fatalf("pairing code %q", code)
	}
	other := DeviceFromSecret(key(4))
	if PairingCode(other.SignPub, d.BoxPub) == code {
		t.Fatal("pairing code does not bind the signing key")
	}
	eph := bytes.Repeat([]byte{9}, 32)
	c1 := ConfirmationCode(Subkeys(key(1)).Pairing, code, "dev1", eph)
	if len(c1) != 9 || c1 != ConfirmationCode(Subkeys(key(1)).Pairing, code, "dev1", eph) {
		t.Fatalf("confirmation %q", c1)
	}
	if ConfirmationCode(Subkeys(key(2)).Pairing, code, "dev1", eph) == c1 {
		t.Fatal("confirmation code does not depend on the master key")
	}
}

func TestKeyEnvelope(t *testing.T) {
	issuer, recipient, stranger := DeviceFromSecret(key(1)), DeviceFromSecret(key(2)), DeviceFromSecret(key(3))
	mk := key(42)
	meta := EnvelopeAAD{AccountID: "acc1", DeviceID: "dev2", Generation: 3, Issuer: "dev1"}
	env, err := SealKeyEnvelope(issuer, recipient.BoxPub, meta, mk)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(env), reveal(mk)) {
		t.Fatal("master key in clear")
	}
	got, aad, err := OpenKeyEnvelope(recipient, issuer.SignPub, env)
	if err != nil || reveal(got) != reveal(mk) || aad != meta {
		t.Fatalf("open: %v %+v", err, aad)
	}
	if _, _, err := OpenKeyEnvelope(stranger, issuer.SignPub, env); !errors.Is(err, ErrEnvelope) {
		t.Fatalf("wrong recipient: %v", err)
	}
	if _, _, err := OpenKeyEnvelope(recipient, stranger.SignPub, env); !errors.Is(err, ErrEnvelope) {
		t.Fatalf("forged issuer: %v", err)
	}
	// A server swapping the generation (or any AAD field) breaks it.
	var m map[string]any
	_ = json.Unmarshal(env, &m)
	m["aad"].(map[string]any)["generation"] = 2
	tampered, _ := json.Marshal(m)
	if _, _, err := OpenKeyEnvelope(recipient, issuer.SignPub, tampered); !errors.Is(err, ErrEnvelope) {
		t.Fatalf("tampered aad: %v", err)
	}
}

func TestRecoveryEnvelope(t *testing.T) {
	rk, _, _ := NewRecoveryKey()
	r := RecoveryFromKey(rk)
	env, err := SealRecovery(r.Wrap, "acc1", 2, key(42))
	if err != nil {
		t.Fatal(err)
	}
	mk, gen, err := OpenRecovery(r.Wrap, "acc1", env)
	if err != nil || gen != 2 || reveal(mk) != reveal(key(42)) {
		t.Fatalf("open: %v gen=%d", err, gen)
	}
	other, _, _ := NewRecoveryKey()
	if _, _, err := OpenRecovery(RecoveryFromKey(other).Wrap, "acc1", env); !errors.Is(err, ErrEnvelope) {
		t.Fatalf("wrong recovery key: %v", err)
	}
	if _, _, err := OpenRecovery(r.Wrap, "acc2", env); !errors.Is(err, ErrEnvelope) {
		t.Fatalf("other account: %v", err)
	}
}

func TestRemoteVaultObject(t *testing.T) {
	rvk := Subkeys(key(1)).Vault
	meta := ObjectAAD{AccountID: "acc1", Generation: 1, Version: 7, Writer: "dev1", CreatedAt: "2026-11-04T00:00:00Z"}
	body := []byte(`{"schema":2,"global":{"A":{"value":"TESTSECRET_remote"}}}`)
	obj, err := SealObject(rvk, meta, body)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(obj, []byte("TESTSECRET_")) || bytes.Contains(obj, []byte(`"A"`)) {
		t.Fatal("body or names visible")
	}
	var m struct {
		CT string `json:"ct"`
	}
	_ = json.Unmarshal(obj, &m)
	if raw := decodedLen(m.CT); (raw-16)%PadBlock != 0 {
		t.Fatalf("ciphertext %d bytes is not padded to %d", raw, PadBlock)
	}
	pt, aad, err := OpenObject(rvk, "acc1", obj)
	if err != nil || !bytes.Equal(pt, body) || aad != meta {
		t.Fatalf("open: %v %q %+v", err, pt, aad)
	}
	if _, _, err := OpenObject(rvk, "acc2", obj); !errors.Is(err, ErrEnvelope) {
		t.Fatalf("other account: %v", err)
	}
	var mm map[string]any
	_ = json.Unmarshal(obj, &mm)
	mm["aad"].(map[string]any)["version"] = 6 // a server replaying under another version
	tampered, _ := json.Marshal(mm)
	if _, _, err := OpenObject(rvk, "acc1", tampered); !errors.Is(err, ErrEnvelope) {
		t.Fatalf("tampered version: %v", err)
	}
	if _, _, err := OpenObject(Subkeys(key(2)).Vault, "acc1", obj); !errors.Is(err, ErrEnvelope) {
		t.Fatalf("wrong key: %v", err)
	}
}

func TestAnchor(t *testing.T) {
	aak := Subkeys(key(1)).Anchor
	a := Anchor{DeviceID: "dev1", Seq: 42, Line: "sha256:abc", At: "2026-11-04T00:00:00Z"}
	blob, err := SealAnchor(aak, "acc1", 1, a)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, []byte("sha256:abc")) {
		t.Fatal("anchor in clear")
	}
	got, err := OpenAnchor(aak, "acc1", blob)
	if err != nil || got != a {
		t.Fatalf("open: %v %+v", err, got)
	}
	if _, err := OpenAnchor(Subkeys(key(2)).Anchor, "acc1", blob); !errors.Is(err, ErrEnvelope) {
		t.Fatalf("wrong key: %v", err)
	}
}

// FuzzOpen: arbitrary input never panics, and whatever does not open is
// ErrEnvelope. (That an altered object never opens is pinned by the tamper
// tests above: a fuzz seed sealed in one process is a valid object in
// another, so "it opened" is not a failure here.)
func FuzzOpen(f *testing.F) {
	rvk := Subkeys(key(1)).Vault
	obj, _ := SealObject(rvk, ObjectAAD{AccountID: "acc1", Generation: 1, Version: 1}, []byte(`{"schema":2}`))
	f.Add(obj)
	f.Add([]byte(`{"format":"qbit-vault-remote/1","aad":{},"nonce":"","ct":""}`))
	f.Fuzz(func(t *testing.T, in []byte) {
		for _, err := range []error{
			func() error { _, _, err := OpenObject(rvk, "acc1", in); return err }(),
			func() error {
				_, _, err := OpenKeyEnvelope(DeviceFromSecret(key(2)), DeviceFromSecret(key(1)).SignPub, in)
				return err
			}(),
			func() error { _, _, err := OpenRecovery(rvk, "acc1", in); return err }(),
			func() error { _, err := OpenAnchor(rvk, "acc1", in); return err }(),
		} {
			if err != nil && !errors.Is(err, ErrEnvelope) {
				t.Fatalf("untyped error: %v", err)
			}
		}
	})
}

func hexOf(s secret.Secret) string { b := s.Reveal(); defer clear(b); return hex.EncodeToString(b) }

func decodedLen(b64 string) int { b, _ := base64.StdEncoding.DecodeString(b64); return len(b) }

// vaultKeyVector is HKDF-SHA256(0x01*32, salt "qbit-vault/v1", info "remote-vault"), first 8 bytes.
const vaultKeyVector = "742d452644d92830"

func TestEnvelopeEphPub(t *testing.T) {
	issuer, recipient := DeviceFromSecret(key(1)), DeviceFromSecret(key(2))
	raw, err := SealKeyEnvelope(issuer, recipient.BoxPub, EnvelopeAAD{AccountID: "acc1", DeviceID: "d2", Generation: 1, Issuer: "d1"}, key(9))
	if err != nil {
		t.Fatal(err)
	}
	eph, err := EnvelopeEphPub(raw)
	if err != nil || len(eph) != 32 {
		t.Fatalf("eph_pub: %d bytes, %v", len(eph), err)
	}
	// It is the key the confirmation code binds: two envelopes differ.
	raw2, _ := SealKeyEnvelope(issuer, recipient.BoxPub, EnvelopeAAD{AccountID: "acc1", DeviceID: "d2", Generation: 1, Issuer: "d1"}, key(9))
	if eph2, _ := EnvelopeEphPub(raw2); bytes.Equal(eph, eph2) {
		t.Fatal("two envelopes share an ephemeral key")
	}
	for _, bad := range [][]byte{nil, []byte(`{}`), []byte(`{"format":"qbit-vault-keyenv/1","eph_pub":"AAAA"}`), []byte(`not json`)} {
		if _, err := EnvelopeEphPub(bad); !errors.Is(err, ErrEnvelope) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

// A key whose 32-character body starts with QVR1 is told apart from the
// prefix by its length, with and without the prefix typed.
func TestRecoveryKeyWhoseBodyStartsWithThePrefix(t *testing.T) {
	body := "QVR1" + strings.Repeat("2", 28)
	want, err := ParseRecoveryKey("QVR1-" + groups(body, 4))
	if err != nil {
		t.Fatalf("with prefix: %v", err)
	}
	got, err := ParseRecoveryKey(groups(body, 4))
	if err != nil || reveal(got) != reveal(want) {
		t.Fatalf("without prefix: %v", err)
	}
	if _, err := ParseRecoveryKey("QVR1-QVR1-" + groups(body, 4)); !errors.Is(err, ErrBadRecoveryKey) {
		t.Fatalf("a double prefix: %v", err)
	}
}
