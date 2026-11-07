// Package remote is the client side of multi-device sync
// (docs/REMOTE_SYNC.md). This file is its cryptography (§ 2-3): pure
// functions, no network, no disk. Everything the server stores is sealed
// here with keys derived from the master key, which is never sent; every
// object is verified (AEAD, AAD, signatures) before it is used.
package remote

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/QuBiit0/qbit-vault/internal/secret"
)

const (
	salt = "qbit-vault/v1"
	// PadBlock is the size the remote vault plaintext is padded to a
	// multiple of, so its size tells the server little (§ 9).
	PadBlock = 4096

	formatObject   = "qbit-vault-remote/1"
	formatKeyEnv   = "qbit-vault-keyenv/1"
	formatRecovery = "qbit-vault-recoveryenv/1"
	formatAnchor   = "qbit-vault-anchor/1"
	cipherName     = "xchacha20poly1305"
)

var (
	// ErrEnvelope is the only answer for anything that does not open:
	// wrong key, wrong recipient, forged issuer, altered AAD or ciphertext.
	ErrEnvelope = errors.New("remote: object cannot be opened or verified")
	// ErrBadRecoveryKey means the text is not a recovery key.
	ErrBadRecoveryKey = errors.New("remote: not a recovery key")
)

func derive(ikm []byte, info string, n int) []byte {
	out, err := hkdf.Key(sha256.New, ikm, []byte(salt), info, n)
	if err != nil {
		panic("remote: hkdf failed")
	}
	return out
}

func deriveSecret(s secret.Secret, info string) secret.Secret {
	raw := s.Reveal()
	defer clear(raw)
	k := derive(raw, info, 32)
	defer clear(k)
	return secret.New(info, k)
}

// Keys are the subkeys of the master key.
type Keys struct {
	Vault   secret.Secret // seals the remote vault object
	Anchor  secret.Secret // seals audit anchors
	Pairing secret.Secret // computes pairing confirmation codes
}

// Subkeys derives the subkeys of mk.
func Subkeys(mk secret.Secret) Keys {
	return Keys{Vault: deriveSecret(mk, "remote-vault"), Anchor: deriveSecret(mk, "audit-anchor"), Pairing: deriveSecret(mk, "pairing-confirm")}
}

// Device is a device's key pair, derived from its 32-byte secret DK.
type Device struct {
	SignPriv ed25519.PrivateKey
	SignPub  []byte
	BoxPriv  *ecdh.PrivateKey
	BoxPub   []byte
}

// DeviceFromSecret derives the signing and box keys of dk.
func DeviceFromSecret(dk secret.Secret) Device {
	raw := dk.Reveal()
	defer clear(raw)
	seed := derive(raw, "device-sign", ed25519.SeedSize)
	defer clear(seed)
	priv := ed25519.NewKeyFromSeed(seed)
	boxSeed := derive(raw, "device-box", 32)
	defer clear(boxSeed)
	box, err := ecdh.X25519().NewPrivateKey(boxSeed)
	if err != nil {
		panic("remote: x25519 key failed")
	}
	return Device{SignPriv: priv, SignPub: append([]byte(nil), priv.Public().(ed25519.PublicKey)...), BoxPriv: box, BoxPub: box.PublicKey().Bytes()}
}

// ---- Crockford base32 ----

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

func b32(b []byte, chars int) string {
	var out strings.Builder
	var acc, bits uint
	for _, x := range b {
		acc, bits = acc<<8|uint(x), bits+8
		for bits >= 5 && out.Len() < chars {
			bits -= 5
			out.WriteByte(crockford[(acc>>bits)&31])
		}
	}
	return out.String()
}

func groups(s string, n int) string {
	var parts []string
	for len(s) > n {
		parts, s = append(parts, s[:n]), s[n:]
	}
	return strings.Join(append(parts, s), "-")
}

// AuthMessage is what a device signs to get a token: the server's origin
// binds the signature to that server, so it cannot be relayed to another.
func AuthMessage(origin string, nonce []byte) []byte {
	return append([]byte("qbit-vault/auth/v1"+origin), nonce...)
}

// ---- recovery key ----

// NewRecoveryKey returns 20 random bytes and their text form
// QVR1-XXXX-...-XXXX (Crockford base32, 8 groups of 4).
func NewRecoveryKey() (secret.Secret, string, error) {
	var b [20]byte
	if _, err := rand.Read(b[:]); err != nil {
		return secret.Secret{}, "", errors.New("remote: random source failed")
	}
	defer clear(b[:])
	return secret.New("recovery", b[:]), "QVR1-" + groups(b32(b[:], 32), 4), nil
}

// ParseRecoveryKey reads a recovery key typed by the user: case, spaces and
// dashes do not matter, I and L read as 1 and O as 0, the QVR1- prefix is
// optional.
func ParseRecoveryKey(text string) (secret.Secret, error) {
	s := strings.ToUpper(strings.NewReplacer("-", "", " ", "", "\t", "").Replace(strings.TrimSpace(text)))
	// The body is 32 characters and may itself start with QVR1, so the prefix
	// counts only when it makes the text longer than a body.
	if len(s) == 36 {
		s = strings.TrimPrefix(s, "QVR1")
	}
	s = strings.NewReplacer("I", "1", "L", "1", "O", "0").Replace(s)
	if len(s) != 32 {
		return secret.Secret{}, ErrBadRecoveryKey
	}
	out := make([]byte, 0, 20)
	var acc, bits uint
	for i := 0; i < len(s); i++ {
		v := strings.IndexByte(crockford, s[i])
		if v < 0 {
			clear(out)
			return secret.Secret{}, ErrBadRecoveryKey
		}
		acc, bits = acc<<5|uint(v), bits+5
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(acc>>bits))
		}
	}
	defer clear(out)
	return secret.New("recovery", out), nil
}

// Recovery is what the recovery key derives (§ 2): the lookup id and the
// auth secret go to the server; the wrap key never does.
type Recovery struct {
	LookupID   []byte
	AuthSecret secret.Secret
	Wrap       secret.Secret
}

// RecoveryFromKey derives the recovery material of rk.
func RecoveryFromKey(rk secret.Secret) Recovery {
	raw := rk.Reveal()
	defer clear(raw)
	return Recovery{LookupID: derive(raw, "recovery-id", 16), AuthSecret: deriveSecret(rk, "recovery-auth"), Wrap: deriveSecret(rk, "recovery-wrap")}
}

// ---- pairing ----

// PairingCode fingerprints a new device's public keys: 80 bits of
// SHA-256("qbit-vault/pairing/v1" || sign_pub || box_pub), XXXX-XXXX-XXXX-XXXX.
func PairingCode(signPub, boxPub []byte) string {
	h := sha256.New()
	h.Write([]byte("qbit-vault/pairing/v1"))
	h.Write(signPub)
	h.Write(boxPub)
	return groups(b32(h.Sum(nil)[:10], 16), 4)
}

// ConfirmationCode is 40 bits of HMAC-SHA256(pck, code || device_id ||
// eph_pub), XXXX-XXXX: only a holder of the real master key computes it.
func ConfirmationCode(pck secret.Secret, code, deviceID string, ephPub []byte) string {
	k := pck.Reveal()
	defer clear(k)
	m := hmac.New(sha256.New, k)
	m.Write([]byte(code))
	m.Write([]byte(deviceID))
	m.Write(ephPub)
	return groups(b32(m.Sum(nil)[:5], 8), 4)
}

// ---- sealed messages ----

type sealed[A any] struct {
	Format string `json:"format"`
	AAD    A      `json:"aad"`
	EphPub string `json:"eph_pub,omitempty"`
	Nonce  string `json:"nonce"`
	CT     string `json:"ct"`
	Sig    string `json:"sig,omitempty"`
}

func aadBytes[A any](format string, a A) []byte {
	b, _ := json.Marshal(struct {
		Format string `json:"format"`
		Cipher string `json:"cipher"`
		AAD    A      `json:"aad"`
	}{format, cipherName, a})
	return b
}

func seal[A any](key []byte, format string, a A, pt []byte) (sealed[A], []byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return sealed[A]{}, nil, errors.New("remote: cipher setup failed")
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return sealed[A]{}, nil, errors.New("remote: random source failed")
	}
	ad := aadBytes(format, a)
	ct := aead.Seal(nil, nonce, pt, ad)
	return sealed[A]{Format: format, AAD: a, Nonce: b64(nonce), CT: b64(ct)}, ad, nil
}

func open[A any](key []byte, format string, raw []byte) (A, []byte, sealed[A], error) {
	var s sealed[A]
	var zero A
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil || s.Format != format {
		return zero, nil, s, ErrEnvelope
	}
	nonce, err1 := unb64(s.Nonce)
	ct, err2 := unb64(s.CT)
	if err1 != nil || err2 != nil || len(nonce) != chacha20poly1305.NonceSizeX {
		return zero, nil, s, ErrEnvelope
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return zero, nil, s, ErrEnvelope
	}
	pt, err := aead.Open(nil, nonce, ct, aadBytes(format, s.AAD))
	if err != nil {
		return zero, nil, s, ErrEnvelope
	}
	return s.AAD, pt, s, nil
}

func b64(b []byte) string            { return base64.StdEncoding.EncodeToString(b) }
func unb64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

// ---- key envelope (§ 3): MK sealed to one device, signed by its issuer ----

// EnvelopeAAD binds a key envelope.
type EnvelopeAAD struct {
	AccountID  string `json:"account_id"`
	DeviceID   string `json:"device_id"`
	Generation int    `json:"generation"`
	Issuer     string `json:"issuer"`
}

// envelopeKey is HKDF-SHA256(shared, salt = eph_pub || box_pub,
// "key-envelope") (REMOTE_SYNC.md § 3).
func envelopeKey(shared, ephPub, boxPub []byte) []byte {
	k, err := hkdf.Key(sha256.New, shared, append(append([]byte{}, ephPub...), boxPub...), "key-envelope", 32)
	if err != nil {
		panic("remote: hkdf failed")
	}
	return k
}

// SealKeyEnvelope seals mk to the recipient's box key with an ephemeral
// X25519 key, and signs AAD, ephemeral key and ciphertext with the issuer's
// signing key.
func SealKeyEnvelope(issuer Device, recipientBoxPub []byte, a EnvelopeAAD, mk secret.Secret) ([]byte, error) {
	return SealKeyEnvelopeAt(issuer, recipientBoxPub, a, mk, 0)
}

// SealKeyEnvelopeAt is SealKeyEnvelope with the issuer's last synced version
// after the key (8 bytes, big endian), so a device that joins starts with the
// same version floor as the one that approved it. Zero writes no field.
func SealKeyEnvelopeAt(issuer Device, recipientBoxPub []byte, a EnvelopeAAD, mk secret.Secret, lastVersion int64) ([]byte, error) {
	pub, err := ecdh.X25519().NewPublicKey(recipientBoxPub)
	if err != nil {
		return nil, ErrEnvelope
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, errors.New("remote: random source failed")
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return nil, ErrEnvelope
	}
	defer clear(shared)
	k := envelopeKey(shared, eph.PublicKey().Bytes(), recipientBoxPub)
	defer clear(k)
	key := mk.Reveal()
	m := append(make([]byte, 0, 40), key...)
	clear(key)
	if lastVersion > 0 {
		m = binary.BigEndian.AppendUint64(m, uint64(lastVersion))
	}
	defer clear(m)
	s, ad, err := seal(k, formatKeyEnv, a, m)
	if err != nil {
		return nil, err
	}
	ct, _ := unb64(s.CT)
	s.EphPub = b64(eph.PublicKey().Bytes())
	s.Sig = b64(ed25519.Sign(issuer.SignPriv, signedBytes(ad, eph.PublicKey().Bytes(), ct)))
	return json.Marshal(s)
}

func signedBytes(ad, eph, ct []byte) []byte {
	out := append(append(append([]byte{}, ad...), eph...), ct...)
	return out
}

// EnvelopeEphPub returns the ephemeral public key of a key envelope: the
// part of the pairing confirmation code (§ 4.2) that ties it to this
// envelope. It reads the key only; opening and verifying is OpenKeyEnvelope.
func EnvelopeEphPub(raw []byte) ([]byte, error) {
	var s sealed[EnvelopeAAD]
	if json.Unmarshal(raw, &s) != nil || s.Format != formatKeyEnv {
		return nil, ErrEnvelope
	}
	eph, err := unb64(s.EphPub)
	if err != nil {
		return nil, ErrEnvelope
	}
	if _, err := ecdh.X25519().NewPublicKey(eph); err != nil {
		return nil, ErrEnvelope
	}
	return eph, nil
}

// OpenKeyEnvelope verifies the issuer's signature with issuerSignPub (from
// the caller's own roster, never from the server), then opens the envelope
// with the recipient's box key.
func OpenKeyEnvelope(recipient Device, issuerSignPub []byte, raw []byte) (secret.Secret, EnvelopeAAD, error) {
	mk, a, _, err := OpenKeyEnvelopeAt(recipient, issuerSignPub, raw)
	return mk, a, err
}

// OpenKeyEnvelopeAt is OpenKeyEnvelope that also returns the issuer's last
// synced version; an envelope without the field (an older issuer) gives 0.
func OpenKeyEnvelopeAt(recipient Device, issuerSignPub []byte, raw []byte) (secret.Secret, EnvelopeAAD, int64, error) {
	var s sealed[EnvelopeAAD]
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil || s.Format != formatKeyEnv || len(issuerSignPub) != ed25519.PublicKeySize {
		return secret.Secret{}, EnvelopeAAD{}, 0, ErrEnvelope
	}
	eph, err1 := unb64(s.EphPub)
	ct, err2 := unb64(s.CT)
	sig, err3 := unb64(s.Sig)
	if err1 != nil || err2 != nil || err3 != nil {
		return secret.Secret{}, EnvelopeAAD{}, 0, ErrEnvelope
	}
	if !ed25519.Verify(issuerSignPub, signedBytes(aadBytes(formatKeyEnv, s.AAD), eph, ct), sig) {
		return secret.Secret{}, EnvelopeAAD{}, 0, ErrEnvelope
	}
	pub, err := ecdh.X25519().NewPublicKey(eph)
	if err != nil {
		return secret.Secret{}, EnvelopeAAD{}, 0, ErrEnvelope
	}
	shared, err := recipient.BoxPriv.ECDH(pub)
	if err != nil {
		return secret.Secret{}, EnvelopeAAD{}, 0, ErrEnvelope
	}
	defer clear(shared)
	k := envelopeKey(shared, eph, recipient.BoxPub)
	defer clear(k)
	a, pt, _, err := open[EnvelopeAAD](k, formatKeyEnv, raw)
	if err != nil || (len(pt) != 32 && len(pt) != 40) {
		clear(pt)
		return secret.Secret{}, EnvelopeAAD{}, 0, ErrEnvelope
	}
	defer clear(pt)
	var last int64
	if len(pt) == 40 {
		v := binary.BigEndian.Uint64(pt[32:])
		if v > math.MaxInt64 {
			return secret.Secret{}, EnvelopeAAD{}, 0, ErrEnvelope
		}
		last = int64(v)
	}
	return secret.New("master", pt[:32]), a, last, nil
}

// ---- recovery envelope ----

type recoveryAAD struct {
	AccountID  string `json:"account_id"`
	Generation int    `json:"generation"`
}

// SealRecovery seals mk with the recovery wrap key.
func SealRecovery(wrap secret.Secret, accountID string, generation int, mk secret.Secret) ([]byte, error) {
	k := wrap.Reveal()
	defer clear(k)
	m := mk.Reveal()
	defer clear(m)
	s, _, err := seal(k, formatRecovery, recoveryAAD{accountID, generation}, m)
	if err != nil {
		return nil, err
	}
	return json.Marshal(s)
}

// OpenRecovery opens a recovery envelope of accountID.
func OpenRecovery(wrap secret.Secret, accountID string, raw []byte) (secret.Secret, int, error) {
	k := wrap.Reveal()
	defer clear(k)
	a, pt, _, err := open[recoveryAAD](k, formatRecovery, raw)
	if err != nil || a.AccountID != accountID || len(pt) != 32 {
		clear(pt)
		return secret.Secret{}, 0, ErrEnvelope
	}
	defer clear(pt)
	return secret.New("master", pt), a.Generation, nil
}

// ---- remote vault object ----

// ObjectAAD binds a remote vault version.
type ObjectAAD struct {
	AccountID  string `json:"account_id"`
	Generation int    `json:"generation"`
	Version    int64  `json:"version"`
	Writer     string `json:"writer"`
	CreatedAt  string `json:"created_at"`
}

// SealObject seals a body, zero-padded to a multiple of PadBlock.
func SealObject(rvk secret.Secret, a ObjectAAD, body []byte) ([]byte, error) {
	n := (len(body)/PadBlock + 1) * PadBlock
	pt := make([]byte, n)
	copy(pt, body)
	defer clear(pt)
	k := rvk.Reveal()
	defer clear(k)
	s, _, err := seal(k, formatObject, a, pt)
	if err != nil {
		return nil, err
	}
	return json.Marshal(s)
}

// OpenObject opens a remote vault object of accountID and strips its
// padding. The caller wipes the body and checks version and generation
// against what it has seen (rollback, § 7.2).
func OpenObject(rvk secret.Secret, accountID string, raw []byte) ([]byte, ObjectAAD, error) {
	k := rvk.Reveal()
	defer clear(k)
	a, pt, _, err := open[ObjectAAD](k, formatObject, raw)
	if err != nil || a.AccountID != accountID || len(pt)%PadBlock != 0 {
		clear(pt)
		return nil, ObjectAAD{}, ErrEnvelope
	}
	return bytes.TrimRight(pt, "\x00"), a, nil
}

// ---- audit anchor (§ 8) ----

// Anchor is the head of a device's audit log.
type Anchor struct {
	DeviceID string `json:"device_id"`
	Seq      int64  `json:"seq"`
	Line     string `json:"line"`
	At       string `json:"at"`
}

type anchorAAD struct {
	AccountID string `json:"account_id"`
	DeviceID  string `json:"device_id"`
}

// SealAnchor seals an anchor with the anchor key.
func SealAnchor(aak secret.Secret, accountID string, generation int, a Anchor) ([]byte, error) {
	pt, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	k := aak.Reveal()
	defer clear(k)
	s, _, err := seal(k, formatAnchor, anchorAAD{accountID, a.DeviceID}, pt)
	if err != nil {
		return nil, err
	}
	_ = generation // the anchor key already changes with the master key
	return json.Marshal(s)
}

// OpenAnchor opens an anchor of accountID.
func OpenAnchor(aak secret.Secret, accountID string, raw []byte) (Anchor, error) {
	k := aak.Reveal()
	defer clear(k)
	aad, pt, _, err := open[anchorAAD](k, formatAnchor, raw)
	var a Anchor
	if err != nil || aad.AccountID != accountID || json.Unmarshal(pt, &a) != nil || a.DeviceID != aad.DeviceID {
		return Anchor{}, ErrEnvelope
	}
	return a, nil
}
