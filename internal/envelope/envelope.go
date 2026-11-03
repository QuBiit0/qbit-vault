// Package envelope is the AEAD envelope shared by vault.enc and grants.enc
// (docs/STORAGE.md § Vault file): XChaCha20-Poly1305 with a canonical JSON
// header as additional data. The format string is a parameter, so one file
// type can never be opened as the other.
package envelope

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/QuBiit0/gentle-vault/internal/secret"
)

// CipherName is the only supported AEAD.
const CipherName = "xchacha20poly1305"

// ErrCorrupt means the file cannot be trusted: it is malformed, was altered,
// or was opened with the wrong key or format. Messages never carry content.
var ErrCorrupt = errors.New("vault_corrupt")

// AAD is the authenticated cleartext header. Field order is part of the
// format: its canonical JSON encoding is the AEAD additional data.
type AAD struct {
	Format    string `json:"format"`
	Cipher    string `json:"cipher"`
	CreatedAt string `json:"created_at"`
	Writes    uint64 `json:"writes"`
}

type envelope struct {
	Format string `json:"format"`
	Cipher string `json:"cipher"`
	Nonce  string `json:"nonce"`
	AAD    AAD    `json:"aad"`
	CT     string `json:"ct"`
}

func corrupt(why string) error { return fmt.Errorf("%w: %s", ErrCorrupt, why) }

// CheckKey reports whether key has the length the cipher needs.
func CheckKey(key secret.Secret) error {
	if key.Len() != chacha20poly1305.KeySize {
		return fmt.Errorf("vault: master key must be %d bytes", chacha20poly1305.KeySize)
	}
	return nil
}

// Seal encrypts plaintext under key with a fresh random nonce and returns the
// envelope JSON. Format and cipher in aad are overwritten with format and
// CipherName. The caller keeps ownership of plaintext.
func Seal(format string, key secret.Secret, aad AAD, plaintext []byte) ([]byte, error) {
	if err := CheckKey(key); err != nil {
		return nil, err
	}
	k := key.Reveal()
	defer clear(k)
	aead, err := chacha20poly1305.NewX(k)
	if err != nil {
		return nil, errors.New("vault: cipher setup failed")
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.New("vault: random source failed")
	}
	aad.Format, aad.Cipher = format, CipherName
	aadBytes, err := json.Marshal(aad)
	if err != nil {
		return nil, errors.New("vault: header encoding failed")
	}
	ct := aead.Seal(nil, nonce, plaintext, aadBytes)
	return json.Marshal(envelope{
		Format: format,
		Cipher: CipherName,
		Nonce:  base64.StdEncoding.EncodeToString(nonce),
		AAD:    aad,
		CT:     base64.StdEncoding.EncodeToString(ct),
	})
}

// Open verifies and decrypts an envelope of the given format. Every failure
// to trust the data is ErrCorrupt. The caller must wipe the returned plaintext.
func Open(format string, key secret.Secret, data []byte) ([]byte, AAD, error) {
	if err := CheckKey(key); err != nil {
		return nil, AAD{}, err
	}
	var env envelope
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return nil, AAD{}, corrupt("unreadable envelope")
	}
	if dec.More() {
		return nil, AAD{}, corrupt("trailing data")
	}
	if env.Format != format || env.AAD.Format != format {
		return nil, AAD{}, corrupt("unsupported format")
	}
	if env.Cipher != CipherName || env.AAD.Cipher != CipherName || env.Cipher != env.AAD.Cipher {
		return nil, AAD{}, corrupt("unsupported cipher")
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil || len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, AAD{}, corrupt("bad nonce")
	}
	ct, err := base64.StdEncoding.DecodeString(env.CT)
	if err != nil {
		return nil, AAD{}, corrupt("bad ciphertext encoding")
	}
	k := key.Reveal()
	defer clear(k)
	aead, err := chacha20poly1305.NewX(k)
	if err != nil {
		return nil, AAD{}, errors.New("vault: cipher setup failed")
	}
	aadBytes, err := json.Marshal(env.AAD)
	if err != nil {
		return nil, AAD{}, corrupt("bad header")
	}
	pt, err := aead.Open(nil, nonce, ct, aadBytes)
	if err != nil {
		return nil, AAD{}, corrupt("authentication failed")
	}
	return pt, env.AAD, nil
}
