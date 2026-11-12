// Package minisigntest makes throwaway Minisign keys and signatures for tests
// of the code that verifies releases. It is imported only by tests, so no
// binary carries it; it never reads the release key or a real secret.
package minisigntest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"

	"github.com/qbitdevz/qbit-vault/internal/minisign"
	"golang.org/x/crypto/blake2b"
)

// Signer signs like `minisign -S` with a key derived from a one-byte tag, so
// two tags give two unrelated keys.
type Signer struct {
	Pub     *minisign.PublicKey
	PubText string
	priv    ed25519.PrivateKey
	id      [8]byte
}

// New returns the signer for tag.
func New(tag byte) *Signer {
	s := &Signer{priv: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{tag}, 32))}
	s.id = [8]byte{tag, 1, 2, 3, 4, 5, 6, 7}
	raw := append(append([]byte("Ed"), s.id[:]...), s.priv.Public().(ed25519.PublicKey)...)
	s.PubText = "untrusted comment: minisign public key TEST\n" + base64.StdEncoding.EncodeToString(raw) + "\n"
	pub, err := minisign.ParsePublicKey([]byte(s.PubText))
	if err != nil {
		panic("minisigntest: " + err.Error())
	}
	s.Pub = pub
	return s
}

// Sign returns the content of the .minisig file for msg.
func (s *Signer) Sign(msg []byte, trusted string) []byte {
	digest := blake2b.Sum512(msg)
	sig := ed25519.Sign(s.priv, digest[:])
	body := append(append([]byte("ED"), s.id[:]...), sig...)
	global := ed25519.Sign(s.priv, append(bytes.Clone(sig), trusted...))
	return []byte("untrusted comment: signature from minisign secret key\n" +
		base64.StdEncoding.EncodeToString(body) + "\n" +
		"trusted comment: " + trusted + "\n" +
		base64.StdEncoding.EncodeToString(global) + "\n")
}
