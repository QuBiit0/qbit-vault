// Package minisign verifies Minisign signatures (https://jedisct1.github.io/minisign/)
// made in the prehashed "ED" mode, which is what `minisign -S` writes. It only
// verifies; signing lives in tools/release-sign.
//
// Errors are fixed strings. They never carry file content.
package minisign

import (
	"bytes"
	"crypto/ed25519"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/blake2b"
)

var (
	errMalformedKey = errors.New("malformed public key")
	errMalformedSig = errors.New("malformed signature")
	errOtherKey     = errors.New("signature made with another key")
	errNoMatch      = errors.New("signature does not match")
)

const (
	untrustedPrefix = "untrusted comment:"
	trustedPrefix   = "trusted comment: "
	idLen           = 8
)

// releaseKeyText is a copy of defaults/release-key.pub; a test keeps them equal.
//
//go:embed release-key.pub
var releaseKeyText string

// PublicKey is a Minisign public key.
type PublicKey struct {
	id  [idLen]byte
	key ed25519.PublicKey
}

// ReleaseKey returns the release public key pinned in this binary.
func ReleaseKey() (*PublicKey, error) { return ParsePublicKey([]byte(releaseKeyText)) }

// ID is the key id the way Minisign prints it (uppercase hex).
func (p *PublicKey) ID() string {
	var r [idLen]byte
	for i, b := range p.id {
		r[idLen-1-i] = b
	}
	return strings.ToUpper(hex.EncodeToString(r[:]))
}

// ParsePublicKey parses the two-line text form of a Minisign public key.
func ParsePublicKey(text []byte) (*PublicKey, error) {
	l, ok := splitLines(text, 2)
	if !ok || !strings.HasPrefix(l[0], untrustedPrefix) {
		return nil, errMalformedKey
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(l[1])
	if err != nil || len(raw) != 2+idLen+ed25519.PublicKeySize || string(raw[:2]) != "Ed" {
		return nil, errMalformedKey
	}
	p := &PublicKey{key: ed25519.PublicKey(bytes.Clone(raw[2+idLen:]))}
	copy(p.id[:], raw[2:2+idLen])
	return p, nil
}

// Verify checks sig, the content of a .minisig file, against msg. It accepts
// only algorithm ED, requires the key id to match, and checks both the file
// signature and the global signature over the trusted comment. It returns the
// trusted comment text.
func Verify(pub *PublicKey, msg, sig []byte) (string, error) {
	l, ok := splitLines(sig, 4)
	if !ok || !strings.HasPrefix(l[0], untrustedPrefix) || !strings.HasPrefix(l[2], trustedPrefix) {
		return "", errMalformedSig
	}
	body, err := base64.StdEncoding.Strict().DecodeString(l[1])
	if err != nil || len(body) != 2+idLen+ed25519.SignatureSize || string(body[:2]) != "ED" {
		return "", errMalformedSig
	}
	global, err := base64.StdEncoding.Strict().DecodeString(l[3])
	if err != nil || len(global) != ed25519.SignatureSize {
		return "", errMalformedSig
	}
	if !bytes.Equal(body[2:2+idLen], pub.id[:]) {
		return "", errOtherKey
	}
	fileSig := body[2+idLen:]
	digest := blake2b.Sum512(msg)
	if !ed25519.Verify(pub.key, digest[:], fileSig) {
		return "", errNoMatch
	}
	trusted := strings.TrimPrefix(l[2], trustedPrefix)
	if !ed25519.Verify(pub.key, append(bytes.Clone(fileSig), trusted...), global) {
		return "", errNoMatch
	}
	return trusted, nil
}

// splitLines splits b into exactly n LF-terminated lines (the last terminator
// is optional) with no CR anywhere.
func splitLines(b []byte, n int) ([]string, bool) {
	s := strings.TrimSuffix(string(b), "\n")
	if strings.Contains(s, "\r") {
		return nil, false
	}
	l := strings.Split(s, "\n")
	return l, len(l) == n
}
