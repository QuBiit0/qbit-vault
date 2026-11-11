// Command release-sign makes and uses the Minisign key that signs releases.
// It is built only by the release workflow and the maintainer; it is not part
// of the qbit-vault binary.
//
//	release-sign keygen --pub <file>
//	release-sign sign <file> --version <tag>
//	release-sign verify <file>
//
// The secret is a seed: base64 (standard, padded) of the 8-byte key id followed
// by the 32-byte Ed25519 seed. keygen prints it once on stdout; sign reads it
// only from the environment variable QBIT_VAULT_SIGNING_KEY, never from an
// argument, and never writes it anywhere. verify checks <file>.minisig against
// the release public key compiled in (internal/minisign), the same check
// qbit-vault update does.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/qbitdevz/qbit-vault/internal/minisign"
	"golang.org/x/crypto/blake2b"
)

const (
	keyEnv  = "QBIT_VAULT_SIGNING_KEY"
	idLen   = 8
	usage   = "usage: release-sign keygen --pub <file> | release-sign sign <file> --version <tag> | release-sign verify <file>"
	sigName = "signature from minisign secret key"
)

type environment struct {
	getenv         func(string) string
	rand           io.Reader
	now            func() time.Time
	pinned         func() (*minisign.PublicKey, error) // nil: the release key compiled in
	stdout, stderr io.Writer
}

func main() {
	e := &environment{os.Getenv, rand.Reader, time.Now, nil, os.Stdout, os.Stderr}
	os.Exit(run(e, os.Args[1:]))
}

func run(e *environment, args []string) int {
	var err error
	switch {
	case len(args) == 0:
		err = errors.New(usage)
	case args[0] == "keygen":
		err = keygen(e, args[1:])
	case args[0] == "sign":
		err = sign(e, args[1:])
	case args[0] == "verify":
		err = verify(e, args[1:])
	default:
		err = errors.New(usage)
	}
	if err != nil {
		fmt.Fprintln(e.stderr, "release-sign:", err)
		return 1
	}
	return 0
}

// flagValue extracts "--name value" from args and returns the rest.
func flagValue(args []string, name string) (value string, rest []string, err error) {
	for i := 0; i < len(args); i++ {
		if args[i] != name {
			rest = append(rest, args[i])
			continue
		}
		if i+1 >= len(args) {
			return "", nil, errors.New(usage)
		}
		value = args[i+1]
		i++
	}
	return value, rest, nil
}

func keyIDHex(id []byte) string {
	r := make([]byte, len(id))
	for i, b := range id {
		r[len(id)-1-i] = b
	}
	return strings.ToUpper(hex.EncodeToString(r))
}

func keygen(e *environment, args []string) error {
	path, rest, err := flagValue(args, "--pub")
	if err != nil || path == "" || len(rest) != 0 {
		return errors.New(usage)
	}
	material := make([]byte, idLen+ed25519.SeedSize)
	if _, err := io.ReadFull(e.rand, material); err != nil {
		return errors.New("cannot read random bytes")
	}
	id, seed := material[:idLen], material[idLen:]
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	raw := append(append([]byte("Ed"), id...), pub...)
	text := "untrusted comment: minisign public key " + keyIDHex(id) + "\n" +
		base64.StdEncoding.EncodeToString(raw) + "\n"
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return errors.New("cannot create the public key file (it must not exist)")
	}
	if _, err := f.WriteString(text); err != nil {
		f.Close()
		return errors.New("cannot write the public key file")
	}
	if err := f.Close(); err != nil {
		return errors.New("cannot write the public key file")
	}
	fmt.Fprintln(e.stdout, base64.StdEncoding.EncodeToString(material))
	return nil
}

func sign(e *environment, args []string) error {
	version, rest, err := flagValue(args, "--version")
	if err != nil || version == "" || len(rest) != 1 || strings.ContainsAny(version, "\r\n") {
		return errors.New(usage)
	}
	file := rest[0]
	encoded := e.getenv(keyEnv)
	if encoded == "" {
		return errors.New(keyEnv + " is not set")
	}
	material, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(encoded))
	if err != nil || len(material) != idLen+ed25519.SeedSize {
		return errors.New(keyEnv + " is malformed")
	}
	id := material[:idLen]
	priv := ed25519.NewKeyFromSeed(material[idLen:])
	msg, err := os.ReadFile(file)
	if err != nil {
		return errors.New("cannot read " + file)
	}
	digest := blake2b.Sum512(msg)
	fileSig := ed25519.Sign(priv, digest[:])
	trusted := fmt.Sprintf("timestamp:%d file:%s version:%s", e.now().Unix(), filepath.Base(file), version)
	global := ed25519.Sign(priv, append(append([]byte{}, fileSig...), trusted...))
	body := append(append([]byte("ED"), id...), fileSig...)
	out := "untrusted comment: " + sigName + "\n" +
		base64.StdEncoding.EncodeToString(body) + "\n" +
		"trusted comment: " + trusted + "\n" +
		base64.StdEncoding.EncodeToString(global) + "\n"
	if err := os.WriteFile(file+".minisig", []byte(out), 0o644); err != nil {
		return errors.New("cannot write " + file + ".minisig")
	}
	fmt.Fprintln(e.stdout, "wrote "+file+".minisig")
	return nil
}

// verify checks <file>.minisig against the pinned release key. The workflow
// runs it after signing and again on the uploaded asset, before publishing.
func verify(e *environment, args []string) error {
	if len(args) != 1 {
		return errors.New(usage)
	}
	file := args[0]
	pinned := e.pinned
	if pinned == nil {
		pinned = minisign.ReleaseKey
	}
	pub, err := pinned()
	if err != nil {
		return errors.New("cannot load the release public key")
	}
	msg, err := os.ReadFile(file)
	if err != nil {
		return errors.New("cannot read " + file)
	}
	sig, err := os.ReadFile(file + ".minisig")
	if err != nil {
		return errors.New("cannot read " + file + ".minisig")
	}
	if _, err := minisign.Verify(pub, msg, sig); err != nil {
		return err
	}
	fmt.Fprintln(e.stdout, "verified "+file+".minisig with key "+pub.ID())
	return nil
}
