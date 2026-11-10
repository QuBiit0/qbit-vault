// Package audit is the append-only, hash-chained audit log
// (docs/STORAGE.md § Audit log, R-AUD-01..03). A record carries secret
// names, never values: the API has no way to pass one in, and a name that
// does not match the secret-name rule is dropped rather than written.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/qbitdevz/qbit-vault/internal/lockfile"
	"github.com/qbitdevz/qbit-vault/internal/perm"
	"github.com/qbitdevz/qbit-vault/internal/vault"
)

const (
	logFile  = "audit.jsonl"
	headFile = "audit.head"
	lockName = "audit.lock"

	hashPrefix = "sha256:"
	// Genesis is the prev of the first record.
	Genesis = hashPrefix + "0000000000000000000000000000000000000000000000000000000000000000"
)

// Events are the values of Record.Event.
const (
	EventInit      = "init"
	EventCapture   = "capture"
	EventGrant     = "grant"
	EventExec      = "exec"
	EventManage    = "manage"
	EventRefusal   = "refusal"
	EventRevoke    = "revoke"
	EventRm        = "rm"
	EventMv        = "mv"
	EventEdit      = "edit"
	EventRelink    = "relink"
	EventLink      = "link"
	EventRekey     = "rekey"
	EventRestore   = "restore"
	EventUninstall = "uninstall"
	EventWarning   = "warning"
	EventPrompt    = "prompt"
	EventRemote    = "remote"
	EventExport    = "export"
)

var events = []string{
	EventInit, EventCapture, EventGrant, EventExec, EventManage, EventRefusal,
	EventRevoke, EventRm, EventMv, EventEdit, EventRelink, EventLink, EventRekey,
	EventRestore, EventUninstall, EventWarning, EventPrompt, EventRemote, EventExport,
}

// ValidEvent reports whether e is a known event name.
func ValidEvent(e string) bool {
	for _, k := range events {
		if k == e {
			return true
		}
	}
	return false
}

// ErrUnknownEvent is returned by Append for an event outside the enum.
var ErrUnknownEvent = errors.New("audit: unknown event")

// Host identifies the agent host a record came from.
type Host struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Record is one audit line. The field order is the wire order and is part of
// the hash; do not reorder. Append fills TS, Seq, Prev and Hash.
type Record struct {
	TS         string   `json:"ts"`
	Seq        uint64   `json:"seq"`
	Prev       string   `json:"prev"`
	Event      string   `json:"event"`
	Session    string   `json:"session"`
	Host       *Host    `json:"host,omitempty"`
	Names      []string `json:"names,omitempty"`
	Layer      string   `json:"layer,omitempty"`
	By         string   `json:"by,omitempty"`
	Reason     string   `json:"reason,omitempty"`
	Cwd        string   `json:"cwd,omitempty"`
	Refusal    string   `json:"refusal,omitempty"`
	Scope      string   `json:"scope,omitempty"`
	ExpiresAt  string   `json:"expires_at,omitempty"`
	Command    string   `json:"command,omitempty"`
	ExitCode   *int     `json:"exit_code,omitempty"`
	DurationMS *int64   `json:"duration_ms,omitempty"`
	Redactions int      `json:"redactions,omitempty"`
	Outcome    string   `json:"outcome,omitempty"`
	Detail     string   `json:"detail,omitempty"`
	Hash       string   `json:"hash"`
}

// now is the clock; tests pin it.
var now = time.Now

// lockOpts bounds the wait for audit.lock.
var lockOpts = lockfile.Options{}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hashPrefix + hex.EncodeToString(h[:])
}

// recordHash is the hash of r's canonical JSON with the hash field omitted.
func recordHash(r Record) string {
	r.Hash = ""
	b, _ := json.Marshal(r) // a Record always marshals
	return sum(b)
}

func lock(home string) (func(), error) {
	return lockfile.Acquire(home, lockName, lockOpts)
}

// cleanNames keeps the names that match the secret-name rule. It reports
// whether any name was dropped; a rejected name is never written.
func cleanNames(in []string) (out []string, dropped bool) {
	for _, n := range in {
		if vault.ValidName(n) {
			out = append(out, n)
		} else {
			dropped = true
		}
	}
	return out, dropped
}

// Append adds r to the log under home. It takes audit.lock, derives seq and
// prev from the last line (seeking from the end), writes one line with
// O_APPEND and fsync, then rewrites audit.head atomically.
//
// The first record of an empty or missing log has seq 1 and prev Genesis. If
// the last line is malformed Append does not guess from it: prev is the hash
// of its raw bytes and seq is the head's seq (or, without a readable head,
// the number of lines in the log) plus one, so Verify reports the damage
// instead of the chain silently continuing. home must exist.
func Append(home string, r Record) error {
	if !ValidEvent(r.Event) {
		return ErrUnknownEvent
	}
	names, dropped := cleanNames(r.Names)
	r.Names = names
	if dropped {
		if r.Detail == "" {
			r.Detail = "invalid name"
		} else {
			r.Detail += "; invalid name"
		}
	}
	release, err := lock(home)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("audit: %w", os.ErrNotExist)
		}
		return errors.New("audit: cannot take the audit lock")
	}
	defer release()

	path := filepath.Join(home, logFile)
	created := false
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		created = true
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return errors.New("audit: cannot open the log")
	}
	defer f.Close()
	if created {
		if err := perm.EnsureFile(path); err != nil {
			return errors.New("audit: cannot secure the log")
		}
	}

	seq, prev, sep, err := tailState(f, home)
	if err != nil {
		return err
	}
	r.TS = now().UTC().Format(time.RFC3339Nano)
	r.Seq, r.Prev = seq, prev
	r.Hash = recordHash(r)
	line, _ := json.Marshal(r)
	buf := make([]byte, 0, len(line)+2)
	if sep {
		buf = append(buf, '\n') // end a partial last line so ours starts fresh
	}
	buf = append(append(buf, line...), '\n')
	if _, err := f.Write(buf); err != nil {
		return errors.New("audit: cannot write the log")
	}
	if err := f.Sync(); err != nil {
		return errors.New("audit: cannot sync the log")
	}
	return writeHead(home, head{Seq: r.Seq, Hash: r.Hash, Line: sum(line)})
}
