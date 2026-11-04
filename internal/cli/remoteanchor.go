package cli

import (
	"context"
	"time"

	"github.com/QuBiit0/qbit-vault/internal/audit"
	"github.com/QuBiit0/qbit-vault/internal/remote"
	"github.com/QuBiit0/qbit-vault/internal/vault"
)

// Audit anchors (docs/REMOTE_SYNC.md § 8). A round uploads the head of the
// local audit log, sealed with the anchor key, at most every 10 minutes;
// `audit --verify` compares the log with the anchors the server kept.

const (
	anchorEvery  = 10 * time.Minute
	anchorBudget = 5 * time.Second
)

// anchorNow is the clock of the 10 minute rule; tests pin it.
var anchorNow = time.Now

// Outcomes of the remote half of `audit --verify`.
const (
	anchorOK          = "ok"
	anchorUnavailable = "unavailable"
	anchorNone        = "none"
	anchorMismatch    = "mismatch"
	// anchorMissing: this device uploaded anchors, yet the server returned
	// none this key opens (a key rotation since, or a server that removed
	// or altered them). It does not fail the verification but must not read
	// like a fresh account.
	anchorMissing = "missing"
)

// uploadAnchor is step 5 of a round. It is best effort: an anchor that
// cannot be sealed or sent never fails the round, and the next round tries
// again.
func (g *globals) uploadAnchor(ctx context.Context, s *session, st *vault.Remote, c *remote.Client, deviceID string) {
	now := anchorNow()
	if at, ok, err := vault.ReadAnchorAt(s.home); err != nil || (ok && now.Sub(at) < anchorEvery) {
		return
	}
	seq, line, ok := audit.ReadHead(s.home)
	if !ok {
		return
	}
	keys := remote.Subkeys(s.key)
	defer keys.Vault.Wipe()
	defer keys.Anchor.Wipe()
	defer keys.Pairing.Wipe()
	blob, err := remote.SealAnchor(keys.Anchor, st.AccountID, st.Generation,
		remote.Anchor{DeviceID: deviceID, Seq: int64(seq), Line: line, At: now.UTC().Format(time.RFC3339)})
	if err != nil {
		return
	}
	if err := c.PutAnchor(ctx, blob); err != nil {
		return
	}
	_ = vault.WriteAnchorAt(s.home, now)
}

// anchorState is the remote half of an audit verification.
type anchorState struct {
	State   string
	Seq     int64
	At      string
	Problem *audit.Problem
}

// verifyAnchors fetches this device's anchors and checks the log against
// them. Anything that keeps it from asking (no key without a prompt, no network, a refusing
// server) is "unavailable": the local verification stands on its own.
func (g *globals) verifyAnchors(ctx context.Context, home string, st *vault.Remote) anchorState {
	unavailable := anchorState{State: anchorUnavailable}
	ctx, cancel := context.WithTimeout(ctx, anchorBudget)
	defer cancel()
	// Never prompts and never finishes a rekey: without a key that opens the
	// vault as it is, the check is unavailable.
	s, err := g.openSessionQuiet()
	if err != nil {
		return unavailable
	}
	defer s.close()
	d, err := s.device()
	if err != nil {
		return unavailable
	}
	defer d.wipe()
	c, err := g.connect(ctx, st, d)
	if err != nil {
		return unavailable
	}
	blobs, err := c.Anchors(ctx, d.id)
	if err != nil {
		return unavailable
	}
	keys := remote.Subkeys(s.key)
	defer keys.Vault.Wipe()
	defer keys.Anchor.Wipe()
	defer keys.Pairing.Wipe()
	var (
		pts    []audit.AnchorPoint
		latest remote.Anchor
	)
	for _, blob := range blobs {
		// An anchor this key does not open (sealed before a key rotation, or
		// altered by the server) proves nothing either way.
		a, err := remote.OpenAnchor(keys.Anchor, st.AccountID, blob)
		if err != nil || a.DeviceID != d.id || a.Seq < 1 {
			continue
		}
		pts = append(pts, audit.AnchorPoint{Seq: uint64(a.Seq), Line: a.Line})
		if a.Seq >= latest.Seq {
			latest = a
		}
	}
	if len(pts) == 0 {
		if _, uploaded, err := vault.ReadAnchorAt(home); err == nil && uploaded {
			return anchorState{State: anchorMissing}
		}
		return anchorState{State: anchorNone}
	}
	p, err := audit.CheckAnchors(home, pts)
	switch {
	case err != nil:
		return unavailable
	case p != nil:
		return anchorState{State: anchorMismatch, Problem: p}
	}
	return anchorState{State: anchorOK, Seq: latest.Seq, At: oneLine(latest.At)}
}
