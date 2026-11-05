package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/QuBiit0/qbit-vault/internal/vault"
)

// Sync rounds inside the ordinary commands (docs/REMOTE_SYNC.md § 7.1). The
// budgets and the pull interval are fixed until a config.yaml loader exists
// (config.remote.timeout and config.remote.pull_interval).
const (
	pushBudget   = 5 * time.Second
	pullBudget   = 2 * time.Second
	pullInterval = 60 * time.Second
)

const (
	warnUnreachable = "warning: not synced (server unreachable); will retry"
	warnConflict    = "warning: not synced (the server changed while syncing); will retry"
)

// Remote outcomes shown in the "remote" field of --json success objects.
const (
	remoteSynced  = "synced"
	remotePending = "pending"
)

func stderrOf(g *globals) io.Writer {
	if g.stderr != nil {
		return g.stderr
	}
	return io.Discard
}

// autoRound runs one round within budget. A server that cannot be reached
// leaves the push pending.
func (g *globals) autoRound(ctx context.Context, s *session, st *vault.Remote, budget time.Duration) (roundResult, error) {
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	d, err := s.device()
	if err != nil {
		return roundResult{}, err
	}
	defer d.wipe()
	c, err := g.connect(ctx, st, d)
	if err != nil {
		return roundResult{}, err
	}
	return g.syncRound(ctx, s, c, d.id)
}

// markPending records, from the state on disk, that a change has not reached
// the server.
func markPending(home string) {
	if st, err := vault.ReadRemote(home); err == nil && st != nil && !st.PendingPush {
		st.PendingPush = true
		_ = vault.WriteRemote(home, st)
	}
}

// warnRound tells the person why a round did not finish. A server that could
// not be reached has its own fixed line; every other failure names its code
// (a rollback or a refused verification must not pass for an outage).
func warnRound(w io.Writer, err error) {
	var ce codedError
	if errors.As(err, &ce) && ce.code == errUnreachable.code {
		fmt.Fprintln(w, warnUnreachable)
		return
	}
	code := "internal"
	if errors.As(err, &ce) {
		code = ce.code
	}
	if code == errRevoked.code {
		fmt.Fprintln(w, "warning: "+errRevoked.msg)
		return
	}
	fmt.Fprintf(w, "warning: not synced (%s); the change is kept on this device; run 'qbit-vault remote status'\n", code)
}

// pushAfter runs the round that follows a change to the vault, once the
// change is committed and the vault lock is released. It returns the value of
// the "remote" field, or "" when this vault does not sync. It never fails the
// command: the change is already local.
func (g *globals) pushAfter(ctx context.Context, stderr io.Writer, s *session) string {
	st, err := vault.ReadRemote(s.home)
	if err != nil || st == nil {
		return ""
	}
	if g.remoteOff() {
		markPending(s.home)
		return remotePending
	}
	res, err := g.autoRound(ctx, s, st, pushBudget)
	if err != nil {
		markPending(s.home)
		warnRound(stderr, err)
		return remotePending
	}
	if res.Result == remotePending { // only after the retries lost to another device
		fmt.Fprintln(stderr, warnConflict)
		return remotePending
	}
	return remoteSynced
}

// pushAfterOpen is pushAfterCmd for a command that holds no session (restore
// works on a vault that may not open); a vault that does not sync opens none.
func (g *globals) pushAfterOpen(cmd *cobra.Command) string {
	if st, err := vault.ReadRemote(g.Home()); err != nil || st == nil {
		return ""
	}
	s, err := g.openSession()
	if err != nil {
		markPending(g.Home())
		warnRound(cmd.ErrOrStderr(), err)
		return remotePending
	}
	defer s.close()
	return g.pushAfterCmd(cmd, s)
}

func (g *globals) pushAfterCmd(cmd *cobra.Command, s *session) string {
	return g.pushAfter(commandContext(cmd), cmd.ErrOrStderr(), s)
}

// pullDue reports whether a read should sync first.
func pullDue(st *vault.Remote) bool {
	if st.PendingPush {
		return true
	}
	t, err := time.Parse(time.RFC3339, st.LastPullAt)
	return err != nil || time.Since(t) > pullInterval
}

// pullBefore syncs before a command reads for a person or the agent, when the
// last pull is older than the pull interval or a push is pending. An
// unreachable server is silent here (remote status shows it); a refused round
// is not.
func (g *globals) pullBefore(ctx context.Context, stderr io.Writer, s *session) {
	if g.remoteOff() {
		return
	}
	st, err := vault.ReadRemote(s.home)
	if err != nil || st == nil || !pullDue(st) {
		return
	}
	wasPending := st.PendingPush
	if _, err := g.autoRound(ctx, s, st, pullBudget); err != nil {
		var ce codedError
		if !errors.As(err, &ce) || ce.code != errUnreachable.code {
			warnRound(stderr, err)
			return
		}
		// Nothing was waiting to be pushed: failing to read is not a pending push.
		if cur, rerr := vault.ReadRemote(s.home); rerr == nil && cur != nil && cur.PendingPush && !wasPending {
			cur.PendingPush = false
			_ = vault.WriteRemote(s.home, cur)
		}
	}
}

func (g *globals) pullBeforeCmd(cmd *cobra.Command, s *session) {
	g.pullBefore(commandContext(cmd), cmd.ErrOrStderr(), s)
}

// pullFirst is pullBefore for callers that have no session yet (the broker
// backend); a vault that does not sync never opens one.
func (g *globals) pullFirst(ctx context.Context) {
	if g.remoteOff() {
		return
	}
	if st, err := vault.ReadRemote(g.Home()); err != nil || st == nil || !pullDue(st) {
		return
	}
	s, err := g.openSession()
	if err != nil {
		return
	}
	defer s.close()
	g.pullBefore(ctx, stderrOf(g), s)
}
