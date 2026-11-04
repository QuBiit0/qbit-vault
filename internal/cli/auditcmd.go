package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/QuBiit0/qbit-vault/internal/audit"
	"github.com/QuBiit0/qbit-vault/internal/exitcode"
	"github.com/QuBiit0/qbit-vault/internal/refusal"
	"github.com/QuBiit0/qbit-vault/internal/vault"
)

// defaultAuditTail is how many records `audit` lists without --tail.
const defaultAuditTail = 50

// cliSession is the audit session of a command run without --session.
const cliSession = "cli"

const auditWriteWarning = "warning: audit log write failed\n"

// exitError ends the process with code without printing anything: the
// command already reported its result.
type exitError struct{ code int }

func (e exitError) Error() string { return "exit " + strconv.Itoa(e.code) }

// auditLayer is the layer text of an audit record: "global" or
// "project:<root>".
func auditLayer(l vault.Layer) string {
	if l.Project {
		return "project:" + l.Root
	}
	return "global"
}

// record appends r to the audit log on behalf of the user. The operations
// that call it have already committed, so a failed write is a warning on
// stderr and never changes the outcome (L4). A home that does not exist has
// no vault to audit and is skipped.
func (g *globals) record(stderr io.Writer, r audit.Record) {
	if r.Session == "" {
		r.Session = g.Session
	}
	if r.Session == "" {
		r.Session = cliSession
	}
	if r.By == "" {
		r.By = "user" // the default actor; a broker capture says "agent"
	}
	err := audit.Append(g.Home(), r)
	if err == nil || errors.Is(err, os.ErrNotExist) {
		return
	}
	_, _ = io.WriteString(stderr, auditWriteWarning)
}

// recordRefusal audits a typed refusal returned by a command. The name is
// the validated one the refusal carries; the audit drops an invalid one.
func (g *globals) recordRefusal(stderr io.Writer, rf refusal.Refusal) {
	r := audit.Record{Event: audit.EventRefusal, Refusal: string(rf.Type)}
	if rf.Name != nil {
		r.Names = []string{*rf.Name}
	}
	g.record(stderr, r)
}

type auditListBody struct {
	OK      bool           `json:"ok"`
	Records []audit.Record `json:"records"`
}

type auditVerifyBody struct {
	OK      bool           `json:"ok"`
	Valid   bool           `json:"valid"`
	Records int            `json:"records"`
	Problem *audit.Problem `json:"problem,omitempty"`
	// Anchor is the state of the check against the server's anchors, only
	// when the vault syncs and the check ran: ok, none, unavailable or
	// mismatch (REMOTE_SYNC § 8).
	Anchor    string `json:"anchor,omitempty"`
	AnchorSeq int64  `json:"anchor_seq,omitempty"`
	AnchorAt  string `json:"anchor_at,omitempty"`
}

func newAudit(g *globals) *cobra.Command {
	var (
		tail    int
		since   string
		name    string
		event   string
		verify  bool
		offline bool
	)
	cmd := &cobra.Command{
		Use:   "audit [--tail N] [--since DURATION] [--name NAME] [--event EVENT] | --verify",
		Short: "Read the audit log or verify its hash chain",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f := cmd.Flags()
			filtered := f.Changed("tail") || f.Changed("since") || f.Changed("name") || f.Changed("event")
			if verify && filtered {
				return usageError{"--verify cannot be combined with filters"}
			}
			if offline && !verify {
				return usageError{"--offline only applies to --verify"}
			}
			if tail <= 0 {
				return usageError{"invalid --tail: must be a positive number"}
			}
			var from time.Time
			if f.Changed("since") {
				d, err := time.ParseDuration(since)
				if err != nil || d <= 0 {
					return usageError{"invalid --since: use a duration such as 24h"}
				}
				from = time.Now().Add(-d)
			}
			if f.Changed("event") && !audit.ValidEvent(event) {
				return usageError{"invalid --event: not a known event"}
			}
			if f.Changed("name") && !vault.ValidName(name) {
				return usageError{"invalid --name: not a valid secret name"}
			}
			home := g.Home()
			if _, err := os.Stat(home); err != nil {
				return mapErr(err, "")
			}
			out := cmd.OutOrStdout()
			if verify {
				return runVerify(cmd.Context(), g, out, home, offline)
			}
			recs, err := audit.Read(home, audit.Filter{Tail: tail, Since: from, Name: name, Event: event})
			if err != nil {
				return err
			}
			if g.JSON {
				if recs == nil {
					recs = []audit.Record{}
				}
				return writeJSON(out, auditListBody{OK: true, Records: recs})
			}
			if len(recs) == 0 {
				_, err = io.WriteString(out, "no audit records\n")
				return err
			}
			var b strings.Builder
			for _, r := range recs {
				b.WriteString(auditLine(r))
				b.WriteByte('\n')
			}
			_, err = io.WriteString(out, b.String())
			return err
		},
	}
	fl := cmd.Flags()
	fl.IntVar(&tail, "tail", defaultAuditTail, "show only the newest N records")
	fl.StringVar(&since, "since", "", "show only records newer than this duration, e.g. 24h")
	fl.StringVar(&name, "name", "", "show only records naming this secret")
	fl.StringVar(&event, "event", "", "show only records of this event")
	fl.BoolVar(&verify, "verify", false, "validate the hash chain instead of listing")
	fl.BoolVar(&offline, "offline", false, "with --verify, do not check the server's audit anchors")
	return cmd
}

func runVerify(ctx context.Context, g *globals, out io.Writer, home string, offline bool) error {
	res, err := audit.Verify(home)
	if err != nil {
		return err
	}
	// With sync enabled the log is also compared with the anchors the server
	// kept (§ 8); an unreachable server never fails the verification.
	var anchor anchorState
	if res.Valid && !offline && !g.remoteOff() {
		st, rerr := vault.ReadRemote(home)
		switch {
		case rerr != nil && !errors.Is(rerr, os.ErrNotExist):
			// The state that says whether this vault syncs cannot be read:
			// say so instead of passing for a vault that does not sync.
			anchor = anchorState{State: anchorUnavailable}
		case rerr == nil && st != nil:
			anchor = g.verifyAnchors(ctx, home, st)
			if anchor.State == anchorMismatch {
				res.Valid, res.Problem = false, anchor.Problem
			}
		}
	}
	if g.JSON {
		body := auditVerifyBody{OK: true, Valid: res.Valid, Records: res.Records, Problem: res.Problem, Anchor: anchor.State, AnchorSeq: anchor.Seq, AnchorAt: anchor.At}
		if err := writeJSON(out, body); err != nil {
			return err
		}
	} else if res.Valid {
		noun := "records"
		if res.Records == 1 {
			noun = "record"
		}
		if _, err := fmt.Fprintf(out, "audit log ok (%d %s)\n", res.Records, noun); err != nil {
			return err
		}
		if line := anchorLine(anchor); line != "" {
			if _, err := fmt.Fprintln(out, line); err != nil {
				return err
			}
		}
	} else if _, err := fmt.Fprintf(out, "audit log broken at line %d (seq %d): %s\n", res.Problem.Line, res.Problem.Seq, res.Problem.Reason); err != nil {
		return err
	}
	if !res.Valid {
		return exitError{exitcode.Failure}
	}
	return nil
}

// anchorLine is the human line for the remote half of a verification; empty
// when it did not run.
func anchorLine(a anchorState) string {
	switch a.State {
	case anchorOK:
		return fmt.Sprintf("remote anchor ok (seq %d, %s)", a.Seq, a.At)
	case anchorUnavailable:
		return "remote anchor: unavailable"
	case anchorNone:
		return "remote anchor: none uploaded"
	case anchorMissing:
		return "remote anchor: missing (this device uploaded anchors; the server returned none this key opens)"
	}
	return ""
}

// auditLine is the human form of one record:
// <ts> <event> <names> <layer> <session> [exit=<code>], with "-" for empty
// names and layer.
func auditLine(r audit.Record) string {
	names, layer := "-", "-"
	if len(r.Names) > 0 {
		names = strings.Join(r.Names, ",")
	}
	if r.Layer != "" {
		layer = r.Layer
	}
	fields := []string{r.TS, r.Event, names, layer, r.Session}
	if r.ExitCode != nil {
		fields = append(fields, "exit="+strconv.Itoa(*r.ExitCode))
	}
	return oneLine(strings.Join(fields, " "))
}
