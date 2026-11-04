package cli

import (
	"errors"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/QuBiit0/qbit-vault/internal/grants"
	"github.com/QuBiit0/qbit-vault/internal/hook"
	"github.com/QuBiit0/qbit-vault/internal/redact"
	"github.com/QuBiit0/qbit-vault/internal/secret"
)

// newHookCmd is the parent of the host hook commands (docs/CLI.md § Host
// plumbing). Each subcommand reads one hook event as JSON on stdin and writes
// the protocol JSON on stdout, nothing on stderr; none prompts or uses the
// network, and a broken hook fails open (exit 0 and a warning), so it does not
// go through the error reporting of the other commands. Only post-bash,
// post-read and user-prompt read the vault, and only without prompting.
func newHookCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hook",
		Short: "Host hooks: read an event on stdin, answer on stdout (host plumbing)",
		Args:  noArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	add := func(use, short string, run func(in io.Reader, out, errOut io.Writer) int) {
		cmd.AddCommand(&cobra.Command{
			Use:   use,
			Short: short,
			Args:  noArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				if code := run(stdinOf(cmd), cmd.OutOrStdout(), cmd.ErrOrStderr()); code != 0 {
					return exitError{code: code}
				}
				return nil
			},
		})
	}
	add("pre-bash", "PreToolUse on Bash/PowerShell: refuse user-only qbit-vault commands", hook.RunPreBash)
	add("post-bash", "PostToolUse on Bash/PowerShell: redact stored secret values from the output",
		func(in io.Reader, out, errOut io.Writer) int { return hook.RunPostBash(in, out, errOut, g.hookSource) })
	add("post-read", "PostToolUse on Read: redact stored secret values from the file content",
		func(in io.Reader, out, errOut io.Writer) int { return hook.RunPostRead(in, out, errOut, g.hookSource) })
	add("user-prompt", "UserPromptSubmit: block a prompt that carries a secret",
		func(in io.Reader, out, errOut io.Writer) int {
			return hook.RunUserPrompt(in, out, errOut, g.hookSource)
		})
	return cmd
}

// hookSource builds the redactor the post and user-prompt hooks use. It opens
// the vault the way `remote status` does, never prompting: a passphrase vault
// with no unlock cache is hook.ErrLocked, and a home with no vault has
// nothing to redact. It redacts every stored value of at least
// redact.ShortLen bytes (a value the agent reads from a file or a log is a
// leak whether or not a grant covers it), plus shorter values that have an
// active grant, which `exec` redacts too; shorter values without a grant are
// left alone because redacting a few characters would mangle ordinary text.
// The values are wiped before it returns; the redactor holds its own copies.
func (g *globals) hookSource() (*redact.Redactor, error) {
	s, err := g.openSessionQuiet()
	switch {
	case errors.Is(err, errSessionLocked):
		return nil, hook.ErrLocked
	case errors.Is(err, errNotInitialized):
		return nil, nil
	case err != nil:
		return nil, err
	}
	defer s.close()
	all, err := s.v.ListAll()
	if err != nil {
		return nil, mapErr(err, "")
	}
	defer wipeEntries(all)

	granted := map[[2]string]bool{}
	if _, err := s.v.ReadGrants(func(body []byte) error {
		st, err := grants.Decode(body)
		if err != nil {
			return err
		}
		for _, gr := range grants.Active(st, time.Now()) {
			granted[[2]string{gr.Name, gr.Layer}] = true
		}
		return nil
	}); err != nil {
		return nil, mapErr(err, "")
	}

	var values []secret.Secret
	for _, e := range all {
		if e.Record.Value.Len() >= redact.ShortLen || granted[[2]string{e.Name, e.Layer.Key()}] {
			values = append(values, e.Record.Value)
		}
	}
	return redact.New(values)
}
