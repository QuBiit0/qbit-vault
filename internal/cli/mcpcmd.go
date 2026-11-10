package cli

import (
	"errors"
	"io"
	"os"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	"github.com/qbitdevz/qbit-vault/internal/mcp"
)

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

// newMCPCmd is the stdio MCP server the hosts start (docs/CLI.md § Host
// plumbing). stdout carries only the protocol; the session is --session /
// QBIT_VAULT_SESSION, else a fresh mcp:<random> id. Each call's cwd is the
// server's working directory, which the host sets to the project.
func newMCPCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Serve the four secret tools over stdio MCP (host plumbing)",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			session := g.Session
			if session == "" {
				session = mcp.NewSession()
			}
			srv := mcp.NewServer(&cliBackend{g: g}, mcp.Options{Session: session, Cwd: os.Getwd, Version: Version})
			t := &sdk.IOTransport{Reader: io.NopCloser(stdinOf(cmd)), Writer: nopWriteCloser{cmd.OutOrStdout()}}
			err := srv.Run(commandContext(cmd), t)
			if err == nil || errors.Is(err, io.EOF) {
				return nil // the host closed the stream
			}
			return codedError{"internal", "mcp server stopped: connection error", 1}
		},
	}
}
