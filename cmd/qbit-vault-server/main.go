// Command qbit-vault-server is the self-hosted, zero-knowledge sync server
// of qbit-vault (docs/REMOTE_SYNC.md § 10).
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/QuBiit0/qbit-vault/internal/server"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := server.Main(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
