package prompt

import (
	"context"
	"sync"
)

// Contexter is a backend whose dialogs can end with a context: a native
// helper is killed and a terminal read stops, and the call fails with
// ErrCancelled. The prompt timeout still applies on top of it.
type Contexter interface {
	// WithContext returns the backend with every dialog bound to ctx.
	WithContext(ctx context.Context) Backend
}

// Bind binds b's dialogs to ctx when b supports it, so a tool call that the
// client cancels closes its dialog. Any other backend is returned as it is.
func Bind(ctx context.Context, b Backend) Backend {
	if c, ok := b.(Contexter); ok {
		return c.WithContext(ctx)
	}
	return b
}

// base is the context a dialog derives its timeout from.
func base(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// dialogs is the process-wide turn for a dialog: size one.
var dialogs = make(chan struct{}, 1)

// AcquireDialog waits for the turn to open a dialog, so two tool calls never
// show two dialogs at once. It returns when the turn is free or ctx ends
// (then with ctx.Err()). release gives the turn back; calling it again does
// nothing. Hold it for the whole interaction of one call and never while
// holding a vault or grants lock.
func AcquireDialog(ctx context.Context) (release func(), err error) {
	select {
	case dialogs <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	var once sync.Once
	return func() { once.Do(func() { <-dialogs }) }, nil
}
