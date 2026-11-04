//go:build !crashseam

package cli

// crashAt is the crash point of a rotation (see remotecrash_on.go). Release
// builds have none: it does nothing and holds no hook.
func crashAt(string) error { return nil }
