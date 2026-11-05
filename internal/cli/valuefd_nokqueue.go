//go:build !windows && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package cli

// isEventPoller is false where the runtime's poller is not a kqueue: on Linux
// it is an epoll, whose fstat reports no file type, so valueFDKindOK already
// refuses it.
func isEventPoller(int) bool { return false }
