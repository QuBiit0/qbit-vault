//go:build !windows && !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package cli

// isEventPoller is false on the remaining Unix systems, whose runtime poller
// is neither an epoll (valuefd_epoll.go) nor a kqueue (valuefd_kqueue.go).
func isEventPoller(int) bool { return false }
