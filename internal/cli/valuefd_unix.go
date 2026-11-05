//go:build !windows

package cli

import "syscall"

// valueFDKindOK reports whether fd is something a host can hand a child for
// `prompt --value`: a pipe, a socket, a regular file or a terminal. It checks
// with fstat, without wrapping fd in an *os.File, so a descriptor that is not
// ours (a directory, a closed number, the Go runtime's own epoll or kqueue,
// which takes fd 3 when the parent passed nothing there) is never closed by a
// finalizer.
func valueFDKindOK(fd int) bool {
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return false
	}
	switch st.Mode & syscall.S_IFMT {
	case syscall.S_IFIFO, syscall.S_IFSOCK, syscall.S_IFREG, syscall.S_IFCHR:
		return true
	}
	return false
}
