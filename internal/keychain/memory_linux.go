//go:build linux

package keychain

import "golang.org/x/sys/unix"

// Filesystem magic numbers (statfs f_type) of memory-backed filesystems.
const (
	tmpfsMagic = 0x01021994
	ramfsMagic = 0x858458f6
)

// onMemory reports whether dir is on tmpfs or ramfs. A directory that cannot
// be inspected is not trusted.
func onMemory(dir string) bool {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return false
	}
	t := uint32(st.Type)
	return t == tmpfsMagic || t == ramfsMagic
}
