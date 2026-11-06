//go:build !linux

package keychain

// onMemory is true off Linux: the cache only runs on Linux, so the answer is
// only reached by tests that pretend to be Linux.
func onMemory(string) bool { return true }
