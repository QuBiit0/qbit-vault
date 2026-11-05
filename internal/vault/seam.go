package vault

// SetWalkStopForTesting makes the upward search for a repository root stop
// before inspecting dir or anything above it, and returns a func that
// restores the previous value. It exists so tests outside this package are
// isolated from a checkout that happens to contain the temp directory
// (for example a home directory that is itself a Git repository). Production
// code must not call it; the default behavior is unchanged.
func SetWalkStopForTesting(dir string) (restore func()) {
	old := walkStop
	walkStop = dir
	return func() { walkStop = old }
}
