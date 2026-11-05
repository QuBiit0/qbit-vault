package cli

import "runtime/debug"

func init() {
	bi, _ := debug.ReadBuildInfo()
	Version, Commit = resolveVersion(Version, Commit, bi)
}

// resolveVersion fills the values a release sets by ldflags from the build
// info Go records, so `go install …@v0.1.0` reports v0.1.0 and a checkout
// build reports its commit. Values set by ldflags always win.
func resolveVersion(version, commit string, bi *debug.BuildInfo) (string, string) {
	if bi == nil {
		return version, commit
	}
	if version == "dev" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		version = bi.Main.Version
	}
	if commit == "unknown" {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" && s.Value != "" {
				commit = s.Value
				if len(commit) > 12 {
					commit = commit[:12]
				}
			}
		}
	}
	return version, commit
}
