package cli

import (
	"runtime/debug"
	"testing"
)

func TestResolveVersionUsesModuleVersionForGoInstall(t *testing.T) {
	bi := &debug.BuildInfo{Main: debug.Module{Version: "v0.1.0-beta.1"}}
	v, c := resolveVersion("dev", "unknown", bi)
	if v != "v0.1.0-beta.1" || c != "unknown" {
		t.Fatalf("resolveVersion = %q, %q", v, c)
	}
}

func TestResolveVersionUsesVCSRevisionForACheckout(t *testing.T) {
	bi := &debug.BuildInfo{
		Main:     debug.Module{Version: "(devel)"},
		Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "43d91a5e0c1b2a3f4d5e6f708192a3b4c5d6e7f8"}},
	}
	v, c := resolveVersion("dev", "unknown", bi)
	if v != "dev" || c != "43d91a5e0c1b" {
		t.Fatalf("resolveVersion = %q, %q", v, c)
	}
}

func TestResolveVersionKeepsLdflagsValues(t *testing.T) {
	bi := &debug.BuildInfo{
		Main:     debug.Module{Version: "v9.9.9"},
		Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "ffffffffffffffff"}},
	}
	v, c := resolveVersion("v0.1.0-beta.1", "abc1234", bi)
	if v != "v0.1.0-beta.1" || c != "abc1234" {
		t.Fatalf("resolveVersion = %q, %q", v, c)
	}
}

func TestResolveVersionWithoutBuildInfo(t *testing.T) {
	v, c := resolveVersion("dev", "unknown", nil)
	if v != "dev" || c != "unknown" {
		t.Fatalf("resolveVersion = %q, %q", v, c)
	}
}
