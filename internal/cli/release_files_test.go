package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// repoFile reads a file of the repository from a test in internal/cli.
func repoFile(t *testing.T, parts ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{"..", ".."}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}

// Every GitHub Action is pinned to a full commit SHA with its version in a
// comment (S8.4), so a moved tag cannot change what a release job runs.
func TestWorkflowActionsArePinnedToCommitSHAs(t *testing.T) {
	pinned := regexp.MustCompile(`^\s*- uses: [\w./-]+@[0-9a-f]{40} # v\d+\.\d+\.\d+$`)
	for _, wf := range []string{"ci.yml", "release.yml"} {
		uses := 0
		for _, line := range strings.Split(repoFile(t, ".github", "workflows", wf), "\n") {
			if !strings.Contains(line, "uses:") {
				continue
			}
			uses++
			if !pinned.MatchString(line) {
				t.Errorf("%s: action not pinned to a SHA with a version comment: %q", wf, line)
			}
		}
		if uses == 0 {
			t.Errorf("%s: no actions found", wf)
		}
	}
}

func TestDependabotUpdatesGitHubActionsWeekly(t *testing.T) {
	d := repoFile(t, ".github", "dependabot.yml")
	for _, want := range []string{"package-ecosystem: github-actions", "directory: /", "interval: weekly"} {
		if !strings.Contains(d, want) {
			t.Errorf("dependabot.yml lacks %q", want)
		}
	}
}

// The installers are release assets listed in checksums.txt, releases are
// regular releases (releases/latest skips pre-releases), and the notes link
// the CHANGELOG instead of listing commits (S8.1, S8.5).
func TestGoReleaserPublishesTheInstallersAsReleaseAssets(t *testing.T) {
	g := repoFile(t, ".goreleaser.yaml")
	if strings.Count(g, "glob: scripts/install.sh") != 2 || strings.Count(g, "glob: scripts/install.ps1") != 2 {
		t.Error("both installers must be in checksum.extra_files and release.extra_files")
	}
	for _, want := range []string{`prerelease: "false"`, "changelog:\n  disable: true", "blob/{{ .Tag }}/CHANGELOG.md"} {
		if !strings.Contains(g, want) {
			t.Errorf(".goreleaser.yaml lacks %q", want)
		}
	}
	if strings.Contains(g, "prerelease: auto") || strings.Contains(g, "use: github") {
		t.Error(".goreleaser.yaml still publishes pre-releases or the commit list")
	}
	if strings.Contains(g, "raw.githubusercontent.com") {
		t.Error("the release footer must point at releases/latest/download, not main")
	}
}

func TestDocsServeTheInstallersFromTheLatestRelease(t *testing.T) {
	for _, f := range [][]string{{"README.md"}, {"docs", "INSTALL.md"}} {
		d := repoFile(t, f...)
		for _, want := range []string{
			"https://github.com/QuBiit0/qbit-vault/releases/latest/download/install.sh",
			"https://github.com/QuBiit0/qbit-vault/releases/latest/download/install.ps1",
		} {
			if !strings.Contains(d, want) {
				t.Errorf("%s lacks %s", filepath.Join(f...), want)
			}
		}
		if strings.Contains(d, "raw.githubusercontent.com/QuBiit0/qbit-vault/main/scripts/install") {
			t.Errorf("%s still shows the installer from main", filepath.Join(f...))
		}
	}
}
