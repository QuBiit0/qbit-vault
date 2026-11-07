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

// The release also publishes the server image (S9.1): multi-arch, tagged with
// the release version and latest, built from deploy/Dockerfile with the
// version baked in, by a job that holds only the permissions it needs.
func TestReleaseWorkflowPublishesTheServerImage(t *testing.T) {
	w := repoFile(t, ".github", "workflows", "release.yml")
	i := strings.Index(w, "\n  server-image:")
	if i < 0 {
		t.Fatal("release.yml has no server-image job")
	}
	job := w[i:]
	for _, want := range []string{
		"needs: release",
		"packages: write",
		"contents: read",
		"docker/setup-qemu-action@",
		"docker/setup-buildx-action@",
		"docker/login-action@",
		"docker/build-push-action@",
		"registry: ghcr.io",
		"platforms: linux/amd64,linux/arm64",
		"file: deploy/Dockerfile",
		"push: true",
		"ghcr.io/qubiit0/qbit-vault-server:${{ github.ref_name }}",
		"ghcr.io/qubiit0/qbit-vault-server:latest",
		"VERSION=${{ github.ref_name }}",
	} {
		if !strings.Contains(job, want) {
			t.Errorf("server-image job lacks %q", want)
		}
	}
	// Only the two permissions the job needs; nothing that can write code or
	// sign attestations.
	for _, bad := range []string{"contents: write", "id-token", "attestations", "pull-requests", "actions: write"} {
		if strings.Contains(job, bad) {
			t.Errorf("server-image job holds %q", bad)
		}
	}
	// Workflow-level permissions stay read-only so no job inherits a write.
	if !strings.Contains(w, "\npermissions:\n  contents: read\n") {
		t.Error("release.yml lost its top-level read-only permissions")
	}
}

// The server reports the version baked into the image (/v1/info, status page).
func TestDockerfileBakesTheVersionIntoTheServer(t *testing.T) {
	d := repoFile(t, "deploy", "Dockerfile")
	for _, want := range []string{"ARG VERSION=dev", "QBV_SERVER_VERSION=${VERSION}"} {
		if !strings.Contains(d, want) {
			t.Errorf("deploy/Dockerfile lacks %q", want)
		}
	}
}

// compose.image.yaml runs the published image with the hardening of
// compose.yaml (S9.1); compose.yaml still builds from the repository.
func TestComposeImageRunsThePublishedImageWithTheSameHardening(t *testing.T) {
	img := repoFile(t, "deploy", "compose.image.yaml")
	if !strings.Contains(img, "image: ghcr.io/qubiit0/qbit-vault-server:latest") {
		t.Error("compose.image.yaml does not run the published image")
	}
	if strings.Contains(img, "build:") {
		t.Error("compose.image.yaml must not build")
	}
	for _, want := range []string{
		"read_only: true",
		`user: "65532:65532"`,
		"cap_drop: [ALL]",
		`security_opt: ["no-new-privileges:true"]`,
		"- vault-data:/data",
		"QBV_SERVER_PUBLIC_URL: ${QBV_SERVER_PUBLIC_URL:?",
		"QBV_SERVER_TRUST_PROXY:",
		`test: ["CMD", "/qbit-vault-server", "health"]`,
		"restart: unless-stopped",
	} {
		if !strings.Contains(img, want) {
			t.Errorf("compose.image.yaml lacks %q", want)
		}
		if !strings.Contains(repoFile(t, "deploy", "compose.yaml"), want) {
			t.Errorf("compose.yaml lacks %q (the two files must stay equally hardened)", want)
		}
	}
	if !strings.Contains(repoFile(t, "deploy", "compose.yaml"), "dockerfile: deploy/Dockerfile") {
		t.Error("compose.yaml must keep building from the repository")
	}
}

func TestDocsShowThePublishedServerImageFirst(t *testing.T) {
	for _, f := range [][]string{{"deploy", "README.md"}, {"docs", "INSTALL.md"}} {
		d := repoFile(t, f...)
		if !strings.Contains(d, "compose.image.yaml") || !strings.Contains(d, "ghcr.io/qubiit0/qbit-vault-server") {
			t.Errorf("%s does not show the published image path", filepath.Join(f...))
		}
		if strings.Contains(d, "No image is published yet") {
			t.Errorf("%s still says no image is published", filepath.Join(f...))
		}
	}
}

func TestReadmeHasFirstFiveMinutesWithTheDialogScreenshot(t *testing.T) {
	r := repoFile(t, "README.md")
	i := strings.Index(r, "First 5 minutes")
	if i < 0 {
		t.Fatal("README lacks a First 5 minutes section")
	}
	sec := r[i:]
	if j := strings.Index(sec[1:], "\n## "); j >= 0 {
		sec = sec[:j+1]
	}
	for _, want := range []string{"qbit-vault init", "assets/screenshots/permission-dialog.png", "Once", "Always: in this project"} {
		if !strings.Contains(sec, want) {
			t.Errorf("First 5 minutes lacks %q", want)
		}
	}
	if _, err := os.Stat(filepath.Join("..", "..", "assets", "screenshots", "permission-dialog.png")); err != nil {
		t.Errorf("screenshot missing: %v", err)
	}
	if strings.Index(r, "releases/latest/download/install.sh") > i {
		t.Error("First 5 minutes must come after the install commands")
	}
}
