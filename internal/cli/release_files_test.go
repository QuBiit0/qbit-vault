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
	for _, wf := range []string{"ci.yml", "release.yml", "pi-extension-release.yml"} {
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
			"https://github.com/qbitdevz/qbit-vault/releases/latest/download/install.sh",
			"https://github.com/qbitdevz/qbit-vault/releases/latest/download/install.ps1",
		} {
			if !strings.Contains(d, want) {
				t.Errorf("%s lacks %s", filepath.Join(f...), want)
			}
		}
		if strings.Contains(d, "raw.githubusercontent.com/qbitdevz/qbit-vault/main/scripts/install") {
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
		"needs: sign",
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
		"ghcr.io/qbitdevz/qbit-vault-server:${{ github.ref_name }}",
		"ghcr.io/qbitdevz/qbit-vault-server:latest",
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
	if !strings.Contains(img, "image: ghcr.io/qbitdevz/qbit-vault-server:latest") {
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
		if !strings.Contains(d, "compose.image.yaml") || !strings.Contains(d, "ghcr.io/qbitdevz/qbit-vault-server") {
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

// The extension workflow is manual, writes only contents, never forces a push
// and never refers to the tag of a binary release; release.yml only reacts to
// tags that start with v, so pi-v* tags cannot start it (S12.1).
func TestPiExtensionReleaseWorkflowIsManualAndNeverForces(t *testing.T) {
	w := repoFile(t, ".github", "workflows", "pi-extension-release.yml")
	for _, want := range []string{
		"\non:\n  workflow_dispatch:\n",
		"\npermissions:\n  contents: read\n",
		"contents: write",
		"git commit-tree",
		"git push --atomic origin",
		"refs/heads/pi-extension",
		"already exists",
		"github-actions[bot]",
	} {
		if !strings.Contains(w, want) {
			t.Errorf("pi-extension-release.yml lacks %q", want)
		}
	}
	for _, bad := range []string{"--force", "push -f", "\n  push:", "id-token"} {
		if strings.Contains(w, bad) {
			t.Errorf("pi-extension-release.yml contains %q", bad)
		}
	}
	if !strings.Contains(repoFile(t, ".github", "workflows", "release.yml"), `tags: ["v*"]`) {
		t.Error("release.yml no longer filters on v* tags: re-check that pi-v* cannot trigger it")
	}
}

// jobText returns the text of one job of release.yml: from its key to the next
// job (or the end of the file).
func jobText(t *testing.T, name string) string {
	t.Helper()
	w := repoFile(t, ".github", "workflows", "release.yml")
	start := strings.Index(w, "\n  "+name+":\n")
	if start < 0 {
		t.Fatalf("release.yml has no %s job", name)
	}
	job := w[start+1:]
	if m := regexp.MustCompile(`\n  [a-z][a-z-]*:\n`).FindStringIndex(job); m != nil {
		job = job[:m[0]+1]
	}
	return job
}

// stepText returns the step of a job whose "name:" is name.
func stepText(t *testing.T, job, name string) string {
	t.Helper()
	for _, step := range strings.Split(job, "\n      - ") {
		if strings.HasPrefix(step, "name: "+name+"\n") {
			return step
		}
	}
	t.Fatalf("no step named %q", name)
	return ""
}

// The release is a draft until the sign job has put checksums.txt.minisig on
// it (S4.1); it stays a regular release, not a pre-release.
func TestGoReleaserPublishesADraft(t *testing.T) {
	g := repoFile(t, ".goreleaser.yaml")
	i := strings.Index(g, "\nrelease:\n")
	if i < 0 {
		t.Fatal(".goreleaser.yaml has no release block")
	}
	block := g[i:]
	for _, want := range []string{"\n  draft: true\n", `prerelease: "false"`} {
		if !strings.Contains(block, want) {
			t.Errorf("release block lacks %q", want)
		}
	}
}

// release -> sign -> server-image: the image is only published for a signed
// release, and the release is only published by sign (S4.1).
func TestReleaseJobsRunInOrder(t *testing.T) {
	w := repoFile(t, ".github", "workflows", "release.yml")
	r, s, im := strings.Index(w, "\n  release:\n"), strings.Index(w, "\n  sign:\n"), strings.Index(w, "\n  server-image:\n")
	if r < 0 || s < 0 || im < 0 || !(r < s && s < im) {
		t.Fatalf("jobs must be release, sign, server-image in that order (at %d, %d, %d)", r, s, im)
	}
	if !strings.Contains(jobText(t, "sign"), "\n    needs: release\n") {
		t.Error("sign must need release")
	}
	if !strings.Contains(jobText(t, "server-image"), "\n    needs: sign\n") {
		t.Error("server-image must need sign")
	}
	if strings.Contains(jobText(t, "release"), "needs:") {
		t.Error("release must not need another job")
	}
}

func TestSignJobIsProtectedAndMinimal(t *testing.T) {
	job := jobText(t, "sign")
	if !strings.Contains(job, "\n    environment: release-signing\n") {
		t.Error("sign must run in the release-signing environment")
	}
	m := regexp.MustCompile(`\n    permissions:\n((?:      .*\n)+)`).FindStringSubmatch(job)
	if m == nil {
		t.Fatal("sign has no permissions block")
	}
	var perms []string
	for _, line := range strings.Split(strings.TrimSpace(m[1]), "\n") {
		perms = append(perms, strings.TrimSpace(strings.SplitN(line, "#", 2)[0]))
	}
	if len(perms) != 1 || perms[0] != "contents: write" {
		t.Errorf("sign permissions = %q, want exactly [contents: write]", perms)
	}
	for _, bad := range []string{"id-token", "attestations", "packages", "secrets: inherit", "\n    env:"} {
		if strings.Contains(job, bad) {
			t.Errorf("sign job contains %q", bad)
		}
	}
}

// The signing seed is set in the environment of one step of the sign job and
// nowhere else in the workflow (S4.3).
func TestOnlyTheSignStepSeesTheSigningKey(t *testing.T) {
	w := repoFile(t, ".github", "workflows", "release.yml")
	const ref = "secrets.QBIT_VAULT_SIGNING_KEY"
	if n := strings.Count(w, ref); n != 1 {
		t.Fatalf("%s appears %d times in release.yml, want 1", ref, n)
	}
	step := stepText(t, jobText(t, "sign"), "sign")
	if !strings.Contains(step, "        env:\n          QBIT_VAULT_SIGNING_KEY: ${{ "+ref+" }}\n") {
		t.Errorf("the secret must be in the env of the sign step only:\n%s", step)
	}
	for _, name := range []string{"release", "server-image"} {
		if strings.Contains(jobText(t, name), "QBIT_VAULT_SIGNING_KEY") {
			t.Errorf("%s job mentions the signing key", name)
		}
	}
}

// The sign job checks what it downloaded, signs, verifies with the pinned
// key, uploads, and only then publishes (S4.1): a failed step leaves a draft.
func TestSignJobStepsRunInTheSafeOrder(t *testing.T) {
	job := jobText(t, "sign")
	order := []string{
		"gh release download",
		"sha256sum --check --strict",
		"go build",
		"QBIT_VAULT_SIGNING_KEY",
		`release-sign" verify`,
		"gh release upload",
		`--draft=false`,
	}
	last := -1
	for _, want := range order {
		i := strings.Index(job, want)
		if i < 0 {
			t.Fatalf("sign job lacks %q", want)
		}
		if i < last {
			t.Errorf("%q comes before an earlier stage of the sign job", want)
		}
		last = i
	}
	if strings.Count(job, "--draft=false") != 1 || strings.Contains(job, "continue-on-error") {
		t.Error("exactly one publish step and no continue-on-error allowed in the sign job")
	}
}

// The release job refuses to build while the test key is pinned (S7).
func TestReleaseJobTestsRunWithTheReleaseCheck(t *testing.T) {
	step := stepText(t, jobText(t, "release"), "test")
	if !strings.Contains(step, "go test") || !strings.Contains(step, `QBIT_VAULT_RELEASE_CHECK: "1"`) {
		t.Errorf("the release test step must run go test with QBIT_VAULT_RELEASE_CHECK=1:\n%s", step)
	}
}

// release.yml starts only on v* tags (pi-v* extension tags and branches
// cannot publish a binary release).
func TestReleaseWorkflowTriggersOnlyOnVersionTags(t *testing.T) {
	w := repoFile(t, ".github", "workflows", "release.yml")
	if !strings.Contains(w, "\non:\n  push:\n    tags: [\"v*\"]\n\npermissions:") {
		t.Error("release.yml must trigger only on push of v* tags")
	}
	for _, bad := range []string{"workflow_dispatch", "pull_request", "branches:"} {
		if strings.Contains(w, bad) {
			t.Errorf("release.yml contains %q", bad)
		}
	}
}
