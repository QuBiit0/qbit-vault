package cli

import (
	"regexp"
	"strings"
	"testing"
)

// The installers pin the release public key (S6, S7): the second line of
// defaults/release-key.pub, the one `minisign -V -P` takes. Changing the key
// means changing all three copies, and this test fails until they agree.
func TestInstallersPinTheReleaseKey(t *testing.T) {
	lines := strings.Split(strings.TrimSpace(repoFile(t, "defaults", "release-key.pub")), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "untrusted comment: minisign public key ") {
		t.Fatalf("defaults/release-key.pub is not a two-line Minisign public key")
	}
	key := lines[1]
	id := strings.TrimPrefix(lines[0], "untrusted comment: minisign public key ")
	keyLike := regexp.MustCompile(`RW[A-Za-z0-9+/]{54}`)
	for file, want := range map[string]string{
		"install.sh":  `MINISIGN_KEY="` + key + `"`,
		"install.ps1": `$minisignKey = '` + key + `'`,
	} {
		src := repoFile(t, "scripts", file)
		if strings.Count(src, want+"\n") != 1 {
			t.Errorf("%s must pin exactly the key of defaults/release-key.pub (%s) on a line of its own: %s", file, id, want)
		}
		if found := keyLike.FindAllString(src, -1); len(found) != 1 {
			t.Errorf("%s carries %d key-like strings, want exactly the pinned one", file, len(found))
		}
		if !strings.Contains(src, "key id "+id) {
			t.Errorf("%s does not name the key id %s next to the key", file, id)
		}
	}
}

// Both installers know the same first signed release and print the same
// SHA-256-only warning.
func TestInstallersAgreeOnFirstSignedAndWarning(t *testing.T) {
	sh, ps := repoFile(t, "scripts", "install.sh"), repoFile(t, "scripts", "install.ps1")
	if !strings.Contains(sh, `FIRST_SIGNED="v1.4.0"`+"\n") || !strings.Contains(ps, `$firstSigned = 'v1.4.0'`+"\n") {
		t.Error("both installers must pin the first signed release, v1.4.0")
	}
	const warning = "minisign not found: checksums.txt was checked with SHA-256 only. Verify the signature with: minisign -V -P "
	const tail = " -m checksums.txt -x checksums.txt.minisig"
	for name, src := range map[string]string{"install.sh": sh, "install.ps1": ps} {
		if !strings.Contains(src, warning) || !strings.Contains(src, tail) {
			t.Errorf("%s lacks the exact SHA-256-only warning", name)
		}
	}
}
