#!/usr/bin/env bash
# Tests scripts/install.sh against a fake local release (file:// URLs) and a
# fake `uname`, so it runs on any POSIX shell host without the network.
#   bash scripts/install_test.sh
set -u

here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fails=0

check() { # check DESCRIPTION CONDITION...
	local what="$1"
	shift
	if "$@"; then echo "ok   $what"; else echo "FAIL $what"; fails=$((fails + 1)); fi
}

sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

# A fake qbit-vault: `version` prints VERSION, `sync` logs to $QBV_TEST_SYNC_LOG,
# anything else prints fake-qbit-vault-ARCH.
fakebin() { # fakebin FILE VERSION ARCH
	cat >"$1" <<EOF
#!/bin/sh
case "\$1" in
	version) echo "qbit-vault $2 (abc1234, linux/$3)" ;;
	sync) echo "sync $3" >>"\$QBV_TEST_SYNC_LOG" ;;
	*) echo fake-qbit-vault-$3 ;;
esac
EOF
	chmod 755 "$1"
}

# A release v0.0.0-test with one archive per arch, each holding a fake binary.
mkrelease() { # mkrelease DIR
	local rel="$1/v0.0.0-test"
	mkdir -p "$rel"
	: >"$rel/checksums.txt"
	for arch in amd64 arm64; do
		local src="$work/src-$arch"
		mkdir -p "$src"
		fakebin "$src/qbit-vault" v0.0.0-test "$arch"
		tar -czf "$rel/qbit-vault_linux_$arch.tar.gz" -C "$src" qbit-vault
		echo "$(sha "$rel/qbit-vault_linux_$arch.tar.gz")  qbit-vault_linux_$arch.tar.gz" >>"$rel/checksums.txt"
	done
}

fakeuname() { # fakeuname DIR MACHINE
	mkdir -p "$1"
	printf '#!/bin/sh\ncase "$1" in -s) echo Linux ;; -m) echo %s ;; esac\n' "$2" >"$1/uname"
	chmod 755 "$1/uname"
}

# Git Bash on Windows hands file:// URLs to a native curl, which needs C:/ paths.
fileurl() { if command -v cygpath >/dev/null 2>&1; then echo "file://$(cygpath -m "$1")"; else echo "file://$1"; fi; }

# The vault home and sync log of every run; a test creates state.json to
# play an already set-up vault.
export QBIT_VAULT_HOME="$work/home" QBV_TEST_SYNC_LOG="$work/sync.log"

run() { # run BIN_DIR RELEASE_DIR INSTALL_DIR [VAR=value...]: output in $out, status in $code
	local bin="$1" rel="$2" dest="$3"
	shift 3
	: >"$QBV_TEST_SYNC_LOG"
	out="$(env PATH="$bin:$PATH" QBIT_VAULT_VERSION=v0.0.0-test QBIT_VAULT_RELEASE_URL="$(fileurl "$rel")" \
		QBIT_VAULT_INSTALL_DIR="$dest" "$@" sh "$here/install.sh" 2>&1)"
	code=$?
}

# 1. A good release installs the binary of the host's architecture.
mkrelease "$work/good"
fakeuname "$work/bin-x86" x86_64
run "$work/bin-x86" "$work/good" "$work/dest1"
check "good release exits 0" test "$code" -eq 0
check "binary is installed and executable" test -x "$work/dest1/qbit-vault"
check "amd64 archive was chosen" test "$("$work/dest1/qbit-vault")" = fake-qbit-vault-amd64
check "output names the version" grep -q "installing qbit-vault v0.0.0-test (linux/amd64)" <<<"$out"
check "output names the next step" grep -q "qbit-vault init" <<<"$out"
check "no temporary file left in the target" test "$(ls -A "$work/dest1")" = qbit-vault

# 2. aarch64 maps to the arm64 archive.
fakeuname "$work/bin-arm" aarch64
run "$work/bin-arm" "$work/good" "$work/dest2"
check "aarch64 installs the arm64 binary" test "$("$work/dest2/qbit-vault" 2>/dev/null)" = fake-qbit-vault-arm64

# 3. A tampered archive is refused and nothing is installed.
cp -r "$work/good" "$work/bad"
printf 'tampered' >>"$work/bad/v0.0.0-test/qbit-vault_linux_amd64.tar.gz"
run "$work/bin-x86" "$work/bad" "$work/dest3"
check "tampered archive exits non-zero" test "$code" -ne 0
check "tampered archive reports the mismatch" grep -q "checksum mismatch for qbit-vault_linux_amd64.tar.gz: nothing was installed" <<<"$out"
check "tampered archive installs nothing" test ! -e "$work/dest3/qbit-vault"

# 4. An archive missing from checksums.txt is refused.
cp -r "$work/good" "$work/unlisted"
grep -v amd64 "$work/good/v0.0.0-test/checksums.txt" >"$work/unlisted/v0.0.0-test/checksums.txt"
run "$work/bin-x86" "$work/unlisted" "$work/dest4"
check "unlisted archive exits non-zero" test "$code" -ne 0
check "unlisted archive is reported" grep -q "qbit-vault_linux_amd64.tar.gz is not listed in checksums.txt" <<<"$out"
check "unlisted archive installs nothing" test ! -e "$work/dest4/qbit-vault"

# 5. An unsupported architecture stops before any download.
fakeuname "$work/bin-mips" mips
run "$work/bin-mips" "$work/good" "$work/dest5"
check "unsupported arch exits non-zero" test "$code" -ne 0
check "unsupported arch is reported" grep -q "unsupported architecture mips" <<<"$out"

# 6. Re-running replaces the binary in place.
run "$work/bin-arm" "$work/good" "$work/dest1"
check "re-install replaces the binary" test "$("$work/dest1/qbit-vault" 2>/dev/null)" = fake-qbit-vault-arm64

# 7. An existing install found on PATH is upgraded in place.
mkdir -p "$work/prev"
fakebin "$work/prev/qbit-vault" v0.0.0-old amd64
run "$work/prev:$work/bin-arm" "$work/good" ""
check "upgrade exits 0" test "$code" -eq 0
check "upgrade replaces the binary where it was" test "$("$work/prev/qbit-vault" 2>/dev/null)" = fake-qbit-vault-arm64
check "upgrade names both versions" grep -q "upgrading qbit-vault v0.0.0-old -> v0.0.0-test" <<<"$out"
check "upgrade installs nothing in the default directory" test ! -e "$HOME/.local/bin/.qbit-vault.new"

# 8. The same version is reported as a reinstall.
run "$work/prev:$work/bin-arm" "$work/good" ""
check "same version is a reinstall" grep -q "qbit-vault v0.0.0-test is already installed; reinstalling it" <<<"$out"

# 9. No vault yet: no sync, the next step is init.
run "$work/bin-x86" "$work/good" "$work/dest9"
check "no vault: sync is not run" test ! -s "$QBV_TEST_SYNC_LOG"
check "no vault: next step is init" grep -q "next: run 'qbit-vault init'\$" <<<"$out"
check "no vault: one next step only" test "$(grep -c 'next:' <<<"$out")" = 1

# 10. A set-up vault: the new binary runs sync, unless QBIT_VAULT_NO_SYNC=1.
mkdir -p "$QBIT_VAULT_HOME"
echo '{}' >"$QBIT_VAULT_HOME/state.json"
run "$work/bin-x86" "$work/good" "$work/dest10"
check "set-up vault: the new binary runs sync" test "$(cat "$QBV_TEST_SYNC_LOG")" = "sync amd64"
check "set-up vault: restart hint" grep -q "agent registrations are up to date; restart your agents" <<<"$out"
check "set-up vault: no init hint" eval '! grep -q "qbit-vault init" <<<"$out"'
run "$work/bin-x86" "$work/good" "$work/dest10" QBIT_VAULT_NO_SYNC=1
check "QBIT_VAULT_NO_SYNC=1 skips sync" test ! -s "$QBV_TEST_SYNC_LOG"
check "QBIT_VAULT_NO_SYNC=1 says so" grep -q "skipped 'qbit-vault sync' (QBIT_VAULT_NO_SYNC=1)" <<<"$out"
rm -rf "$QBIT_VAULT_HOME"

# 11. An explicit directory leaves the old copy alone and warns that it shadows.
fakebin "$work/prev/qbit-vault" v0.0.0-old amd64
run "$work/prev:$work/bin-x86" "$work/good" "$work/dest11"
check "explicit dir installs there" test "$("$work/dest11/qbit-vault")" = fake-qbit-vault-amd64
check "explicit dir leaves the old copy" grep -q v0.0.0-old <<<"$("$work/prev/qbit-vault" version)"
check "explicit dir warns about the shadowing copy" grep -q "another qbit-vault at $work/prev/qbit-vault comes first on your PATH" <<<"$out"

# 12. Without QBIT_VAULT_VERSION the newest published release wins, wherever the
# API lists it (GitHub orders by tag text, so v0.1.0-beta.10 comes after beta.9).
cat >"$work/releases.json" <<'JSON'
[
  {
    "tag_name": "v0.0.9-old",
    "draft": false,
    "prerelease": true,
    "created_at": "2026-11-06T16:37:55Z",
    "published_at": "2026-11-06T16:41:42Z",
    "assets": [{"name": "checksums.txt", "created_at": "2026-11-06T18:00:00Z"}]
  },
  {
    "tag_name": "v0.0.0-draft",
    "draft": true,
    "created_at": "2026-11-06T19:00:00Z",
    "published_at": null
  },
  {
    "tag_name": "v0.0.0-test",
    "draft": false,
    "prerelease": true,
    "created_at": "2026-11-06T16:57:22Z",
    "published_at": "2026-11-06T17:00:26Z"
  }
]
JSON
run "$work/bin-x86" "$work/good" "$work/dest12" QBIT_VAULT_VERSION= QBIT_VAULT_RELEASES_API="$(fileurl "$work/releases.json")"
check "newest published release is chosen" grep -q "installing qbit-vault v0.0.0-test (linux/amd64)" <<<"$out"
check "newest published release installs" test "$("$work/dest12/qbit-vault" 2>/dev/null)" = fake-qbit-vault-amd64

# 13. The same list as one line (minified JSON, as the API may send it), with
# the newest release in the middle, a draft and a null date.
printf '%s' '[{"tag_name":"v0.0.9-old","draft":false,"published_at":"2026-11-06T16:41:42Z","assets":[{"name":"checksums.txt"}]},{"tag_name":"v0.0.0-test","draft":false,"published_at":"2026-11-06T17:00:26Z","body":"notes, with {braces}"},{"tag_name":"v0.0.0-draft","draft":true,"published_at":null},{"tag_name":"v0.0.1-older","draft":false,"published_at":"2026-11-05T09:00:00Z"}]' >"$work/releases-min.json"
check "the one-line fixture is one line" test "$(wc -l <"$work/releases-min.json" | tr -d ' ')" = 0
run "$work/bin-x86" "$work/good" "$work/dest13" QBIT_VAULT_VERSION= QBIT_VAULT_RELEASES_API="$(fileurl "$work/releases-min.json")"
check "newest release is chosen from one-line JSON" grep -q "installing qbit-vault v0.0.0-test (linux/amd64)" <<<"$out"
check "newest release from one-line JSON installs" test "$("$work/dest13/qbit-vault" 2>/dev/null)" = fake-qbit-vault-amd64

if [ "$fails" -ne 0 ]; then
	echo "$fails check(s) failed"
	exit 1
fi
echo "all install.sh checks passed"
