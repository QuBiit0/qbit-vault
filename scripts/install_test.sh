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

# A release (v0.0.0-test unless VERSION is given) with one archive per arch,
# each holding a fake binary.
mkrelease() { # mkrelease DIR [VERSION]
	local rel="$1/${2:-v0.0.0-test}"
	mkdir -p "$rel"
	: >"$rel/checksums.txt"
	for arch in amd64 arm64; do
		local src="$work/src-$arch"
		mkdir -p "$src"
		fakebin "$src/qbit-vault" "${2:-v0.0.0-test}" "$arch"
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

# 14. Minisign (S6). The pinned key is the second line of defaults/release-key.pub.
# A stub `minisign` on PATH stands in for the real one: it logs its arguments and
# exits 0 only when -P is the pinned key, -m exists and the -x file starts with
# STUB-VALID.
key="$(sed -n 2p "$here/../defaults/release-key.pub")"
# The key is base64: escape it before it goes into a regular expression (+ and /).
key_re="$(printf '%s' "$key" | sed 's/[][\.*^$+?(){}|/]/\\&/g')"
export QBV_TEST_MINISIGN_LOG="$work/minisign.log" QBV_TEST_KEY="$key"
mkdir -p "$work/bin-ms"
cat >"$work/bin-ms/minisign" <<'STUB'
#!/bin/sh
echo "$*" >>"$QBV_TEST_MINISIGN_LOG"
while [ $# -gt 0 ]; do
	case "$1" in -P) k="$2"; shift ;; -x) x="$2"; shift ;; -m) m="$2"; shift ;; esac
	shift
done
[ "$k" = "$QBV_TEST_KEY" ] && [ -f "$m" ] && [ "$(head -n 1 "$x")" = STUB-VALID ]
STUB
chmod 755 "$work/bin-ms/minisign"
warning="minisign not found: checksums.txt was checked with SHA-256 only. Verify the signature with: minisign -V -P $key -m checksums.txt -x checksums.txt.minisig"

signed() { # signed DIR VERSION [SIGFILE_CONTENT]: a release; the .minisig is written when content is given
	mkrelease "$1" "$2"
	[ $# -lt 3 ] || printf '%s
' "$3" >"$1/$2/checksums.txt.minisig"
}
msrun() { # msrun RELEASE_DIR INSTALL_DIR VERSION [stub|none]
	: >"$QBV_TEST_MINISIGN_LOG"
	if [ "${4:-stub}" = stub ]; then run "$work/bin-ms:$work/bin-x86" "$1" "$2" QBIT_VAULT_VERSION="$3"; else run "$work/bin-x86" "$1" "$2" QBIT_VAULT_VERSION="$3"; fi
}

signed "$work/s-valid" v1.4.0 STUB-VALID
msrun "$work/s-valid" "$work/dest14a" v1.4.0
check "signed release with minisign exits 0" test "$code" -eq 0
check "signed release is installed" test -x "$work/dest14a/qbit-vault"
check "signed release says it verified" grep -q "checksums.txt signature verified with minisign" <<<"$out"
check "minisign gets the pinned key and files" grep -Eq -e "^-V -q -P $key_re -m .*checksums.txt -x .*checksums.txt.minisig\$" "$QBV_TEST_MINISIGN_LOG"
check "signed release prints no SHA-256-only warning" eval '! grep -q "minisign not found" <<<"$out"'

signed "$work/s-bad" v1.4.0 STUB-BAD
msrun "$work/s-bad" "$work/dest14b" v1.4.0
check "bad signature exits non-zero" test "$code" -ne 0
check "bad signature is reported" grep -q "the signature of checksums.txt for v1.4.0 does not verify with the QBit Vault release key: nothing was installed" <<<"$out"
check "bad signature installs nothing" test ! -e "$work/dest14b"

signed "$work/s-missing" v1.4.0
msrun "$work/s-missing" "$work/dest14c" v1.4.0
check "missing signature of a signed version exits non-zero" test "$code" -ne 0
check "missing signature is reported" grep -q "the release v1.4.0 has no checksums.txt.minisig" <<<"$out"
check "missing signature installs nothing" test ! -e "$work/dest14c"

# Without minisign: the exact warning, and the install goes on. A host that has
# the real minisign cannot play this case.
if PATH="$work/bin-x86:$PATH" command -v minisign >/dev/null 2>&1; then
	echo "skip minisign absent (minisign is installed on this host)"
else
	msrun "$work/s-valid" "$work/dest14d" v1.4.0 none
	check "no minisign: install goes on" test "$code" -eq 0 -a -x "$work/dest14d/qbit-vault"
	check "no minisign: the warning is printed exactly" grep -qxF "$warning" <<<"$out"
	msrun "$work/s-missing" "$work/dest14e" v1.4.0 none
	check "no minisign, no .minisig: install goes on with the warning" test "$code" -eq 0 -a -x "$work/dest14e/qbit-vault"
fi

# Versions below the first signed one say they are unsigned; at or above it a
# missing .minisig is refused (compared numerically: 1.10.0 > 1.4.0 > 1.3.9).
signed "$work/s-old" v1.3.9
msrun "$work/s-old" "$work/dest14f" v1.3.9
check "older release without .minisig installs" test "$code" -eq 0 -a -x "$work/dest14f/qbit-vault"
check "older release says it is unsigned" grep -q "v1.3.9 predates signed releases (first signed: v1.4.0)" <<<"$out"
signed "$work/s-old2" v0.0.0-test STUB-BAD
msrun "$work/s-old2" "$work/dest14g" v0.0.0-test
check "older release with a bad .minisig is still refused" test "$code" -ne 0 -a ! -e "$work/dest14g"
signed "$work/s-ten" v1.10.0
msrun "$work/s-ten" "$work/dest14h" v1.10.0
check "v1.10.0 counts as signed (numeric compare)" test "$code" -ne 0 -a ! -e "$work/dest14h"
signed "$work/s-beta" v1.4.0-beta.1
msrun "$work/s-beta" "$work/dest14i" v1.4.0-beta.1
check "a pre-release of the first signed version counts as signed" test "$code" -ne 0 -a ! -e "$work/dest14i"
if ! PATH="$work/bin-x86:$PATH" command -v minisign >/dev/null 2>&1; then
	msrun "$work/s-old" "$work/dest14j" v1.3.9 none
	check "older release, no minisign: unsigned note, no warning" eval 'test "$code" -eq 0 && ! grep -q "minisign not found" <<<"$out"'
fi

# A .minisig that cannot be downloaded is not "no .minisig" (S2): the user is
# told the download failed, with a fixed short reason, and nothing is installed.
# A stub `curl` fails only the signature download; every other URL goes to the
# real curl.
real_curl="$(command -v curl || true)"
export QBV_TEST_REAL_CURL="$real_curl"
mkdir -p "$work/bin-curl"
cat >"$work/bin-curl/curl" <<'STUB'
#!/bin/sh
for a in "$@"; do url="$a"; done
case "$url" in
	*checksums.txt.minisig)
		case "${QBV_TEST_SIG_MODE:-}" in
			500) echo 500; exit 0 ;;
			403) echo 403; exit 0 ;;
			reset) echo 000; exit 56 ;;
			timeout) echo 000; exit 28 ;;
		esac ;;
esac
exec "$QBV_TEST_REAL_CURL" "$@"
STUB
chmod 755 "$work/bin-curl/curl"
if [ -n "$real_curl" ]; then
	for mode in "500:server answered 500" "403:server answered 403" "reset:request failed" "timeout:timed out"; do
		export QBV_TEST_SIG_MODE="${mode%%:*}"
		reason="${mode#*:}"
		: >"$QBV_TEST_MINISIGN_LOG"
		run "$work/bin-curl:$work/bin-ms:$work/bin-x86" "$work/s-valid" "$work/dest15-${mode%%:*}" QBIT_VAULT_VERSION=v1.4.0
		check "signature download failure ($reason) exits non-zero" test "$code" -ne 0
		check "signature download failure ($reason) is reported" grep -qxF "qbit-vault install: error: could not download the signature of the release v1.4.0: $reason; nothing was installed" <<<"$out"
		check "signature download failure ($reason) installs nothing" test ! -e "$work/dest15-${mode%%:*}"
		check "signature download failure ($reason) never runs minisign" test ! -s "$QBV_TEST_MINISIGN_LOG"
	done
	unset QBV_TEST_SIG_MODE
	# The same failure on a version older than the first signed one is still refused.
	export QBV_TEST_SIG_MODE=500
	run "$work/bin-curl:$work/bin-ms:$work/bin-x86" "$work/s-old" "$work/dest15-old" QBIT_VAULT_VERSION=v1.3.9
	check "signature download failure on an older release is refused too" test "$code" -ne 0 -a ! -e "$work/dest15-old"
	unset QBV_TEST_SIG_MODE
fi

if [ "$fails" -ne 0 ]; then
	echo "$fails check(s) failed"
	exit 1
fi
echo "all install.sh checks passed"
