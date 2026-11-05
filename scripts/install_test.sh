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

# A release v0.0.0-test with one archive per arch, each holding a fake binary.
mkrelease() { # mkrelease DIR
	local rel="$1/v0.0.0-test"
	mkdir -p "$rel"
	: >"$rel/checksums.txt"
	for arch in amd64 arm64; do
		local src="$work/src-$arch"
		mkdir -p "$src"
		printf '#!/bin/sh\necho fake-qbit-vault-%s\n' "$arch" >"$src/qbit-vault"
		chmod 755 "$src/qbit-vault"
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

run() { # run BIN_DIR RELEASE_DIR INSTALL_DIR: runs install.sh, output in $out, status in $code
	out="$(PATH="$1:$PATH" QBIT_VAULT_VERSION=v0.0.0-test QBIT_VAULT_RELEASE_URL="$(fileurl "$2")" \
		QBIT_VAULT_INSTALL_DIR="$3" sh "$here/install.sh" 2>&1)"
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

if [ "$fails" -ne 0 ]; then
	echo "$fails check(s) failed"
	exit 1
fi
echo "all install.sh checks passed"
