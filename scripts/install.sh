#!/bin/sh
# Install qbit-vault from a GitHub release (docs/INSTALL.md § One-line install).
#
#   curl -fsSL https://raw.githubusercontent.com/QuBiit0/qbit-vault/main/scripts/install.sh | sh
#
# Environment:
#   QBIT_VAULT_VERSION      tag to install (default: the newest release, pre-releases included)
#   QBIT_VAULT_INSTALL_DIR  target directory (default: $HOME/.local/bin)
#   QBIT_VAULT_RELEASE_URL  base download URL (default: the GitHub releases of QuBiit0/qbit-vault)
#
# It downloads one archive and checksums.txt, verifies the SHA-256, and copies
# the binary. It never asks for, reads or stores a secret, and it does not run
# `qbit-vault init`: that stays your explicit step.
set -eu

REPO="QuBiit0/qbit-vault"
RELEASE_URL="${QBIT_VAULT_RELEASE_URL:-https://github.com/$REPO/releases/download}"
INSTALL_DIR="${QBIT_VAULT_INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${QBIT_VAULT_VERSION:-}"

say() { printf 'qbit-vault install: %s\n' "$*"; }
die() { printf 'qbit-vault install: error: %s\n' "$*" >&2; exit 1; }

fetch() { # fetch URL FILE
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --proto '=https,file' --retry 2 -o "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then
		wget -q -O "$2" "$1"
	else
		die "curl or wget is required"
	fi
}

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d' ' -f1
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | cut -d' ' -f1
	else
		die "sha256sum or shasum is required to verify the download"
	fi
}

case "$(uname -s)" in
	Linux) os=linux ;;
	Darwin) os=darwin ;;
	*) die "unsupported OS $(uname -s); on Windows use install.ps1" ;;
esac
case "$(uname -m)" in
	x86_64 | amd64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	*) die "unsupported architecture $(uname -m)" ;;
esac

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

if [ -z "$VERSION" ]; then
	# releases/latest skips pre-releases, so ask for the newest release of any kind.
	fetch "https://api.github.com/repos/$REPO/releases?per_page=1" "$tmp/releases.json" ||
		die "could not query the releases of $REPO"
	VERSION="$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$tmp/releases.json" | head -n 1)"
	[ -n "$VERSION" ] || die "no release of $REPO found"
fi

archive="qbit-vault_${os}_${arch}.tar.gz"
say "installing qbit-vault $VERSION ($os/$arch)"
fetch "$RELEASE_URL/$VERSION/$archive" "$tmp/$archive" || die "could not download $archive for $VERSION"
fetch "$RELEASE_URL/$VERSION/checksums.txt" "$tmp/checksums.txt" || die "could not download checksums.txt for $VERSION"

want="$(awk -v f="$archive" '$2 == f { print $1 }' "$tmp/checksums.txt")"
[ -n "$want" ] || die "$archive is not listed in checksums.txt"
got="$(sha256 "$tmp/$archive")"
[ "$want" = "$got" ] || die "checksum mismatch for $archive: nothing was installed"

tar -xzf "$tmp/$archive" -C "$tmp" qbit-vault || die "the archive has no qbit-vault binary"
previous="$(command -v qbit-vault 2>/dev/null || true)"
mkdir -p "$INSTALL_DIR"
# Copy beside the target then rename, so a running qbit-vault is never half-written.
cp "$tmp/qbit-vault" "$INSTALL_DIR/.qbit-vault.new"
chmod 755 "$INSTALL_DIR/.qbit-vault.new"
mv -f "$INSTALL_DIR/.qbit-vault.new" "$INSTALL_DIR/qbit-vault"
say "installed $INSTALL_DIR/qbit-vault"

case ":$PATH:" in
	*":$INSTALL_DIR:"*) ;;
	*) say "$INSTALL_DIR is not on your PATH; add it, for example: export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
esac
if [ -n "$previous" ] && [ "$previous" != "$INSTALL_DIR/qbit-vault" ]; then
	say "another qbit-vault is at $previous; remove it, then run 'qbit-vault sync' so your agents use the new path"
fi
say "next: run 'qbit-vault' (guided setup) or 'qbit-vault init', then 'qbit-vault doctor'"
say "already set up? run 'qbit-vault sync' after an upgrade"
