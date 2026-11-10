#!/bin/sh
# Install qbit-vault from a GitHub release (docs/INSTALL.md § One-line install).
#
#   curl -fsSL https://github.com/qbitdevz/qbit-vault/releases/latest/download/install.sh | sh
#
# Environment:
#   QBIT_VAULT_VERSION      tag to install (default: the newest release, pre-releases included)
#   QBIT_VAULT_RELEASES_API release list to pick the newest from (default: the GitHub releases API)
#   QBIT_VAULT_INSTALL_DIR  target directory (default: where qbit-vault already is, else $HOME/.local/bin)
#   QBIT_VAULT_RELEASE_URL  base download URL (default: the GitHub releases of qbitdevz/qbit-vault)
#   QBIT_VAULT_NO_SYNC      set to 1 to skip `qbit-vault sync` after an upgrade
#
# It downloads one archive and checksums.txt, verifies the SHA-256, and copies
# the binary. An existing install is upgraded in place, and when the vault is
# already set up it runs `qbit-vault sync` so your agents use the new binary.
# It never asks for, reads or stores a secret, and it never runs
# `qbit-vault init`: that stays your explicit step.
set -eu

REPO="qbitdevz/qbit-vault"
RELEASE_URL="${QBIT_VAULT_RELEASE_URL:-https://github.com/$REPO/releases/download}"
INSTALL_DIR="${QBIT_VAULT_INSTALL_DIR:-}"
VERSION="${QBIT_VAULT_VERSION:-}"
VAULT_HOME="${QBIT_VAULT_HOME:-$HOME/.qbit-vault}"

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
	# releases/latest skips pre-releases, so list releases of any kind. The API
	# orders them by tag text (v0.1.0-beta.10 after v0.1.0-beta.9), so take the
	# newest publish date; a draft has none.
	fetch "${QBIT_VAULT_RELEASES_API:-https://api.github.com/repos/$REPO/releases?per_page=100}" "$tmp/releases.json" ||
		die "could not query the releases of $REPO"
	# One field per line first, so minified JSON reads like the indented kind.
	VERSION="$(tr ',{}[]' '\n\n\n\n\n' <"$tmp/releases.json" | awk '
		/"tag_name"[[:space:]]*:/ { t = $0; sub(/.*"tag_name"[[:space:]]*:[[:space:]]*"/, "", t); sub(/".*/, "", t) }
		/"published_at"[[:space:]]*:[[:space:]]*"/ { p = $0; sub(/.*"published_at"[[:space:]]*:[[:space:]]*"/, "", p); sub(/".*/, "", p); if (p > best) { best = p; tag = t } }
		END { print tag }')"
	[ -n "$VERSION" ] || die "no release of $REPO found"
fi

archive="qbit-vault_${os}_${arch}.tar.gz"
say "installing qbit-vault $VERSION ($os/$arch)"
fetch "$RELEASE_URL/$VERSION/$archive" "$tmp/$archive" ||
	die "could not download $archive for $VERSION (a release being published uploads its files for a few minutes; try again)"
fetch "$RELEASE_URL/$VERSION/checksums.txt" "$tmp/checksums.txt" || die "could not download checksums.txt for $VERSION"

want="$(awk -v f="$archive" '$2 == f { print $1 }' "$tmp/checksums.txt")"
[ -n "$want" ] || die "$archive is not listed in checksums.txt"
got="$(sha256 "$tmp/$archive")"
[ "$want" = "$got" ] || die "checksum mismatch for $archive: nothing was installed"

tar -xzf "$tmp/$archive" -C "$tmp" qbit-vault || die "the archive has no qbit-vault binary"

# An existing install is upgraded where it is, so its path (and every agent
# registration that holds it) stays the same.
previous="$(command -v qbit-vault 2>/dev/null || true)"
previous_version=""
if [ -n "$previous" ]; then
	previous_version="$("$previous" version 2>/dev/null | awk '{ print $2 }')" || previous_version=""
fi
if [ -z "$INSTALL_DIR" ]; then
	INSTALL_DIR="$HOME/.local/bin"
	if [ -n "$previous" ] && [ -w "$(dirname "$previous")" ]; then
		INSTALL_DIR="$(dirname "$previous")"
	fi
fi
if [ -n "$previous_version" ] && [ "$previous" = "$INSTALL_DIR/qbit-vault" ]; then
	if [ "$previous_version" = "$VERSION" ]; then
		say "qbit-vault $VERSION is already installed; reinstalling it"
	else
		say "upgrading qbit-vault $previous_version -> $VERSION"
	fi
fi
mkdir -p "$INSTALL_DIR"
# Copy beside the target then rename, so a running qbit-vault is never
# half-written and a failed copy (a full disk) leaves the old one in place.
if ! cp "$tmp/qbit-vault" "$INSTALL_DIR/.qbit-vault.new" || ! chmod 755 "$INSTALL_DIR/.qbit-vault.new"; then
	rm -f "$INSTALL_DIR/.qbit-vault.new"
	die "could not write $INSTALL_DIR/qbit-vault: the previous binary was kept"
fi
mv -f "$INSTALL_DIR/.qbit-vault.new" "$INSTALL_DIR/qbit-vault"
say "installed $INSTALL_DIR/qbit-vault"

case ":$PATH:" in
	*":$INSTALL_DIR:"*) ;;
	*) say "$INSTALL_DIR is not on your PATH; add it, for example: export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
esac
active="$(command -v qbit-vault 2>/dev/null || true)"
if [ -n "$active" ] && [ "$active" != "$INSTALL_DIR/qbit-vault" ]; then
	say "another qbit-vault at $active comes first on your PATH; remove it so your shell runs the new one"
fi

if [ -f "$VAULT_HOME/state.json" ]; then
	# Already set up: re-apply the recorded agent registrations, so they point at
	# this binary. sync reads no secret and asks nothing.
	if [ "${QBIT_VAULT_NO_SYNC:-}" = 1 ]; then
		say "skipped 'qbit-vault sync' (QBIT_VAULT_NO_SYNC=1); run it yourself so your agents use this binary"
	elif "$INSTALL_DIR/qbit-vault" sync; then
		say "agent registrations are up to date; restart your agents to load the new version"
	else
		say "'qbit-vault sync' reported a problem (see above); run 'qbit-vault doctor', then restart your agents"
	fi
else
	say "next: run 'qbit-vault init'"
fi
