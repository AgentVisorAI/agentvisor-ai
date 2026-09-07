#!/bin/sh
# AgentVisor AI — daemon installer.
#
# What this does, in order:
#   1. Detects your platform. For Linux x86_64 and macOS (arm64/x86_64)
#      it downloads the prebuilt release binaries from GitHub, verifies
#      the SHA-256 checksum, and installs `agentvisord` + `avctl`.
#   2. Anywhere else — or with AV_INSTALL_SOURCE=1 — it cargo-installs
#      both from source, exactly as before:
#        https://github.com/AgentVisorAI/agentvisor
#   3. Prints the one guided next step (`avctl setup`).
#
# Environment overrides:
#   AV_VERSION=0.1.0-rc.2   release to install (default: pinned below)
#   AV_INSTALL_DIR=~/bin    where prebuilt binaries land
#   AV_INSTALL_SOURCE=1     skip prebuilt path, build from source
#
# Nothing here touches your shell profile, sudo, or anything outside
# the install dir / ~/.cargo. Uninstall: remove the two binaries, or
# `cargo uninstall av-harness av-cli` for source installs.
set -eu

REPO="https://github.com/AgentVisorAI/agentvisor"
RELEASE_REPO="https://github.com/AgentVisorAI/agentvisor-ai"
# Pinned to the latest published release; bump alongside each tag.
AV_VERSION="${AV_VERSION:-0.1.0-rc.2}"

say()  { printf '\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }

say "AgentVisor AI installer"

# ── Platform → release target triple ────────────────────────────────
target=""
if [ "${AV_INSTALL_SOURCE:-}" != "1" ]; then
  os="$(uname -s 2>/dev/null || echo unknown)"
  arch="$(uname -m 2>/dev/null || echo unknown)"
  case "$os/$arch" in
    Linux/x86_64)          target="x86_64-unknown-linux-gnu" ;;
    Darwin/arm64)          target="aarch64-apple-darwin" ;;
    Darwin/x86_64)         target="x86_64-apple-darwin" ;;
    *)                     target="" ;;
  esac
fi

install_prebuilt() {
  stage="agentvisor-ai-${AV_VERSION}-${target}"
  url="${RELEASE_REPO}/releases/download/v${AV_VERSION}/${stage}.tar.gz"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  say "Downloading prebuilt binaries (${target}, v${AV_VERSION}) …"
  if ! curl -fsSL "$url" -o "$tmp/pkg.tar.gz" || ! curl -fsSL "$url.sha256" -o "$tmp/pkg.sha256"; then
    return 1
  fi
  # Verify the checksum before anything is extracted or executed.
  expected="$(awk '{print $1}' "$tmp/pkg.sha256")"
  if command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "$tmp/pkg.tar.gz" | awk '{print $1}')"
  elif command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$tmp/pkg.tar.gz" | awk '{print $1}')"
  else
    note "no shasum/sha256sum available — refusing unverified binaries"
    return 1
  fi
  if [ "$expected" != "$actual" ]; then
    say "Checksum MISMATCH — refusing to install."
    note "expected: $expected"
    note "actual:   $actual"
    exit 1
  fi
  # NOTE: this function runs as an `if` condition, which suspends
  # `set -e` for its whole body (POSIX). Every step below must guard
  # its own failure explicitly, or a failed tar/install would fall
  # through to the success message and exit 0 with nothing installed.
  tar -xzf "$tmp/pkg.tar.gz" -C "$tmp" || {
    note "archive extraction failed"
    return 1
  }
  # Default into ~/.cargo/bin when it exists (already on PATH for every
  # Rust user and the CI consumer); otherwise ~/.local/bin.
  if [ -n "${AV_INSTALL_DIR:-}" ]; then dest="$AV_INSTALL_DIR"
  elif [ -d "$HOME/.cargo/bin" ]; then dest="$HOME/.cargo/bin"
  else dest="$HOME/.local/bin"; fi
  mkdir -p "$dest" || {
    note "cannot create $dest"
    return 1
  }
  install -m 0755 "$tmp/$stage/agentvisord" "$tmp/$stage/avctl" "$dest/" || {
    note "copying binaries into $dest failed"
    return 1
  }
  say "Installed to $dest (checksum verified)."
  case ":$PATH:" in
    *":$dest:"*) ;;
    *) note "add it to your PATH:  export PATH=\"$dest:\$PATH\"" ;;
  esac
  return 0
}

installed=""
if [ -n "$target" ]; then
  if install_prebuilt; then installed=1
  else note "prebuilt download unavailable — falling back to source install."; fi
fi

if [ -z "$installed" ]; then
  if ! command -v cargo >/dev/null 2>&1; then
    say "Rust toolchain not found."
    note "No prebuilt binaries for this platform, so the daemon installs from source."
    note "Install Rust first (one line, takes ~a minute):"
    note ""
    note "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    note ""
    note "then re-run this script."
    exit 1
  fi
  say "Installing agentvisord (runtime daemon) from $REPO …"
  cargo install --locked --git "$REPO" av-harness
  say "Installing avctl (operator CLI) …"
  cargo install --locked --git "$REPO" av-cli
  say "Installed."
fi
note "Get a working proxy in one guided step:"
note ""
note "  avctl setup"
note ""
note "It writes agentvisor.toml, checks your provider key, and prints"
note "the localhost URL to point your AI app at. The hosted-console"
note "link (AV_INGEST_TOKEN from Deployments → New deployment) ships"
note "with the beta — tokens you mint now stay valid."
note ""
note "Docs: https://agentvisorai.me/api/  ·  Console: https://agentvisorai.me/app/"
