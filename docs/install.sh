#!/bin/sh
# AgentVisor AI — daemon installer.
#
# What this does, in order:
#   1. Checks for a Rust toolchain (cargo). The daemon installs from
#      source today — prebuilt binaries land with the beta.
#   2. cargo-installs `agentvisord` (the runtime daemon) and `avctl`
#      (the operator CLI) from the public repository:
#        https://github.com/AgentVisorAI/agentvisor
#   3. Prints the two-line start command with your ingest token.
#
# Nothing here touches your shell profile, sudo, or anything outside
# ~/.cargo. Uninstall: `cargo uninstall av-harness av-cli`.
set -eu

REPO="https://github.com/AgentVisorAI/agentvisor"

say()  { printf '\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }

say "AgentVisor AI installer"

if ! command -v cargo >/dev/null 2>&1; then
  say "Rust toolchain not found."
  note "agentvisord installs from source today (prebuilt binaries ship with the beta)."
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
