#!/usr/bin/env bash
# Live identity, backend credentials, token exchange, revocation, and receipts.
# Build first: cargo build --release -p av-harness --bin agentvisord \
#   -p av-cli --bin avctl --features av-harness/redis,av-cli/redis
# Usage: scripts/live-pillars.sh [--redis redis://127.0.0.1:6379]
# Override AGENTVISORD, AVCTL, AV_LIVE_TMPDIR, or AV_KEEP_TMP=1 as needed.
# Python owns cleanup even when startup fails or the script receives a signal.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec python3 "$REPO_ROOT/scripts/live-pillars-helper.py" run "$@"
