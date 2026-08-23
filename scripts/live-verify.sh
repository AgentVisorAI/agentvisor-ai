#!/usr/bin/env bash
# Round-51 §11 live verification: reproduce the review's headline
# claims end-to-end against a real release daemon on a real HTTP
# port, with a scripted mock upstream. Runnable without any live
# broker; all state lives in a temp directory that is cleaned up on
# exit. Prints VERIFIED / FAILED for each check.
#
# Usage:  scripts/live-verify.sh
#
# Verifies:
#   1. Hero snippet (§9.1): SDK-shaped `Authorization: Bearer sk-*`
#      admits, streams, closes cleanly. Round-51 §9.1 said this used
#      to 401 on request one.
#   2. Signed receipt round-trip (chat -> close -> promote).
#   3. Public key extraction (§9.1): `avctl pubkey` produces the
#      trust anchor the review said had no supported extraction path.
#   4. Offline receipt verification (VERIFYING-A-RECEIPT.md): the
#      receipt promoted by the daemon verifies with the extracted
#      pubkey.
#   5. Tamper detection (§3.1): a single-byte change to the receipt
#      body is refused by `avctl receipt-verify`.
#   6. Forgery refusal (§3.1): the review's PoC (identity-point
#      public key + `01 00...00` signature) is refused BEFORE the
#      verify call -- `add_key_bytes` rejects the small-order key.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AGENTVISORD="${AGENTVISORD:-$REPO_ROOT/target/release/agentvisord}"
AVCTL="${AVCTL:-$REPO_ROOT/target/release/avctl}"
LISTEN_PORT="${LISTEN_PORT:-18484}"
UPSTREAM_PORT="${UPSTREAM_PORT:-18099}"
BASE="http://127.0.0.1:${LISTEN_PORT}"

if [[ ! -x "$AGENTVISORD" || ! -x "$AVCTL" ]]; then
    echo "Missing release binaries; run: cargo build --release -p av-harness --bin agentvisord -p av-cli --bin avctl" >&2
    exit 2
fi

WORK="$(mktemp -d /tmp/av-live-verify.XXXXXX)"
DAEMON_PID=""
MOCK_PID=""
cleanup() {
    set +e
    [[ -n "$DAEMON_PID" ]] && kill "$DAEMON_PID" 2>/dev/null
    [[ -n "$MOCK_PID"   ]] && kill "$MOCK_PID"   2>/dev/null
    wait 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$WORK/spool" "$WORK/config" "$WORK/tool-schemas"

cat > "$WORK/mock_upstream.py" <<PY
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get('content-length', 0)))
        body = (b'data: {"choices":[{"delta":{"content":"hello from live-verify"},"finish_reason":"stop"}],'
                b'"usage":{"prompt_tokens":12,"completion_tokens":6}}\n\n'
                b'data: [DONE]\n\n')
        self.send_response(200)
        self.send_header('content-type', 'text/event-stream')
        self.send_header('content-length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
HTTPServer(('127.0.0.1', ${UPSTREAM_PORT}), H).serve_forever()
PY

cat > "$WORK/config/harness.toml" <<TOML
config_version = 1
listen = "127.0.0.1:${LISTEN_PORT}"
upstream_url = "http://127.0.0.1:${UPSTREAM_PORT}"
require_identity = false
ignore_client_authorization = true
default_workflow = "signed"
dashboard_enabled = false
atif_spool_dir = "$WORK/spool"
bridge_data_dir = "$WORK/bridge"
tool_schema_dir = "$WORK/tool-schemas"
TOML

python3 "$WORK/mock_upstream.py" &
MOCK_PID=$!

(cd "$WORK" && "$AGENTVISORD" --config "$WORK/config/harness.toml" > "$WORK/daemon.log" 2>&1) &
DAEMON_PID=$!

# Wait for /readyz
for i in $(seq 1 40); do
    if [[ "$(curl -s -o /dev/null -w '%{http_code}' -m 1 "$BASE/readyz")" == "200" ]]; then
        break
    fi
    sleep 0.25
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "FAILED - daemon exited early:" >&2
        cat "$WORK/daemon.log" >&2
        exit 1
    fi
done

pass() { echo "VERIFIED  $1"; }
fail() { echo "FAILED    $1" >&2; exit 1; }

# --- 1. Hero snippet: SDK-shaped auth is accepted end to end.
status=$(curl -s -o "$WORK/hero.body" -w '%{http_code}' \
    "$BASE/v1/chat/completions" \
    -H 'content-type: application/json' \
    -H 'authorization: Bearer sk-anything-at-all' \
    -H 'x-av-session: live-hero' \
    -H 'x-av-workflow: signed' \
    -d '{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hello"}]}')
[[ "$status" == "200" ]] || fail "hero snippet returned HTTP $status"
grep -q 'hello from live-verify' "$WORK/hero.body" || fail "hero response body missing streamed content"
pass "hero snippet: 200 + streamed body (§9.1)"

# --- 2. Close + promote produce a signed receipt.
close_body=$(curl -s -X POST "$BASE/v1/sessions/live-hero/close")
grep -q '"kind":"receipt"' <<<"$close_body" || fail "close returned unexpected shape: $close_body"
curl -s -X POST "$BASE/v1/sessions/live-hero/promote" > "$WORK/receipt.json"
grep -q '"receipt_id"' "$WORK/receipt.json" || fail "promote did not return a receipt"
pass "signed receipt round-trip: chat -> close -> promote"

# --- 3. avctl pubkey extracts the trust anchor.
PUB=$("$AVCTL" pubkey --seed "$WORK/config/signing.seed" | python3 -c "import json,sys; print(json.load(sys.stdin)['public_key_hex'])")
[[ ${#PUB} -eq 64 ]] || fail "avctl pubkey produced malformed hex: $PUB"
pass "avctl pubkey extracts the trust anchor (§9.1)"

# --- 4. Offline verify succeeds against that pubkey.
"$AVCTL" receipt-verify "$WORK/receipt.json" --public-key-hex "$PUB" > "$WORK/verify.out"
grep -q '^verified ' "$WORK/verify.out" || fail "receipt-verify did not report verified: $(cat "$WORK/verify.out")"
pass "offline receipt verification (VERIFYING-A-RECEIPT.md)"

# --- 5. Single-byte tamper is refused.
python3 -c "import json; r=json.load(open('$WORK/receipt.json')); r['cost']['prompt_tokens']=999999; json.dump(r, open('$WORK/tampered.json','w'))"
if "$AVCTL" receipt-verify "$WORK/tampered.json" --public-key-hex "$PUB" > "$WORK/tamper.out" 2>&1; then
    fail "receipt-verify accepted a tampered receipt"
fi
pass "tampered receipt refused (§3.1)"

# --- 6. §3.1 forgery PoC (identity-point key + small-order signature).
python3 - <<PY
import json, base64
r = json.load(open('$WORK/receipt.json'))
r['public_key_b64'] = base64.b64encode(bytes([1] + [0]*31)).decode()
r['signature_b64']  = base64.b64encode(bytes([1] + [0]*63)).decode()
json.dump(r, open('$WORK/forged.json','w'))
PY
FORGE_OUT=$("$AVCTL" receipt-verify "$WORK/forged.json" \
    --public-key-hex 0100000000000000000000000000000000000000000000000000000000000000 2>&1 || true)
grep -q 'small-order' <<<"$FORGE_OUT" || fail "forgery PoC not refused at add_key_bytes: $FORGE_OUT"
pass "§3.1 forgery PoC refused at add_key_bytes (small-order key)"

echo
echo "All 6 live checks VERIFIED against release binaries."
