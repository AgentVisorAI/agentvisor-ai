# Security

## Trust boundaries

AgentVisor AI treats request bodies, JWTs, MCP arguments, upstream responses, manifests, and persisted event files as untrusted.

## Controls

- NHI JWT verification binds algorithms to key types and rejects `alg=none`, confusion attacks, future timestamps, expired tokens, TTLs above 15 minutes, unknown keys, scope escalation, and delegation depth above four.
- Corporate Ed25519 JWKS keys load at boot and refresh periodically. The last valid set remains available during endpoint failures; a successful refresh retires keys no longer advertised by the IdP.
- MCP calls pass parse, JSON Schema, WASM/native policy, and atomic budget gates. Any failure blocks the call.
- Multi-dimensional action budgets commit through one in-memory transaction or one Redis Lua script.
- WASM policies have fuel and memory limits and fail closed on traps or ABI errors.
- Receipt signatures cover RFC 8785 canonical JSON. `avctl receipt-verify` requires an independently trusted public key; embedded receipt keys are not trust anchors.
- Active journals use signer-derived HMAC envelopes with contiguous indexes and matched request/terminal response attempts. Recovery quarantines incomplete sessions without stopping unrelated recovery.
- Receipt and close events persist actual broker acknowledgments. Tool executions use exact-request/principal-bound HMAC claims, disable redirects, and cache outcomes to prevent automatic duplicate effects.
- Cold intents are HMAC-authenticated and fsynced before managed broker publication; object writes use create-or-compare semantics.
- Bridge topics reject events that fail their declared JSON Schema.
- Signing seeds use mode-0600 temporary files, exclusive atomic installation, file and parent `fsync`, and race-loser reload. The image build context and runtime copy exclude seed/key files.
- Session ids are hashed before becoming spool filenames.

## Deployment

- Set `require_identity = true` and configure `identity_jwks_url` plus `identity_allowed_issuers`.
- Mount signing seeds from a secret manager. Do not bake them into images.
- Use TLS/SASL or authenticated private networks for provider, Redis, Redpanda, NATS, Qdrant, and IdP endpoints.
- Restrict `/metrics`, close, promotion, and the dashboard routes (`/dashboard`, `/api/v1/dashboard/*` — enabled by default and unauthenticated, exposing per-session receipts and costs; or set `dashboard_enabled = false`) at the ingress layer.
- Configure customer-owned cold storage and SIEM sinks in Vector.
- Keep old public verification keys available for receipt validation.
- Keep the configured signing key stable until active journals have drained; rotate only after preserving historical receipt verification keys.

## Reporting

Report vulnerabilities privately to the repository maintainers. Include a minimal reproduction, affected version, impact, and suggested mitigation. Do not include production credentials or customer data.
