# OpenAI Compatibility

AgentVisor AI is an OpenAI-compatible reverse proxy. Any client that
speaks the `POST /v1/chat/completions` protocol (OpenAI Python SDK,
LangChain, LlamaIndex, curl) can point at the harness with:

```
export OPENAI_API_BASE=http://localhost:8484/v1
export OPENAI_API_KEY=<your NHI bearer, if require_identity is true>
```

This document explains exactly what "compatible" means — the
supported surface, the intentional differences, and the failure modes
so you can reason about incidents without reading the full route
handler.

## Upstream provider dialects

The client-facing surface is always the OpenAI protocol. The
*upstream* wire dialect is selected by the `provider` config key
(round-51 §4.2, S3):

| `provider` | Upstream dialect | Also fits |
| --- | --- | --- |
| `"openai"` (default) | OpenAI Chat Completions | vLLM, LiteLLM, Groq, Together, DeepSeek, OpenRouter, Ollama, LM Studio, llama.cpp, xAI, Mistral, Azure OpenAI |
| `"anthropic"` | Anthropic Messages API (named SSE events, content blocks, `input_tokens`/`output_tokens`) | — |
| `"gemini"` | Google Gemini `generateContent` (candidates/parts, `usageMetadata`, SCREAMING_CASE finish reasons) | — |

All three dialects normalize into one provider-neutral chunk before
accounting, enforcement, and capture, so the audit chain (receipts,
ATIF trajectories, stop-reason taxonomy, provider-true token totals)
records the same shape regardless of the upstream. Pair `provider`
with the matching `upstream_url`, `upstream_chat_path`,
`upstream_auth_header` and `upstream_auth_scheme` (e.g. Anthropic's
`x-api-key` header with an empty scheme). Unsupported `provider`
values are refused at pre-flight by `avctl config-validate` and at
boot by the daemon.

The rest of this document describes the client-facing OpenAI surface,
which does not change with the upstream dialect.

## Supported route

| Method | Path | Notes |
| --- | --- | --- |
| `POST` | `/v1/chat/completions` | Full request/response, streaming SSE and non-streaming JSON. |

Every other route on the harness (`/promote`, `/close`, `/health`,
`/livez`, `/readyz`, `/metrics`, `/dashboard/*`) is AgentVisor AI
territory and is documented separately. Only the chat route is
"OpenAI-compatible" in the strict sense.

### The `/v1` vs `/api/v1` split (round-51 §9.3)

The prefix split is deliberate, not accidental:

* **`/v1/*`** is the client-facing **agent API** — the surface an
  agent or SDK touches during a conversation: `/v1/chat/completions`
  (OpenAI-shaped), `/v1/mcp` (JSON-RPC tool gate), and the two
  session lifecycle verbs `/v1/sessions/{id}/close` and
  `/v1/sessions/{id}/promote`. Errors on this surface use the
  OpenAI error body (`{"error":{"message","type","param","code"}}`)
  so SDK `e.code` handling works — including the 413 body-limit
  rejection.
* **`/api/v1/*`** is the **operator API** behind the dashboard
  (`stats`, `sessions`, `sessions/{id}`), plus the unprefixed
  operational probes (`/health`, `/livez`, `/readyz`, `/metrics`).
  These return operator-shaped JSON, not OpenAI error bodies.

Success shapes on the lifecycle verbs are versioned operator
contracts, intentionally NOT OpenAI-shaped: `close` returns
`{"kind":"receipt",...}` / `{"kind":"atif",...}` /
`{"kind":"already_closed"}` and `promote` returns the bare signed
receipt object (the artifact itself, suitable for piping to
`avctl receipt-verify`).

## Supported request fields

Passed through verbatim to the upstream:

* `model` (required by the upstream, opaque to the harness)
* `messages` (system / user / assistant / tool)
* `stream` (boolean)
* `stream_options` (`include_usage`)
* `temperature`, `top_p`, `max_tokens`, `presence_penalty`,
  `frequency_penalty`, `stop`, `n`, `seed`
* `tools` (function-calling schema)
* `tool_choice`
* `response_format` (`{"type":"json_object"}`, `json_schema`)
* `logprobs`, `top_logprobs`
* `user` (opaque)
* `parallel_tool_calls`

Anything the harness doesn't recognize is forwarded unchanged. Adding
a new upstream-specific field does NOT require a code change here.

## Supported response fields

Streaming and non-streaming responses are re-emitted verbatim, with
one intentional filtering step:

* Only SSE frames with `event:` empty or `event: message` are
  captured for audit. A frame whose `event:` names something else
  and carries **non-empty** `data:` is refused: it would otherwise
  attribute forged content to the model output. A dataless named
  event (`event: ping\n\n`, `event: heartbeat\ndata:\n\n`) is
  treated as a keepalive and passes through without affecting audit
  (see round 51 §6.2 for the CVE-shaped rationale).

Both the strict-mode refusal and the keepalive pass-through are
covered by `parse_provider_chunk_refuses_non_message_sse_event_types`
and `parse_provider_chunk_treats_dataless_named_events_as_keepalives`.

## Context compression rewrites your payload (on by default)

`compression_enabled` defaults to **true**. Before forwarding, the
harness runs lossy compression passes over the `messages` array —
which means the bytes the provider receives are NOT byte-identical
to the bytes your client sent. This is the one deliberate exception
to "nothing else in your app moves":

| Pass | Engages at | Effect |
| --- | --- | --- |
| duplicate-system collapse | 512 approx tokens | Repeated identical system messages collapse to one |
| duplicate-message collapse | 512 approx tokens | Byte-identical repeated messages become `[pruned: N tokens (duplicate message), sha256:…]` stubs |
| middle stubbing | 512 approx tokens | Middle-of-history messages are stubbed toward a target size; the first system message and the tail are preserved byte-identical |
| middle summarization | 50,000 approx tokens | Aggressive middle-of-history summarization |

Invariants the passes guarantee: message count order and roles are
preserved, the first system message and the `keep_tail` suffix are
byte-identical, and `tool_call_id` linkage survives (property-tested
in `av-compress/tests/invariants.rs`). Every stub names the pruned
token count and the SHA-256 of the removed content, so the audit
trail records what was elided.

The signed receipt and the budget both use the **post-compression**
token count, so enforcement and attestation agree with what the
provider actually saw.

To forward payloads verbatim, set:

```toml
compression_enabled = false
```


## Intentional differences from openai.com

### 1. HTTP status codes

| Situation | OpenAI | AgentVisor AI |
| --- | --- | --- |
| Rate limit | `429` | `429` |
| Post-compression session budget refusal | n/a | `403` (deliberately not 429, which SDKs auto-retry — the cap is permanent for the session) |
| Post-compression principal budget refusal | n/a | `403` |
| Semantic loop breaker refusal | n/a | `403` |
| Semantic loop breaker abort | n/a | `499`-ish (severed connection) |
| Missing/invalid bearer | `401` | `401` (identity required) or `403` (scope missing) |
| Compression floor exceeded and request oversized | n/a | `413` |
| Upstream 5xx | 5xx | forwarded, plus refund of pre-debited tokens |

### 2. Error bodies are OpenAI-shaped

Every 4xx/5xx from the chat and lifecycle routes carries
`{"error": {"message", "type", "param", "code"}}` — `type` follows
OpenAI's taxonomy (`invalid_request_error`, `authentication_error`,
`permission_error`, `rate_limit_error`, `api_error`) and `code` is
the numeric HTTP status, so stock SDK `e.type` / `e.code` dispatch
and retry classifiers behave correctly. 429/502/503/504 responses
additionally carry `Retry-After`; 401 carries `WWW-Authenticate`.

### 3. Streaming is a real SSE stream

The harness does NOT buffer streaming responses beyond a per-frame
window. Streaming clients receive bytes with roughly the same
latency as connecting directly to the upstream, minus a fixed few
hundred microseconds for capture and budget checking (production p95
is 33 µs; see `BENCHMARKS.md`).

### 4. `stream_options.include_usage` is honoured

The final SSE frame carries the true `usage` block, mirroring OpenAI.
Intermediate frames may carry `"usage": null` (vLLM/LiteLLM shim
behaviour) — the harness treats these as absent and does not feed
them to the accumulator.

### 5. Tool calls carry the audited `tool_call_id`

The audit ID is used as the `tool_call_id` field for downstream
consumers. When the upstream doesn't supply one, the harness
generates a stable `event_uid` and uses that.

## Session semantics

Chat requests carry two AgentVisor-specific headers:

| Header | Purpose |
| --- | --- |
| `X-AV-Session` | Client-chosen session id. Rotating this restarts the audit chain; the harness treats each `session_id` as an independent conversation. |
| `X-AV-Workflow` | `signed` or `unsigned`. Chooses whether the session's audit lands as a signed receipt (Kafka topic `agent.receipt`) or as an ATIF trajectory (spool + broker fold). |

If your client speaks OpenAI's protocol out of the box, it will not
set these. The harness defaults them from config
(`default_workflow`) and generates a fresh session id per request —
echoed back in the `X-AV-Session` **response** header, so you can
`avctl receipt-locate` the audit artifact later.
The session then closes immediately after the response — one turn,
one audit event.

For long-lived multi-turn agent conversations, set the same
`X-AV-Session` on every request and either explicitly
`POST /close` when done or rely on the idle-close sweeper
(`session_idle_close_s`).

## Unsupported OpenAI features

* `/v1/embeddings`, `/v1/audio/*`, `/v1/images/*`, `/v1/completions`
  (deprecated non-chat completion endpoint), `/v1/models`,
  `/v1/files`, `/v1/moderations`, `/v1/assistants`. The harness
  responds 404 to these; if you need them, front the harness with a
  path-based router.
* Fine-tuning APIs (`/v1/fine_tuning/*`). Same disposition.
* Assistants Threads/Runs APIs. Same disposition.

## Testing your client

The simplest smoke test:

```
curl -sS http://localhost:8484/v1/chat/completions \
     -H 'content-type: application/json' \
     -H "authorization: Bearer $OPENAI_API_KEY" \
     -d '{
       "model": "gpt-4o-mini",
       "messages": [{"role": "user", "content": "ping"}]
     }' | jq .
```

The response is an OpenAI-shaped `ChatCompletion` object. Your
audit event lands on the broker in parallel; verify it with
`avctl event-tail --topic agent.step`.
