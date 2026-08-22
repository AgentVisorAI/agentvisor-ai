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

## Supported route

| Method | Path | Notes |
| --- | --- | --- |
| `POST` | `/v1/chat/completions` | Full request/response, streaming SSE and non-streaming JSON. |

Every other route on the harness (`/promote`, `/close`, `/health`,
`/livez`, `/readyz`, `/metrics`, `/dashboard/*`) is AgentVisor AI
territory and is documented separately. Only the chat route is
"OpenAI-compatible" in the strict sense.

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

## Intentional differences from openai.com

### 1. HTTP status codes

| Situation | OpenAI | AgentVisor AI |
| --- | --- | --- |
| Rate limit | `429` | `429` |
| Post-compression session budget refusal | n/a | `429` |
| Post-compression principal budget refusal | n/a | `429` |
| Semantic loop breaker refusal | n/a | `429` |
| Semantic loop breaker abort | n/a | `499`-ish (severed connection) |
| Missing/invalid bearer | `401` | `401` (identity required) or `403` (scope missing) |
| Compression floor exceeded and request oversized | n/a | `413` |
| Upstream 5xx | 5xx | forwarded, plus refund of pre-debited tokens |

### 2. Errors carry an `X-Agentvisor-*` prefix

Every 4xx/5xx response body includes an `error.metadata` block with
AgentVisor-specific fields (`session_id`, `event_uid`,
`stop_reason`). Clients that only read `error.message` see something
compatible with OpenAI's shape; sophisticated clients get the audit
handle.

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
| `X-Agentvisor-Session-Id` | Client-chosen session id. Rotating this restarts the audit chain; the harness treats each `session_id` as an independent conversation. |
| `X-Agentvisor-Workflow` | `signed` or `unsigned`. Chooses whether the session's audit lands as a signed receipt (Kafka topic `agent.receipt`) or as an ATIF trajectory (spool + broker fold). |

If your client speaks OpenAI's protocol out of the box, it will not
set these. The harness defaults them from config
(`default_workflow`) and generates a fresh session id per request.
The session then closes immediately after the response — one turn,
one audit event.

For long-lived multi-turn agent conversations, set the same
`X-Agentvisor-Session-Id` on every request and either explicitly
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
