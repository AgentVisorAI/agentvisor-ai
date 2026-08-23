//! Provider adapter seam (round-51 §4.2, S3 step 1).
//!
//! The upstream was treated as OpenAI-shaped throughout the response
//! path; the review's cost-of-change analysis names "a second
//! provider" as the change this design makes painful. This module
//! introduces the `ProviderAdapter` trait from the S3 migration plan
//! (`docs/reference/STRUCTURAL-REFACTORS.md`) with the OpenAI
//! adapter as its only implementation — a pure refactor. The SSE
//! parser keeps its battle-tested implementation in `routes.rs`
//! verbatim (BOM handling, `[DONE]`, `usage: null`, named-event
//! refusal, metric-regression rejection); the adapter owns
//! *selection*, so `AnthropicAdapter` / `GoogleGeminiAdapter` (S3
//! steps 2-3) become additive.

use std::sync::Arc;

/// One upstream provider's wire dialect. Implementations must be
/// total over arbitrary input (the fuzz target pins this for the
/// OpenAI adapter) and must never panic on hostile frames.
pub(crate) trait ProviderAdapter: Send + Sync {
    /// Stable name, matching the `provider` config value.
    fn name(&self) -> &'static str;
    /// Parse one SSE frame (or one buffered non-streaming body) into
    /// the provider-neutral chunk shape. `Ok(None)` means a
    /// keepalive/`[DONE]`-style frame carrying nothing attributable.
    fn parse_sse_chunk(&self, raw: &str) -> Result<Option<crate::routes::ParsedProviderChunk>, String>;
}

/// OpenAI wire dialect. Also fits vLLM, LiteLLM, Groq, Together,
/// DeepSeek, OpenRouter, Ollama, LM Studio, llama.cpp, xAI, Mistral
/// and Azure OpenAI, which emulate it.
pub(crate) struct OpenAiAdapter;

impl ProviderAdapter for OpenAiAdapter {
    fn name(&self) -> &'static str {
        "openai"
    }

    fn parse_sse_chunk(&self, raw: &str) -> Result<Option<crate::routes::ParsedProviderChunk>, String> {
        crate::routes::parse_provider_chunk(raw)
    }
}

/// Look up the adapter for a configured `provider` value. `None`
/// means unsupported — config validation names the supported set so
/// the daemon refuses at boot, not mid-stream.
pub(crate) fn adapter_for(provider: &str) -> Option<Arc<dyn ProviderAdapter>> {
    match provider {
        "openai" => Some(Arc::new(OpenAiAdapter)),
        "anthropic" => Some(Arc::new(AnthropicAdapter)),
        "gemini" => Some(Arc::new(GoogleGeminiAdapter)),
        _ => None,
    }
}

/// The provider names `adapter_for` accepts, for config-validation
/// error messages.
pub(crate) const SUPPORTED_PROVIDERS: &[&str] = &["openai", "anthropic", "gemini"];

/// Anthropic Messages API wire dialect (S3 step 2).
///
/// Streaming frames are named SSE events (`message_start`,
/// `content_block_start/delta/stop`, `message_delta`, `message_stop`,
/// `ping`, `error`); non-streaming bodies are a single
/// `{"type":"message", "content":[...]}` document. Mapping into the
/// provider-neutral chunk:
///
/// * `text_delta`/`text` blocks → `message`;
///   `thinking_delta`/`thinking` blocks → `reasoning`.
/// * `tool_use` blocks / `input_json_delta` → tool-call deltas keyed
///   by the content-block `index` (Anthropic has no choices array;
///   `choice_index` is always 0).
/// * `usage.input_tokens` → prompt, `usage.output_tokens` →
///   completion (Anthropic reports output cumulatively, matching the
///   `completion_reported` cumulative contract),
///   `usage.cache_read_input_tokens` → cached.
/// * `stop_reason` passes through natively — `map_finish_reason`
///   already folds `end_turn`/`max_tokens`/`tool_use`/
///   `stop_sequence` into the audit-chain stop taxonomy.
/// * `event: error` fails the frame (capture must not attribute an
///   error payload as model output — same posture as the OpenAI
///   adapter's named-event refusal); `ping`/`message_stop` are
///   keepalives.
pub(crate) struct AnthropicAdapter;

/// Anthropic SSE event names whose payloads this adapter captures.
const ANTHROPIC_CONTENT_EVENTS: &[&str] = &[
    "message_start",
    "content_block_start",
    "content_block_delta",
    "content_block_stop",
    "message_delta",
];

impl ProviderAdapter for AnthropicAdapter {
    fn name(&self) -> &'static str {
        "anthropic"
    }

    fn parse_sse_chunk(&self, raw: &str) -> Result<Option<crate::routes::ParsedProviderChunk>, String> {
        // Same SSE §9.2 discipline as the OpenAI parser: strip one
        // leading BOM, collect `data:` lines (one optional leading
        // space each), track the frame's `event:` name.
        let raw = raw.strip_prefix('\u{feff}').unwrap_or(raw);
        let mut is_sse = false;
        let mut event_type = String::new();
        let mut data = Vec::new();
        for line in raw.split(['\r', '\n']) {
            if let Some(value) = line.strip_prefix("data:") {
                is_sse = true;
                data.push(value.strip_prefix(' ').unwrap_or(value));
            } else if let Some(value) = line.strip_prefix("event:") {
                is_sse = true;
                event_type = value.strip_prefix(' ').unwrap_or(value).to_owned();
            } else if line == "data"
                || line.starts_with("id:")
                || line.starts_with("retry:")
                || line.starts_with(':')
            {
                is_sse = true;
            }
        }
        let candidate = if is_sse {
            if data.iter().all(|entry| entry.trim().is_empty()) {
                // Dataless frames — named keepalives included — carry
                // nothing attributable.
                return Ok(None);
            }
            data.join("\n")
        } else {
            raw.trim().to_owned()
        };
        if candidate.is_empty() {
            return Ok(None);
        }
        let value: serde_json::Value = serde_json::from_str(&candidate)
            .map_err(|error| format!("invalid provider JSON frame: {error}"))?;
        let frame_type = value
            .get("type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        // The SSE event name and the payload's `type` field are
        // redundant in the Anthropic dialect; require agreement when
        // both are present so a hostile frame cannot smuggle an error
        // payload under a content event name (or vice versa).
        if is_sse && !event_type.is_empty() && event_type != frame_type {
            return Err(format!(
                "provider SSE event name {event_type:?} does not match payload type {frame_type:?}"
            ));
        }
        match frame_type.as_str() {
            "ping" | "message_stop" => return Ok(None),
            "error" => {
                return Err(format!(
                    "provider streamed an error event: {}",
                    value
                        .pointer("/error/message")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("(no message)")
                ));
            }
            "message" => {} // non-streaming body
            other if ANTHROPIC_CONTENT_EVENTS.contains(&other) => {}
            other => {
                return Err(format!(
                    "provider frame carries unsupported Anthropic type {other:?}; refusing to \
                     attribute it to the audit surface"
                ));
            }
        }
        parse_anthropic_payload(&frame_type, &value)
    }
}

/// Shared payload → chunk mapping for streaming events and the
/// non-streaming `message` document.
#[allow(clippy::too_many_lines)]
fn parse_anthropic_payload(
    frame_type: &str,
    value: &serde_json::Value,
) -> Result<Option<crate::routes::ParsedProviderChunk>, String> {
    use crate::routes::{provider_u64, ParsedProviderChunk, ProviderToolCallDelta};
    use serde_json::Value;

    let mut message = String::new();
    let mut reasoning = String::new();
    let mut finish_reason = None;
    let mut tool_call_deltas = Vec::new();

    // Usage may sit at the top level (message_delta, non-streaming) or
    // under `message` (message_start).
    let usage = value
        .get("usage")
        .or_else(|| value.pointer("/message/usage"))
        .filter(|usage| !usage.is_null());
    let mut usage_reported = false;
    let mut prompt_tokens = None;
    let mut completion_tokens = None;
    let mut cached_tokens = None;
    if let Some(usage) = usage {
        usage_reported = true;
        prompt_tokens = provider_u64(usage.get("input_tokens"), "input_tokens")?;
        completion_tokens = provider_u64(usage.get("output_tokens"), "output_tokens")?;
        cached_tokens = provider_u64(usage.get("cache_read_input_tokens"), "cache_read_input_tokens")?;
    }
    let model_name = value
        .get("model")
        .or_else(|| value.pointer("/message/model"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    if let Some(reason) = value
        .get("stop_reason")
        .or_else(|| value.pointer("/delta/stop_reason"))
        .or_else(|| value.pointer("/message/stop_reason"))
        .and_then(Value::as_str)
        .filter(|reason| !reason.is_empty())
    {
        finish_reason = Some(reason.to_owned());
    }

    let mut absorb_block = |index: u64, block: &Value| -> Result<(), String> {
        match block.get("type").and_then(Value::as_str).unwrap_or_default() {
            "text" | "text_delta" => {
                if let Some(text) = block.get("text").and_then(Value::as_str) {
                    message.push_str(text);
                }
            }
            "thinking" | "thinking_delta" => {
                if let Some(text) = block
                    .get("thinking")
                    .or_else(|| block.get("text"))
                    .and_then(Value::as_str)
                {
                    reasoning.push_str(text);
                }
            }
            "tool_use" => {
                // Non-streaming (or content_block_start): id + name,
                // with `input` as a JSON object.
                let arguments = match block.get("input") {
                    Some(input) if !input.is_null() && input != &Value::Object(serde_json::Map::new()) => {
                        serde_json::to_string(input)
                            .map_err(|error| format!("provider tool input is not serializable: {error}"))?
                    }
                    _ => String::new(),
                };
                tool_call_deltas.push(ProviderToolCallDelta {
                    choice_index: 0,
                    index,
                    id: block.get("id").and_then(Value::as_str).map(str::to_owned),
                    name: block.get("name").and_then(Value::as_str).map(str::to_owned),
                    arguments,
                });
            }
            "input_json_delta" => {
                tool_call_deltas.push(ProviderToolCallDelta {
                    choice_index: 0,
                    index,
                    id: None,
                    name: None,
                    arguments: block
                        .get("partial_json")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                });
            }
            // signature_delta, redacted_thinking, server_tool_use
            // results, citations: nothing attributable to capture.
            _ => {}
        }
        Ok(())
    };

    match frame_type {
        "content_block_start" | "content_block_delta" => {
            let index = provider_u64(value.get("index"), "content block index")?
                .ok_or_else(|| "provider content block has no index".to_owned())?;
            let block = value
                .get("content_block")
                .or_else(|| value.get("delta"))
                .ok_or_else(|| "provider content frame has no block payload".to_owned())?;
            absorb_block(index, block)?;
        }
        "message" | "message_start" => {
            let content = value.get("content").or_else(|| value.pointer("/message/content"));
            if let Some(Value::Array(blocks)) = content {
                for (position, block) in blocks.iter().enumerate() {
                    let index =
                        u64::try_from(position).map_err(|_| "provider content index overflow".to_owned())?;
                    absorb_block(index, block)?;
                }
            }
        }
        // message_delta / content_block_stop carry no content blocks.
        _ => {}
    }

    let completion_reported = completion_tokens.is_some();
    let completion_tokens = completion_tokens.unwrap_or_else(|| {
        let mut estimated = av_core::tokens::approx_tokens(&message)
            .saturating_add(av_core::tokens::approx_tokens(&reasoning));
        for call in &tool_call_deltas {
            estimated = estimated
                .saturating_add(call.name.as_deref().map_or(0, av_core::tokens::approx_tokens))
                .saturating_add(av_core::tokens::approx_tokens(&call.arguments));
        }
        estimated
    });
    Ok(Some(ParsedProviderChunk {
        message,
        reasoning: (!reasoning.is_empty()).then_some(reasoning),
        model_name,
        metrics: av_events::EventMetrics {
            prompt_tokens,
            completion_tokens: Some(completion_tokens),
            cached_tokens,
            pruned_tokens: None,
            pruning_ratio_millis: None,
        },
        usage_reported,
        completion_reported,
        finish_reason,
        // Anthropic does not report request cost on the wire.
        cost_usd_micros: 0,
        cost_reported: false,
        // A recognized Anthropic frame is the dialect's equivalent of
        // "has a choices array": absorb_frame's empty-200 guard keys
        // on this.
        has_choices: true,
        tool_call_deltas,
    }))
}

/// Google Gemini `generateContent`/`streamGenerateContent` wire
/// dialect (S3 step 3).
///
/// Streaming uses UNNAMED `data:` frames (`?alt=sse`); each frame and
/// the non-streaming body share one shape:
/// `candidates[].content.parts[]` for text/`thought`/`functionCall`
/// parts, `usageMetadata` for accounting, `finishReason` (SCREAMING
/// case) on the final candidate frame. Mapping into the
/// provider-neutral chunk:
///
/// * text parts → `message`; parts flagged `"thought": true` →
///   `reasoning`.
/// * `functionCall` parts → tool-call deltas keyed by
///   (candidate index, part position); Gemini function calls arrive
///   complete, with `args` as a JSON object serialized verbatim.
/// * `promptTokenCount` → prompt, `candidatesTokenCount` →
///   completion (cumulative across frames), `cachedContentTokenCount`
///   → cached.
/// * `finishReason` folds into the OpenAI-lowercase taxonomy the
///   audit chain understands: `STOP`→`stop`, `MAX_TOKENS`→
///   `max_tokens`, safety-class refusals → `content_filter`; other
///   values pass through lowercased (→ `StopReason::Other`).
/// * `promptFeedback.blockReason` (request refused before any
///   candidate) → `content_filter`.
/// * Named SSE events are refused when they carry data (Gemini never
///   names its frames; a named frame is not attributable), mirroring
///   the OpenAI adapter's posture.
pub(crate) struct GoogleGeminiAdapter;

impl ProviderAdapter for GoogleGeminiAdapter {
    fn name(&self) -> &'static str {
        "gemini"
    }

    fn parse_sse_chunk(&self, raw: &str) -> Result<Option<crate::routes::ParsedProviderChunk>, String> {
        use crate::routes::{provider_u64, ParsedProviderChunk, ProviderToolCallDelta};
        use serde_json::Value;

        let raw = raw.strip_prefix('\u{feff}').unwrap_or(raw);
        let mut is_sse = false;
        let mut event_type = String::new();
        let mut data = Vec::new();
        for line in raw.split(['\r', '\n']) {
            if let Some(value) = line.strip_prefix("data:") {
                is_sse = true;
                data.push(value.strip_prefix(' ').unwrap_or(value));
            } else if let Some(value) = line.strip_prefix("event:") {
                is_sse = true;
                event_type = value.strip_prefix(' ').unwrap_or(value).to_owned();
            } else if line == "data"
                || line.starts_with("id:")
                || line.starts_with("retry:")
                || line.starts_with(':')
            {
                is_sse = true;
            }
        }
        if is_sse && !event_type.is_empty() && event_type != "message" {
            if data.iter().all(|entry| entry.trim().is_empty()) {
                return Ok(None);
            }
            return Err(format!(
                "provider SSE frame carries unsupported event type {event_type:?}; the Gemini \
                 dialect uses unnamed data frames, so a named frame is not attributable"
            ));
        }
        let candidate = if is_sse {
            if data.iter().all(|entry| entry.trim().is_empty()) {
                return Ok(None);
            }
            data.join("\n")
        } else {
            raw.trim().to_owned()
        };
        if candidate.is_empty() {
            return Ok(None);
        }
        let value: Value = serde_json::from_str(&candidate)
            .map_err(|error| format!("invalid provider JSON frame: {error}"))?;

        let mut message = String::new();
        let mut reasoning = String::new();
        let mut finish_reason = None;
        let mut tool_call_deltas = Vec::new();

        let mut usage_reported = false;
        let mut prompt_tokens = None;
        let mut completion_tokens = None;
        let mut cached_tokens = None;
        if let Some(usage) = value.get("usageMetadata").filter(|usage| !usage.is_null()) {
            usage_reported = true;
            prompt_tokens = provider_u64(usage.get("promptTokenCount"), "promptTokenCount")?;
            completion_tokens = provider_u64(usage.get("candidatesTokenCount"), "candidatesTokenCount")?;
            cached_tokens = provider_u64(usage.get("cachedContentTokenCount"), "cachedContentTokenCount")?;
        }
        let model_name = value
            .get("modelVersion")
            .and_then(Value::as_str)
            .map(str::to_owned);
        // A safety block before any candidate is a terminal refusal.
        if value
            .pointer("/promptFeedback/blockReason")
            .and_then(Value::as_str)
            .is_some_and(|reason| !reason.is_empty())
        {
            finish_reason = Some("content_filter".to_owned());
        }

        let has_candidates = value.get("candidates").is_some();
        let candidates = match value.get("candidates") {
            Some(Value::Array(candidates)) => Some(candidates),
            Some(_) => return Err("provider candidates is not an array".to_owned()),
            None => None,
        };
        if let Some(candidates) = candidates {
            for (candidate_position, entry) in candidates.iter().enumerate() {
                let choice_index = entry
                    .get("index")
                    .and_then(Value::as_u64)
                    .or_else(|| u64::try_from(candidate_position).ok())
                    .unwrap_or(u64::MAX);
                if let Some(reason) = entry
                    .get("finishReason")
                    .and_then(Value::as_str)
                    .filter(|reason| !reason.is_empty())
                {
                    finish_reason = Some(map_gemini_finish_reason(reason));
                }
                let parts = match entry.pointer("/content/parts") {
                    Some(Value::Array(parts)) => parts.as_slice(),
                    Some(Value::Null) | None => &[],
                    Some(_) => return Err("provider content parts is not an array".to_owned()),
                };
                for (position, part) in parts.iter().enumerate() {
                    if let Some(text) = part.get("text").and_then(Value::as_str) {
                        if part.get("thought").and_then(Value::as_bool).unwrap_or(false) {
                            reasoning.push_str(text);
                        } else {
                            message.push_str(text);
                        }
                    }
                    if let Some(call) = part.get("functionCall").filter(|call| !call.is_null()) {
                        let arguments = match call.get("args") {
                            Some(args) if !args.is_null() => {
                                serde_json::to_string(args).map_err(|error| {
                                    format!("provider function args are not serializable: {error}")
                                })?
                            }
                            _ => String::new(),
                        };
                        tool_call_deltas.push(ProviderToolCallDelta {
                            choice_index,
                            index: u64::try_from(position)
                                .map_err(|_| "provider part index overflow".to_owned())?,
                            id: call.get("id").and_then(Value::as_str).map(str::to_owned),
                            name: call.get("name").and_then(Value::as_str).map(str::to_owned),
                            arguments,
                        });
                    }
                }
            }
        }
        let completion_reported = completion_tokens.is_some();
        let completion_tokens = completion_tokens.unwrap_or_else(|| {
            let mut estimated = av_core::tokens::approx_tokens(&message)
                .saturating_add(av_core::tokens::approx_tokens(&reasoning));
            for call in &tool_call_deltas {
                estimated = estimated
                    .saturating_add(call.name.as_deref().map_or(0, av_core::tokens::approx_tokens))
                    .saturating_add(av_core::tokens::approx_tokens(&call.arguments));
            }
            estimated
        });
        Ok(Some(ParsedProviderChunk {
            message,
            reasoning: (!reasoning.is_empty()).then_some(reasoning),
            model_name,
            metrics: av_events::EventMetrics {
                prompt_tokens,
                completion_tokens: Some(completion_tokens),
                cached_tokens,
                pruned_tokens: None,
                pruning_ratio_millis: None,
            },
            usage_reported,
            completion_reported,
            finish_reason,
            // Gemini does not report request cost on the wire.
            cost_usd_micros: 0,
            cost_reported: false,
            // Candidates or usage-only frames are the dialect's
            // equivalent of a choices array for the empty-200 guard.
            has_choices: has_candidates || usage_reported,
            tool_call_deltas,
        }))
    }
}

/// Fold Gemini's SCREAMING_CASE `finishReason` into the lowercase
/// taxonomy `map_finish_reason` understands. Safety-class refusals
/// all map to `content_filter`; unknown values pass through
/// lowercased and land on `StopReason::Other`.
fn map_gemini_finish_reason(reason: &str) -> String {
    match reason {
        "STOP" => "stop".to_owned(),
        "MAX_TOKENS" => "max_tokens".to_owned(),
        "SAFETY" | "RECITATION" | "BLOCKLIST" | "PROHIBITED_CONTENT" | "SPII" => "content_filter".to_owned(),
        other => other.to_ascii_lowercase(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    /// The adapter must be a transparent shim over the routes parser
    /// (S3 step 1 is a pure refactor): same chunk for a normal
    /// frame, same keepalive `None`, same totality on garbage.
    #[test]
    fn openai_adapter_is_a_transparent_shim() {
        let adapter = adapter_for("openai").unwrap();
        assert_eq!(adapter.name(), "openai");
        let parsed = adapter
            .parse_sse_chunk(r#"data: {"choices":[{"delta":{"content":"hi"}}]}"#)
            .unwrap()
            .unwrap();
        assert_eq!(parsed.message, "hi");
        assert!(adapter.parse_sse_chunk("data: [DONE]").unwrap().is_none());
        assert!(adapter.parse_sse_chunk(": keepalive").unwrap().is_none());
        // Total over hostile input: an error, never a panic.
        let _ = adapter.parse_sse_chunk("data: {\"usage\":{\"prompt_tokens\":-1}}");
    }

    #[test]
    fn unknown_providers_are_refused() {
        assert!(
            adapter_for("google").is_none(),
            "the Gemini dialect registers as \"gemini\", not \"google\""
        );
        assert!(adapter_for("").is_none());
        for name in SUPPORTED_PROVIDERS {
            assert!(adapter_for(name).is_some(), "{name} must be constructible");
        }
    }

    /// The Gemini streaming dialect maps into the provider-neutral
    /// chunk: text and thought parts, complete functionCall parts,
    /// cumulative usageMetadata, SCREAMING_CASE finish reasons folded
    /// into the audit taxonomy, and safety blocks.
    #[test]
    fn gemini_streaming_dialect_maps_to_neutral_chunks() {
        let adapter = adapter_for("gemini").unwrap();
        assert_eq!(adapter.name(), "gemini");

        let first = adapter
            .parse_sse_chunk(
                "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"Hello\"},{\"text\":\"plan...\",\"thought\":true}],\"role\":\"model\"},\"index\":0}],\"usageMetadata\":{\"promptTokenCount\":25,\"candidatesTokenCount\":1,\"cachedContentTokenCount\":7},\"modelVersion\":\"gemini-2.0-flash\"}",
            )
            .unwrap()
            .unwrap();
        assert_eq!(first.message, "Hello");
        assert_eq!(first.reasoning.as_deref(), Some("plan..."));
        assert_eq!(first.model_name.as_deref(), Some("gemini-2.0-flash"));
        assert!(first.usage_reported && first.completion_reported);
        assert_eq!(first.metrics.prompt_tokens, Some(25));
        assert_eq!(first.metrics.completion_tokens, Some(1));
        assert_eq!(first.metrics.cached_tokens, Some(7));
        assert!(first.has_choices);

        let tool = adapter
            .parse_sse_chunk(
                "data: {\"candidates\":[{\"content\":{\"parts\":[{\"functionCall\":{\"name\":\"get_weather\",\"args\":{\"city\":\"Paris\"}}}]},\"index\":0}]}",
            )
            .unwrap()
            .unwrap();
        let delta = &tool.tool_call_deltas[0];
        assert_eq!(delta.name.as_deref(), Some("get_weather"));
        assert_eq!(delta.arguments, r#"{"city":"Paris"}"#);
        assert_eq!((delta.choice_index, delta.index), (0, 0));

        let last = adapter
            .parse_sse_chunk(
                "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"!\"}]},\"finishReason\":\"STOP\",\"index\":0}],\"usageMetadata\":{\"promptTokenCount\":25,\"candidatesTokenCount\":15}}",
            )
            .unwrap()
            .unwrap();
        assert_eq!(last.finish_reason.as_deref(), Some("stop"));
        assert_eq!(last.metrics.completion_tokens, Some(15));

        let blocked = adapter
            .parse_sse_chunk(
                "data: {\"promptFeedback\":{\"blockReason\":\"SAFETY\"},\"usageMetadata\":{\"promptTokenCount\":9}}",
            )
            .unwrap()
            .unwrap();
        assert_eq!(blocked.finish_reason.as_deref(), Some("content_filter"));
        assert!(blocked.has_choices, "usage-only frames pass the empty-200 guard");

        let max = adapter
            .parse_sse_chunk("data: {\"candidates\":[{\"finishReason\":\"MAX_TOKENS\",\"index\":0}]}")
            .unwrap()
            .unwrap();
        assert_eq!(max.finish_reason.as_deref(), Some("max_tokens"));

        assert!(adapter.parse_sse_chunk(": keepalive").unwrap().is_none());
        assert!(adapter.parse_sse_chunk("event: ping\ndata:").unwrap().is_none());
        assert!(
            adapter
                .parse_sse_chunk("event: custom\ndata: {\"candidates\":[]}")
                .is_err(),
            "named frames with data are not attributable in the Gemini dialect"
        );
        let _ = adapter.parse_sse_chunk("data: {not json");
    }

    /// The full Anthropic streaming dialect maps into the
    /// provider-neutral chunk: text/thinking deltas, tool_use blocks
    /// with input_json_delta argument fragments, cumulative usage,
    /// native stop reasons, and keepalives.
    #[test]
    fn anthropic_streaming_dialect_maps_to_neutral_chunks() {
        let adapter = adapter_for("anthropic").unwrap();
        assert_eq!(adapter.name(), "anthropic");

        let start = adapter
            .parse_sse_chunk(
                "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-sonnet-4-5\",\"usage\":{\"input_tokens\":25,\"output_tokens\":1,\"cache_read_input_tokens\":7}}}",
            )
            .unwrap()
            .unwrap();
        assert_eq!(start.model_name.as_deref(), Some("claude-sonnet-4-5"));
        assert!(start.usage_reported && start.completion_reported);
        assert_eq!(start.metrics.prompt_tokens, Some(25));
        assert_eq!(start.metrics.completion_tokens, Some(1));
        assert_eq!(start.metrics.cached_tokens, Some(7));
        assert!(start.has_choices);

        let text = adapter
            .parse_sse_chunk(
                "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}",
            )
            .unwrap()
            .unwrap();
        assert_eq!(text.message, "Hello");
        assert!(!text.completion_reported, "no usage on content deltas");

        let thinking = adapter
            .parse_sse_chunk(
                "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"hmm\"}}",
            )
            .unwrap()
            .unwrap();
        assert_eq!(thinking.reasoning.as_deref(), Some("hmm"));

        let tool_start = adapter
            .parse_sse_chunk(
                "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"get_weather\",\"input\":{}}}",
            )
            .unwrap()
            .unwrap();
        let delta = &tool_start.tool_call_deltas[0];
        assert_eq!((delta.choice_index, delta.index), (0, 1));
        assert_eq!(delta.id.as_deref(), Some("toolu_1"));
        assert_eq!(delta.name.as_deref(), Some("get_weather"));
        assert!(
            delta.arguments.is_empty(),
            "empty input carries no argument bytes"
        );

        let args = adapter
            .parse_sse_chunk(
                "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"city\\\":\"}}",
            )
            .unwrap()
            .unwrap();
        assert_eq!(args.tool_call_deltas[0].arguments, "{\"city\":");

        let finish = adapter
            .parse_sse_chunk(
                "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":15}}",
            )
            .unwrap()
            .unwrap();
        assert_eq!(finish.finish_reason.as_deref(), Some("end_turn"));
        assert!(finish.completion_reported);
        assert_eq!(finish.metrics.completion_tokens, Some(15));

        // Keepalives and stream end: nothing attributable.
        assert!(adapter
            .parse_sse_chunk("event: ping\ndata: {\"type\": \"ping\"}")
            .unwrap()
            .is_none());
        assert!(adapter
            .parse_sse_chunk("event: message_stop\ndata: {\"type\":\"message_stop\"}")
            .unwrap()
            .is_none());
        assert!(adapter.parse_sse_chunk(": keepalive").unwrap().is_none());
    }

    /// Non-streaming Anthropic bodies (one `message` document) carry
    /// content blocks, usage and stop_reason in one frame.
    #[test]
    fn anthropic_non_streaming_body_parses_whole_message() {
        let adapter = adapter_for("anthropic").unwrap();
        let parsed = adapter
            .parse_sse_chunk(
                r#"{"type":"message","model":"claude-sonnet-4-5","content":[{"type":"text","text":"Hi there"},{"type":"tool_use","id":"toolu_2","name":"read","input":{"path":"x"}}],"stop_reason":"tool_use","usage":{"input_tokens":9,"output_tokens":12}}"#,
            )
            .unwrap()
            .unwrap();
        assert_eq!(parsed.message, "Hi there");
        assert_eq!(parsed.finish_reason.as_deref(), Some("tool_use"));
        assert_eq!(parsed.metrics.prompt_tokens, Some(9));
        assert_eq!(parsed.metrics.completion_tokens, Some(12));
        assert_eq!(parsed.tool_call_deltas[0].arguments, r#"{"path":"x"}"#);
    }

    /// Hostile frames: error events must fail capture (never be
    /// attributed as model output), event-name/payload-type mismatch
    /// is refused, negative usage is refused, and the parser is total
    /// over garbage.
    #[test]
    fn anthropic_hostile_frames_fail_closed() {
        let adapter = adapter_for("anthropic").unwrap();
        let error = adapter
            .parse_sse_chunk(
                "event: error\ndata: {\"type\":\"error\",\"error\":{\"message\":\"overloaded\"}}",
            )
            .unwrap_err();
        assert!(
            error.contains("overloaded"),
            "error payload must fail capture: {error}"
        );
        assert!(adapter
            .parse_sse_chunk(
                "event: message_delta\ndata: {\"type\":\"error\",\"error\":{\"message\":\"smuggled\"}}"
            )
            .is_err());
        assert!(adapter
            .parse_sse_chunk(
                "event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":-1}}"
            )
            .is_err());
        let _ = adapter.parse_sse_chunk("data: {not json");
        let _ = adapter.parse_sse_chunk("\u{feff}data: {\"type\":\"unknown_event\",\"x\":1}");
    }
}
