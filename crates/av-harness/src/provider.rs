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
        _ => None,
    }
}

/// The provider names `adapter_for` accepts, for config-validation
/// error messages.
pub(crate) const SUPPORTED_PROVIDERS: &[&str] = &["openai"];

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

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
        assert!(adapter_for("anthropic").is_none(), "S3 step 2 not landed yet");
        assert!(adapter_for("").is_none());
        assert!(SUPPORTED_PROVIDERS.contains(&"openai"));
    }
}
