//! Full-content OpenTelemetry export to the tenant collector.
//!
//! [`TenantContentSink`] turns every journaled step into an OpenTelemetry
//! span that follows the GenAI semantic conventions
//! (<https://github.com/open-telemetry/semantic-conventions-genai>):
//!
//! - a chat call (request record plus terminal response record, joined by
//!   their response-attempt id) becomes one `chat {model}` span of kind
//!   `CLIENT` with `gen_ai.input.messages`, `gen_ai.output.messages`, token
//!   usage, finish reasons, and `gen_ai.conversation.id` (the session);
//! - a tool authorization becomes an `execute_tool {tool}` span with the
//!   tool name, call id, and arguments, plus the gateway's verdict;
//! - a tool completion becomes an `execute_tool.result` span carrying
//!   `gen_ai.tool.call.result`;
//! - every other audit event becomes an `agentvisor.{class}` span carrying
//!   the redacted event.
//!
//! Every content field passes through the redaction engine (the built-in
//! patterns plus the configured `redaction_patterns` and `redaction_paths`)
//! before it becomes an attribute, even when journal redaction is off. The
//! sink exports through its own tracer provider, whose only exporter is the
//! tenant endpoint, so the operator's collector never receives content.

use crate::content::{ContentRecord, ContentSink};
use av_events::EventClass;
use opentelemetry::trace::{Span as _, SpanKind, TracerProvider as _};
use opentelemetry::{Array, KeyValue, StringValue, Value as OtelValue};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Chat requests waiting for their terminal response record.
const MAX_PENDING_CHATS: usize = 4096;

/// Longest content attribute exported; longer values are truncated with a
/// marker that states how many bytes were cut.
pub const MAX_ATTRIBUTE_BYTES: usize = 256 * 1024;

/// Content sink exporting GenAI spans to the tenant collector.
pub struct TenantContentSink {
    tracer: opentelemetry_sdk::trace::SdkTracer,
    redaction: av_redact::RedactionEngine,
    provider_name: String,
    pending: parking_lot::Mutex<(HashMap<String, ContentRecord>, VecDeque<String>)>,
}

impl TenantContentSink {
    /// Build a sink on `provider` (which must export only to the tenant),
    /// redacting with `redaction`. `provider_name` is the configured
    /// upstream provider dialect (`gen_ai.provider.name`).
    pub fn new(
        provider: &opentelemetry_sdk::trace::SdkTracerProvider,
        redaction: av_redact::RedactionEngine,
        provider_name: &str,
    ) -> Self {
        Self {
            tracer: provider.tracer("agentvisor-ai.content"),
            redaction,
            provider_name: provider_name.to_owned(),
            pending: parking_lot::Mutex::new((HashMap::new(), VecDeque::new())),
        }
    }

    fn redact(&self, record: &mut ContentRecord) {
        let scrub = |value: &mut Option<Value>| {
            if let Some(value) = value.as_mut() {
                self.redaction.redact_value(value);
            }
        };
        scrub(&mut record.message);
        scrub(&mut record.tool_calls);
        scrub(&mut record.observation);
        self.redaction.redact_value(&mut record.event);
        if let Some(reasoning) = record.reasoning.take() {
            let mut value = Value::String(reasoning);
            self.redaction.redact_value(&mut value);
            record.reasoning = value.as_str().map(str::to_owned);
        }
    }

    fn emit(&self, name: String, kind: SpanKind, start_ms: u64, end_ms: u64, attributes: Vec<KeyValue>) {
        let at = |ms: u64| UNIX_EPOCH + Duration::from_millis(ms);
        let builder = opentelemetry::trace::SpanBuilder::from_name(name)
            .with_kind(kind)
            .with_start_time(at(start_ms.min(end_ms)))
            .with_attributes(attributes);
        let mut span = builder.start_with_context(&self.tracer, &opentelemetry::Context::new());
        span.end_with_timestamp(at(end_ms));
    }

    fn common(&self, record: &ContentRecord) -> Vec<KeyValue> {
        let mut attributes = vec![
            KeyValue::new("gen_ai.conversation.id", record.session_id.clone()),
            KeyValue::new("gen_ai.agent.id", record.identity.instance_uid.clone()),
            KeyValue::new("gen_ai.agent.name", record.identity.charter.name.clone()),
            KeyValue::new("agentvisor.agent.version", record.identity.version.clone()),
            KeyValue::new("agentvisor.event.uid", record.event_uid.clone()),
            KeyValue::new("agentvisor.event.class", class_label(record.class)),
            KeyValue::new("agentvisor.success", record.success),
        ];
        if !record.success {
            attributes.push(KeyValue::new("error.type", "agentvisor.failure"));
        }
        attributes
    }

    fn chat(&self, request: Option<ContentRecord>, response: ContentRecord) {
        let model = response.model.clone().unwrap_or_default();
        let mut attributes = self.common(&response);
        attributes.extend([
            KeyValue::new("gen_ai.operation.name", "chat"),
            KeyValue::new("gen_ai.provider.name", self.provider_name.clone()),
        ]);
        if !model.is_empty() {
            attributes.push(KeyValue::new("gen_ai.request.model", model.clone()));
            attributes.push(KeyValue::new("gen_ai.response.model", model.clone()));
        }
        let input_tokens = request
            .as_ref()
            .and_then(|request| request.prompt_tokens)
            .or(response.prompt_tokens);
        if let Some(tokens) = input_tokens.and_then(|tokens| i64::try_from(tokens).ok()) {
            attributes.push(KeyValue::new("gen_ai.usage.input_tokens", tokens));
        }
        if let Some(tokens) = response
            .completion_tokens
            .and_then(|tokens| i64::try_from(tokens).ok())
        {
            attributes.push(KeyValue::new("gen_ai.usage.output_tokens", tokens));
        }
        if let Some(reason) = &response.finish_reason {
            attributes.push(KeyValue::new(
                "gen_ai.response.finish_reasons",
                OtelValue::Array(Array::String(vec![StringValue::from(reason.clone())])),
            ));
        }
        if let Some(request) = &request {
            if let Some(message) = &request.message {
                let input = json!([{
                    "role": role(request.source.as_deref()),
                    "parts": parts(message),
                }]);
                attributes.push(KeyValue::new(
                    "gen_ai.input.messages",
                    bounded(&input.to_string()),
                ));
            }
            attributes.push(KeyValue::new(
                "agentvisor.request.event.uid",
                request.event_uid.clone(),
            ));
        }
        let mut output_parts = response.message.as_ref().map(parts).unwrap_or_default();
        if let Some(Value::Array(calls)) = &response.tool_calls {
            for call in calls {
                output_parts.push(json!({
                    "type": "tool_call",
                    "id": call.get("tool_call_id"),
                    "name": call.get("function_name"),
                    "arguments": call.get("arguments"),
                }));
            }
        }
        if let Some(reasoning) = &response.reasoning {
            output_parts.insert(0, json!({"type": "reasoning", "content": reasoning}));
        }
        let output = json!([{
            "role": "assistant",
            "parts": output_parts,
            "finish_reason": response.finish_reason,
        }]);
        attributes.push(KeyValue::new(
            "gen_ai.output.messages",
            bounded(&output.to_string()),
        ));
        let start = request
            .as_ref()
            .map_or(response.time_ms, |request| request.time_ms);
        let name = if model.is_empty() {
            "chat".to_owned()
        } else {
            format!("chat {model}")
        };
        self.emit(name, SpanKind::Client, start, response.time_ms, attributes);
    }

    fn tool(&self, record: &ContentRecord) {
        let call = record
            .tool_calls
            .as_ref()
            .and_then(Value::as_array)
            .and_then(|calls| calls.first());
        let tool = call
            .and_then(|call| call.get("function_name"))
            .and_then(Value::as_str)
            .or_else(|| record.event.pointer("/payload/tool").and_then(Value::as_str))
            .unwrap_or("unknown")
            .to_owned();
        let mut attributes = self.common(record);
        attributes.extend([
            KeyValue::new("gen_ai.operation.name", "execute_tool"),
            KeyValue::new("gen_ai.tool.name", tool.clone()),
            KeyValue::new("gen_ai.tool.type", "extension"),
        ]);
        if let Some(id) = call
            .and_then(|call| call.get("tool_call_id"))
            .and_then(Value::as_str)
        {
            attributes.push(KeyValue::new("gen_ai.tool.call.id", id.to_owned()));
        }
        if let Some(arguments) = call.and_then(|call| call.get("arguments")) {
            attributes.push(KeyValue::new(
                "gen_ai.tool.call.arguments",
                bounded(&arguments.to_string()),
            ));
        }
        let payload = record.event.get("payload").cloned().unwrap_or(Value::Null);
        if let Some(allowed) = payload.get("allowed").and_then(Value::as_bool) {
            attributes.push(KeyValue::new("agentvisor.tool.allowed", allowed));
        }
        for (key, attribute) in [
            ("denial_code", "agentvisor.tool.denial_code"),
            ("policy", "agentvisor.tool.policy"),
            ("stage", "agentvisor.tool.stage"),
            ("reason", "agentvisor.tool.reason"),
        ] {
            if let Some(value) = payload.get(key).and_then(Value::as_str) {
                attributes.push(KeyValue::new(attribute, bounded(value)));
            }
        }
        self.emit(
            format!("execute_tool {tool}"),
            SpanKind::Internal,
            record.time_ms,
            record.time_ms,
            attributes,
        );
    }

    fn tool_result(&self, record: &ContentRecord) {
        let mut attributes = self.common(record);
        attributes.push(KeyValue::new("gen_ai.operation.name", "execute_tool"));
        if let Some(key) = record
            .event
            .pointer("/payload/execution_key")
            .and_then(Value::as_str)
        {
            attributes.push(KeyValue::new("agentvisor.tool.execution_key", key.to_owned()));
        }
        if let Some(status) = record.event.pointer("/payload/status").and_then(Value::as_i64) {
            attributes.push(KeyValue::new("agentvisor.tool.http_status", status));
        }
        if let Some(message) = &record.message {
            let text = message
                .as_str()
                .map_or_else(|| message.to_string(), str::to_owned);
            attributes.push(KeyValue::new("gen_ai.tool.call.result", bounded(&text)));
        }
        self.emit(
            "execute_tool.result".to_owned(),
            SpanKind::Internal,
            record.time_ms,
            record.time_ms,
            attributes,
        );
    }

    fn event(&self, record: &ContentRecord) {
        let mut attributes = self.common(record);
        attributes.push(KeyValue::new(
            "agentvisor.event",
            bounded(&record.event.to_string()),
        ));
        self.emit(
            format!("agentvisor.{}", class_label(record.class)),
            SpanKind::Internal,
            record.time_ms,
            record.time_ms,
            attributes,
        );
    }
}

impl ContentSink for TenantContentSink {
    fn record(&self, mut record: ContentRecord) {
        self.redact(&mut record);
        let attempt = record.attempt_id.clone();
        match (attempt, record.terminal) {
            // A chat request: hold it until its response completes.
            (Some(attempt), false) => {
                let evicted = {
                    let mut pending = self.pending.lock();
                    let (by_id, order) = &mut *pending;
                    by_id.insert(attempt.clone(), record);
                    order.push_back(attempt);
                    let mut evicted = Vec::new();
                    while order.len() > MAX_PENDING_CHATS {
                        if let Some(stale) = order.pop_front().and_then(|id| by_id.remove(&id)) {
                            evicted.push(stale);
                        }
                    }
                    evicted
                };
                for stale in evicted {
                    self.event(&stale);
                }
            }
            (Some(attempt), true) => {
                let request = {
                    let mut pending = self.pending.lock();
                    let (by_id, order) = &mut *pending;
                    order.retain(|id| *id != attempt);
                    by_id.remove(&attempt)
                };
                self.chat(request, record);
            }
            (None, _) if record.class == EventClass::ToolCall => self.tool(&record),
            (None, _)
                if record.class == EventClass::Session
                    && record.event.pointer("/payload/action").and_then(Value::as_str)
                        == Some("tool_completed") =>
            {
                self.tool_result(&record);
            }
            (None, _) => self.event(&record),
        }
    }
}

fn class_label(class: EventClass) -> &'static str {
    match class {
        EventClass::ToolCall => "tool_call",
        EventClass::StopReason => "stop_reason",
        EventClass::Receipt => "receipt",
        EventClass::Compression => "compression",
        EventClass::Identity => "identity",
        EventClass::Session => "session",
        _ => "event",
    }
}

fn role(source: Option<&str>) -> &'static str {
    match source {
        Some("agent") => "assistant",
        Some("system") => "system",
        _ => "user",
    }
}

/// GenAI message parts for a chat message's content: a string becomes one
/// text part; OpenAI content-part arrays keep their text parts and carry
/// any other part as JSON.
fn parts(message: &Value) -> Vec<Value> {
    match message {
        Value::String(text) => vec![json!({"type": "text", "content": text})],
        Value::Array(items) => items
            .iter()
            .map(|item| match item.get("text").and_then(Value::as_str) {
                Some(text) => json!({"type": "text", "content": text}),
                None => json!({"type": "text", "content": item.to_string()}),
            })
            .collect(),
        other => vec![json!({"type": "text", "content": other.to_string()})],
    }
}

/// Truncate at a character boundary so no attribute exceeds the limit.
fn bounded(text: &str) -> String {
    if text.len() <= MAX_ATTRIBUTE_BYTES {
        return text.to_owned();
    }
    let mut end = MAX_ATTRIBUTE_BYTES;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    let cut = text.len().saturating_sub(end);
    format!("{}…[truncated {cut} bytes]", text.get(..end).unwrap_or_default())
}

/// Wall-clock milliseconds, for records built outside the worker.
pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| {
        u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;

    #[test]
    fn long_values_are_truncated_on_a_character_boundary() {
        let text = "é".repeat(MAX_ATTRIBUTE_BYTES);
        let cut = bounded(&text);
        assert!(cut.len() < text.len());
        assert!(cut.contains("[truncated"));
        assert_eq!(bounded("short"), "short");
    }

    fn record(class: EventClass, attempt: Option<&str>, terminal: bool) -> ContentRecord {
        ContentRecord {
            session_id: "session-1".into(),
            event_uid: av_core::ids::new_event_uid(),
            class,
            success: true,
            identity: av_events::AgentIdentity {
                version: "1".into(),
                charter: "support".into(),
                instance_uid: "inst-1".into(),
                ttl_remaining_s: None,
            },
            time_ms: 1_000,
            event: json!({"payload": {}}),
            source: None,
            message: None,
            reasoning: None,
            model: None,
            tool_calls: None,
            observation: None,
            prompt_tokens: None,
            completion_tokens: None,
            finish_reason: None,
            attempt_id: attempt.map(str::to_owned),
            terminal,
        }
    }

    fn attribute(span: &opentelemetry_sdk::trace::SpanData, key: &str) -> Option<String> {
        span.attributes
            .iter()
            .find(|attribute| attribute.key.as_str() == key)
            .map(|attribute| attribute.value.to_string())
    }

    #[test]
    fn steps_become_redacted_genai_spans() {
        let exporter = opentelemetry_sdk::trace::InMemorySpanExporter::default();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let redaction = av_redact::RedactionEngine::new(av_redact::RedactionConfig {
            include_builtin_patterns: true,
            ..av_redact::RedactionConfig::default()
        })
        .unwrap();
        let sink = TenantContentSink::new(&provider, redaction, "openai");

        let mut request = record(EventClass::Compression, Some("a1"), false);
        request.source = Some("user".into());
        request.message = Some(json!("mail me at bob@example.com"));
        request.prompt_tokens = Some(12);
        sink.record(request);
        let mut response = record(EventClass::StopReason, Some("a1"), true);
        response.time_ms = 1_500;
        response.model = Some("gpt-x".into());
        response.message = Some(json!("done"));
        response.completion_tokens = Some(3);
        response.finish_reason = Some("stop".into());
        sink.record(response);

        let mut tool = record(EventClass::ToolCall, None, false);
        tool.tool_calls = Some(json!([{
            "tool_call_id": "7", "function_name": "lookup",
            "arguments": {"card": "4111 1111 1111 1111"}
        }]));
        tool.event = json!({"payload": {"tool": "lookup", "allowed": true}});
        sink.record(tool);
        let mut result = record(EventClass::Session, None, false);
        result.event = json!({"payload": {"action": "tool_completed", "execution_key": "k", "status": 200}});
        result.message = Some(json!("{\"answer\": 42}"));
        sink.record(result);
        sink.record(record(EventClass::StopReason, None, false));

        provider.force_flush().unwrap();
        let spans = exporter.get_finished_spans().unwrap();
        let names: Vec<&str> = spans.iter().map(|span| span.name.as_ref()).collect();
        assert_eq!(
            names,
            vec![
                "chat gpt-x",
                "execute_tool lookup",
                "execute_tool.result",
                "agentvisor.stop_reason"
            ]
        );
        let chat = &spans[0];
        assert_eq!(chat.span_kind, SpanKind::Client);
        let input = attribute(chat, "gen_ai.input.messages").unwrap();
        assert!(
            input.contains("[REDACTED]") && !input.contains("bob@example.com"),
            "{input}"
        );
        assert!(attribute(chat, "gen_ai.output.messages")
            .unwrap()
            .contains("done"));
        assert_eq!(
            attribute(chat, "gen_ai.usage.input_tokens").as_deref(),
            Some("12")
        );
        assert_eq!(
            attribute(chat, "gen_ai.usage.output_tokens").as_deref(),
            Some("3")
        );
        assert_eq!(attribute(chat, "gen_ai.provider.name").as_deref(), Some("openai"));
        assert_eq!(
            attribute(chat, "gen_ai.conversation.id").as_deref(),
            Some("session-1")
        );
        assert_eq!(
            chat.end_time.duration_since(chat.start_time).unwrap(),
            Duration::from_millis(500),
            "the chat span runs from the request to the response"
        );
        let arguments = attribute(&spans[1], "gen_ai.tool.call.arguments").unwrap();
        assert!(!arguments.contains("4111 1111 1111 1111"), "{arguments}");
        assert_eq!(attribute(&spans[1], "gen_ai.tool.call.id").as_deref(), Some("7"));
        assert_eq!(
            attribute(&spans[1], "agentvisor.tool.allowed").as_deref(),
            Some("true")
        );
        assert!(attribute(&spans[2], "gen_ai.tool.call.result")
            .unwrap()
            .contains("42"));
    }

    #[test]
    fn parts_follow_the_genai_message_shape() {
        assert_eq!(
            parts(&json!("hi")),
            vec![json!({"type": "text", "content": "hi"})]
        );
        assert_eq!(
            parts(&json!([{"type": "text", "text": "a"}, {"type": "image_url", "image_url": {"url": "x"}}]))
                [0],
            json!({"type": "text", "content": "a"})
        );
        assert_eq!(role(Some("agent")), "assistant");
        assert_eq!(role(Some("user")), "user");
    }
}
