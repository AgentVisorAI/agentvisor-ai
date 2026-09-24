//! Real-time sensitive-data redaction engine for audit event payloads.
//!
//! Scans JSON values (or raw JSON bytes) for sensitive data — API keys,
//! email addresses, credit card numbers, Social Security numbers, public
//! IPv4 addresses — and replaces matching spans with a configurable
//! placeholder (default `[REDACTED]`). JSON pointer paths can be used to
//! unconditionally redact specific subtrees.
//!
//! All regex compilation happens once at engine construction. The resulting
//! [`RedactionEngine`] is `Send + Sync` and safe for use across async
//! worker tasks.

pub mod engine;

pub use engine::{RedactError, RedactionConfig, RedactionEngine};

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;
    use serde_json::json;

    /// Helper: build an engine with default (built-in) patterns.
    fn default_engine() -> RedactionEngine {
        RedactionEngine::new(RedactionConfig::default()).unwrap()
    }

    // ---------------------------------------------------------------
    // Send + Sync compile-time check
    // ---------------------------------------------------------------

    fn _assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn engine_is_send_and_sync() {
        _assert_send_sync::<RedactionEngine>();
    }

    // ---------------------------------------------------------------
    // Bearer tokens
    // ---------------------------------------------------------------

    #[test]
    fn bearer_token_is_redacted() {
        let engine = default_engine();
        let mut val = json!("Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123");
        engine.redact_value(&mut val);
        assert_eq!(val, json!("[REDACTED]"));
    }

    #[test]
    fn bearer_in_context_preserves_surrounding_text() {
        let engine = default_engine();
        let mut val = json!("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc123XY");
        engine.redact_value(&mut val);
        let s = val.as_str().unwrap();
        assert!(s.starts_with("Authorization: [REDACTED]"), "got: {s}");
        assert!(!s.contains("eyJ"));
    }

    #[test]
    fn bearer_of_bad_news_is_not_redacted() {
        let engine = default_engine();
        let mut val = json!("Bearer of bad news");
        engine.redact_value(&mut val);
        assert_eq!(val, json!("Bearer of bad news"));
    }

    // ---------------------------------------------------------------
    // API keys (sk-*, key-*)
    // ---------------------------------------------------------------

    #[test]
    fn sk_api_key_is_redacted() {
        let engine = default_engine();
        let mut val = json!("sk-abc123def456ghi789jk");
        engine.redact_value(&mut val);
        let s = val.as_str().unwrap();
        assert!(s.contains("[REDACTED]"), "got: {s}");
        assert!(!s.contains("sk-abc123"));
    }

    #[test]
    fn key_api_key_is_redacted() {
        let engine = default_engine();
        let mut val = json!("key-ABCDEF0123456789XY");
        engine.redact_value(&mut val);
        let s = val.as_str().unwrap();
        assert!(s.contains("[REDACTED]"), "got: {s}");
    }

    #[test]
    fn key_value_is_not_redacted() {
        let engine = default_engine();
        let mut val = json!("key-value");
        engine.redact_value(&mut val);
        assert_eq!(val, json!("key-value"));
    }

    #[test]
    fn segmented_api_keys_are_redacted_in_full() {
        let engine = default_engine();
        for key in [
            "sk-proj-Ab3dEf_Gh1jK-Lm4nOp5qRs6tUv7wXy8zA9bC0dE_",
            "sk-svcacct-AbCdEf0123456789_-",
            "sk-admin-AbCdEf0123456789_-",
            "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AbCdAA",
            "key-AbCdEf0123456789_-",
        ] {
            let mut value = json!(format!("key: {key}; done"));
            engine.redact_value(&mut value);
            assert_eq!(value, json!("key: [REDACTED]; done"));
        }
    }

    #[test]
    fn sensitive_values_touching_unicode_text_are_redacted() {
        let engine = default_engine();
        for (input, expected) in [
            ("カード番号は4111111111111111です", "カード番号は[REDACTED]です"),
            ("社会保障番号123-45-6789です", "社会保障番号[REDACTED]です"),
            ("IP地址8.8.8.8です", "IP地址[REDACTED]です"),
            ("密钥sk-proj-AbCdEf0123456789_です", "密钥[REDACTED]です"),
            ("Nº4111111111111111", "Nº[REDACTED]"),
        ] {
            let mut value = json!(input);
            engine.redact_value(&mut value);
            assert_eq!(value, json!(expected));
        }
    }

    #[test]
    fn task_something_is_not_redacted() {
        let engine = default_engine();
        let mut val = json!("task-manager");
        engine.redact_value(&mut val);
        assert_eq!(val, json!("task-manager"));
    }

    // ---------------------------------------------------------------
    // Email addresses
    // ---------------------------------------------------------------

    #[test]
    fn email_is_redacted() {
        let engine = default_engine();
        let mut val = json!("user@example.com");
        engine.redact_value(&mut val);
        let s = val.as_str().unwrap();
        assert!(s.contains("[REDACTED]"), "got: {s}");
        assert!(!s.contains("user@"));
    }

    #[test]
    fn email_in_sentence_preserves_context() {
        let engine = default_engine();
        let mut val = json!("Contact alice@example.org for help");
        engine.redact_value(&mut val);
        let s = val.as_str().unwrap();
        assert!(s.starts_with("Contact "), "got: {s}");
        assert!(s.ends_with(" for help"), "got: {s}");
        assert!(!s.contains("alice@"));
    }

    #[test]
    fn non_email_at_sign_is_not_redacted() {
        let engine = default_engine();
        let mut val = json!("@mention in chat");
        engine.redact_value(&mut val);
        assert_eq!(val, json!("@mention in chat"));
    }

    // ---------------------------------------------------------------
    // Credit card numbers (Luhn-validated)
    // ---------------------------------------------------------------

    #[test]
    fn valid_visa_card_is_redacted() {
        let engine = default_engine();
        // 4111111111111111 passes Luhn.
        let mut val = json!("4111111111111111");
        engine.redact_value(&mut val);
        let s = val.as_str().unwrap();
        assert!(s.contains("[REDACTED]"), "got: {s}");
    }

    #[test]
    fn valid_card_with_dashes_is_redacted() {
        let engine = default_engine();
        let mut val = json!("4111-1111-1111-1111");
        engine.redact_value(&mut val);
        let s = val.as_str().unwrap();
        assert!(s.contains("[REDACTED]"), "got: {s}");
    }

    #[test]
    fn valid_card_with_spaces_is_redacted() {
        let engine = default_engine();
        let mut val = json!("4111 1111 1111 1111");
        engine.redact_value(&mut val);
        let s = val.as_str().unwrap();
        assert!(s.contains("[REDACTED]"), "got: {s}");
    }

    #[test]
    fn invalid_luhn_card_is_not_redacted() {
        let engine = default_engine();
        // 4111111111111112 fails Luhn.
        let mut val = json!("4111111111111112");
        engine.redact_value(&mut val);
        assert_eq!(val, json!("4111111111111112"));
    }

    // ---------------------------------------------------------------
    // US Social Security Numbers
    // ---------------------------------------------------------------

    #[test]
    fn ssn_is_redacted() {
        let engine = default_engine();
        let mut val = json!("SSN: 123-45-6789");
        engine.redact_value(&mut val);
        let s = val.as_str().unwrap();
        assert!(s.contains("[REDACTED]"), "got: {s}");
        assert!(!s.contains("123-45-6789"));
    }

    #[test]
    fn non_ssn_dashes_are_not_redacted() {
        let engine = default_engine();
        let mut val = json!("phone: 555-1234");
        engine.redact_value(&mut val);
        assert_eq!(val, json!("phone: 555-1234"));
    }

    // ---------------------------------------------------------------
    // IPv4 addresses (non-RFC 1918)
    // ---------------------------------------------------------------

    #[test]
    fn public_ipv4_is_redacted() {
        let engine = default_engine();
        let mut val = json!("Connected from 8.8.8.8 on port 443");
        engine.redact_value(&mut val);
        let s = val.as_str().unwrap();
        assert!(s.contains("[REDACTED]"), "got: {s}");
        assert!(!s.contains("8.8.8.8"));
        assert!(s.contains("on port 443"), "surrounding text lost: {s}");
    }

    #[test]
    fn private_10_x_is_not_redacted() {
        let engine = default_engine();
        let mut val = json!("10.0.0.1");
        engine.redact_value(&mut val);
        assert_eq!(val, json!("10.0.0.1"));
    }

    #[test]
    fn private_172_16_is_not_redacted() {
        let engine = default_engine();
        let mut val = json!("172.16.0.1");
        engine.redact_value(&mut val);
        assert_eq!(val, json!("172.16.0.1"));
    }

    #[test]
    fn private_172_31_is_not_redacted() {
        let engine = default_engine();
        let mut val = json!("172.31.255.255");
        engine.redact_value(&mut val);
        assert_eq!(val, json!("172.31.255.255"));
    }

    #[test]
    fn public_172_15_is_redacted() {
        let engine = default_engine();
        let mut val = json!("172.15.255.255");
        engine.redact_value(&mut val);
        let s = val.as_str().unwrap();
        assert!(s.contains("[REDACTED]"), "got: {s}");
    }

    #[test]
    fn public_172_32_is_redacted() {
        let engine = default_engine();
        let mut val = json!("172.32.0.0");
        engine.redact_value(&mut val);
        let s = val.as_str().unwrap();
        assert!(s.contains("[REDACTED]"), "got: {s}");
    }

    #[test]
    fn private_192_168_is_not_redacted() {
        let engine = default_engine();
        let mut val = json!("192.168.1.1");
        engine.redact_value(&mut val);
        assert_eq!(val, json!("192.168.1.1"));
    }

    #[test]
    fn invalid_ipv4_999_is_not_redacted() {
        let engine = default_engine();
        let mut val = json!("999.1.1.1");
        engine.redact_value(&mut val);
        assert_eq!(val, json!("999.1.1.1"));
    }

    // ---------------------------------------------------------------
    // Custom regex patterns
    // ---------------------------------------------------------------

    #[test]
    fn custom_pattern_works() {
        let config = RedactionConfig {
            regex_patterns: vec![r"secret_[a-z]+".to_owned()],
            include_builtin_patterns: false,
            ..RedactionConfig::default()
        };
        let engine = RedactionEngine::new(config).unwrap();
        let mut val = json!("my secret_token is here");
        engine.redact_value(&mut val);
        let s = val.as_str().unwrap();
        assert!(s.contains("[REDACTED]"), "got: {s}");
        assert!(!s.contains("secret_token"));
        assert!(s.contains("my "));
    }

    #[test]
    fn invalid_regex_returns_error() {
        let config = RedactionConfig {
            regex_patterns: vec![r"[invalid".to_owned()],
            include_builtin_patterns: false,
            ..RedactionConfig::default()
        };
        let result = RedactionEngine::new(config);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, RedactError::InvalidPattern { .. }));
    }

    // ---------------------------------------------------------------
    // Custom replacement string
    // ---------------------------------------------------------------

    #[test]
    fn custom_replacement_string() {
        let config = RedactionConfig {
            regex_patterns: vec![r"secret".to_owned()],
            replacement: "***".to_owned(),
            include_builtin_patterns: false,
            ..RedactionConfig::default()
        };
        let engine = RedactionEngine::new(config).unwrap();
        let mut val = json!("the secret is here");
        engine.redact_value(&mut val);
        assert_eq!(val, json!("the *** is here"));
    }

    // ---------------------------------------------------------------
    // JSON pointer redaction
    // ---------------------------------------------------------------

    #[test]
    fn pointer_path_redacts_string_value() {
        let config = RedactionConfig {
            pointer_paths: vec!["/password".to_owned()],
            include_builtin_patterns: false,
            ..RedactionConfig::default()
        };
        let engine = RedactionEngine::new(config).unwrap();
        let mut val = json!({"username": "alice", "password": "hunter2"});
        engine.redact_value(&mut val);
        assert_eq!(val["password"], json!("[REDACTED]"));
        assert_eq!(val["username"], json!("alice"));
    }

    #[test]
    fn pointer_path_redacts_nested_value() {
        let config = RedactionConfig {
            pointer_paths: vec!["/credentials/secret".to_owned()],
            include_builtin_patterns: false,
            ..RedactionConfig::default()
        };
        let engine = RedactionEngine::new(config).unwrap();
        let mut val = json!({"credentials": {"secret": "abc", "id": "xyz"}});
        engine.redact_value(&mut val);
        assert_eq!(val["credentials"]["secret"], json!("[REDACTED]"));
        assert_eq!(val["credentials"]["id"], json!("xyz"));
    }

    #[test]
    fn pointer_path_redacts_non_string_value() {
        let config = RedactionConfig {
            pointer_paths: vec!["/debug_flag".to_owned()],
            include_builtin_patterns: false,
            ..RedactionConfig::default()
        };
        let engine = RedactionEngine::new(config).unwrap();
        let mut val = json!({"debug_flag": true, "name": "test"});
        engine.redact_value(&mut val);
        assert_eq!(val["debug_flag"], json!("[REDACTED]"));
        assert_eq!(val["name"], json!("test"));
    }

    #[test]
    fn invalid_pointer_path_returns_error() {
        let config = RedactionConfig {
            pointer_paths: vec!["no-leading-slash".to_owned()],
            include_builtin_patterns: false,
            ..RedactionConfig::default()
        };
        let result = RedactionEngine::new(config);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RedactError::InvalidPointerPath { .. }
        ));
    }

    #[test]
    fn missing_pointer_path_is_harmless() {
        let config = RedactionConfig {
            pointer_paths: vec!["/nonexistent".to_owned()],
            include_builtin_patterns: false,
            ..RedactionConfig::default()
        };
        let engine = RedactionEngine::new(config).unwrap();
        let mut val = json!({"name": "alice"});
        engine.redact_value(&mut val);
        assert_eq!(val, json!({"name": "alice"}));
    }

    // ---------------------------------------------------------------
    // Idempotency
    // ---------------------------------------------------------------

    #[test]
    fn idempotency_across_all_patterns() {
        let engine = default_engine();
        let fixtures = vec![
            json!("Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123"),
            json!("sk-abc123def456ghi789jk"),
            json!("user@example.com"),
            json!("4111111111111111"),
            json!("123-45-6789"),
            json!("8.8.8.8"),
            json!({"password": "secret", "email": "a@b.com"}),
            json!(["Bearer token123456789012", "10.0.0.1"]),
        ];
        for original in fixtures {
            let mut first = original.clone();
            engine.redact_value(&mut first);
            let mut second = first.clone();
            engine.redact_value(&mut second);
            assert_eq!(first, second, "idempotency failed for {original}");
        }
    }

    #[test]
    fn replacement_string_is_not_re_redacted() {
        let engine = default_engine();
        let mut val = json!("[REDACTED]");
        engine.redact_value(&mut val);
        assert_eq!(val, json!("[REDACTED]"));
    }

    // ---------------------------------------------------------------
    // Recursive JSON walking
    // ---------------------------------------------------------------

    #[test]
    fn nested_objects_are_walked() {
        let engine = default_engine();
        let mut val = json!({
            "outer": {
                "inner": {
                    "deep": "user@example.com"
                }
            }
        });
        engine.redact_value(&mut val);
        let deep = val["outer"]["inner"]["deep"].as_str().unwrap();
        assert!(deep.contains("[REDACTED]"), "got: {deep}");
    }

    #[test]
    fn array_elements_are_walked() {
        let engine = default_engine();
        let mut val = json!([
            "safe text",
            "user@example.com",
            {"key": "123-45-6789"}
        ]);
        engine.redact_value(&mut val);
        assert_eq!(val[0], json!("safe text"));
        let email = val[1].as_str().unwrap();
        assert!(email.contains("[REDACTED]"), "email not redacted: {email}");
        let ssn = val[2]["key"].as_str().unwrap();
        assert!(ssn.contains("[REDACTED]"), "SSN not redacted: {ssn}");
    }

    // ---------------------------------------------------------------
    // Non-string values left alone
    // ---------------------------------------------------------------

    #[test]
    fn numbers_are_not_modified() {
        let engine = default_engine();
        let mut val = json!({"count": 42, "price": 9.99});
        engine.redact_value(&mut val);
        assert_eq!(val["count"], json!(42));
        assert_eq!(val["price"], json!(9.99));
    }

    #[test]
    fn user_integer_cards_are_redacted_without_changing_typed_event_numbers() {
        let engine = default_engine();
        let input = json!({"card": 4_111_111_111_111_111_u64, "count": 42, "price": 9.99});
        let mut event = input.clone();
        engine.redact_value(&mut event);
        assert_eq!(event, input);
        let mut arguments = input;
        engine.redact_user_value(&mut arguments);
        assert_eq!(
            arguments,
            json!({"card": "[REDACTED]", "count": 42, "price": 9.99})
        );
    }

    #[test]
    fn redacted_user_keys_preserve_colliding_values_and_are_idempotent() {
        let engine = default_engine();
        let mut value = json!({"share_with": {
            "alice@example.com": "editor",
            "bob@example.com": ["viewer", "reader"],
            "[REDACTED]": "owner",
            "safe": "kept"
        }});
        engine.redact_user_value(&mut value);
        assert_eq!(
            value,
            json!({"share_with": {
                "[REDACTED]": ["editor", ["viewer", "reader"], "owner"],
                "safe": "kept"
            }})
        );
        let once = value.clone();
        engine.redact_user_value(&mut value);
        assert_eq!(value, once);
    }

    #[test]
    fn booleans_are_not_modified() {
        let engine = default_engine();
        let mut val = json!({"active": true, "deleted": false});
        engine.redact_value(&mut val);
        assert_eq!(val["active"], json!(true));
        assert_eq!(val["deleted"], json!(false));
    }

    #[test]
    fn null_is_not_modified() {
        let engine = default_engine();
        let mut val = json!({"field": null});
        engine.redact_value(&mut val);
        assert!(val["field"].is_null());
    }

    // ---------------------------------------------------------------
    // Empty and whitespace strings
    // ---------------------------------------------------------------

    #[test]
    fn empty_string_is_left_alone() {
        let engine = default_engine();
        let mut val = json!("");
        engine.redact_value(&mut val);
        assert_eq!(val, json!(""));
    }

    #[test]
    fn whitespace_only_string_is_left_alone() {
        let engine = default_engine();
        let mut val = json!("   \t\n  ");
        engine.redact_value(&mut val);
        assert_eq!(val, json!("   \t\n  "));
    }

    // ---------------------------------------------------------------
    // redact_bytes round-trip
    // ---------------------------------------------------------------

    #[test]
    fn redact_bytes_round_trip() {
        let engine = default_engine();
        let input = br#"{"email":"user@example.com","safe":"hello"}"#;
        let output = engine.redact_bytes(input).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&output).unwrap();
        let email = parsed["email"].as_str().unwrap();
        assert!(email.contains("[REDACTED]"), "got: {email}");
        assert_eq!(parsed["safe"], json!("hello"));
    }

    #[test]
    fn redact_bytes_invalid_json_returns_error() {
        let engine = default_engine();
        let result = engine.redact_bytes(b"not json");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RedactError::JsonParse(_)));
    }

    #[test]
    fn redact_bytes_idempotency() {
        let engine = default_engine();
        let input = br#"{"token":"Bearer eyJhbGciOiJIUzI1NiJ9.test1234"}"#;
        let first = engine.redact_bytes(input).unwrap();
        let second = engine.redact_bytes(&first).unwrap();
        assert_eq!(first, second);
    }

    // ---------------------------------------------------------------
    // Negative cases: things that must NOT be redacted
    // ---------------------------------------------------------------

    #[test]
    fn uuid_is_not_redacted() {
        let engine = default_engine();
        let mut val = json!("550e8400-e29b-41d4-a716-446655440000");
        engine.redact_value(&mut val);
        assert_eq!(val, json!("550e8400-e29b-41d4-a716-446655440000"));
    }

    #[test]
    fn iso_date_is_not_redacted() {
        let engine = default_engine();
        let mut val = json!("2024-01-15T10:30:00Z");
        engine.redact_value(&mut val);
        assert_eq!(val, json!("2024-01-15T10:30:00Z"));
    }

    #[test]
    fn plain_text_is_not_redacted() {
        let engine = default_engine();
        let mut val = json!("This is a normal log message with no sensitive data");
        engine.redact_value(&mut val);
        assert_eq!(val, json!("This is a normal log message with no sensitive data"));
    }

    // ---------------------------------------------------------------
    // Construction-time validation
    // ---------------------------------------------------------------

    #[test]
    fn replacement_matching_a_pattern_is_rejected() {
        let config = RedactionConfig {
            regex_patterns: vec![r"REDACTED".to_owned()],
            replacement: "REDACTED".to_owned(),
            include_builtin_patterns: false,
            ..RedactionConfig::default()
        };
        let result = RedactionEngine::new(config);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RedactError::ReplacementMatchesPattern { .. }
        ));
    }

    // ---------------------------------------------------------------
    // Mixed scenario: multiple sensitive values in one payload
    // ---------------------------------------------------------------

    #[test]
    fn mixed_payload_redaction() {
        let engine = default_engine();
        let mut val = json!({
            "event": "login",
            "user_email": "admin@corp.io",
            "source_ip": "203.0.113.5",
            "internal_ip": "10.1.2.3",
            "metadata": {
                "auth_header": "Bearer eyJhbGciOiJIUzI1NiJ9.test1234",
                "timestamp": "2024-01-15T10:30:00Z",
                "count": 42
            },
            "tags": ["production", "us-east"]
        });
        engine.redact_value(&mut val);

        // Email redacted.
        let email = val["user_email"].as_str().unwrap();
        assert!(email.contains("[REDACTED]"), "email not redacted: {email}");

        // Public IP redacted.
        let src_ip = val["source_ip"].as_str().unwrap();
        assert!(src_ip.contains("[REDACTED]"), "public IP not redacted: {src_ip}");

        // Private IP preserved.
        assert_eq!(val["internal_ip"], json!("10.1.2.3"));

        // Bearer token redacted.
        let auth = val["metadata"]["auth_header"].as_str().unwrap();
        assert!(auth.contains("[REDACTED]"), "bearer not redacted: {auth}");

        // Timestamp preserved.
        assert_eq!(val["metadata"]["timestamp"], json!("2024-01-15T10:30:00Z"));

        // Number preserved.
        assert_eq!(val["metadata"]["count"], json!(42));

        // Array strings preserved.
        assert_eq!(val["tags"][0], json!("production"));
    }

    // ---------------------------------------------------------------
    // Card numbers with adjacent digit groups (bug fix coverage)
    // ---------------------------------------------------------------

    #[test]
    fn card_with_trailing_cvv_is_redacted() {
        let engine = default_engine();
        let mut val = json!("4111111111111111 123");
        engine.redact_value(&mut val);
        assert_eq!(val, json!("[REDACTED] 123"));
    }

    #[test]
    fn card_with_trailing_year_is_redacted() {
        let engine = default_engine();
        let mut val = json!("4111 1111 1111 1111 2025");
        engine.redact_value(&mut val);
        assert_eq!(val, json!("[REDACTED] 2025"));
    }

    #[test]
    fn card_with_leading_ref_number() {
        let engine = default_engine();
        let mut val = json!("Ref 1234 4111 1111 1111 1111");
        engine.redact_value(&mut val);
        assert_eq!(val, json!("Ref 1234 [REDACTED]"));
    }

    #[test]
    fn amex_card_in_standard_spacing() {
        let engine = default_engine();
        // 378282246310005 passes Luhn (standard Amex test number).
        let mut val = json!("3782 822463 10005");
        engine.redact_value(&mut val);
        assert_eq!(val, json!("[REDACTED]"));
    }

    #[test]
    fn card_extraction_prefers_the_longest_valid_window() {
        let engine = default_engine();
        // Both 15 and 18 zero digits pass Luhn. All 18 must be removed.
        let mut value = json!("000 000 000 000 000 000");
        engine.redact_value(&mut value);
        assert_eq!(value, json!("[REDACTED]"));
    }

    #[test]
    fn long_digit_group_runs_complete_with_bounded_work() {
        let engine = default_engine();
        // Neither five nor six groups of 100 pass Luhn, so every start
        // position is visited. The former cubic scan cannot finish this run.
        let input = "100 ".repeat(100_000);
        let mut value = json!(input);
        let started = std::time::Instant::now();
        engine.redact_value(&mut value);
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        assert_eq!(value, json!(input));
    }

    // ---------------------------------------------------------------
    // Idempotency with adjacent sensitive data (word-boundary bug fix)
    // ---------------------------------------------------------------

    #[test]
    fn adjacent_email_and_ssn_idempotency() {
        let engine = default_engine();
        let mut val = json!("user@example.com123-45-6789");
        engine.redact_value(&mut val);
        // After full redaction, both should be gone.
        let s = val.as_str().unwrap();
        assert!(!s.contains("user@"), "email leaked: {s}");
        assert!(!s.contains("123-45-6789"), "SSN leaked: {s}");
        // Verify idempotency.
        let mut second = val.clone();
        engine.redact_value(&mut second);
        assert_eq!(val, second, "idempotency failed for adjacent email+SSN");
    }

    // ---------------------------------------------------------------
    // Case-insensitive Bearer
    // ---------------------------------------------------------------

    #[test]
    fn lowercase_bearer_is_redacted() {
        let engine = default_engine();
        let mut val = json!("bearer eyJhbGciOiJIUzI1NiJ9.test1234");
        engine.redact_value(&mut val);
        assert_eq!(val, json!("[REDACTED]"));
    }

    #[test]
    fn mixed_case_bearer_is_redacted() {
        let engine = default_engine();
        let mut val = json!("BEARER eyJhbGciOiJIUzI1NiJ9.test1234");
        engine.redact_value(&mut val);
        assert_eq!(val, json!("[REDACTED]"));
    }

    // ---------------------------------------------------------------
    // Exact-output assertions for core patterns
    // ---------------------------------------------------------------

    #[test]
    fn bearer_exact_output() {
        let engine = default_engine();
        let mut val = json!("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123");
        engine.redact_value(&mut val);
        assert_eq!(val, json!("Authorization: [REDACTED]"));
    }

    #[test]
    fn email_exact_output() {
        let engine = default_engine();
        let mut val = json!("Contact alice@example.org for help");
        engine.redact_value(&mut val);
        assert_eq!(val, json!("Contact [REDACTED] for help"));
    }

    #[test]
    fn ssn_exact_output() {
        let engine = default_engine();
        let mut val = json!("SSN: 123-45-6789");
        engine.redact_value(&mut val);
        assert_eq!(val, json!("SSN: [REDACTED]"));
    }

    #[test]
    fn public_ipv4_exact_output() {
        let engine = default_engine();
        let mut val = json!("Connected from 8.8.8.8 on port 443");
        engine.redact_value(&mut val);
        assert_eq!(val, json!("Connected from [REDACTED] on port 443"));
    }
}
