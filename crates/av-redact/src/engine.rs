//! Core redaction engine: pattern matching, JSON-tree walking, pointer-path redaction.

use regex::Regex;
use serde_json::Value;
use std::net::Ipv4Addr;

/// Maximum number of redaction passes per string. Replacing a span can
/// expose new word boundaries that enable additional matches, so the engine
/// loops until no new spans are found. This cap prevents runaway looping
/// from pathological custom patterns.
const MAX_REDACTION_PASSES: usize = 8;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by the redaction engine.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RedactError {
    /// A regex pattern string failed to compile.
    #[error("invalid regex pattern {pattern:?}: {source}")]
    InvalidPattern {
        /// The raw pattern string that failed.
        pattern: String,
        /// The underlying regex compilation error.
        source: regex::Error,
    },
    /// A JSON pointer path is malformed (non-empty but does not start with `/`).
    #[error("invalid JSON pointer path {path:?}: must be empty or start with '/'")]
    InvalidPointerPath {
        /// The offending path.
        path: String,
    },
    /// The replacement string itself matches one of the configured patterns,
    /// which would break the idempotency guarantee.
    #[error("replacement string {replacement:?} matches a configured pattern")]
    ReplacementMatchesPattern {
        /// The replacement string.
        replacement: String,
    },
    /// The input bytes are not valid JSON.
    #[error("failed to parse JSON: {0}")]
    JsonParse(#[from] serde_json::Error),
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for constructing a [`RedactionEngine`].
///
/// Call [`RedactionEngine::new`] to compile the patterns and build a
/// thread-safe engine instance.
#[derive(Debug, Clone)]
pub struct RedactionConfig {
    /// Raw regex pattern strings. Each is compiled once at engine construction.
    pub regex_patterns: Vec<String>,
    /// JSON pointer paths (RFC 6901) whose values are always replaced
    /// regardless of content (e.g. `"/password"`, `"/credentials/secret"`).
    pub pointer_paths: Vec<String>,
    /// The string that replaces every redacted value. Defaults to `"[REDACTED]"`.
    pub replacement: String,
    /// When `true`, the engine includes built-in patterns for common sensitive
    /// data: Bearer tokens, `sk-*`/`key-*` API keys, email addresses, credit
    /// card numbers (Luhn-validated), US Social Security numbers, and public
    /// (non-RFC 1918) IPv4 addresses.
    pub include_builtin_patterns: bool,
}

impl Default for RedactionConfig {
    fn default() -> Self {
        Self {
            regex_patterns: Vec::new(),
            pointer_paths: Vec::new(),
            replacement: "[REDACTED]".to_owned(),
            include_builtin_patterns: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Redaction rule: a compiled regex plus an optional span extractor
// ---------------------------------------------------------------------------

/// A function that receives the full regex match text and returns a list of
/// `(start, end)` byte offsets *relative to the match start* that should
/// actually be redacted. Returning an empty list means the match should be
/// skipped entirely.
type SpanExtractorFn = fn(&str) -> Vec<(usize, usize)>;

/// A single redaction rule: a compiled regex paired with an optional span
/// extractor that can return sub-spans of the matched region.
///
/// Using plain `fn` pointers (not closures) keeps the engine `Send + Sync`.
struct RedactionRule {
    pattern: Regex,
    /// When `Some`, the extractor function inspects each match and decides
    /// which sub-spans to redact. Used for Luhn validation on credit card
    /// candidates (which may need to select a sub-window) and for RFC 1918
    /// filtering on IPv4 addresses.
    span_extractor: Option<SpanExtractorFn>,
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// A thread-safe, reusable sensitive-data redaction engine.
///
/// All regex compilation happens at construction time inside
/// [`RedactionEngine::new`]. The resulting engine is `Send + Sync` and can
/// be shared across async worker tasks.
///
/// # Redaction semantics
///
/// For each JSON string value the engine performs *span-level* replacement:
/// every non-overlapping match of any rule inside the string is replaced with
/// the configured replacement text, while surrounding text is preserved. This
/// keeps audit context intact (e.g. `"Connection from 8.8.8.8 accepted"`
/// becomes `"Connection from [REDACTED] accepted"` rather than losing the
/// entire message).
///
/// Because replacing a span can create new word boundaries that expose
/// additional matches, the engine loops until no new spans are found (up
/// to a bounded cap). The built-in patterns settle within a few passes.
///
/// JSON pointer paths are applied first and replace the entire subtree at
/// that path with the replacement string, regardless of its type.
pub struct RedactionEngine {
    rules: Vec<RedactionRule>,
    pointer_paths: Vec<String>,
    replacement: String,
}

impl std::fmt::Debug for RedactionEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedactionEngine")
            .field("rules_count", &self.rules.len())
            .field("pointer_paths", &self.pointer_paths)
            .field("replacement", &self.replacement)
            .finish()
    }
}

impl RedactionEngine {
    /// Build a new engine from the given configuration.
    ///
    /// Returns an error if any regex pattern fails to compile, any JSON
    /// pointer path is malformed, or the replacement string would itself be
    /// matched by a configured rule (which would break idempotency).
    pub fn new(config: RedactionConfig) -> Result<Self, RedactError> {
        let mut rules = Vec::new();

        // Built-in rules ------------------------------------------------
        if config.include_builtin_patterns {
            rules.extend(builtin_rules()?);
        }

        // User-supplied regex patterns -----------------------------------
        for raw in &config.regex_patterns {
            let compiled = Regex::new(raw).map_err(|source| RedactError::InvalidPattern {
                pattern: raw.clone(),
                source,
            })?;
            rules.push(RedactionRule {
                pattern: compiled,
                span_extractor: None,
            });
        }

        // Validate pointer paths -----------------------------------------
        for path in &config.pointer_paths {
            if !path.is_empty() && !path.starts_with('/') {
                return Err(RedactError::InvalidPointerPath { path: path.clone() });
            }
        }

        // Verify that the replacement string does not match any rule -----
        let replacement = &config.replacement;
        if !collect_spans(&rules, replacement).is_empty() {
            return Err(RedactError::ReplacementMatchesPattern {
                replacement: replacement.clone(),
            });
        }

        Ok(Self {
            rules,
            pointer_paths: config.pointer_paths,
            replacement: config.replacement,
        })
    }

    /// Redact a mutable JSON value in place.
    ///
    /// 1. Values at configured JSON pointer paths are replaced first.
    /// 2. The entire tree is then walked (iteratively, to avoid stack
    ///    overflow on deeply nested input). Each string value is scanned
    ///    against all compiled rules: matching spans are replaced with the
    ///    configured replacement text.
    /// 3. Non-string leaves (numbers, booleans, null) are never modified.
    /// 4. The operation is idempotent: calling it again on already-redacted
    ///    output produces the same value, provided custom patterns settle
    ///    within the internal pass limit.
    pub fn redact_value(&self, value: &mut Value) {
        self.redact_tree(value, false);
    }

    /// Redact arbitrary user data, including integer values and object keys.
    ///
    /// Unlike [`Self::redact_value`], this can change numeric leaves into
    /// strings. Use it for tool arguments, not typed event accounting fields.
    /// When multiple keys redact to the same name, their values are collected
    /// into an array in input order so no value is silently overwritten.
    /// Floating-point values retain their type because parsing may already
    /// have rounded their original digits.
    pub fn redact_user_value(&self, value: &mut Value) {
        self.redact_tree(value, true);
    }

    fn redact_tree(&self, value: &mut Value, scan_numbers_and_keys: bool) {
        // Phase 1: pointer-path redaction (whole subtrees).
        for path in &self.pointer_paths {
            if let Some(target) = value.pointer_mut(path) {
                *target = Value::String(self.replacement.clone());
            }
        }

        // Phase 2: iterative tree walk for pattern-based redaction.
        let mut stack: Vec<&mut Value> = vec![value];
        while let Some(node) = stack.pop() {
            match node {
                Value::String(s) => {
                    self.redact_string(s);
                }
                Value::Number(number) if scan_numbers_and_keys => {
                    if number.is_i64() || number.is_u64() {
                        let mut text = number.to_string();
                        let original = text.clone();
                        self.redact_string(&mut text);
                        if text != original {
                            *node = Value::String(self.replacement.clone());
                        }
                    }
                }
                Value::Array(arr) => {
                    for item in arr.iter_mut() {
                        stack.push(item);
                    }
                }
                Value::Object(map) => {
                    if scan_numbers_and_keys {
                        let mut entries = serde_json::Map::new();
                        let mut collisions = std::collections::HashSet::new();
                        for (mut key, value) in std::mem::take(map) {
                            self.redact_string(&mut key);
                            if let Some(existing) = entries.get_mut(&key) {
                                if collisions.insert(key.clone()) {
                                    *existing = Value::Array(vec![existing.take(), value]);
                                } else if let Value::Array(values) = existing {
                                    values.push(value);
                                }
                            } else {
                                entries.insert(key, value);
                            }
                        }
                        *map = entries;
                    }
                    for (_key, val) in map.iter_mut() {
                        stack.push(val);
                    }
                }
                // Numbers, booleans, null — leave untouched.
                _ => {}
            }
        }
    }

    /// Parse raw JSON bytes, redact, and re-serialize.
    ///
    /// Returns the redacted JSON as UTF-8 bytes, or an error if the input
    /// is not valid JSON.
    pub fn redact_bytes(&self, raw: &[u8]) -> Result<Vec<u8>, RedactError> {
        let mut value: Value = serde_json::from_slice(raw)?;
        self.redact_value(&mut value);
        let output = serde_json::to_vec(&value)?;
        Ok(output)
    }

    /// Perform span-level redaction on a single string.
    ///
    /// Loops until no new spans are found, because replacing a span can
    /// create new word boundaries that let additional patterns match.
    /// The loop is capped at [`MAX_REDACTION_PASSES`].
    fn redact_string(&self, s: &mut String) {
        // Skip strings that are exactly the replacement (idempotency fast path).
        if *s == self.replacement {
            return;
        }

        // Skip empty and whitespace-only strings.
        if s.is_empty() || s.chars().all(char::is_whitespace) {
            return;
        }

        for _ in 0..MAX_REDACTION_PASSES {
            let spans = collect_spans(&self.rules, s);
            if spans.is_empty() {
                return;
            }

            let merged = merge_spans(&spans);
            let original = s.as_str();
            let mut result = String::with_capacity(s.len());
            let mut cursor = 0;
            for (start, end) in &merged {
                result.push_str(original.get(cursor..*start).unwrap_or_default());
                result.push_str(&self.replacement);
                cursor = *end;
            }
            result.push_str(original.get(cursor..).unwrap_or_default());
            *s = result;
        }
    }
}

// ---------------------------------------------------------------------------
// Span collection
// ---------------------------------------------------------------------------

/// Collect all redaction spans in `text` across all rules.
///
/// Returns a sorted, merged list of `(start, end)` byte offsets.
fn collect_spans(rules: &[RedactionRule], text: &str) -> Vec<(usize, usize)> {
    let mut spans: Vec<(usize, usize)> = Vec::new();
    for rule in rules {
        for m in rule.pattern.find_iter(text) {
            let match_start = m.start();
            let matched = text.get(m.start()..m.end()).unwrap_or_default();
            match &rule.span_extractor {
                None => {
                    spans.push((m.start(), m.end()));
                }
                Some(extract) => {
                    for (sub_start, sub_end) in extract(matched) {
                        spans.push((match_start + sub_start, match_start + sub_end));
                    }
                }
            }
        }
    }
    spans.sort_unstable();
    spans
}

// ---------------------------------------------------------------------------
// Span merging
// ---------------------------------------------------------------------------

/// Merge a sorted list of `(start, end)` byte spans into non-overlapping spans.
fn merge_spans(sorted: &[(usize, usize)]) -> Vec<(usize, usize)> {
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(sorted.len());
    for &(start, end) in sorted {
        if let Some(last) = merged.last_mut() {
            if start <= last.1 {
                // Overlapping or adjacent — extend.
                if end > last.1 {
                    last.1 = end;
                }
                continue;
            }
        }
        merged.push((start, end));
    }
    merged
}

// ---------------------------------------------------------------------------
// Built-in rules
// ---------------------------------------------------------------------------

/// Construct the built-in redaction rules.
///
/// Patterns use `[0-9]` instead of `\d` because the regex crate's `\d`
/// matches Unicode digits, which would cause validators (Luhn, IP parsing)
/// that work on ASCII digits to produce incorrect results.
fn builtin_rules() -> Result<Vec<RedactionRule>, RedactError> {
    let compile = |pattern: &str| -> Result<Regex, RedactError> {
        Regex::new(pattern).map_err(|source| RedactError::InvalidPattern {
            pattern: pattern.to_owned(),
            source,
        })
    };

    Ok(vec![
        // Bearer tokens (case-insensitive): "Bearer " followed by a typical
        // token body. The 8-character minimum avoids "Bearer of bad news".
        RedactionRule {
            pattern: compile(r"(?i:bearer)\s+[A-Za-z0-9._~+/=-]{8,}")?,
            span_extractor: None,
        },
        // API keys: sk-* or key-* with a sufficiently long URL-safe tail
        // to avoid false positives on natural words like "key-value".
        RedactionRule {
            pattern: compile(r"(?-u:\b)(?:sk|key)-[A-Za-z0-9_-]{16,}")?,
            span_extractor: None,
        },
        // Email addresses (simplified RFC 5321).
        RedactionRule {
            pattern: compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")?,
            span_extractor: None,
        },
        // Credit card candidates: runs of digit groups separated by spaces
        // or dashes. The span extractor finds Luhn-valid windows inside the
        // run, which handles cases where adjacent digit groups (CVV, year)
        // get captured by the greedy match.
        RedactionRule {
            pattern: compile(r"(?-u:\b)[0-9]{3,19}(?:[- ][0-9]{3,19})*(?-u:\b)")?,
            span_extractor: Some(card_span_extractor),
        },
        // US Social Security Numbers: NNN-NN-NNNN.
        RedactionRule {
            pattern: compile(r"(?-u:\b)[0-9]{3}-[0-9]{2}-[0-9]{4}(?-u:\b)")?,
            span_extractor: None,
        },
        // IPv4 addresses. Only non-private (non-RFC 1918) addresses are redacted.
        RedactionRule {
            pattern: compile(r"(?-u:\b)(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?-u:\b)")?,
            span_extractor: Some(ipv4_span_extractor),
        },
    ])
}

// ---------------------------------------------------------------------------
// Card number span extraction
// ---------------------------------------------------------------------------

/// A digit group parsed from a card candidate: byte offset and digit count.
struct DigitGroup {
    /// Byte offset of this group's first character within the matched text.
    start: usize,
    /// Byte offset one past this group's last character.
    end: usize,
    /// Number of ASCII digits in this group.
    digit_count: usize,
}

/// Extract the sub-spans of a card candidate that are Luhn-valid numbers
/// with 13 to 19 digits. Scans windows of consecutive groups from left to
/// right, trying the longest window first.
fn card_span_extractor(matched: &str) -> Vec<(usize, usize)> {
    let groups = parse_digit_groups(matched);
    if groups.is_empty() {
        return Vec::new();
    }

    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut i = 0;
    while i < groups.len() {
        let mut found = false;
        // A card can contain at most 19 digits. Find the longest candidate
        // using a running sum, then try shorter windows. This does bounded
        // work per start group, even for an entire document of digit groups.
        let mut j = i;
        let mut total_digits = 0;
        while let Some(group) = groups.get(j) {
            if total_digits + group.digit_count > 19 {
                break;
            }
            total_digits += group.digit_count;
            j += 1;
        }
        while j > i {
            let Some(window) = groups.get(i..j) else {
                j -= 1;
                continue;
            };
            if (13..=19).contains(&total_digits) {
                let Some(first) = window.first() else {
                    j -= 1;
                    continue;
                };
                let Some(last) = window.last() else {
                    j -= 1;
                    continue;
                };
                // Collect all digits from the window.
                let digits: Vec<u32> = matched
                    .get(first.start..last.end)
                    .unwrap_or_default()
                    .chars()
                    .filter(|c| c.is_ascii_digit())
                    .filter_map(|c| c.to_digit(10))
                    .collect();
                if passes_luhn(&digits) {
                    spans.push((first.start, last.end));
                    i = j; // skip past this window
                    found = true;
                    break;
                }
            }
            if let Some(last) = window.last() {
                total_digits -= last.digit_count;
            }
            j -= 1;
        }
        if !found {
            i += 1;
        }
    }
    spans
}

/// Parse a matched string into its constituent digit groups.
fn parse_digit_groups(s: &str) -> Vec<DigitGroup> {
    let mut groups = Vec::new();
    let mut group_start: Option<usize> = None;
    let mut digit_count = 0;
    for (i, c) in s.char_indices() {
        if c.is_ascii_digit() {
            if group_start.is_none() {
                group_start = Some(i);
                digit_count = 0;
            }
            digit_count += 1;
        } else if let Some(gs) = group_start.take() {
            groups.push(DigitGroup {
                start: gs,
                end: i,
                digit_count,
            });
        }
    }
    // Handle the final group.
    if let Some(gs) = group_start {
        groups.push(DigitGroup {
            start: gs,
            end: s.len(),
            digit_count,
        });
    }
    groups
}

/// Standard Luhn check on a pre-extracted digit sequence.
fn passes_luhn(digits: &[u32]) -> bool {
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    let mut sum: u32 = 0;
    for (i, &d) in digits.iter().rev().enumerate() {
        if i % 2 == 1 {
            let doubled = d * 2;
            sum += if doubled > 9 { doubled - 9 } else { doubled };
        } else {
            sum += d;
        }
    }
    sum.is_multiple_of(10)
}

// ---------------------------------------------------------------------------
// IPv4 span extraction
// ---------------------------------------------------------------------------

/// Returns the full match as a span if the IPv4 address is not private
/// (RFC 1918), or an empty list if it should be left alone.
fn ipv4_span_extractor(matched: &str) -> Vec<(usize, usize)> {
    let Ok(ip) = matched.parse::<Ipv4Addr>() else {
        return Vec::new();
    };
    if ip.is_private() {
        Vec::new()
    } else {
        vec![(0, matched.len())]
    }
}
