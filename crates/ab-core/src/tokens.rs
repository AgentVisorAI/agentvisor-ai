//! Deterministic approximate tokenizer.
//!
//! Used for budgets, token-velocity tracking, and compression ratios. This is
//! an *approximation* (documented, deliberate): exact counts differ per
//! provider/model and arrive with responses; we record those separately when
//! present. Properties guaranteed (and property-tested):
//!
//! - deterministic;
//! - monotone: appending text never lowers the count;
//! - Unicode-safe (multi-byte chars never split or panic);
//! - zero for the empty string.
//!
//! Heuristic: ASCII words contribute `ceil(len/4)` tokens (the ~4 chars/token
//! BPE rule of thumb), each punctuation/symbol char is one token, and each CJK
//! or other non-ASCII alphabetic char is one token.

/// Approximate token count for `text`.
pub fn approx_tokens(text: &str) -> u64 {
    let mut tokens: u64 = 0;
    let mut ascii_run: u64 = 0;
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() {
            ascii_run += 1;
        } else {
            tokens += ascii_run.div_ceil(4);
            ascii_run = 0;
            if ch.is_whitespace() {
                continue;
            }
            // Punctuation, symbols, CJK, emoji: one token each.
            tokens += 1;
        }
    }
    tokens + ascii_run.div_ceil(4)
}

/// Approximate token count for a serialized JSON value.
pub fn approx_tokens_json(value: &serde_json::Value) -> u64 {
    match serde_json::to_string(value) {
        Ok(s) => approx_tokens(&s),
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn empty_is_zero() {
        assert_eq!(approx_tokens(""), 0);
    }

    #[test]
    fn simple_words() {
        // "hello world" => hello(2) + world(2)
        assert_eq!(approx_tokens("hello world"), 4);
    }

    #[test]
    fn punctuation_counts() {
        assert_eq!(approx_tokens("a,b"), 3); // a(1) , (1) b(1)
    }

    #[test]
    fn cjk_one_per_char() {
        assert_eq!(approx_tokens("日本語"), 3);
    }

    #[test]
    fn emoji_do_not_panic() {
        assert!(approx_tokens("🎉🎉🎉") >= 3);
    }

    proptest! {
        #[test]
        fn monotone_under_append(a in ".{0,200}", b in ".{0,200}") {
            let joined = format!("{a}{b}");
            prop_assert!(approx_tokens(&joined) >= approx_tokens(&a));
        }

        #[test]
        fn never_panics(s in "\\PC{0,500}") {
            let _ = approx_tokens(&s);
        }

        #[test]
        fn nonempty_ascii_word_is_positive(s in "[a-zA-Z0-9]{1,100}") {
            prop_assert!(approx_tokens(&s) > 0);
        }
    }
}
