//! Unicode text guards: block characters that let hostile input spoof how
//! logs, receipts, and identifiers look on a terminal.
//!
//! The dangerous set here is the "Trojan Source" family — bidirectional
//! overrides and zero-width formatting characters — that render invisibly (or
//! reverse the visible order of surrounding text) while remaining part of the
//! string's bytes. When those characters ride along in a JWT identity claim
//! or a tool name, an operator investigating an audit chain sees one thing
//! while the on-wire bytes say another.

/// Code points that visually reorder or hide surrounding text.
///
/// Includes the bidirectional formatting/override/isolate family (U+202A..E,
/// U+2066..9), the LTR/RTL/Arabic marks (U+061C, U+200E..F), the zero-width
/// glyphs (U+200B..D, U+2060, U+FEFF), the invisible operators (U+2061..4),
/// the deprecated shaping controls (U+206A..F), the soft hyphen, the
/// Mongolian vowel separator, and the line/paragraph separators (which
/// inject fake line breaks into log views). Kept as a small hand-curated
/// set so this stays a std-only helper — a full Unicode-Cf gate
/// would need an extra crate for a benefit no legitimate identifier needs.
const DANGEROUS_CODEPOINTS: &[char] = &[
    '\u{00AD}', // SOFT HYPHEN (renders invisibly outside line breaks)
    '\u{061C}', // ARABIC LETTER MARK
    '\u{180E}', // MONGOLIAN VOWEL SEPARATOR (invisible, Cf in older Unicode)
    '\u{200B}', // ZERO WIDTH SPACE
    '\u{200C}', // ZERO WIDTH NON-JOINER
    '\u{200D}', // ZERO WIDTH JOINER
    '\u{200E}', // LEFT-TO-RIGHT MARK
    '\u{200F}', // RIGHT-TO-LEFT MARK
    '\u{2028}', // LINE SEPARATOR (injects fake line breaks into log views)
    '\u{2029}', // PARAGRAPH SEPARATOR
    '\u{202A}', // LEFT-TO-RIGHT EMBEDDING
    '\u{202B}', // RIGHT-TO-LEFT EMBEDDING
    '\u{202C}', // POP DIRECTIONAL FORMATTING
    '\u{202D}', // LEFT-TO-RIGHT OVERRIDE
    '\u{202E}', // RIGHT-TO-LEFT OVERRIDE (the classic "reverse the string" glyph)
    '\u{2060}', // WORD JOINER
    '\u{2061}', // FUNCTION APPLICATION (invisible operator)
    '\u{2062}', // INVISIBLE TIMES
    '\u{2063}', // INVISIBLE SEPARATOR
    '\u{2064}', // INVISIBLE PLUS
    '\u{2066}', // LEFT-TO-RIGHT ISOLATE
    '\u{2067}', // RIGHT-TO-LEFT ISOLATE
    '\u{2068}', // FIRST STRONG ISOLATE
    '\u{2069}', // POP DIRECTIONAL ISOLATE
    '\u{206A}', // INHIBIT SYMMETRIC SWAPPING (deprecated format control)
    '\u{206B}', // ACTIVATE SYMMETRIC SWAPPING
    '\u{206C}', // INHIBIT ARABIC FORM SHAPING
    '\u{206D}', // ACTIVATE ARABIC FORM SHAPING
    '\u{206E}', // NATIONAL DIGIT SHAPES
    '\u{206F}', // NOMINAL DIGIT SHAPES
    '\u{FEFF}', // ZERO WIDTH NO-BREAK SPACE / BOM
];

/// True if `s` carries any character that visually reorders or hides
/// surrounding text (Trojan-Source-class spoofing).
pub fn contains_bidi_or_zero_width(s: &str) -> bool {
    s.chars().any(|c| DANGEROUS_CODEPOINTS.contains(&c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_ascii_and_common_utf8_pass() {
        for s in ["", "hello", "agent:test", "réseau", "支付", "abc\u{1F600}xyz"] {
            assert!(!contains_bidi_or_zero_width(s), "wrong reject: {s:?}");
        }
    }

    /// Every dangerous code point flags whether it appears alone, at the
    /// start, in the middle, at the end, or inside legitimate UTF-8.
    #[test]
    fn every_dangerous_code_point_is_detected_in_every_position() {
        for &c in DANGEROUS_CODEPOINTS {
            for position in [
                format!("{c}"),
                format!("{c}legit"),
                format!("le{c}git"),
                format!("legit{c}"),
                format!("réseau{c}pay"),
            ] {
                assert!(
                    contains_bidi_or_zero_width(&position),
                    "missed U+{:04X} in {position:?}",
                    c as u32,
                );
            }
        }
    }

    /// The infamous Trojan Source RLO attack: `admin\u{202E}nimda` looks
    /// like two admin fields on a terminal but is one hostile identifier.
    #[test]
    fn trojan_source_admin_swap_is_detected() {
        let hostile = "admin\u{202E}nimda";
        assert!(contains_bidi_or_zero_width(hostile));
        // Sanity: the raw bytes and the visible glyphs disagree — the whole
        // point of the attack, and the whole point of blocking the guard.
        assert_ne!(hostile.len(), "adminnimda".len());
    }
}
