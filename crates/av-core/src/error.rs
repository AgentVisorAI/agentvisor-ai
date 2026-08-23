//! Core error type shared across AgentVisor AI crates.

/// Errors produced by core primitives.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CoreError {
    /// A numeric value exceeded the 2^53 safe-integer bound required for
    /// RFC 8785 (JCS) canonicalization (IEEE-754 double mantissa limit).
    #[error("integer {0} exceeds the 2^53 JCS-safe bound")]
    UnsafeInteger(u64),
    /// A counter or arithmetic operation would overflow.
    #[error("arithmetic overflow in {context}")]
    Overflow {
        /// Human-readable operation description.
        context: &'static str,
    },
    /// An identifier failed to parse.
    #[error("invalid identifier: {0}")]
    InvalidId(String),
}

/// Largest integer exactly representable as an IEEE-754 double (2^53).
///
/// JCS (RFC 8785) serializes all numbers as doubles; integers above this bound
/// would silently lose precision, corrupting canonical hashes.
pub const JCS_SAFE_MAX: u64 = 1 << 53;

/// Validate that `n` is exactly representable in a JCS number.
pub fn check_jcs_safe(n: u64) -> Result<u64, CoreError> {
    if n > JCS_SAFE_MAX {
        Err(CoreError::UnsafeInteger(n))
    } else {
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jcs_bound_accepts_max() {
        assert!(check_jcs_safe(JCS_SAFE_MAX).is_ok());
        assert!(check_jcs_safe(0).is_ok());
    }

    #[test]
    fn jcs_bound_rejects_above_max() {
        assert!(check_jcs_safe(JCS_SAFE_MAX + 1).is_err());
        assert!(check_jcs_safe(u64::MAX).is_err());
    }
}

#[cfg(test)]
mod const_tests {
    /// Mutation-run hardening: `1 << 53` -> `1 >> 53` would
    /// silently turn every overflow guard in the workspace into
    /// "reject everything above 0". Pin the exact value.
    #[test]
    fn jcs_safe_max_is_two_to_the_53rd() {
        assert_eq!(super::JCS_SAFE_MAX, 9_007_199_254_740_992);
        assert_eq!(super::JCS_SAFE_MAX, 2u64.pow(53));
    }
}
