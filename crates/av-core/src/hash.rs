//! Non-cryptographic hash helpers.
//!
//! For SHA-256 and other cryptographic digests use [`crate::digest`].

/// FNV-1a 64-bit hash of `bytes`.
///
/// Deterministic across processes and platforms; used for partition
/// assignment (`av-bridge`) and hashed embeddings (`av-loopdetect`).
/// A single implementation prevents silent drift between producers and
/// consumers of the same hash.
pub fn fnv1a(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = OFFSET;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(PRIME);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reference vectors from http://www.isthe.com/chongo/tech/comp/fnv/#FNV-test-vectors
    #[test]
    fn empty_matches_offset_basis() {
        assert_eq!(fnv1a(b""), 0xcbf2_9ce4_8422_2325);
    }

    #[test]
    fn known_vector_a() {
        assert_eq!(fnv1a(b"a"), 0xaf63_dc4c_8601_ec8c);
    }

    #[test]
    fn known_vector_foobar() {
        assert_eq!(fnv1a(b"foobar"), 0x8594_4171_f739_67e8);
    }
}
