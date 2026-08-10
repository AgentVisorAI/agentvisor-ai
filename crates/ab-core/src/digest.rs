//! SHA-256 digest helpers used by receipts, chains, and audit stubs.

use sha2::{Digest, Sha256};

/// SHA-256 of `data`, hex-encoded (lowercase, 64 chars).
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// SHA-256 over the concatenation of `parts` (no separator — callers must
/// ensure unambiguous framing, e.g. fixed-width prefix or hash-of-hash).
pub fn sha256_concat_hex(parts: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vector_empty() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn known_vector_abc() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn concat_equals_joined() {
        assert_eq!(sha256_concat_hex(&[b"ab", b"c"]), sha256_hex(b"abc"));
    }
}
