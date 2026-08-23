//! Embedding abstraction + the deterministic feature-hashing default.

/// Text → fixed-dim L2-normalized vector.
pub trait Embedder: Send + Sync {
    /// Embedding dimensionality.
    fn dim(&self) -> usize;
    /// Embed `text`. Must return an L2-normalized vector of length `dim()`
    /// (the zero vector is allowed for empty/degenerate input).
    fn embed(&self, text: &str) -> Vec<f32>;
    /// Fallible embedding path used by production workers. Deterministic
    /// embedders use the infallible default implementation.
    fn try_embed(&self, text: &str) -> Result<Vec<f32>, String> {
        Ok(self.embed(text))
    }
}

/// Character-n-gram feature-hashing embedder.
///
/// Deterministic, dependency-free, CPU-cheap (~µs per step). N-grams (3..=5)
/// of the lowercased, whitespace-collapsed text are FNV-hashed into `dim`
/// buckets with a signed hash trick, then L2-normalized. Near-duplicate
/// paraphrases share most n-grams → cosine ≈ 1; genuinely progressing content
/// (new entities, numbers, code) diverges.
#[derive(Debug, Clone)]
pub struct HashEmbedder {
    dim: usize,
}

impl Default for HashEmbedder {
    fn default() -> Self {
        Self { dim: 512 }
    }
}

impl HashEmbedder {
    /// Create with an explicit dimension (≥ 64 recommended).
    pub fn new(dim: usize) -> Self {
        Self { dim: dim.max(8) }
    }
}

impl Embedder for HashEmbedder {
    fn dim(&self) -> usize {
        self.dim
    }

    fn embed(&self, text: &str) -> Vec<f32> {
        let mut v = vec![0.0f32; self.dim];
        // Normalize: lowercase, collapse whitespace runs.
        let normalized: String = {
            let mut out = String::with_capacity(text.len());
            let mut last_ws = false;
            for ch in text.chars() {
                if ch.is_whitespace() {
                    if !last_ws && !out.is_empty() {
                        out.push(' ');
                    }
                    last_ws = true;
                } else {
                    for lower in ch.to_lowercase() {
                        out.push(lower);
                    }
                    last_ws = false;
                }
            }
            // The loop pushes the collapsed separator eagerly, so a
            // trailing whitespace run leaves a dangling ' ' — making
            // embed("abc") != embed("abc ") and breaking the documented
            // whitespace-collapse invariance (a large delta for short
            // steps). Trim it so trailing runs collapse to nothing,
            // symmetric with the leading-run suppression above.
            if out.ends_with(' ') {
                out.pop();
            }
            out
        };
        let chars: Vec<char> = normalized.chars().collect();
        if chars.is_empty() {
            return v;
        }
        let mut buf = String::with_capacity(8);
        for n in 3..=5usize {
            if chars.len() < n {
                // Short text: hash the whole string once per n to keep signal.
                buf.clear();
                buf.extend(chars.iter());
                bump(&mut v, &buf, self.dim);
                continue;
            }
            for w in chars.windows(n) {
                buf.clear();
                buf.extend(w.iter());
                bump(&mut v, &buf, self.dim);
            }
        }
        // L2 normalize.
        let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.0 {
            for x in &mut v {
                *x /= norm;
            }
        }
        v
    }
}

fn bump(v: &mut [f32], gram: &str, dim: usize) {
    let h = av_core::hash::fnv1a(gram.as_bytes());
    #[allow(clippy::cast_possible_truncation)]
    let idx = (h % dim as u64) as usize;
    let sign = if (h >> 63) == 0 { 1.0 } else { -1.0 };
    if let Some(slot) = v.get_mut(idx) {
        *slot += sign;
    }
}

/// Cosine similarity of two equal-length vectors (0 when either is zero).
///
/// Accumulates in f64: an f32 sum-of-squares underflows to exactly 0.0
/// for vectors of tiny finite components (all ≲ 5e-23), which made
/// `cosine(v, v)` return 0 for such vectors — maximum "novelty" for a
/// byte-identical repeat, defeating the loop breaker whenever a
/// degenerate embedder emitted tiny activations. The breaker's hostile-
/// embedding gate only catches exact zeros and non-finite values, so
/// the underflow case must be correct here.
pub fn cosine(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() {
        return 0.0;
    }
    let dot: f64 = a.iter().zip(b).map(|(x, y)| f64::from(*x) * f64::from(*y)).sum();
    let na: f64 = a
        .iter()
        .map(|x| f64::from(*x) * f64::from(*x))
        .sum::<f64>()
        .sqrt();
    let nb: f64 = b
        .iter()
        .map(|x| f64::from(*x) * f64::from(*x))
        .sum::<f64>()
        .sqrt();
    if na == 0.0 || nb == 0.0 {
        return 0.0;
    }
    // Truncating f64→f32 is intentional: the ratio is in [-1, 1] where
    // the conversion only rounds, never overflows.
    #[allow(clippy::cast_possible_truncation)]
    let similarity = (dot / (na * nb)) as f32;
    similarity.clamp(-1.0, 1.0)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn deterministic() {
        let e = HashEmbedder::default();
        assert_eq!(e.embed("the same text"), e.embed("the same text"));
    }

    /// Mutation-run hardening: pin the embedder's shape contract — the
    /// default dimension, `embed()` output length == `dim()`, and the
    /// `try_embed` default forwarding to `embed` (the production worker
    /// path). Mutants returning fixed dims/vectors survived without these.
    #[test]
    fn dim_len_and_try_embed_contract() {
        let e = HashEmbedder::default();
        assert_eq!(e.dim(), 512);
        assert_eq!(e.embed("x").len(), e.dim());
        assert_eq!(e.try_embed("some step text").unwrap(), e.embed("some step text"));
        let small = HashEmbedder::new(64);
        assert_eq!(small.dim(), 64);
        assert_eq!(small.embed("x").len(), 64);
    }

    /// The documented whitespace-collapse invariance covers LEADING runs
    /// too — a mutant dropping the `!out.is_empty()` guard kept a leading
    /// space and made `embed("  abc def")` diverge from `embed("abc def")`.
    #[test]
    fn whitespace_invariance_covers_leading_runs() {
        let e = HashEmbedder::default();
        assert_eq!(e.embed("  abc def"), e.embed("abc def"));
        assert_eq!(e.embed("\t\nabc def \n"), e.embed("abc def"));
    }

    /// `cosine` must divide by the norm product — verified on NON-unit
    /// vectors where the correct value is strictly inside (-1, 1), so a
    /// `/`→`*` (or `*`→`/`) mutant cannot hide behind the final clamp.
    /// Also pin the zero-vector arm for EACH side independently (the
    /// `||`→`&&` mutant produced NaN when only one side was zero).
    #[test]
    fn cosine_normalizes_unnormalized_vectors_and_handles_one_sided_zero() {
        let value = cosine(&[2.0, 0.0], &[1.0, 1.0]);
        assert!(
            (value - std::f32::consts::FRAC_1_SQRT_2).abs() < 1e-6,
            "expected ~0.7071, got {value}"
        );
        assert_eq!(cosine(&[0.0, 0.0], &[1.0, 0.0]), 0.0);
        assert_eq!(cosine(&[1.0, 0.0], &[0.0, 0.0]), 0.0);
    }

    #[test]
    fn normalized_output() {
        let e = HashEmbedder::default();
        let v = e.embed("some reasonably long reasoning step about databases");
        let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-5, "norm = {norm}");
    }

    #[test]
    fn identical_texts_cosine_one() {
        let e = HashEmbedder::default();
        let a = e.embed("check the database for pending orders");
        let b = e.embed("check the database for pending orders");
        assert!((cosine(&a, &b) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn whitespace_and_case_invariant() {
        let e = HashEmbedder::default();
        let a = e.embed("Check   the Database\nfor pending Orders");
        let b = e.embed("check the database for pending orders");
        assert!(cosine(&a, &b) > 0.999, "{}", cosine(&a, &b));
    }

    #[test]
    fn paraphrase_loops_are_close_progress_is_far() {
        let e = HashEmbedder::default();
        // Paraphrase family (loop-like): high overlap expected.
        let p1 = e.embed("I should try checking the order database again for the pending records");
        let p2 = e.embed("Let me try checking the order database again for pending records");
        // Progress: same domain but genuinely new content.
        let q = e.embed("The API returned 502; switching to the backup endpoint and paging the on-call");
        let sim_paraphrase = cosine(&p1, &p2);
        let sim_progress = cosine(&p1, &q);
        assert!(
            sim_paraphrase > sim_progress + 0.2,
            "paraphrase {sim_paraphrase} vs progress {sim_progress}: separation too weak"
        );
    }

    #[test]
    fn empty_and_unicode_do_not_panic() {
        let e = HashEmbedder::default();
        assert_eq!(e.embed("").iter().map(|x| x * x).sum::<f32>(), 0.0);
        let _ = e.embed("日本語のテキスト 🎉 emoji مرحبا");
        let _ = e.embed("ab"); // shorter than smallest n-gram
    }

    #[test]
    fn cosine_edge_cases() {
        assert_eq!(cosine(&[], &[]), 0.0);
        assert_eq!(cosine(&[1.0], &[1.0, 2.0]), 0.0); // length mismatch
        assert_eq!(cosine(&[0.0, 0.0], &[0.0, 0.0]), 0.0); // zero vectors
    }
}
