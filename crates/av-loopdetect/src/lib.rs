//! Semantic loop detection & circuit breaking (brief Module A).
//!
//! Recursive agents stuck in loops rarely repeat verbatim — they paraphrase.
//! Off the hot path, a worker embeds each reasoning step and computes the
//! semantic delta Δ = 1 − cosine(eᵢ, eᵢ₊₁). The breaker trips when Δ ≈ 0
//! (below `delta_epsilon`) for `window` consecutive steps while the session
//! consumed ≥ `min_tokens` — exactly the brief's rule (Δ≈0 across 3 steps
//! while consuming N+ tokens).
//!
//! The default [`HashEmbedder`] is a deterministic char-n-gram
//! feature-hashing embedder: zero model downloads, air-gap-safe, catches
//! verbatim and paraphrase-dense loops (SLA-tested). MiniLM-class ONNX models
//! plug in behind the `onnx` feature via the same [`Embedder`] trait
//! (tract-onnx, pure Rust — no PyTorch/Python runtime, per the brief).

pub mod breaker;
pub mod embed;
pub mod vector_sink;

pub use breaker::{BreakerAction, BreakerConfig, BreakerState, BreakerVerdict, SessionLoopState};
pub use embed::{cosine, Embedder, HashEmbedder};
pub use vector_sink::{NoopVectorSink, VectorSearchFuture, VectorSink, VectorSinkFuture};

#[cfg(feature = "qdrant")]
pub use vector_sink::QdrantVectorSink;

#[cfg(feature = "onnx")]
pub mod onnx_embed;
#[cfg(feature = "onnx")]
pub use onnx_embed::OnnxEmbedder;
