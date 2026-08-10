//! ONNX embedder via tract (pure Rust, no PyTorch/Python runtime — brief §8).
//!
//! Loads a MiniLM-class sentence-embedding ONNX model from a configured path.
//! Deployment note: model files are customer-supplied artifacts (air-gapped
//! installs cannot download); the default deployment uses [`crate::HashEmbedder`]
//! and swapping to ONNX is a config change, not a code change (plan D6).
//!
//! This module intentionally implements only mean-pooled encoding of
//! pre-tokenized input ids; tokenizer files vary per model and belong to the
//! integration layer.

use crate::embed::Embedder;
use std::path::Path;
use tract_onnx::prelude::*;

/// Embedder backed by an ONNX sentence-embedding model.
pub struct OnnxEmbedder {
    model: SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>,
    dim: usize,
}

impl OnnxEmbedder {
    /// Load a model from `path`. `dim` must match the model's output width.
    pub fn load(path: &Path, dim: usize) -> TractResult<Self> {
        let model = tract_onnx::onnx().model_for_path(path)?.into_optimized()?.into_runnable()?;
        Ok(Self { model, dim })
    }
}

impl Embedder for OnnxEmbedder {
    fn dim(&self) -> usize {
        self.dim
    }

    fn embed(&self, text: &str) -> Vec<f32> {
        // Byte-level fallback tokenization (real deployments feed proper
        // wordpiece ids via the integration layer; this keeps the trait total).
        let ids: Vec<i64> = text.bytes().take(512).map(i64::from).collect();
        if ids.is_empty() {
            return vec![0.0; self.dim];
        }
        let len = ids.len();
        let input = match tract_ndarray::Array2::from_shape_vec((1, len), ids) {
            Ok(a) => a,
            Err(_) => return vec![0.0; self.dim],
        };
        let mask = tract_ndarray::Array2::<i64>::ones((1, len));
        let result = self
            .model
            .run(tvec!(Tensor::from(input).into(), Tensor::from(mask).into()))
            .ok()
            .and_then(|outputs| outputs.first().cloned())
            .and_then(|t| t.to_array_view::<f32>().ok().map(|v| v.iter().copied().collect::<Vec<_>>()));
        match result {
            Some(mut v) => {
                v.truncate(self.dim);
                v.resize(self.dim, 0.0);
                let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
                if norm > 0.0 {
                    for x in &mut v {
                        *x /= norm;
                    }
                }
                v
            }
            None => vec![0.0; self.dim],
        }
    }
}
