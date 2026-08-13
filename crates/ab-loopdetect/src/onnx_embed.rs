//! ONNX embedder via tract (pure Rust, no PyTorch/Python runtime — brief §8).
//!
//! Loads a MiniLM-class sentence-embedding ONNX model from a configured path.
//! Deployment note: model files are customer-supplied artifacts (air-gapped
//! installs cannot download); the default deployment uses [`crate::HashEmbedder`]
//! and swapping to ONNX is a config change, not a code change (plan D6).
//!
//! Tokenization is supplied by the model's Hugging Face `tokenizer.json`.

use crate::embed::Embedder;
use std::path::Path;
use tract_onnx::prelude::*;

type RunnableOnnxModel = SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>;

/// Embedder backed by an ONNX sentence-embedding model.
pub struct OnnxEmbedder {
    model: RunnableOnnxModel,
    tokenizer: tokenizers::Tokenizer,
    input_count: usize,
    dim: usize,
}

impl OnnxEmbedder {
    /// Load a model and its paired tokenizer. `dim` must match the output width.
    pub fn load(path: &Path, tokenizer_path: &Path, dim: usize) -> Result<Self, String> {
        if dim == 0 {
            return Err("ONNX embedding dimension must be greater than zero".to_owned());
        }
        let model = tract_onnx::onnx()
            .model_for_path(path)
            .map_err(|error| error.to_string())?
            .into_optimized()
            .map_err(|error| error.to_string())?;
        let input_count = model.input_outlets().map_err(|error| error.to_string())?.len();
        if !(2..=3).contains(&input_count) {
            return Err(format!(
                "ONNX sentence model must have 2 or 3 inputs, found {input_count}"
            ));
        }
        let model = model.into_runnable().map_err(|error| error.to_string())?;
        let tokenizer =
            tokenizers::Tokenizer::from_file(tokenizer_path).map_err(|error| error.to_string())?;
        Ok(Self {
            model,
            tokenizer,
            input_count,
            dim,
        })
    }

    fn infer(&self, text: &str) -> Result<Vec<f32>, String> {
        let encoding = self
            .tokenizer
            .encode(text, true)
            .map_err(|error| error.to_string())?;
        let ids: Vec<i64> = encoding
            .get_ids()
            .iter()
            .take(512)
            .map(|id| i64::from(*id))
            .collect();
        if ids.is_empty() {
            return Ok(vec![0.0; self.dim]);
        }
        let len = ids.len();
        let input =
            tract_ndarray::Array2::from_shape_vec((1, len), ids).map_err(|error| error.to_string())?;
        let mask_values: Vec<i64> = encoding
            .get_attention_mask()
            .iter()
            .take(len)
            .map(|value| i64::from(*value))
            .collect();
        let mask = tract_ndarray::Array2::from_shape_vec((1, len), mask_values.clone())
            .map_err(|error| error.to_string())?;
        let inputs = if self.input_count == 3 {
            let token_types: Vec<i64> = encoding
                .get_type_ids()
                .iter()
                .take(len)
                .map(|value| i64::from(*value))
                .collect();
            let token_types = tract_ndarray::Array2::from_shape_vec((1, len), token_types)
                .map_err(|error| error.to_string())?;
            tvec!(
                Tensor::from(input).into(),
                Tensor::from(mask).into(),
                Tensor::from(token_types).into()
            )
        } else {
            tvec!(Tensor::from(input).into(), Tensor::from(mask).into())
        };
        let outputs = self.model.run(inputs).map_err(|error| error.to_string())?;
        let output = outputs
            .first()
            .ok_or_else(|| "ONNX model returned no output".to_owned())?;
        let view = output.to_array_view::<f32>().map_err(|error| error.to_string())?;
        let mut vector = pool_output(view, &mask_values, self.dim)?;
        let norm: f32 = vector.iter().map(|value| value * value).sum::<f32>().sqrt();
        if norm > 0.0 {
            for value in &mut vector {
                *value /= norm;
            }
        }
        Ok(vector)
    }
}

fn pool_output(
    output: tract_ndarray::ArrayViewD<'_, f32>,
    attention_mask: &[i64],
    expected_dim: usize,
) -> Result<Vec<f32>, String> {
    let shape = output.shape();
    let vector = match shape {
        [width] if *width == expected_dim => output.iter().copied().collect(),
        [1, width] if *width == expected_dim => output.iter().copied().collect(),
        [1, tokens, width] if *width == expected_dim && *tokens == attention_mask.len() => {
            let mut pooled = vec![0.0f32; expected_dim];
            let mut weight = 0.0f32;
            for (token, mask) in attention_mask.iter().enumerate() {
                if *mask <= 0 {
                    continue;
                }
                let token_weight = *mask as f32;
                weight += token_weight;
                for (feature, value) in pooled.iter_mut().enumerate() {
                    let index = tract_ndarray::IxDyn(&[0, token, feature]);
                    let embedding = output
                        .get(index)
                        .ok_or_else(|| "ONNX output index escaped validated shape".to_owned())?;
                    *value += *embedding * token_weight;
                }
            }
            if weight == 0.0 {
                return Err("ONNX attention mask contains no active tokens".to_owned());
            }
            for value in &mut pooled {
                *value /= weight;
            }
            pooled
        }
        _ => {
            return Err(format!(
                "ONNX output shape {shape:?} is incompatible with embedding dimension {expected_dim} and token count {}",
                attention_mask.len()
            ));
        }
    };
    if vector.iter().any(|value| !value.is_finite()) {
        return Err("ONNX output contains non-finite values".to_owned());
    }
    Ok(vector)
}

impl Embedder for OnnxEmbedder {
    fn dim(&self) -> usize {
        self.dim
    }

    fn embed(&self, text: &str) -> Vec<f32> {
        self.infer(text).unwrap_or_else(|error| {
            tracing::warn!(%error, dim = self.dim, "ONNX inference failed; returning zero vector");
            vec![0.0; self.dim]
        })
    }

    fn try_embed(&self, text: &str) -> Result<Vec<f32>, String> {
        self.infer(text)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn token_embeddings_use_masked_mean_pooling() {
        let output = tract_ndarray::Array3::from_shape_vec((1, 3, 2), vec![1.0, 0.0, 1.0, 2.0, 100.0, 100.0])
            .unwrap()
            .into_dyn();
        let mut vector = pool_output(output.view(), &[1, 1, 0], 2).unwrap();
        let norm = vector.iter().map(|value| value * value).sum::<f32>().sqrt();
        for value in &mut vector {
            *value /= norm;
        }
        let expected = 1.0 / 2.0f32.sqrt();
        assert!((vector[0] - expected).abs() < 1e-6);
        assert!((vector[1] - expected).abs() < 1e-6);
    }

    #[test]
    fn pooled_export_requires_exact_embedding_width() {
        let output = tract_ndarray::Array2::from_shape_vec((1, 3), vec![1.0, 2.0, 3.0])
            .unwrap()
            .into_dyn();
        let error = pool_output(output.view(), &[1], 2).unwrap_err();
        assert!(error.contains("output shape"));
    }

    #[test]
    fn token_output_requires_matching_attention_mask() {
        let output = tract_ndarray::Array3::zeros((1, 2, 3)).into_dyn();
        let error = pool_output(output.view(), &[1], 3).unwrap_err();
        assert!(error.contains("token count 1"));
    }
}
