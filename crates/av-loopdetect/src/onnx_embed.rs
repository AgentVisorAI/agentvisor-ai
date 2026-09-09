//! ONNX embedder via tract (pure Rust, no PyTorch/Python runtime).
//!
//! Loads a MiniLM-class sentence-embedding ONNX model from a configured path.
//! Deployment note: model files are customer-supplied artifacts (air-gapped
//! installs cannot download); the default deployment uses [`crate::HashEmbedder`]
//! and swapping to ONNX is a config change, not a code change (plan D6).
//!
//! Tokenization is supplied by the model's Hugging Face `tokenizer.json`.

use crate::embed::Embedder;
use std::path::Path;
use std::sync::Arc;
use tract_onnx::prelude::*;

type RunnableOnnxModel = Arc<TypedRunnableModel>;

/// Embedder backed by an ONNX sentence-embedding model.
pub struct OnnxEmbedder {
    model: RunnableOnnxModel,
    tokenizer: tokenizers::Tokenizer,
    input_count: usize,
    /// `input_order[i]` is the SEMANTIC tensor for graph input
    /// position `i`: 0 = input_ids, 1 = attention_mask,
    /// 2 = token_type_ids. See [`resolve_input_order`].
    input_order: Vec<usize>,
    dim: usize,
}

/// Map a graph input name to its semantic slot
/// (0 = input_ids, 1 = attention_mask, 2 = token_type_ids).
fn classify_input_name(name: &str) -> Option<usize> {
    let lower = name.to_ascii_lowercase();
    if lower.contains("input_id") {
        Some(0)
    } else if lower.contains("attention") || lower.contains("mask") {
        Some(1)
    } else if lower.contains("token_type") || lower.contains("segment") {
        Some(2)
    } else {
        None
    }
}

/// Resolve the semantic binding of the model's graph inputs.
///
/// Tensors were previously bound purely by POSITION
/// (`input_ids, attention_mask[, token_type_ids]`): an otherwise valid
/// BERT export whose graph declares the inputs in a different order
/// loaded fine (only the COUNT was checked) and then silently swapped
/// the mask and token ids at inference — same tensor types and shapes,
/// so nothing downstream errored; every embedding was just garbage,
/// and loop detection quietly stopped detecting. Model files are
/// customer-supplied artifacts, so hostile-or-hasty exports are the
/// expected input class.
///
/// Policy: when every input name is recognizable, bind by NAME in any
/// order; when none are (minimal/anonymized exports), fall back to the
/// positional convention; a PARTIALLY recognizable or duplicated set is
/// ambiguous and refuses to load.
fn resolve_input_order(names: &[String]) -> Result<Vec<usize>, String> {
    let classified: Vec<Option<usize>> = names.iter().map(|n| classify_input_name(n)).collect();
    if classified.iter().all(Option::is_none) {
        return Ok((0..names.len()).collect());
    }
    let Some(order) = classified.into_iter().collect::<Option<Vec<usize>>>() else {
        return Err(format!(
            "ONNX sentence model input names {names:?} are only partially recognizable; \
             refusing an ambiguous tensor binding (expected names containing \
             input_ids / attention_mask / token_type_ids, or none of them)"
        ));
    };
    let mut seen = vec![false; names.len()];
    for &slot in &order {
        if slot >= names.len() || seen.get(slot).copied().unwrap_or(true) {
            return Err(format!(
                "ONNX sentence model input names {names:?} do not form exactly one each of \
                 input_ids / attention_mask{}",
                if names.len() == 3 { " / token_type_ids" } else { "" }
            ));
        }
        if let Some(flag) = seen.get_mut(slot) {
            *flag = true;
        }
    }
    Ok(order)
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
        let input_outlets = model.input_outlets().map_err(|error| error.to_string())?.to_vec();
        let input_count = input_outlets.len();
        if !(2..=3).contains(&input_count) {
            return Err(format!(
                "ONNX sentence model must have 2 or 3 inputs, found {input_count}"
            ));
        }
        let input_names: Vec<String> = input_outlets
            .iter()
            .map(|outlet| model.node(outlet.node).name.clone())
            .collect();
        let input_order = resolve_input_order(&input_names)?;
        let model = model.into_runnable().map_err(|error| error.to_string())?;
        let tokenizer =
            tokenizers::Tokenizer::from_file(tokenizer_path).map_err(|error| error.to_string())?;
        Ok(Self {
            model,
            tokenizer,
            input_count,
            input_order,
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
        let inputs = {
            // Semantic tensors: slot 0 = input_ids, 1 = attention_mask,
            // 2 = token_type_ids; arranged into the model's declared
            // graph-input order (see `resolve_input_order`).
            let mut semantic: Vec<TValue> = vec![Tensor::from(input).into(), Tensor::from(mask).into()];
            if self.input_count == 3 {
                let token_types: Vec<i64> = encoding
                    .get_type_ids()
                    .iter()
                    .take(len)
                    .map(|value| i64::from(*value))
                    .collect();
                let token_types = tract_ndarray::Array2::from_shape_vec((1, len), token_types)
                    .map_err(|error| error.to_string())?;
                semantic.push(Tensor::from(token_types).into());
            }
            self.input_order
                .iter()
                .map(|&slot| {
                    semantic
                        .get(slot)
                        .cloned()
                        .ok_or_else(|| format!("ONNX input slot {slot} out of range"))
                })
                .collect::<Result<TVec<TValue>, String>>()?
        };
        let outputs = self.model.run(inputs).map_err(|error| error.to_string())?;
        let output = outputs
            .first()
            .ok_or_else(|| "ONNX model returned no output".to_owned())?;
        let view = output
            .to_plain_array_view::<f32>()
            .map_err(|error| error.to_string())?;
        let mut vector = pool_output(view, &mask_values, self.dim)?;
        // f64 accumulation: an f32 sum-of-squares underflows to 0.0 for
        // tiny finite activations, which skipped normalization and
        // emitted the exact vector shape that used to defeat `cosine`
        // (see embed.rs::cosine). Keep the two computations consistent.
        let norm = vector
            .iter()
            .map(|value| f64::from(*value) * f64::from(*value))
            .sum::<f64>()
            .sqrt();
        if norm > 0.0 {
            for value in &mut vector {
                // Intentional f64→f32 rounding: unit-normalized
                // components are in [-1, 1].
                #[allow(clippy::cast_possible_truncation)]
                {
                    *value = (f64::from(*value) / norm) as f32;
                }
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
        self.infer(text)
            .unwrap_or_else(|error| fallback_hash_embedding(self.dim, text, &error))
    }

    fn try_embed(&self, text: &str) -> Result<Vec<f32>, String> {
        // Production callers go through
        // `try_embed`, so a fallback that lived only in `embed()` was
        // dead code — every ONNX inference failure bricked the session
        // upstream. Apply the same
        // HashEmbedder fallback here so we always return Ok. The sink
        // path is now warn+continue anyway, but this preserves breaker
        // observations on transient ONNX errors.
        Ok(self
            .infer(text)
            .unwrap_or_else(|error| fallback_hash_embedding(self.dim, text, &error)))
    }
}

/// The prior fallback returned a zero vector on ONNX
/// inference failure, which the breaker interprets as an
/// empty/degenerate input signal (`delta ≈ 0`) — so an outage could
/// trip the loop-breaker mid-flight. HashEmbedder returns a non-zero
/// content-derived vector: same text → same vector, distinct texts →
/// distinct vectors, breaker semantics preserved through the outage.
fn fallback_hash_embedding(dim: usize, text: &str, error: &str) -> Vec<f32> {
    tracing::warn!(
        error = %error,
        dim,
        "ONNX inference failed; falling back to deterministic HashEmbedder \
         (non-zero so the breaker does not treat outages as false duplicates)"
    );
    crate::HashEmbedder::new(dim).embed(text)
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

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    /// Inputs were previously bound purely by position; a reordered but
    /// otherwise valid export silently swapped mask and token ids
    /// (identical tensor types/shapes — nothing errored, embeddings
    /// were garbage). Recognizable names must bind semantically in any
    /// order; anonymized exports keep the positional convention; a
    /// partially recognizable or duplicated set refuses to load.
    #[test]
    fn input_order_resolves_names_in_any_order() {
        assert_eq!(
            resolve_input_order(&names(&["input_ids", "attention_mask", "token_type_ids"])).unwrap(),
            vec![0, 1, 2]
        );
        assert_eq!(
            resolve_input_order(&names(&["attention_mask", "input_ids", "token_type_ids"])).unwrap(),
            vec![1, 0, 2]
        );
        assert_eq!(
            resolve_input_order(&names(&["input_ids", "attention_mask"])).unwrap(),
            vec![0, 1]
        );
        // tract-optimized graphs may decorate source names; substring
        // classification must survive that.
        assert_eq!(
            resolve_input_order(&names(&["input_ids.cast", "ATTENTION_MASK_0"])).unwrap(),
            vec![0, 1]
        );
    }

    #[test]
    fn input_order_falls_back_to_position_for_anonymized_exports() {
        assert_eq!(
            resolve_input_order(&names(&["input.1", "input.3", "input.5"])).unwrap(),
            vec![0, 1, 2]
        );
    }

    #[test]
    fn input_order_refuses_ambiguous_name_sets() {
        // Partially recognizable.
        assert!(resolve_input_order(&names(&["input_ids", "input.3"]))
            .unwrap_err()
            .contains("partially recognizable"));
        // Two masks, no ids.
        assert!(resolve_input_order(&names(&["attention_mask", "mask_two"]))
            .unwrap_err()
            .contains("exactly one each"));
        // token_type_ids in a 2-input model.
        assert!(resolve_input_order(&names(&["input_ids", "token_type_ids"]))
            .unwrap_err()
            .contains("exactly one each"));
    }
}
