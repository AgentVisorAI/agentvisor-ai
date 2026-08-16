//! Live-gated contract for a configured MiniLM-class ONNX deployment artifact.
#![cfg(feature = "onnx")]
#![allow(clippy::unwrap_used)]

use av_loopdetect::{Embedder, OnnxEmbedder};
use std::path::Path;

#[test]
fn configured_minilm_model_embeds_real_text() {
    let Ok(model) = std::env::var("AV_ONNX_MODEL_PATH") else {
        eprintln!("SKIPPED (AV_ONNX_MODEL_PATH unset): ONNX contract requires a model");
        return;
    };
    let tokenizer = std::env::var("AV_ONNX_TOKENIZER_PATH").unwrap();
    let embedder = OnnxEmbedder::load(Path::new(&model), Path::new(&tokenizer), 384).unwrap();
    let vector = embedder
        .try_embed("the agent is making measurable progress")
        .unwrap();
    assert_eq!(vector.len(), 384);
    assert!(vector.iter().any(|value| *value != 0.0));
    let norm = vector.iter().map(|value| value * value).sum::<f32>().sqrt();
    assert!((norm - 1.0).abs() < 1e-4, "embedding norm is {norm}");
}
