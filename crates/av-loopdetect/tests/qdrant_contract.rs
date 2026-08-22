//! Live Qdrant contract, explicitly gated by AV_QDRANT_URL.
#![cfg(feature = "qdrant")]
#![allow(clippy::unwrap_used)]

#[cfg(feature = "onnx")]
use av_loopdetect::{Embedder, OnnxEmbedder};
use av_loopdetect::{QdrantVectorSink, VectorSink};

#[tokio::test]
async fn qdrant_collection_and_record_contract() {
    let Ok(url) = std::env::var("AV_QDRANT_URL") else {
        eprintln!("SKIPPED (AV_QDRANT_URL unset): Qdrant contract requires a live server");
        return;
    };
    let collection = format!("agentvisor_test_{}", av_core::new_event_uid().replace('-', ""));
    let sink = QdrantVectorSink::new(url.clone(), collection.clone()).unwrap();
    #[cfg(feature = "onnx")]
    let vector = match (
        std::env::var("AV_ONNX_MODEL_PATH"),
        std::env::var("AV_ONNX_TOKENIZER_PATH"),
    ) {
        (Ok(model), Ok(tokenizer)) => OnnxEmbedder::load(
            std::path::Path::new(&model),
            std::path::Path::new(&tokenizer),
            384,
        )
        .unwrap()
        .try_embed("a real semantic vector for the Qdrant contract")
        .unwrap(),
        _ => vec![0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7],
    };
    #[cfg(not(feature = "onnx"))]
    let vector = vec![0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7];
    sink.ensure_collection(vector.len()).await.unwrap();
    sink.record("contract-session", &vector).await.unwrap();
    let score = sink
        .nearest_similarity("contract-session", &vector)
        .await
        .unwrap()
        .unwrap();
    assert!(score > 0.999, "unexpected nearest-neighbor score {score}");
    // Clean up the per-run collection: without this every run left an
    // `agentvisor_test_*` collection behind, growing the live server
    // without bound across CI reruns.
    let endpoint = format!("{}/collections/{collection}", url.trim_end_matches('/'));
    if let Err(error) = reqwest::Client::new().delete(&endpoint).send().await {
        eprintln!("test-collection cleanup failed (server keeps one stray collection): {error}");
    }
}
