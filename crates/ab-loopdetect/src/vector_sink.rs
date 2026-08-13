//! Off-path vector persistence for semantic-loop observability.

use std::future::Future;
use std::pin::Pin;

/// Future returned by vector sinks.
pub type VectorSinkFuture<'a> = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

/// Future returned by vector similarity lookups.
pub type VectorSearchFuture<'a> = Pin<Box<dyn Future<Output = Result<Option<f32>, String>> + Send + 'a>>;

/// Storage boundary for reasoning-step embeddings.
pub trait VectorSink: Send + Sync {
    /// Return the highest cosine similarity among prior vectors for a session.
    fn nearest_similarity<'a>(&'a self, _session_id: &'a str, _vector: &'a [f32]) -> VectorSearchFuture<'a> {
        Box::pin(async { Ok(None) })
    }

    /// Persist one session vector without participating in the hot path.
    fn record<'a>(&'a self, session_id: &'a str, vector: &'a [f32]) -> VectorSinkFuture<'a>;
}

/// Sink used when external vector persistence is disabled.
#[derive(Debug, Default)]
pub struct NoopVectorSink;

impl VectorSink for NoopVectorSink {
    fn record<'a>(&'a self, _session_id: &'a str, _vector: &'a [f32]) -> VectorSinkFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

/// Qdrant HTTP sink for local, edge, or customer-managed deployments.
#[cfg(feature = "qdrant")]
pub struct QdrantVectorSink {
    client: reqwest::Client,
    base_url: String,
    collection: String,
}

#[cfg(feature = "qdrant")]
impl QdrantVectorSink {
    /// Create a Qdrant sink. Collection creation remains an operator decision
    /// because distance metric and replication are deployment policy.
    pub fn new(base_url: impl Into<String>, collection: impl Into<String>) -> Result<Self, String> {
        Ok(Self {
            // No redirect following: a hostile or misconfigured Qdrant host
            // returning a 3xx would let it pivot the harness into an SSRF
            // probe against private services on the harness's network.
            client: reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(1))
                .timeout(std::time::Duration::from_secs(2))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|error| error.to_string())?,
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            collection: collection.into(),
        })
    }

    /// Create or update the collection with cosine distance and the configured
    /// embedding width.
    pub async fn ensure_collection(&self, dimension: usize) -> Result<(), String> {
        let url = format!("{}/collections/{}", self.base_url, self.collection);
        self.client
            .put(url)
            .json(&serde_json::json!({
                "vectors": {
                    "size": dimension,
                    "distance": "Cosine"
                }
            }))
            .send()
            .await
            .map_err(|error| error.to_string())?
            .error_for_status()
            .map_err(|error| error.to_string())?;
        Ok(())
    }
}

#[cfg(feature = "qdrant")]
impl VectorSink for QdrantVectorSink {
    fn nearest_similarity<'a>(&'a self, session_id: &'a str, vector: &'a [f32]) -> VectorSearchFuture<'a> {
        Box::pin(async move {
            let url = format!("{}/collections/{}/points/search", self.base_url, self.collection);
            let response: serde_json::Value = self
                .client
                .post(url)
                .json(&serde_json::json!({
                    "vector": vector,
                    "filter": {
                        "must": [{
                            "key": "session_id",
                            "match": { "value": session_id }
                        }]
                    },
                    "limit": 1,
                    "with_payload": false,
                    "with_vector": false
                }))
                .send()
                .await
                .map_err(|error| error.to_string())?
                .error_for_status()
                .map_err(|error| error.to_string())?
                .json()
                .await
                .map_err(|error| error.to_string())?;
            let Some(score) = response
                .pointer("/result/0/score")
                .and_then(serde_json::Value::as_f64)
            else {
                return Ok(None);
            };
            if !score.is_finite() || !(-1.0..=1.000_001).contains(&score) {
                return Err(format!("Qdrant returned invalid cosine score {score}"));
            }
            #[allow(clippy::cast_possible_truncation)]
            let score = score.clamp(-1.0, 1.0) as f32;
            Ok(Some(score))
        })
    }

    fn record<'a>(&'a self, session_id: &'a str, vector: &'a [f32]) -> VectorSinkFuture<'a> {
        Box::pin(async move {
            let recorded_at = ab_core::time::now_ms();
            let id = ab_core::new_event_uid();
            let url = format!(
                "{}/collections/{}/points?wait=true",
                self.base_url, self.collection
            );
            self.client
                .put(url)
                .json(&serde_json::json!({
                    "points": [{
                        "id": id,
                        "vector": vector,
                        "payload": {
                            "session_id": session_id,
                            "recorded_at": recorded_at,
                        }
                    }]
                }))
                .send()
                .await
                .map_err(|error| error.to_string())?
                .error_for_status()
                .map_err(|error| error.to_string())?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[tokio::test]
    async fn noop_sink_is_total() {
        NoopVectorSink.record("session", &[0.0, 1.0]).await.unwrap();
    }
}
