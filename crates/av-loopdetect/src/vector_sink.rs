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

    /// Delete every vector recorded under
    /// `session_scope`. Called best-effort when a session finalizes so
    /// the external store does not grow without bound — the
    /// `id#generation` scoping makes prior-generation points
    /// permanently unreachable dead weight otherwise. Default no-op
    /// for sinks without external state.
    fn delete_scope<'a>(&'a self, _session_scope: &'a str) -> VectorSinkFuture<'a> {
        Box::pin(async { Ok(()) })
    }
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

    /// Idempotent create — GET the collection first,
    /// verify size + distance if it exists, PUT-create only when
    /// absent. The prior code used PUT unconditionally, but Qdrant's
    /// `PUT /collections/{name}` is CREATE, not create-or-update (see
    /// qdrant/qdrant#3217/#3422). Every daemon restart hit the existing
    /// collection and boot aborted with a misleading "provision Qdrant
    /// collection" error; an embedder-dimension change also surfaced
    /// as the same message rather than a precise dim-conflict.
    pub async fn ensure_collection(&self, dimension: usize) -> Result<(), String> {
        let url = format!("{}/collections/{}", self.base_url, self.collection);
        let get_response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(classify_qdrant_error)?;
        let status = get_response.status();
        if status.is_success() {
            let body: serde_json::Value = get_response.json().await.map_err(classify_qdrant_error)?;
            let params = body.pointer("/result/config/params/vectors");
            let existing_size = params
                .and_then(|value| value.get("size"))
                .and_then(serde_json::Value::as_u64);
            let existing_distance = params
                .and_then(|value| value.get("distance"))
                .and_then(serde_json::Value::as_str);
            match (existing_size, existing_distance) {
                (Some(size), Some(distance))
                    if usize::try_from(size) == Ok(dimension) && distance.eq_ignore_ascii_case("Cosine") =>
                {
                    return Ok(());
                }
                (Some(size), Some(distance)) => {
                    return Err(format!(
                        "Qdrant collection {:?} exists with size={size}, distance={distance:?} \
                         but embedder configured for size={dimension}, distance=\"Cosine\" — \
                         refusing to overwrite; delete the collection or reconfigure the embedder",
                        self.collection
                    ));
                }
                _ => {
                    // Existing but with an unrecognized shape — treat
                    // as a hostile/unexpected environment and refuse
                    // rather than silently reprovisioning.
                    return Err(format!(
                        "Qdrant collection {:?} exists but its config shape is unrecognized \
                         (no `vectors.size`/`vectors.distance`); refusing to overwrite",
                        self.collection
                    ));
                }
            }
        }
        if status.as_u16() != 404 {
            return Err(format!(
                "Qdrant returned {status} when probing collection {:?}",
                self.collection
            ));
        }
        // Absent: create.
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
            .map_err(classify_qdrant_error)?
            .error_for_status()
            .map_err(classify_qdrant_error)?;
        Ok(())
    }
}

/// Qdrant reqwest errors embed the request URL in
/// `Display`, leaking the internal vector-store hostname/collection to
/// every downstream log (worker warn, boot bail). Strip the URL so the
/// logged text carries only the failure class. `without_url` moves the
/// error so we accept ownership; the callers were about to `to_string`
/// and drop it anyway.
#[cfg(feature = "qdrant")]
fn classify_qdrant_error(error: reqwest::Error) -> String {
    error.without_url().to_string()
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
                .map_err(classify_qdrant_error)?
                .error_for_status()
                .map_err(classify_qdrant_error)?
                .json()
                .await
                .map_err(classify_qdrant_error)?;
            let Some(score) = response
                .pointer("/result/0/score")
                .and_then(serde_json::Value::as_f64)
            else {
                return Ok(None);
            };
            // Cosine similarity is mathematically bounded to [-1, 1];
            // Qdrant's f64 dot products of unit-normalized f32 vectors
            // drift by ~1e-6 in EITHER direction, so the slop must be
            // symmetric: a legitimate antipodal score of -1.0000003 is
            // as valid as an identical-vector score of +1.0000003.
            // Truly wild values (a compromised Qdrant) still error out.
            if !score.is_finite() || !(-1.000_001..=1.000_001).contains(&score) {
                return Err(format!("Qdrant returned invalid cosine score {score}"));
            }
            #[allow(clippy::cast_possible_truncation)]
            let score = score.clamp(-1.0, 1.0) as f32;
            Ok(Some(score))
        })
    }

    fn record<'a>(&'a self, session_id: &'a str, vector: &'a [f32]) -> VectorSinkFuture<'a> {
        Box::pin(async move {
            let recorded_at = av_core::time::now_ms();
            let id = av_core::new_event_uid();
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
                .map_err(classify_qdrant_error)?
                .error_for_status()
                .map_err(classify_qdrant_error)?;
            Ok(())
        })
    }

    fn delete_scope<'a>(&'a self, session_scope: &'a str) -> VectorSinkFuture<'a> {
        Box::pin(async move {
            let url = format!(
                "{}/collections/{}/points/delete?wait=true",
                self.base_url, self.collection
            );
            self.client
                .post(url)
                .json(&serde_json::json!({
                    "filter": {
                        "must": [{
                            "key": "session_id",
                            "match": { "value": session_scope }
                        }]
                    }
                }))
                .send()
                .await
                .map_err(classify_qdrant_error)?
                .error_for_status()
                .map_err(classify_qdrant_error)?;
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
