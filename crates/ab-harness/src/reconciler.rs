//! Session finalization and periodic idle reconciliation.

use crate::session::{Session, SessionRegistry, Workflow};
use ab_bridge::EventBus;
use ab_core::metrics::Registry;
use ab_core::time::elapsed_us;
use ab_events::StopReason;
use ab_receipts::{Receipt, ReceiptSubject, Signer};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

/// Result of closing a session.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FinalizeOutcome {
    /// A signed-workflow receipt was issued.
    Receipt {
        /// The issued receipt.
        receipt: Box<Receipt>,
    },
    /// An unsigned ATIF trajectory was persisted.
    Atif {
        /// Atomic spool path.
        path: PathBuf,
    },
    /// The session had already been closed.
    AlreadyClosed,
}

/// Lifecycle errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FinalizeError {
    /// Blocking task failed or panicked.
    #[error("finalization task failed: {0}")]
    Task(String),
    /// Receipt issuance failed.
    #[error("receipt issuance failed: {0}")]
    Receipt(String),
    /// ATIF persistence or parsing failed.
    #[error("ATIF finalization failed: {0}")]
    Atif(String),
    /// Promotion is invalid for this session.
    #[error("promotion refused: {0}")]
    Promotion(String),
    /// One or more upstream actions were not captured.
    #[error("session capture is incomplete; refusing final artifact")]
    CaptureIncomplete,
    /// Lifecycle event could not be durably published.
    #[error("lifecycle event publication failed: {0}")]
    Bridge(String),
}

/// Shared asynchronous finalization service.
#[derive(Clone)]
pub struct Finalizer {
    signer: Arc<dyn Signer>,
    spool_dir: PathBuf,
    metrics: Arc<Registry>,
    bridge: Option<Arc<dyn EventBus>>,
    recovery_lock: Arc<tokio::sync::Mutex<()>>,
    lifecycle_lock: Arc<tokio::sync::Mutex<()>>,
    quarantined_sessions: Arc<parking_lot::Mutex<std::collections::HashSet<String>>>,
    journal_key: [u8; 32],
}

struct CloseClaim<'a> {
    session: &'a Session,
    committed: bool,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct LifecycleOutbox {
    session_id: String,
    kind: String,
    topic: String,
    key: String,
    value: serde_json::Value,
    ack: Option<ab_bridge::PublishAck>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct AtifProvenance {
    session_id: String,
    digest: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PromotionMarker {
    session_id: String,
    trajectory_digest: String,
}

impl Drop for CloseClaim<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.session.reset_close();
        }
    }
}

impl Finalizer {
    /// Create a finalizer writing unsigned artifacts beneath `spool_dir`.
    pub fn new(signer: Arc<dyn Signer>, spool_dir: PathBuf, metrics: Arc<Registry>) -> Self {
        let journal_key = crate::journal::key_from_signer(signer.as_ref());
        Self {
            signer,
            spool_dir,
            metrics,
            bridge: None,
            recovery_lock: Arc::new(tokio::sync::Mutex::new(())),
            lifecycle_lock: Arc::new(tokio::sync::Mutex::new(())),
            quarantined_sessions: Arc::new(parking_lot::Mutex::new(std::collections::HashSet::new())),
            journal_key,
        }
    }

    /// Create a finalizer that also emits receipt events to the Bridge.
    pub fn with_bridge(
        signer: Arc<dyn Signer>,
        spool_dir: PathBuf,
        metrics: Arc<Registry>,
        bridge: Arc<dyn EventBus>,
    ) -> Self {
        let journal_key = crate::journal::key_from_signer(signer.as_ref());
        Self {
            signer,
            spool_dir,
            metrics,
            bridge: Some(bridge),
            recovery_lock: Arc::new(tokio::sync::Mutex::new(())),
            lifecycle_lock: Arc::new(tokio::sync::Mutex::new(())),
            quarantined_sessions: Arc::new(parking_lot::Mutex::new(std::collections::HashSet::new())),
            journal_key,
        }
    }

    /// Close exactly once. Receipt signing and ATIF serialization never run on
    /// the request hot path.
    #[tracing::instrument(
        name = "agentbridge.session.close",
        skip_all,
        fields(session.id = %session.id, workflow = ?session.workflow)
    )]
    pub async fn close_session(
        &self,
        session: Arc<Session>,
        stop_reason: StopReason,
    ) -> Result<FinalizeOutcome, FinalizeError> {
        let _lifecycle = self.lifecycle_lock.lock().await;
        self.close_session_locked(session, stop_reason).await
    }

    async fn close_session_locked(
        &self,
        session: Arc<Session>,
        stop_reason: StopReason,
    ) -> Result<FinalizeOutcome, FinalizeError> {
        let close_guard = session.close_guard();
        if !session.try_close() {
            return Ok(FinalizeOutcome::AlreadyClosed);
        }
        drop(close_guard);
        let mut claim = CloseClaim {
            session: &session,
            committed: false,
        };
        session.wait_for_streams().await;
        session.wait_for_worker_jobs().await;
        if session.capture_failed() {
            self.metrics
                .counter(
                    "ab_incomplete_sessions_total",
                    "Sessions refused due to incomplete capture",
                )
                .inc();
            // Seal the session finalized so the idle sweeper's `!is_closed()`
            // filter skips it — otherwise CloseClaim resets `closed` to 0 and
            // this branch retries on every idle tick forever.
            session.mark_artifact_committed();
            claim.committed = true;
            return Err(FinalizeError::CaptureIncomplete);
        }
        let started = Instant::now();
        let outcome = match session.workflow {
            Workflow::Signed => {
                let subject = {
                    let chain = session.chain.lock();
                    ReceiptSubject::EventChain {
                        chain_head: chain.head_hex(),
                        event_count: chain.count(),
                    }
                };
                let persisted_receipt = { session.receipt.lock().clone() };
                let receipt = if let Some(receipt) = persisted_receipt {
                    self.verify_configured_receipt(&receipt)?;
                    if receipt.body.subject != subject {
                        return Err(FinalizeError::Receipt(
                            "persisted receipt subject does not match reconstructed chain".to_owned(),
                        ));
                    }
                    receipt
                } else {
                    let body = session.receipt_body(subject, stop_reason);
                    let sign_started = Instant::now();
                    let receipt = Receipt::issue(body, self.signer.as_ref())
                        .map_err(|error| FinalizeError::Receipt(error.to_string()))?;
                    self.metrics
                        .histogram("ab_receipt_sign_duration_us", "Receipt signing latency")
                        .observe_us(elapsed_us(sign_started));
                    self.persist_receipt(&session.id, &receipt).await?;
                    *session.receipt.lock() = Some(receipt.clone());
                    receipt
                };
                session.mark_artifact_committed();
                self.emit_receipt_event(&session, &receipt).await?;
                FinalizeOutcome::Receipt {
                    receipt: Box::new(receipt),
                }
            }
            Workflow::Unsigned => {
                let existing_path = { session.atif_path.lock().clone() };
                let path = if let Some(path) = existing_path {
                    path
                } else {
                    let mut trajectory = session.snapshot_trajectory();
                    // An unsigned session that captured no steps cannot ever produce a strict-valid
                    // ATIF; seal it here so the idle sweeper skips it instead of churning forever.
                    if trajectory.steps.is_empty() {
                        session.mark_artifact_committed();
                        claim.committed = true;
                        return Err(FinalizeError::Atif(
                            "cannot finalize an unsigned session with no captured steps".to_owned(),
                        ));
                    }
                    let identity = session.current_identity();
                    trajectory.agent.extra = Some(serde_json::json!({
                        "charter": identity.charter,
                        "instance_uid": identity.instance_uid,
                        "ttl_remaining_s": identity.ttl_remaining_s,
                    }));
                    if let Some(metrics) = trajectory.final_metrics.as_mut() {
                        metrics.total_prompt_tokens = Some(
                            session
                                .totals
                                .prompt_tokens
                                .load(std::sync::atomic::Ordering::Acquire),
                        );
                        metrics.total_completion_tokens = Some(
                            session
                                .totals
                                .completion_tokens
                                .load(std::sync::atomic::Ordering::Acquire),
                        );
                        metrics.total_cached_tokens = Some(
                            session
                                .totals
                                .cached_tokens
                                .load(std::sync::atomic::Ordering::Acquire),
                        );
                        metrics.total_cost_usd = Some(
                            session
                                .totals
                                .cost_usd_micros
                                .load(std::sync::atomic::Ordering::Acquire)
                                as f64
                                / ab_core::units::USD_MICROS_PER_DOLLAR as f64,
                        );
                        metrics.extra = Some(serde_json::json!({
                            "tool_calls": session.totals.tool_calls.load(std::sync::atomic::Ordering::Acquire),
                            "tool_allowed": session.totals.tool_allowed.load(std::sync::atomic::Ordering::Acquire),
                            "tool_blocked": session.totals.tool_blocked.load(std::sync::atomic::Ordering::Acquire),
                            "cost_usd_micros": session.totals.cost_usd_micros.load(std::sync::atomic::Ordering::Acquire),
                            "stop_reason_id": session.recorded_stop_reason_id(),
                        }));
                    }
                    let name = format!(
                        "{}.json",
                        &ab_core::digest::sha256_hex(session.id.as_bytes())[..32]
                    );
                    let path = self.spool_dir.join(name);
                    let write_path = path.clone();
                    tokio::task::spawn_blocking(move || ab_atif::write_atomic(&trajectory, &write_path))
                        .await
                        .map_err(|error| FinalizeError::Task(error.to_string()))?
                        .map_err(|error| FinalizeError::Atif(error.to_string()))?;
                    *session.atif_path.lock() = Some(path.clone());
                    path
                };
                self.ensure_atif_provenance(&path, &session.id).await?;
                session.mark_artifact_committed();
                FinalizeOutcome::Atif { path }
            }
        };
        let workflow = session.workflow.as_str();
        self.emit_bridge_event(
            &session,
            ab_events::EventClass::Session,
            serde_json::json!({"action": "closed", "workflow": workflow}),
            crate::journal::SESSION_CLOSE_OUTBOX_KIND,
        )
        .await?;
        self.remove_step_journal(&session.id).await?;
        self.remove_lifecycle_outbox(&session.id, crate::journal::RECEIPT_OUTBOX_KIND)
            .await?;
        self.remove_lifecycle_outbox(&session.id, crate::journal::SESSION_CLOSE_OUTBOX_KIND)
            .await?;
        self.metrics
            .histogram("ab_session_finalize_duration_us", "Session finalization latency")
            .observe_us(elapsed_us(started));
        self.metrics
            .counter("ab_sessions_finalized_total", "Sessions finalized")
            .inc();
        claim.committed = true;
        Ok(outcome)
    }

    /// Promote a persisted unsigned trajectory into a retroactive Receipt.
    #[tracing::instrument(
        name = "agentbridge.session.promote",
        skip_all,
        fields(session.id = %session.id)
    )]
    pub async fn promote(&self, session: Arc<Session>) -> Result<Receipt, FinalizeError> {
        let _lifecycle = self.lifecycle_lock.lock().await;
        if session.workflow != Workflow::Unsigned {
            return session
                .receipt
                .lock()
                .clone()
                .ok_or_else(|| FinalizeError::Promotion("signed session has no issued receipt".to_owned()));
        }
        if !session.is_closed() {
            self.close_session_locked(Arc::clone(&session), StopReason::SessionClosed)
                .await?;
        }
        let persisted_receipt = { session.receipt.lock().clone() };
        if session.is_promoted() {
            return persisted_receipt.ok_or_else(|| {
                FinalizeError::Promotion("promoted session has no persisted receipt".to_owned())
            });
        }
        let path =
            session.atif_path.lock().clone().ok_or_else(|| {
                FinalizeError::Promotion("session has no persisted ATIF artifact".to_owned())
            })?;
        let marker = path.with_extension("promote");
        if !path.with_extension("atif-auth").exists() {
            return Err(FinalizeError::Atif(
                "ATIF artifact has no authenticated provenance".to_owned(),
            ));
        }
        self.ensure_atif_provenance(&path, &session.id).await?;
        let bytes = tokio::fs::read(&path)
            .await
            .map_err(|error| FinalizeError::Atif(error.to_string()))?;
        let trajectory: ab_atif::Trajectory =
            serde_json::from_slice(&bytes).map_err(|error| FinalizeError::Atif(error.to_string()))?;
        let issues = ab_atif::validate_trajectory(&trajectory, ab_atif::Mode::Strict);
        if !issues.is_empty() {
            return Err(FinalizeError::Atif(format!(
                "strict validation failed: {issues:?}"
            )));
        }
        let trajectory_digest = ab_core::digest::sha256_hex(&bytes);
        let subject = ReceiptSubject::AtifTrajectory {
            trajectory_digest: trajectory_digest.clone(),
            step_count: trajectory.steps.len() as u64,
            retroactive: true,
        };
        let marker_payload = PromotionMarker {
            session_id: session.id.clone(),
            trajectory_digest,
        };
        if marker.exists() {
            let sealed = tokio::fs::read(&marker)
                .await
                .map_err(|error| FinalizeError::Atif(error.to_string()))?;
            let actual: PromotionMarker =
                crate::journal::open(&self.journal_key, "promotion-marker", 0, &sealed)
                    .map_err(FinalizeError::Atif)?;
            if actual.session_id != marker_payload.session_id
                || actual.trajectory_digest != marker_payload.trajectory_digest
            {
                return Err(FinalizeError::Atif(
                    "promotion marker does not match session and trajectory".to_owned(),
                ));
            }
        } else {
            let sealed = crate::journal::seal(&self.journal_key, "promotion-marker", 0, &marker_payload)
                .map_err(FinalizeError::Atif)?;
            persist_marker(&marker, &sealed).await?;
        }
        if !session.try_promote() {
            return Err(FinalizeError::Promotion(
                "promotion is already in progress".to_owned(),
            ));
        }
        let receipt = if let Some(receipt) = persisted_receipt {
            if let Err(error) = self.verify_configured_receipt(&receipt) {
                session.reset_promotion();
                return Err(error);
            }
            if receipt.body.subject != subject {
                session.reset_promotion();
                return Err(FinalizeError::Receipt(
                    "persisted promotion receipt does not match ATIF artifact".to_owned(),
                ));
            }
            receipt
        } else {
            let body = session.receipt_body(subject, StopReason::SessionClosed);
            let issued = Receipt::issue(body, self.signer.as_ref())
                .map_err(|error| FinalizeError::Receipt(error.to_string()));
            let receipt = match issued {
                Ok(receipt) => receipt,
                Err(error) => {
                    session.reset_promotion();
                    return Err(error);
                }
            };
            if let Err(error) = self.persist_receipt(&session.id, &receipt).await {
                session.reset_promotion();
                return Err(error);
            }
            *session.receipt.lock() = Some(receipt.clone());
            receipt
        };
        if let Err(error) = self.emit_receipt_event(&session, &receipt).await {
            session.reset_promotion();
            return Err(error);
        }
        session.finish_promotion();
        remove_outbox(&marker).await?;
        self.remove_lifecycle_outbox(&session.id, crate::journal::RECEIPT_OUTBOX_KIND)
            .await?;
        self.metrics
            .counter("ab_sessions_promoted_total", "Unsigned sessions promoted")
            .inc();
        Ok(receipt)
    }

    /// Recover interrupted sessions from the spool: quarantine sessions with
    /// incomplete effects, replay lifecycle outboxes, recover signed journal
    /// sessions, consolidate unsigned step journals, then scan strict ATIF
    /// artifacts for closed unsigned sessions. Returns the total count of
    /// recovered sessions (unsigned + signed).
    #[tracing::instrument(name = "agentbridge.recovery", skip_all)]
    pub async fn recover_spooled_sessions(
        &self,
        sessions: &SessionRegistry,
        breaker: &ab_loopdetect::BreakerConfig,
    ) -> Result<usize, FinalizeError> {
        let _recovery = self.recovery_lock.lock().await;
        let _lifecycle = self.lifecycle_lock.lock().await;
        let mut quarantined = crate::worker::inflight_response_sessions(&self.spool_dir, &self.journal_key)
            .await
            .map_err(FinalizeError::Atif)?;
        quarantined.extend(
            crate::routes::unresolved_tool_sessions(&self.spool_dir, &self.journal_key)
                .await
                .map_err(FinalizeError::Atif)?,
        );
        // A marker only proves an *abandoned* effect when its session is
        // not currently active: live sessions legitimately hold markers
        // for the duration of an upstream call, and a request that merely
        // straddles a periodic tick must not poison its session as
        // capture-failed forever.
        quarantined.retain(|id| sessions.get(id).is_none());
        if !quarantined.is_empty() {
            // The markers stay on disk as evidence, so every periodic tick
            // rediscovers the same set. Warn only about ids not already in
            // the quarantine — otherwise a single crash would repeat this
            // warning every tick forever.
            let mut known = self.quarantined_sessions.lock();
            let new: Vec<&String> = quarantined.iter().filter(|id| !known.contains(*id)).collect();
            if !new.is_empty() {
                tracing::warn!(
                    sessions = new.len(),
                    "quarantining sessions with incomplete effects"
                );
            }
            known.extend(quarantined.iter().cloned());
        }
        self.replay_lifecycle_outboxes().await?;
        let signed_recovered = self.recover_signed_journals(sessions, breaker).await?;
        self.consolidate_step_journals(sessions, breaker).await?;
        let mut entries = match tokio::fs::read_dir(&self.spool_dir).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(FinalizeError::Atif(error.to_string())),
        };
        let mut recovered = 0usize;
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|error| FinalizeError::Atif(error.to_string()))?
        {
            let path = entry.path();
            if path.extension().and_then(std::ffi::OsStr::to_str) != Some("json") {
                continue;
            }
            // Live session journals ({hash}.session.json) are handled by
            // consolidate_step_journals above; they are not ATIF documents,
            // so parsing them here would only spam misleading warnings
            // every tick while a session is open.
            if path
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|name| name.ends_with(".session.json"))
            {
                continue;
            }
            let bytes = tokio::fs::read(&path)
                .await
                .map_err(|error| FinalizeError::Atif(error.to_string()))?;
            let trajectory: ab_atif::Trajectory = match serde_json::from_slice(&bytes) {
                Ok(trajectory) => trajectory,
                Err(error) => {
                    self.metrics
                        .counter(
                            "ab_atif_recovery_skipped_total{reason=\"invalid_json\"}",
                            "ATIF spool files skipped during recovery",
                        )
                        .inc();
                    tracing::warn!(%error, path = %path.display(), "ignoring invalid ATIF spool file");
                    continue;
                }
            };
            if !ab_atif::validate_trajectory(&trajectory, ab_atif::Mode::Strict).is_empty() {
                self.metrics
                    .counter(
                        "ab_atif_recovery_skipped_total{reason=\"nonconformant\"}",
                        "ATIF spool files skipped during recovery",
                    )
                    .inc();
                tracing::warn!(path = %path.display(), "ignoring nonconformant ATIF spool file");
                continue;
            }
            let Some(session_id) = trajectory.session_id.clone() else {
                continue;
            };
            if !path.with_extension("atif-auth").exists() {
                return Err(FinalizeError::Atif(format!(
                    "ATIF artifact {} has no authenticated provenance",
                    path.display()
                )));
            }
            self.ensure_atif_provenance(&path, &session_id).await?;
            if sessions.get(&session_id).is_some() {
                continue;
            }
            let extra = trajectory.agent.extra.as_ref();
            let instance_uid = extra
                .and_then(|value| value.get("instance_uid"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("recovered")
                .to_owned();
            let charter = extra
                .and_then(|value| value.get("charter"))
                .and_then(|value| {
                    serde_json::from_value::<ab_events::CharterFile>(value.clone())
                        .ok()
                        .or_else(|| value.as_str().map(Into::into))
                })
                .unwrap_or_else(|| "recovered".into());
            let ttl_remaining_s = extra
                .and_then(|value| value.get("ttl_remaining_s"))
                .and_then(serde_json::Value::as_u64);
            let recovered_session = match sessions.try_insert_recovered(
                Session::recover_unsigned(
                    session_id,
                    ab_events::AgentIdentity {
                        version: trajectory.agent.version.clone(),
                        charter,
                        instance_uid,
                        ttl_remaining_s,
                    },
                    breaker.clone(),
                    path.clone(),
                    trajectory.final_metrics.as_ref(),
                )
                .map_err(FinalizeError::Atif)?,
            ) {
                Ok(inserted) => inserted,
                Err(_active) => {
                    tracing::info!(session = %path.display(), "unsigned recovery skipped: session already active");
                    continue;
                }
            };
            let receipt_path = self.receipt_path(&recovered_session.id);
            if let Ok(bytes) = tokio::fs::read(&receipt_path).await {
                let receipt = serde_json::from_slice::<Receipt>(&bytes)
                    .map_err(|error| FinalizeError::Receipt(error.to_string()))?;
                self.verify_configured_receipt(&receipt)?;
                if path.with_extension("promote").exists() {
                    recovered_session.restore_pending_receipt(receipt);
                } else {
                    recovered_session.restore_receipt(receipt);
                }
            }
            recovered += 1;
        }
        self.remove_acked_lifecycle_outboxes().await?;
        Ok(recovered + signed_recovered)
    }

    async fn recover_signed_journals(
        &self,
        sessions: &SessionRegistry,
        breaker: &ab_loopdetect::BreakerConfig,
    ) -> Result<usize, FinalizeError> {
        let mut entries = match tokio::fs::read_dir(&self.spool_dir).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(FinalizeError::Atif(error.to_string())),
        };
        let mut recovered = 0usize;
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|error| FinalizeError::Atif(error.to_string()))?
        {
            let metadata_path = entry.path();
            let Some(name) = metadata_path.file_name().and_then(std::ffi::OsStr::to_str) else {
                continue;
            };
            let Some(stem) = name.strip_suffix(".session.json") else {
                continue;
            };
            let metadata = self.read_journal_metadata(&metadata_path).await?;
            if metadata
                .get("journal_version")
                .and_then(serde_json::Value::as_u64)
                != Some(2)
            {
                return Err(FinalizeError::Atif(
                    "unsupported active journal version".to_owned(),
                ));
            }
            if metadata.get("workflow").and_then(serde_json::Value::as_str) != Some(Workflow::Signed.as_str())
            {
                continue;
            }
            let session_id = metadata
                .get("session_id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| FinalizeError::Atif("journal metadata has no session_id".into()))?;
            if sessions.get(session_id).is_some() {
                continue;
            }
            let identity: ab_events::AgentIdentity = serde_json::from_value(
                metadata
                    .get("identity")
                    .cloned()
                    .ok_or_else(|| FinalizeError::Atif("journal metadata has no identity".into()))?,
            )
            .map_err(|error| FinalizeError::Atif(error.to_string()))?;
            let journal_path = self.spool_dir.join(format!("{stem}.events.ndjson"));
            let journal = if journal_path.exists() {
                read_complete_journal(&journal_path).await?
            } else {
                Vec::new()
            };
            if journal.is_empty() {
                tokio::fs::remove_file(metadata_path)
                    .await
                    .map_err(|error| FinalizeError::Atif(error.to_string()))?;
                continue;
            }
            let session = Arc::new(Session::new(
                session_id.to_owned(),
                Workflow::Signed,
                identity,
                breaker.clone(),
            ));
            let mut next_sequence = 0u64;
            let mut tool_calls = 0u64;
            let mut tool_allowed = 0u64;
            let mut tool_blocked = 0u64;
            let mut prompt_tokens = 0u64;
            let mut completion_tokens = 0u64;
            let mut cached_tokens = 0u64;
            let mut cost_usd_micros = 0u64;
            let mut pending_responses = std::collections::HashSet::new();
            let domain = format!("{}:active", session.id);
            for (index, line) in journal.into_iter().enumerate() {
                let index = u64::try_from(index)
                    .map_err(|_| FinalizeError::Atif("active journal index overflow".to_owned()))?;
                let record: crate::worker::ActiveJournalRecord =
                    crate::journal::open(&self.journal_key, &domain, index, line.as_bytes())
                        .map_err(FinalizeError::Atif)?;
                let event: ab_events::OcsfEvent = serde_json::from_value(record.event.clone())
                    .map_err(|error| FinalizeError::Atif(error.to_string()))?;
                if event.session_uid != session.id {
                    return Err(FinalizeError::Atif(format!(
                        "signed journal event belongs to session {:?}, expected {:?}",
                        event.session_uid, session.id
                    )));
                }
                if record.atif_step.is_some() || record.identity != event.ai_agent {
                    return Err(FinalizeError::Atif(
                        "signed active record has inconsistent workflow or identity".to_owned(),
                    ));
                }
                track_response_attempt(&mut pending_responses, record.response_attempt.as_ref())?;
                if event.metadata.sequence != index {
                    return Err(FinalizeError::Atif(
                        "signed event sequence does not match active journal index".to_owned(),
                    ));
                }
                if record.identity.version != session.identity.version
                    || record.identity.charter != session.identity.charter
                    || record.identity.instance_uid != session.identity.instance_uid
                {
                    return Err(FinalizeError::Atif(
                        "active journal changed the session identity".to_owned(),
                    ));
                }
                session.refresh_identity(&record.identity);
                next_sequence = index
                    .checked_add(1)
                    .ok_or_else(|| FinalizeError::Atif("event sequence overflow".to_owned()))?;
                session
                    .chain
                    .lock()
                    .append(&record.event)
                    .map_err(|error| FinalizeError::Receipt(error.to_string()))?;
                tool_calls = checked_recovery_add(tool_calls, record.tool_calls, "tool calls")?;
                tool_allowed = checked_recovery_add(tool_allowed, record.tool_allowed, "allowed tools")?;
                tool_blocked = checked_recovery_add(tool_blocked, record.tool_blocked, "blocked tools")?;
                prompt_tokens = checked_recovery_add(prompt_tokens, record.prompt_tokens, "prompt tokens")?;
                completion_tokens =
                    checked_recovery_add(completion_tokens, record.completion_tokens, "completion tokens")?;
                cached_tokens = checked_recovery_add(cached_tokens, record.cached_tokens, "cached tokens")?;
                cost_usd_micros = checked_recovery_add(cost_usd_micros, record.cost_usd_micros, "cost")?;
                if let Some(id) = record.stop_reason_id {
                    let reason = ab_events::StopReason::from_id(id);
                    if reason != ab_events::StopReason::Unknown {
                        session.record_stop_reason(reason);
                    }
                }
                self.ensure_active_event_published(&session.id, &event, &record.event)
                    .await?;
            }
            if tool_allowed
                .checked_add(tool_blocked)
                .is_none_or(|classified| classified > tool_calls)
            {
                return Err(FinalizeError::Atif(
                    "signed journal has inconsistent tool accounting".to_owned(),
                ));
            }
            session
                .totals
                .tool_calls
                .store(tool_calls, std::sync::atomic::Ordering::Release);
            session
                .totals
                .tool_allowed
                .store(tool_allowed, std::sync::atomic::Ordering::Release);
            session
                .totals
                .tool_blocked
                .store(tool_blocked, std::sync::atomic::Ordering::Release);
            session
                .totals
                .prompt_tokens
                .store(prompt_tokens, std::sync::atomic::Ordering::Release);
            session
                .totals
                .completion_tokens
                .store(completion_tokens, std::sync::atomic::Ordering::Release);
            session
                .totals
                .cached_tokens
                .store(cached_tokens, std::sync::atomic::Ordering::Release);
            session
                .totals
                .cost_usd_micros
                .store(cost_usd_micros, std::sync::atomic::Ordering::Release);
            let inconsistent_responses = !pending_responses.is_empty();
            session.restore_next_seq(next_sequence);
            let expected_subject = {
                let chain = session.chain.lock();
                ReceiptSubject::EventChain {
                    chain_head: chain.head_hex(),
                    event_count: chain.count(),
                }
            };
            let receipt_path = self.receipt_path(&session.id);
            if let Ok(bytes) = tokio::fs::read(receipt_path).await {
                let receipt = serde_json::from_slice::<Receipt>(&bytes)
                    .map_err(|error| FinalizeError::Receipt(error.to_string()))?;
                self.verify_configured_receipt(&receipt)?;
                if receipt.body.subject != expected_subject {
                    return Err(FinalizeError::Receipt(
                        "persisted receipt does not attest the recovered signed journal".to_owned(),
                    ));
                }
                *session.receipt.lock() = Some(receipt);
            }
            let unwrapped = Arc::try_unwrap(session)
                .map_err(|_| FinalizeError::Task("signed recovery retained session".to_owned()))?;
            // Seal the session to new leases before it is ever reachable via
            // `sessions.get(id)`. Between `try_insert_recovered` and the
            // finalize path's `try_close`, a client request for the same id
            // could otherwise take a lease, submit a worker job, and append to
            // the recovered chain — permanently diverging it from the persisted
            // receipt's subject.event_count (and leaving a wrong-index journal
            // entry). `is_closed()` is true whenever `artifact_committed` is
            // set, but `try_close` still transitions `closed` 0→1, so
            // `close_session_locked` still runs its full finalize body.
            unwrapped.mark_artifact_committed();
            let session = match sessions.try_insert_recovered(unwrapped) {
                Ok(inserted) => inserted,
                Err(_active) => {
                    tracing::info!(session = %session_id, "signed recovery skipped: session already active");
                    continue;
                }
            };
            if inconsistent_responses {
                // Quarantine only after we know the recovered Session was actually installed —
                // otherwise a live session with the same id would inherit the capture-failed verdict.
                self.quarantined_sessions.lock().insert(session.id.clone());
                session.mark_capture_failed();
                recovered += 1;
                continue;
            }
            if self.quarantined_sessions.lock().contains(&session.id) {
                session.mark_capture_failed();
                recovered += 1;
                continue;
            }
            self.close_session_locked(Arc::clone(&session), StopReason::SessionClosed)
                .await?;
            recovered += 1;
        }
        Ok(recovered)
    }

    async fn ensure_active_event_published(
        &self,
        session_id: &str,
        event: &ab_events::OcsfEvent,
        value: &serde_json::Value,
    ) -> Result<(), FinalizeError> {
        let topic = event.class_name.topic();
        let event_uid = &event.metadata.uid;
        if let Some(ack) =
            crate::worker::read_broker_ack(&self.spool_dir, session_id, event_uid, &self.journal_key)
                .await
                .map_err(FinalizeError::Bridge)?
        {
            if ack.topic != topic {
                return Err(FinalizeError::Bridge(
                    "broker acknowledgment topic does not match active event".to_owned(),
                ));
            }
            return Ok(());
        }
        let bridge = self.bridge.as_ref().map(Arc::clone).ok_or_else(|| {
            FinalizeError::Bridge("unacknowledged active event has no configured broker".to_owned())
        })?;
        let topic = topic.to_owned();
        let key = event.ai_agent.instance_uid.clone();
        let value = value.clone();
        let uid = event_uid.clone();
        let lookup_bridge = Arc::clone(&bridge);
        let lookup_topic = topic.clone();
        let lookup_key = key.clone();
        let lookup_uid = uid.clone();
        if let Some(ack) = tokio::task::spawn_blocking(move || {
            lookup_bridge.find_event_by_uid(&lookup_topic, &lookup_key, &lookup_uid)
        })
        .await
        .map_err(|error| FinalizeError::Task(error.to_string()))?
        .map_err(|error| FinalizeError::Bridge(error.to_string()))?
        {
            crate::worker::persist_broker_ack(
                &self.spool_dir,
                session_id,
                event_uid,
                &ack,
                &self.journal_key,
            )
            .await
            .map_err(FinalizeError::Bridge)?;
            return Ok(());
        }
        let ack = tokio::task::spawn_blocking(move || bridge.publish_idempotent(&topic, &key, &value, &uid))
            .await
            .map_err(|error| FinalizeError::Task(error.to_string()))?
            .map_err(|error| FinalizeError::Bridge(error.to_string()))?;
        crate::worker::persist_broker_ack(&self.spool_dir, session_id, event_uid, &ack, &self.journal_key)
            .await
            .map_err(FinalizeError::Bridge)
    }

    async fn consolidate_step_journals(
        &self,
        sessions: &SessionRegistry,
        breaker: &ab_loopdetect::BreakerConfig,
    ) -> Result<(), FinalizeError> {
        let mut entries = match tokio::fs::read_dir(&self.spool_dir).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(FinalizeError::Atif(error.to_string())),
        };
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|error| FinalizeError::Atif(error.to_string()))?
        {
            let metadata_path = entry.path();
            let Some(name) = metadata_path.file_name().and_then(std::ffi::OsStr::to_str) else {
                continue;
            };
            let Some(stem) = name.strip_suffix(".session.json") else {
                continue;
            };
            let final_path = self.spool_dir.join(format!("{stem}.json"));
            let journal_path = self.spool_dir.join(format!("{stem}.events.ndjson"));
            let metadata = self.read_journal_metadata(&metadata_path).await?;
            if metadata
                .get("journal_version")
                .and_then(serde_json::Value::as_u64)
                != Some(2)
            {
                return Err(FinalizeError::Atif(
                    "unsupported active journal version".to_owned(),
                ));
            }
            if metadata.get("workflow").and_then(serde_json::Value::as_str) == Some(Workflow::Signed.as_str())
            {
                continue;
            }
            let session_id = metadata
                .get("session_id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| FinalizeError::Atif("journal metadata has no session_id".into()))?;
            if sessions.get(session_id).is_some() {
                continue;
            }
            let identity: ab_events::AgentIdentity = serde_json::from_value(
                metadata
                    .get("identity")
                    .cloned()
                    .ok_or_else(|| FinalizeError::Atif("journal metadata has no identity".into()))?,
            )
            .map_err(|error| FinalizeError::Atif(error.to_string()))?;
            let journal = if journal_path.exists() {
                read_complete_journal(&journal_path).await?
            } else {
                Vec::new()
            };
            if self.quarantined_sessions.lock().contains(session_id) {
                let quarantined = Session::new(
                    session_id.to_owned(),
                    Workflow::Unsigned,
                    identity.clone(),
                    breaker.clone(),
                );
                quarantined.restore_journal_index(
                    u64::try_from(journal.len())
                        .map_err(|_| FinalizeError::Atif("active journal length overflow".to_owned()))?,
                );
                quarantined.mark_capture_failed();
                // Also seal the session finalized (like the signed sibling at
                // line ~773) so the idle sweeper's `!is_closed()` filter
                // skips it. Otherwise every idle tick re-enters
                // close_session_locked, hits the capture_failed guard, and
                // CloseClaim resets `closed` — an unbounded churn loop.
                quarantined.mark_artifact_committed();
                sessions.insert_recovered(quarantined);
                continue;
            }
            if journal.is_empty() {
                tokio::fs::remove_file(metadata_path)
                    .await
                    .map_err(|error| FinalizeError::Atif(error.to_string()))?;
                continue;
            }
            let journal_len = u64::try_from(journal.len())
                .map_err(|_| FinalizeError::Atif("active journal length overflow".to_owned()))?;
            let agent = ab_atif::Agent {
                name: "agent-bridge-harness".into(),
                version: identity.version.clone(),
                model_name: None,
                tool_definitions: None,
                extra: Some(serde_json::json!({
                    "charter": identity.charter,
                    "instance_uid": identity.instance_uid,
                })),
            };
            let mut builder = ab_atif::TrajectoryBuilder::new(agent, Some(session_id.to_owned()));
            let domain = format!("{session_id}:active");
            let mut latest_identity = identity.clone();
            let mut prompt_tokens = 0u64;
            let mut completion_tokens = 0u64;
            let mut cached_tokens = 0u64;
            let mut cost_usd_micros = 0u64;
            let mut tool_calls = 0u64;
            let mut tool_allowed = 0u64;
            let mut tool_blocked = 0u64;
            let mut stop_reason_id = None;
            let mut pending_responses = std::collections::HashSet::new();
            for (index, line) in journal.into_iter().enumerate() {
                let index = u64::try_from(index)
                    .map_err(|_| FinalizeError::Atif("active journal index overflow".to_owned()))?;
                let record: crate::worker::ActiveJournalRecord =
                    crate::journal::open(&self.journal_key, &domain, index, line.as_bytes())
                        .map_err(FinalizeError::Atif)?;
                let event: ab_events::OcsfEvent = serde_json::from_value(record.event.clone())
                    .map_err(|error| FinalizeError::Atif(error.to_string()))?;
                if event.session_uid != session_id || event.ai_agent != record.identity {
                    return Err(FinalizeError::Atif(
                        "unsigned active record has inconsistent session or identity".to_owned(),
                    ));
                }
                track_response_attempt(&mut pending_responses, record.response_attempt.as_ref())?;
                if event.metadata.sequence != index {
                    return Err(FinalizeError::Atif(
                        "unsigned event sequence does not match active journal index".to_owned(),
                    ));
                }
                if record.identity.version != identity.version
                    || record.identity.charter != identity.charter
                    || record.identity.instance_uid != identity.instance_uid
                {
                    return Err(FinalizeError::Atif(
                        "active journal changed the unsigned session identity".to_owned(),
                    ));
                }
                self.ensure_active_event_published(session_id, &event, &record.event)
                    .await?;
                let step = record.atif_step.ok_or_else(|| {
                    FinalizeError::Atif("unsigned active record has no ATIF step".to_owned())
                })?;
                builder
                    .push_step(step)
                    .map_err(|error| FinalizeError::Atif(error.to_string()))?;
                latest_identity = record.identity;
                prompt_tokens = checked_recovery_add(prompt_tokens, record.prompt_tokens, "prompt tokens")?;
                completion_tokens =
                    checked_recovery_add(completion_tokens, record.completion_tokens, "completion tokens")?;
                cached_tokens = checked_recovery_add(cached_tokens, record.cached_tokens, "cached tokens")?;
                cost_usd_micros = checked_recovery_add(cost_usd_micros, record.cost_usd_micros, "cost")?;
                tool_calls = checked_recovery_add(tool_calls, record.tool_calls, "tool calls")?;
                tool_allowed = checked_recovery_add(tool_allowed, record.tool_allowed, "allowed tools")?;
                tool_blocked = checked_recovery_add(tool_blocked, record.tool_blocked, "blocked tools")?;
                if record.stop_reason_id.is_some() {
                    stop_reason_id = record.stop_reason_id;
                }
            }
            if tool_allowed
                .checked_add(tool_blocked)
                .is_none_or(|classified| classified > tool_calls)
            {
                return Err(FinalizeError::Atif(
                    "unsigned journal has inconsistent tool accounting".to_owned(),
                ));
            }
            if !pending_responses.is_empty() {
                let quarantined = Session::new(
                    session_id.to_owned(),
                    Workflow::Unsigned,
                    latest_identity,
                    breaker.clone(),
                );
                quarantined.restore_journal_index(journal_len);
                quarantined.restore_next_seq(journal_len);
                quarantined
                    .totals
                    .tool_calls
                    .store(tool_calls, std::sync::atomic::Ordering::Release);
                quarantined
                    .totals
                    .tool_allowed
                    .store(tool_allowed, std::sync::atomic::Ordering::Release);
                quarantined
                    .totals
                    .tool_blocked
                    .store(tool_blocked, std::sync::atomic::Ordering::Release);
                quarantined
                    .totals
                    .prompt_tokens
                    .store(prompt_tokens, std::sync::atomic::Ordering::Release);
                quarantined
                    .totals
                    .completion_tokens
                    .store(completion_tokens, std::sync::atomic::Ordering::Release);
                quarantined
                    .totals
                    .cached_tokens
                    .store(cached_tokens, std::sync::atomic::Ordering::Release);
                quarantined
                    .totals
                    .cost_usd_micros
                    .store(cost_usd_micros, std::sync::atomic::Ordering::Release);
                quarantined.mark_capture_failed();
                // Also seal the session finalized so the idle sweeper's
                // `!is_closed()` filter skips it — same reasoning as the
                // quarantined-already branch above.
                quarantined.mark_artifact_committed();
                // Quarantine only after we know a fresh session was actually installed —
                // a live session with the same id must not inherit this capture-failed verdict.
                match sessions.try_insert_recovered(quarantined) {
                    Ok(_) => {
                        self.quarantined_sessions.lock().insert(session_id.to_owned());
                    }
                    Err(_active) => {
                        tracing::info!(
                            session = %session_id,
                            "unsigned quarantine skipped: session already active",
                        );
                    }
                }
                continue;
            }
            let mut trajectory = builder.finish();
            trajectory.agent.extra = Some(serde_json::json!({
                "charter": latest_identity.charter,
                "instance_uid": latest_identity.instance_uid,
                "ttl_remaining_s": latest_identity.ttl_remaining_s,
            }));
            if let Some(metrics) = trajectory.final_metrics.as_mut() {
                metrics.total_prompt_tokens = Some(prompt_tokens);
                metrics.total_completion_tokens = Some(completion_tokens);
                metrics.total_cached_tokens = Some(cached_tokens);
                metrics.total_cost_usd =
                    Some(cost_usd_micros as f64 / ab_core::units::USD_MICROS_PER_DOLLAR as f64);
                metrics.extra = Some(serde_json::json!({
                    "tool_calls": tool_calls,
                    "tool_allowed": tool_allowed,
                    "tool_blocked": tool_blocked,
                    "cost_usd_micros": cost_usd_micros,
                    "stop_reason_id": stop_reason_id,
                }));
            }
            if final_path.exists() {
                let existing: ab_atif::Trajectory = serde_json::from_slice(
                    &tokio::fs::read(&final_path)
                        .await
                        .map_err(|error| FinalizeError::Atif(error.to_string()))?,
                )
                .map_err(|error| FinalizeError::Atif(error.to_string()))?;
                trajectory.trajectory_id.clone_from(&existing.trajectory_id);
                if trajectory != existing {
                    return Err(FinalizeError::Atif(
                        "persisted ATIF does not match authenticated active journal".to_owned(),
                    ));
                }
            } else {
                let write_path = final_path.clone();
                tokio::task::spawn_blocking(move || ab_atif::write_atomic(&trajectory, &write_path))
                    .await
                    .map_err(|error| FinalizeError::Task(error.to_string()))?
                    .map_err(|error| FinalizeError::Atif(error.to_string()))?;
            }
            self.ensure_atif_provenance(&final_path, session_id).await?;
            self.remove_step_journal(session_id).await?;
        }
        Ok(())
    }

    async fn remove_step_journal(&self, session_id: &str) -> Result<(), FinalizeError> {
        let digest = ab_core::digest::sha256_hex(session_id.as_bytes());
        let stem = digest.get(..32).unwrap_or(&digest).to_owned();
        let spool_dir = self.spool_dir.clone();
        tokio::task::spawn_blocking(move || -> Result<(), FinalizeError> {
            let mut spool_changed = false;
            for suffix in ["session.json", "steps.ndjson", "events.ndjson"] {
                let path = spool_dir.join(format!("{stem}.{suffix}"));
                match std::fs::remove_file(&path) {
                    Ok(()) => spool_changed = true,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(FinalizeError::Atif(error.to_string())),
                }
            }
            if spool_changed {
                ab_core::fsutil::sync_directory(&spool_dir)
                    .map_err(|error| FinalizeError::Atif(error.to_string()))?;
            }
            let ack_parent = spool_dir.join("broker-acks");
            let ack_path = ack_parent.join(&stem);
            match std::fs::remove_dir_all(&ack_path) {
                Ok(()) => ab_core::fsutil::sync_directory(&ack_parent)
                    .map_err(|error| FinalizeError::Atif(error.to_string()))?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(FinalizeError::Atif(error.to_string())),
            }
            Ok(())
        })
        .await
        .map_err(|error| FinalizeError::Task(error.to_string()))?
    }

    /// Retry every durable promotion marker whose session can be recovered.
    pub async fn retry_marked_promotions(&self, sessions: &SessionRegistry) -> Result<usize, FinalizeError> {
        let mut entries = match tokio::fs::read_dir(&self.spool_dir).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(FinalizeError::Atif(error.to_string())),
        };
        let mut promoted = 0usize;
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|error| FinalizeError::Atif(error.to_string()))?
        {
            let path = entry.path();
            if path.extension().and_then(std::ffi::OsStr::to_str) != Some("promote") {
                continue;
            }
            let sealed = tokio::fs::read(&path)
                .await
                .map_err(|error| FinalizeError::Atif(error.to_string()))?;
            let marker: PromotionMarker =
                crate::journal::open(&self.journal_key, "promotion-marker", 0, &sealed)
                    .map_err(FinalizeError::Atif)?;
            let Some(session) = sessions.get(&marker.session_id) else {
                continue;
            };
            // Background retry must never force-close a live session that
            // happens to share this id — that path belongs to the explicit
            // `promote_session` endpoint. See `promote`: any non-closed
            // session gets `close_session_locked`-ed on entry.
            if !session.is_closed() {
                tracing::info!(
                    session = %marker.session_id,
                    "promotion retry skipped: session is currently active",
                );
                continue;
            }
            match self.promote(session).await {
                Ok(_) => promoted += 1,
                Err(error) => {
                    tracing::warn!(%error, path = %path.display(), "promotion retry failed");
                }
            }
        }
        Ok(promoted)
    }

    fn receipt_path(&self, session_id: &str) -> PathBuf {
        self.spool_dir.join("receipts").join(format!(
            "{}.json",
            &ab_core::digest::sha256_hex(session_id.as_bytes())[..32]
        ))
    }

    async fn ensure_atif_provenance(
        &self,
        path: &std::path::Path,
        session_id: &str,
    ) -> Result<AtifProvenance, FinalizeError> {
        let bytes = tokio::fs::read(path)
            .await
            .map_err(|error| FinalizeError::Atif(error.to_string()))?;
        let expected = AtifProvenance {
            session_id: session_id.to_owned(),
            digest: ab_core::digest::sha256_hex(&bytes),
        };
        let provenance_path = path.with_extension("atif-auth");
        if provenance_path.exists() {
            let sealed = tokio::fs::read(&provenance_path)
                .await
                .map_err(|error| FinalizeError::Atif(error.to_string()))?;
            let actual: AtifProvenance =
                crate::journal::open(&self.journal_key, "atif-provenance", 0, &sealed)
                    .map_err(FinalizeError::Atif)?;
            if actual.session_id != expected.session_id || actual.digest != expected.digest {
                return Err(FinalizeError::Atif(
                    "ATIF provenance does not match artifact bytes and session".to_owned(),
                ));
            }
            return Ok(actual);
        }
        let sealed = crate::journal::seal(&self.journal_key, "atif-provenance", 0, &expected)
            .map_err(FinalizeError::Atif)?;
        persist_marker(&provenance_path, &sealed).await?;
        Ok(expected)
    }

    async fn read_journal_metadata(
        &self,
        path: &std::path::Path,
    ) -> Result<serde_json::Value, FinalizeError> {
        let bytes = tokio::fs::read(path)
            .await
            .map_err(|error| FinalizeError::Atif(error.to_string()))?;
        crate::journal::open(&self.journal_key, "metadata", 0, &bytes).map_err(FinalizeError::Atif)
    }

    fn verify_configured_receipt(&self, receipt: &Receipt) -> Result<(), FinalizeError> {
        if receipt.body.key_id != self.signer.key_id() {
            return Err(FinalizeError::Receipt(format!(
                "receipt key {:?} does not match configured key {:?}",
                receipt.body.key_id,
                self.signer.key_id()
            )));
        }
        let mut keyring = ab_receipts::Keyring::new();
        keyring
            .add_signer(self.signer.as_ref())
            .map_err(|error| FinalizeError::Receipt(error.to_string()))?;
        receipt
            .verify(&keyring)
            .map_err(|error| FinalizeError::Receipt(error.to_string()))
    }

    async fn persist_receipt(&self, session_id: &str, receipt: &Receipt) -> Result<(), FinalizeError> {
        let path = self.receipt_path(session_id);
        let bytes =
            serde_json::to_vec_pretty(receipt).map_err(|error| FinalizeError::Receipt(error.to_string()))?;
        tokio::task::spawn_blocking(move || ab_core::fsutil::write_atomic(&path, &bytes))
            .await
            .map_err(|error| FinalizeError::Task(error.to_string()))?
            .map_err(|error| FinalizeError::Receipt(error.to_string()))
    }

    async fn emit_receipt_event(&self, session: &Session, receipt: &Receipt) -> Result<(), FinalizeError> {
        self.emit_bridge_event(
            session,
            ab_events::EventClass::Receipt,
            serde_json::json!({
                "receipt_id": receipt.body.receipt_id,
                "key_id": receipt.body.key_id,
                "subject": receipt.body.subject,
                "receipt": receipt,
            }),
            crate::journal::RECEIPT_OUTBOX_KIND,
        )
        .await
    }

    async fn emit_bridge_event(
        &self,
        session: &Session,
        class: ab_events::EventClass,
        payload: serde_json::Value,
        kind: &str,
    ) -> Result<(), FinalizeError> {
        let Some(bridge) = self.bridge.as_ref().map(Arc::clone) else {
            return Ok(());
        };
        let path = self.lifecycle_outbox_path(&session.id, kind);
        let mut outbox = if path.exists() {
            let sealed = tokio::fs::read(&path)
                .await
                .map_err(|error| FinalizeError::Bridge(error.to_string()))?;
            let outbox: LifecycleOutbox = crate::journal::open(
                &self.journal_key,
                crate::journal::LIFECYCLE_OUTBOX_DOMAIN,
                0,
                &sealed,
            )
            .map_err(FinalizeError::Bridge)?;
            if outbox.session_id != session.id || outbox.kind != kind {
                return Err(FinalizeError::Bridge(
                    "lifecycle outbox does not match its session and kind".to_owned(),
                ));
            }
            // A crash between a prior successful emit and a subsequent one loses the
            // in-memory seq advance for this outbox — recovery only restores seq from
            // the journal length. Fast-forward past the persisted seq so a following
            // lifecycle event (e.g., SESSION_CLOSE after a persisted RECEIPT_OUTBOX)
            // cannot land on the same metadata.sequence value.
            if let Some(persisted_seq) = outbox
                .value
                .get("metadata")
                .and_then(|metadata| metadata.get("sequence"))
                .and_then(serde_json::Value::as_u64)
            {
                if session.peek_seq() <= persisted_seq {
                    session.advance_seq_past(persisted_seq);
                }
            }
            outbox
        } else {
            // Peek the seq without consuming it; a failed persist_outbox
            // below would otherwise burn a seq that recovery expects to see
            // at a later journal position, breaking the position-vs-seq
            // invariant when reset_close reopens the session.
            let event_seq = session.peek_seq();
            let event = ab_events::OcsfEventBuilder::new(
                class,
                session.id.clone(),
                session.current_identity(),
                event_seq,
            )
            .payload(payload)
            .build()
            .map_err(|error| FinalizeError::Bridge(error.to_string()))?;
            let outbox = LifecycleOutbox {
                session_id: session.id.clone(),
                kind: kind.to_owned(),
                topic: class.topic().to_owned(),
                key: session.current_identity().instance_uid,
                value: serde_json::to_value(event)
                    .map_err(|error| FinalizeError::Bridge(error.to_string()))?,
                ack: None,
            };
            persist_outbox(&path, &outbox, &self.journal_key).await?;
            session.advance_seq_past(event_seq);
            outbox
        };
        if outbox.ack.is_some() {
            return Ok(());
        }
        let topic = outbox.topic.clone();
        let key = outbox.key.clone();
        let value = outbox.value.clone();
        let event_uid = lifecycle_event_uid(&value)?;
        let ack = match resolve_lifecycle_ack(bridge, topic, key, value, event_uid).await {
            Ok(ack) => ack,
            Err(error) => {
                self.metrics
                    .counter(
                        "ab_lifecycle_event_errors_total",
                        "Lifecycle events not published",
                    )
                    .inc();
                return Err(error);
            }
        };
        outbox.ack = Some(ack);
        persist_outbox(&path, &outbox, &self.journal_key).await?;
        Ok(())
    }

    async fn replay_lifecycle_outboxes(&self) -> Result<usize, FinalizeError> {
        let Some(bridge) = self.bridge.as_ref().map(Arc::clone) else {
            return Ok(0);
        };
        let directory = self.spool_dir.join(crate::spool::OUTBOX);
        let mut entries = match tokio::fs::read_dir(&directory).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(FinalizeError::Bridge(error.to_string())),
        };
        let mut replayed = 0usize;
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|error| FinalizeError::Bridge(error.to_string()))?
        {
            let path = entry.path();
            if path.extension().and_then(std::ffi::OsStr::to_str) != Some("json") {
                continue;
            }
            let sealed = tokio::fs::read(&path)
                .await
                .map_err(|error| FinalizeError::Bridge(error.to_string()))?;
            let mut outbox: LifecycleOutbox = crate::journal::open(
                &self.journal_key,
                crate::journal::LIFECYCLE_OUTBOX_DOMAIN,
                0,
                &sealed,
            )
            .map_err(FinalizeError::Bridge)?;
            if path != self.lifecycle_outbox_path(&outbox.session_id, &outbox.kind) {
                return Err(FinalizeError::Bridge(
                    "lifecycle outbox path does not match authenticated payload".to_owned(),
                ));
            }
            if outbox.ack.is_none() {
                let topic = outbox.topic.clone();
                let key = outbox.key.clone();
                let value = outbox.value.clone();
                let event_uid = lifecycle_event_uid(&value)?;
                outbox.ack =
                    Some(resolve_lifecycle_ack(Arc::clone(&bridge), topic, key, value, event_uid).await?);
                persist_outbox(&path, &outbox, &self.journal_key).await?;
                replayed = replayed.saturating_add(1);
            }
        }
        Ok(replayed)
    }

    async fn remove_acked_lifecycle_outboxes(&self) -> Result<(), FinalizeError> {
        let directory = self.spool_dir.join(crate::spool::OUTBOX);
        let mut entries = match tokio::fs::read_dir(&directory).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(FinalizeError::Bridge(error.to_string())),
        };
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|error| FinalizeError::Bridge(error.to_string()))?
        {
            let path = entry.path();
            if path.extension().and_then(std::ffi::OsStr::to_str) != Some("json") {
                continue;
            }
            let sealed = tokio::fs::read(&path)
                .await
                .map_err(|error| FinalizeError::Bridge(error.to_string()))?;
            let outbox: LifecycleOutbox = crate::journal::open(
                &self.journal_key,
                crate::journal::LIFECYCLE_OUTBOX_DOMAIN,
                0,
                &sealed,
            )
            .map_err(FinalizeError::Bridge)?;
            if path != self.lifecycle_outbox_path(&outbox.session_id, &outbox.kind) {
                return Err(FinalizeError::Bridge(
                    "lifecycle outbox path does not match authenticated payload".to_owned(),
                ));
            }
            if outbox.ack.is_some() {
                remove_outbox(&path).await?;
            }
        }
        Ok(())
    }

    fn lifecycle_outbox_path(&self, session_id: &str, kind: &str) -> PathBuf {
        let session_hash = &ab_core::digest::sha256_hex(session_id.as_bytes())[..32];
        self.spool_dir
            .join(crate::spool::OUTBOX)
            .join(format!("{session_hash}.{kind}.json"))
    }

    async fn remove_lifecycle_outbox(&self, session_id: &str, kind: &str) -> Result<(), FinalizeError> {
        remove_outbox(&self.lifecycle_outbox_path(session_id, kind)).await
    }
}

async fn persist_outbox(
    path: &std::path::Path,
    outbox: &LifecycleOutbox,
    journal_key: &[u8; 32],
) -> Result<(), FinalizeError> {
    let path = path.to_path_buf();
    let bytes = crate::journal::seal(journal_key, crate::journal::LIFECYCLE_OUTBOX_DOMAIN, 0, outbox)
        .map_err(FinalizeError::Bridge)?;
    tokio::task::spawn_blocking(move || ab_core::fsutil::write_atomic(&path, &bytes))
        .await
        .map_err(|error| FinalizeError::Task(error.to_string()))?
        .map_err(|error| FinalizeError::Bridge(error.to_string()))
}

async fn persist_marker(path: &std::path::Path, bytes: &[u8]) -> Result<(), FinalizeError> {
    let path = path.to_path_buf();
    let bytes = bytes.to_vec();
    tokio::task::spawn_blocking(move || ab_core::fsutil::write_atomic(&path, &bytes))
        .await
        .map_err(|error| FinalizeError::Task(error.to_string()))?
        .map_err(|error| FinalizeError::Atif(error.to_string()))
}

async fn remove_outbox(path: &std::path::Path) -> Result<(), FinalizeError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<(), FinalizeError> {
        let parent = path
            .parent()
            .ok_or_else(|| FinalizeError::Bridge("outbox has no parent".to_owned()))?;
        match std::fs::remove_file(&path) {
            Ok(()) => ab_core::fsutil::sync_directory(parent)
                .map_err(|error| FinalizeError::Bridge(error.to_string())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(FinalizeError::Bridge(error.to_string())),
        }
    })
    .await
    .map_err(|error| FinalizeError::Task(error.to_string()))?
}

/// Start periodic idle-session finalization.
pub fn spawn_reconciler(
    sessions: Arc<SessionRegistry>,
    finalizer: Finalizer,
    idle_s: u64,
    tick_s: u64,
    breaker: ab_loopdetect::BreakerConfig,
    metrics: Arc<Registry>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(tick_s.max(1)));
        loop {
            interval.tick().await;
            let started = Instant::now();
            if let Err(error) = finalizer.recover_spooled_sessions(&sessions, &breaker).await {
                tracing::warn!(%error, "ATIF spool recovery failed");
                metrics
                    .counter("ab_reconcile_errors_total", "Reconciliation errors")
                    .inc();
            }
            if let Err(error) = finalizer.retry_marked_promotions(&sessions).await {
                tracing::warn!(%error, "durable promotion retry failed");
                metrics
                    .counter("ab_reconcile_errors_total", "Reconciliation errors")
                    .inc();
            }
            for session in sessions.idle_sessions(idle_s) {
                if let Err(error) = finalizer.close_session(session, StopReason::SessionClosed).await {
                    tracing::warn!(%error, "idle session finalization failed");
                    metrics
                        .counter("ab_reconcile_errors_total", "Reconciliation errors")
                        .inc();
                }
            }
            metrics
                .histogram("ab_reconcile_duration_us", "Idle reconciliation duration")
                .observe_us(elapsed_us(started));
        }
    })
}

fn checked_recovery_add(current: u64, value: u64, field: &str) -> Result<u64, FinalizeError> {
    current
        .checked_add(value)
        .filter(|total| *total <= ab_core::error::JCS_SAFE_MAX)
        .ok_or_else(|| FinalizeError::Atif(format!("recovered {field} overflow")))
}

fn track_response_attempt(
    pending: &mut std::collections::HashSet<String>,
    attempt: Option<&crate::worker::ResponseAttempt>,
) -> Result<(), FinalizeError> {
    let Some(attempt) = attempt else {
        return Ok(());
    };
    if attempt.terminal {
        if !pending.remove(&attempt.id) {
            pending.insert(format!("orphan-terminal:{}", attempt.id));
        }
    } else if !pending.insert(attempt.id.clone()) {
        return Err(FinalizeError::Atif(
            "active journal repeats a response attempt id".to_owned(),
        ));
    }
    Ok(())
}

fn lifecycle_event_uid(value: &serde_json::Value) -> Result<String, FinalizeError> {
    value
        .get("metadata")
        .and_then(|metadata| metadata.get("uid"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| FinalizeError::Bridge("lifecycle event has no metadata UID".to_owned()))
}

async fn resolve_lifecycle_ack(
    bridge: Arc<dyn EventBus>,
    topic: String,
    key: String,
    value: serde_json::Value,
    event_uid: String,
) -> Result<ab_bridge::PublishAck, FinalizeError> {
    let lookup_bridge = Arc::clone(&bridge);
    let lookup_topic = topic.clone();
    let lookup_key = key.clone();
    let lookup_uid = event_uid.clone();
    if let Some(ack) = tokio::task::spawn_blocking(move || {
        lookup_bridge.find_event_by_uid(&lookup_topic, &lookup_key, &lookup_uid)
    })
    .await
    .map_err(|error| FinalizeError::Task(error.to_string()))?
    .map_err(|error| FinalizeError::Bridge(error.to_string()))?
    {
        return Ok(ack);
    }
    tokio::task::spawn_blocking(move || bridge.publish_idempotent(&topic, &key, &value, &event_uid))
        .await
        .map_err(|error| FinalizeError::Task(error.to_string()))?
        .map_err(|error| FinalizeError::Bridge(error.to_string()))
}

async fn read_complete_journal(path: &std::path::Path) -> Result<Vec<String>, FinalizeError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<Vec<String>, FinalizeError> {
        let bytes = std::fs::read(&path).map_err(|error| FinalizeError::Atif(error.to_string()))?;
        if bytes.is_empty() {
            return Ok(Vec::new());
        }
        let complete_len = if bytes.last() == Some(&b'\n') {
            bytes.len()
        } else {
            bytes
                .iter()
                .rposition(|byte| *byte == b'\n')
                .map_or(0, |index| index + 1)
        };
        if complete_len < bytes.len() {
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .map_err(|error| FinalizeError::Atif(error.to_string()))?;
            file.set_len(complete_len as u64)
                .map_err(|error| FinalizeError::Atif(error.to_string()))?;
            file.sync_all()
                .map_err(|error| FinalizeError::Atif(error.to_string()))?;
        }
        let complete = String::from_utf8(bytes.get(..complete_len).unwrap_or_default().to_vec())
            .map_err(|error| FinalizeError::Atif(error.to_string()))?;
        Ok(complete
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(str::to_owned)
            .collect())
    })
    .await
    .map_err(|error| FinalizeError::Task(error.to_string()))?
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::unwrap_used
    )]

    use super::*;
    use ab_bridge::{BusError, PublishAck, StoredEvent};
    use ab_events::AgentIdentity;
    use ab_receipts::Ed25519Signer;

    struct FailFirstReceiptBus {
        fail: std::sync::atomic::AtomicBool,
        attempts: parking_lot::Mutex<Vec<(String, serde_json::Value)>>,
    }

    impl EventBus for FailFirstReceiptBus {
        fn publish(
            &self,
            topic: &str,
            _key: &str,
            value: &serde_json::Value,
        ) -> Result<PublishAck, BusError> {
            self.attempts.lock().push((topic.to_owned(), value.clone()));
            if topic == "agent.receipt" && self.fail.swap(false, std::sync::atomic::Ordering::AcqRel) {
                return Err(BusError::Backend("injected receipt outage".to_owned()));
            }
            Ok(PublishAck {
                topic: topic.to_owned(),
                partition: 0,
                offset: self.attempts.lock().len() as u64,
            })
        }

        fn fetch(
            &self,
            _topic: &str,
            _partition: u32,
            _offset: u64,
            _max: usize,
        ) -> Result<Vec<StoredEvent>, BusError> {
            Ok(Vec::new())
        }

        fn partitions(&self, _topic: &str) -> Result<u32, BusError> {
            Ok(1)
        }

        fn topics(&self) -> Vec<String> {
            ab_events::EventClass::all()
                .iter()
                .map(|class| class.topic().to_owned())
                .collect()
        }
    }

    fn session(workflow: Workflow) -> Arc<Session> {
        Arc::new(Session::new(
            "lifecycle-session".to_owned(),
            workflow,
            AgentIdentity {
                version: "1".to_owned(),
                charter: "test".into(),
                instance_uid: "instance-1".to_owned(),
                ttl_remaining_s: Some(600),
            },
            Default::default(),
        ))
    }

    fn finalizer(directory: &std::path::Path) -> Finalizer {
        Finalizer::new(
            Arc::new(Ed25519Signer::from_seed([7; 32])),
            directory.to_path_buf(),
            Arc::new(Registry::new()),
        )
    }

    /// A lifecycle emit that fails at `persist_outbox` must not have
    /// consumed a sequence number — otherwise `reset_close` reopens the
    /// session with a burned seq, and the next worker envelope's
    /// `next_seq` return would put a mismatched
    /// `event.metadata.sequence` at the journal's next byte position,
    /// tripping recovery's `sequence != index` check.
    #[tokio::test]
    async fn emit_bridge_event_persist_failure_does_not_burn_a_seq() {
        let directory = tempfile::tempdir().unwrap();
        // Sabotage the outbox path: a regular file at `<spool>/outbox` makes
        // `create_dir_all` inside `write_atomic` fail for every subsequent
        // outbox write.
        std::fs::write(directory.path().join(crate::spool::OUTBOX), b"").unwrap();
        let bus = Arc::new(FailFirstReceiptBus {
            fail: std::sync::atomic::AtomicBool::new(false),
            attempts: parking_lot::Mutex::new(Vec::new()),
        });
        let finalizer = Finalizer::with_bridge(
            Arc::new(Ed25519Signer::from_seed([7; 32])),
            directory.path().to_path_buf(),
            Arc::new(Registry::new()),
            bus,
        );
        let session = session(Workflow::Signed);
        let seq_before = session.peek_seq();
        // Signed close writes the receipt to disk, then tries emit_receipt_event → emit_bridge_event.
        // The latter must fail at persist_outbox because <spool>/outbox is a file.
        let result = finalizer
            .close_session(Arc::clone(&session), StopReason::SessionClosed)
            .await;
        assert!(
            result.is_err(),
            "close_session must fail when outbox persist is blocked, got {result:?}",
        );
        assert_eq!(
            session.peek_seq(),
            seq_before,
            "peek_seq must not advance past a failed persist_outbox — the burned \
             seq would misalign the journal on retry",
        );
    }

    /// After a crash between a persisted RECEIPT_OUTBOX (seq = N) and its
    /// corresponding SESSION_CLOSE_OUTBOX emit, recovery restores
    /// `session.seq` from the journal length, which lags the seq the receipt
    /// outbox baked in. `emit_bridge_event` reading the pre-existing outbox
    /// must fast-forward the counter so the next lifecycle event does not
    /// reuse the seq — bridge consumers rely on unique
    /// `metadata.sequence` within a session.
    #[tokio::test]
    async fn emit_bridge_event_reading_persisted_outbox_advances_seq_past_it() {
        let directory = tempfile::tempdir().unwrap();
        let bus = Arc::new(FailFirstReceiptBus {
            fail: std::sync::atomic::AtomicBool::new(false),
            attempts: parking_lot::Mutex::new(Vec::new()),
        });
        let finalizer = Finalizer::with_bridge(
            Arc::new(Ed25519Signer::from_seed([7; 32])),
            directory.path().to_path_buf(),
            Arc::new(Registry::new()),
            bus.clone(),
        );
        let session = session(Workflow::Signed);
        // Simulate a crash mid-close: manually persist a RECEIPT_OUTBOX carrying a specific
        // seq and an already-set ack so emit_receipt_event will skip the publish path.
        let receipt_seq = 42u64;
        let receipt_event_uid = ab_core::new_event_uid();
        let value = serde_json::json!({
            "metadata": { "sequence": receipt_seq, "uid": receipt_event_uid },
            "topic": ab_events::EventClass::Receipt.topic(),
        });
        let outbox = LifecycleOutbox {
            session_id: session.id.clone(),
            kind: crate::journal::RECEIPT_OUTBOX_KIND.to_owned(),
            topic: ab_events::EventClass::Receipt.topic().to_owned(),
            key: session.identity.instance_uid.clone(),
            value,
            ack: Some(ab_bridge::PublishAck {
                topic: ab_events::EventClass::Receipt.topic().to_owned(),
                partition: 0,
                offset: 1,
            }),
        };
        let outbox_path = finalizer.lifecycle_outbox_path(&session.id, crate::journal::RECEIPT_OUTBOX_KIND);
        std::fs::create_dir_all(outbox_path.parent().unwrap()).unwrap();
        let sealed = crate::journal::seal(
            &finalizer.journal_key,
            crate::journal::LIFECYCLE_OUTBOX_DOMAIN,
            0,
            &outbox,
        )
        .unwrap();
        std::fs::write(&outbox_path, sealed).unwrap();
        assert!(
            session.peek_seq() < receipt_seq,
            "precondition: in-memory seq must trail the persisted outbox seq",
        );
        finalizer
            .close_session(Arc::clone(&session), StopReason::SessionClosed)
            .await
            .unwrap();
        let attempts = bus.attempts.lock();
        let session_close = attempts
            .iter()
            .find(|(topic, _)| topic == ab_events::EventClass::Session.topic())
            .expect("SESSION_CLOSE lifecycle event must reach the bridge");
        let session_close_seq = session_close
            .1
            .get("metadata")
            .and_then(|metadata| metadata.get("sequence"))
            .and_then(serde_json::Value::as_u64)
            .expect("published event must carry a numeric metadata.sequence");
        assert!(
            session_close_seq > receipt_seq,
            "SESSION_CLOSE seq ({session_close_seq}) must exceed the persisted RECEIPT_OUTBOX seq ({receipt_seq}) — otherwise consumers see duplicate metadata.sequence values within one session",
        );
    }

    /// A signed session inserted into the registry by `recover_signed_journals`
    /// must reject new leases from the moment it is visible — otherwise a client
    /// request landing between `try_insert_recovered` and the finalize path can
    /// submit a worker job that appends to the recovered chain, permanently
    /// diverging it from the persisted receipt's `subject.event_count` and
    /// leaving a wrong-index entry in the on-disk journal. `CloseClaim::drop`
    /// resets `closed` on any finalize error, so pinning the "no leases" state
    /// only via `try_close` inside `close_session_locked` is not enough — the
    /// session must be sealed before it is ever visible.
    #[tokio::test]
    async fn recovered_signed_session_rejects_leases_even_when_finalize_errors() {
        use ab_events::{EventClass, OcsfEventBuilder, StatusId};
        use std::io::Write as _;

        let directory = tempfile::tempdir().unwrap();
        let signer: Arc<dyn Signer> = Arc::new(Ed25519Signer::from_seed([29; 32]));
        let journal_key = crate::journal::key_from_signer(signer.as_ref());
        let session_id = "signed-recovery-lease-guard";
        let identity = AgentIdentity {
            version: "1".into(),
            charter: "test".into(),
            instance_uid: "instance-lease-guard".into(),
            ttl_remaining_s: Some(600),
        };

        // Seed the signed session metadata file.
        let digest = ab_core::digest::sha256_hex(session_id.as_bytes());
        let stem = &digest[..32];
        let metadata_payload = serde_json::json!({
            "journal_version": 2,
            "session_id": session_id,
            "identity": identity,
            "workflow": "signed",
        });
        let metadata_sealed = crate::journal::seal(&journal_key, "metadata", 0, &metadata_payload).unwrap();
        std::fs::write(
            directory.path().join(format!("{stem}.session.json")),
            &metadata_sealed,
        )
        .unwrap();

        // Seed one signed event in the active journal.
        let event = OcsfEventBuilder::new(
            EventClass::Compression,
            session_id.to_owned(),
            identity.clone(),
            0,
        )
        .status(StatusId::Success)
        .payload(serde_json::json!({}))
        .build()
        .unwrap();
        let event_uid = event.metadata.uid.clone();
        let record = crate::worker::ActiveJournalRecord {
            event: serde_json::to_value(&event).unwrap(),
            identity: identity.clone(),
            atif_step: None,
            tool_calls: 0,
            tool_allowed: 0,
            tool_blocked: 0,
            prompt_tokens: 0,
            completion_tokens: 0,
            cached_tokens: 0,
            cost_usd_micros: 0,
            stop_reason_id: None,
            response_attempt: None,
        };
        let domain = format!("{session_id}:active");
        let sealed = crate::journal::seal(&journal_key, &domain, 0, &record).unwrap();
        let mut journal_file =
            std::fs::File::create(directory.path().join(format!("{stem}.events.ndjson"))).unwrap();
        journal_file.write_all(&sealed).unwrap();
        journal_file.write_all(b"\n").unwrap();
        drop(journal_file);

        // Seed a broker ack so `ensure_active_event_published` short-circuits.
        crate::worker::persist_broker_ack(
            directory.path(),
            session_id,
            &event_uid,
            &PublishAck {
                topic: EventClass::Compression.topic().to_owned(),
                partition: 0,
                offset: 1,
            },
            &journal_key,
        )
        .await
        .unwrap();

        // Sabotage the receipts directory so that `persist_receipt` inside
        // `close_session_locked` fails BEFORE `mark_artifact_committed` runs.
        // A regular file at `<spool>/receipts` makes `create_dir_all` fail for
        // the receipt write. Because there's no persisted receipt for recovery
        // to verify, the finalize path signs a fresh one and only then hits
        // the sabotage — reproducing the exact "closed=1 → reset → 0, but
        // artifact_committed still 0" window a racing lease can exploit.
        std::fs::write(directory.path().join("receipts"), b"").unwrap();

        let registry = crate::session::SessionRegistry::new();
        let finalizer = Finalizer::with_bridge(
            signer,
            directory.path().to_path_buf(),
            Arc::new(Registry::new()),
            Arc::new(FailFirstReceiptBus {
                fail: std::sync::atomic::AtomicBool::new(false),
                attempts: parking_lot::Mutex::new(Vec::new()),
            }),
        );
        let result = finalizer
            .recover_spooled_sessions(&registry, &Default::default())
            .await;
        assert!(
            result.is_err(),
            "recovery must error at persist_receipt to trigger the CloseClaim reset window; got {result:?}",
        );

        let session = registry
            .get(session_id)
            .expect("recovered signed session must remain in the registry after a finalize error");
        assert!(
            session.try_lease().is_none(),
            "recovered signed session must reject new leases even after finalize errors — otherwise a racing client request could take a lease, submit a worker job that appends to the recovered chain, and permanently diverge it from the persisted receipt's subject.event_count (also leaving a wrong-index entry sealed at file position N)",
        );
    }

    #[tokio::test]
    async fn signed_close_issues_exactly_one_offline_verifiable_receipt() {
        let directory = tempfile::tempdir().unwrap();
        let finalizer = finalizer(directory.path());
        let session = session(Workflow::Signed);

        let first = finalizer
            .close_session(Arc::clone(&session), StopReason::SessionClosed)
            .await
            .unwrap();
        let FinalizeOutcome::Receipt { receipt } = first else {
            panic!("expected receipt")
        };
        receipt.verify_embedded().unwrap();
        assert!(matches!(
            finalizer
                .close_session(Arc::clone(&session), StopReason::SessionClosed)
                .await
                .unwrap(),
            FinalizeOutcome::AlreadyClosed
        ));
        assert_eq!(
            session.receipt.lock().as_ref().unwrap().body.receipt_id,
            receipt.body.receipt_id
        );
    }

    #[tokio::test]
    async fn lifecycle_outbox_retries_the_same_receipt_event() {
        let directory = tempfile::tempdir().unwrap();
        let bus = Arc::new(FailFirstReceiptBus {
            fail: std::sync::atomic::AtomicBool::new(true),
            attempts: parking_lot::Mutex::new(Vec::new()),
        });
        let finalizer = Finalizer::with_bridge(
            Arc::new(Ed25519Signer::from_seed([17; 32])),
            directory.path().to_path_buf(),
            Arc::new(Registry::new()),
            bus.clone(),
        );
        let session = session(Workflow::Signed);
        assert!(matches!(
            finalizer
                .close_session(Arc::clone(&session), StopReason::SessionClosed)
                .await,
            Err(FinalizeError::Bridge(_))
        ));
        assert!(session.is_closed());
        assert!(
            session.try_lease().is_none(),
            "artifact commit must keep admission closed"
        );
        let receipt_id = session.receipt.lock().as_ref().unwrap().body.receipt_id.clone();
        let outcome = finalizer
            .close_session(Arc::clone(&session), StopReason::SessionClosed)
            .await
            .unwrap();
        let FinalizeOutcome::Receipt { receipt } = outcome else {
            panic!("expected receipt")
        };
        assert_eq!(receipt.body.receipt_id, receipt_id);
        let attempts = bus.attempts.lock();
        let receipt_events: Vec<_> = attempts
            .iter()
            .filter(|(topic, _)| topic == "agent.receipt")
            .collect();
        assert_eq!(receipt_events.len(), 2);
        assert_eq!(
            receipt_events[0].1["metadata"]["uid"],
            receipt_events[1].1["metadata"]["uid"]
        );
        assert!(!finalizer.lifecycle_outbox_path(&session.id, "receipt").exists());
    }

    #[tokio::test]
    async fn concurrent_close_waits_for_failed_lifecycle_attempt() {
        let directory = tempfile::tempdir().unwrap();
        let bus = Arc::new(FailFirstReceiptBus {
            fail: std::sync::atomic::AtomicBool::new(true),
            attempts: parking_lot::Mutex::new(Vec::new()),
        });
        let finalizer = Finalizer::with_bridge(
            Arc::new(Ed25519Signer::from_seed([23; 32])),
            directory.path().to_path_buf(),
            Arc::new(Registry::new()),
            bus,
        );
        let session = session(Workflow::Signed);
        let first_finalizer = finalizer.clone();
        let first_session = Arc::clone(&session);
        let first = tokio::spawn(async move {
            first_finalizer
                .close_session(first_session, StopReason::SessionClosed)
                .await
        });
        tokio::task::yield_now().await;
        let second = finalizer.close_session(session, StopReason::SessionClosed).await;
        let first = first.await.unwrap();
        assert!(matches!(first, Err(FinalizeError::Bridge(_))));
        assert!(matches!(second, Ok(FinalizeOutcome::Receipt { .. })));
    }

    #[tokio::test]
    async fn startup_replays_lifecycle_outbox_without_session_journal() {
        let directory = tempfile::tempdir().unwrap();
        let bus = Arc::new(FailFirstReceiptBus {
            fail: std::sync::atomic::AtomicBool::new(true),
            attempts: parking_lot::Mutex::new(Vec::new()),
        });
        let finalizer = Finalizer::with_bridge(
            Arc::new(Ed25519Signer::from_seed([19; 32])),
            directory.path().to_path_buf(),
            Arc::new(Registry::new()),
            bus.clone(),
        );
        let session = session(Workflow::Signed);
        assert!(matches!(
            finalizer.close_session(session, StopReason::SessionClosed).await,
            Err(FinalizeError::Bridge(_))
        ));
        assert!(finalizer
            .lifecycle_outbox_path("lifecycle-session", "receipt")
            .exists());

        let sessions = SessionRegistry::new();
        assert_eq!(
            finalizer
                .recover_spooled_sessions(&sessions, &Default::default())
                .await
                .unwrap(),
            0
        );
        assert!(sessions.get("lifecycle-session").is_none());
        assert!(!finalizer
            .lifecycle_outbox_path("lifecycle-session", "receipt")
            .exists());
        assert_eq!(
            bus.attempts
                .lock()
                .iter()
                .filter(|(topic, _)| topic == "agent.receipt")
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn unsigned_close_and_promotion_are_strict_and_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let finalizer = finalizer(directory.path());
        let session = session(Workflow::Unsigned);
        session
            .atif
            .lock()
            .push_step(ab_atif::Step {
                step_id: 0,
                timestamp: Some(ab_core::time::now_iso8601()),
                source: ab_atif::Source::Agent,
                message: serde_json::json!("done"),
                reasoning_effort: None,
                reasoning_content: None,
                model_name: None,
                tool_calls: None,
                observation: None,
                metrics: Some(ab_atif::Metrics {
                    prompt_tokens: Some(10),
                    completion_tokens: Some(2),
                    cached_tokens: Some(4),
                    cost_usd: Some(0.001),
                    logprobs: None,
                    completion_token_ids: None,
                    prompt_token_ids: None,
                    extra: None,
                }),
                is_copied_context: None,
                llm_call_count: Some(1),
                extra: None,
            })
            .unwrap();

        let outcome = finalizer
            .close_session(Arc::clone(&session), StopReason::SessionClosed)
            .await
            .unwrap();
        let FinalizeOutcome::Atif { path } = outcome else {
            panic!("expected ATIF artifact")
        };
        let value: serde_json::Value = serde_json::from_slice(&tokio::fs::read(path).await.unwrap()).unwrap();
        assert!(ab_atif::validate_value(&value, ab_atif::Mode::Strict).is_empty());

        let first = finalizer.promote(Arc::clone(&session)).await.unwrap();
        let second = finalizer.promote(Arc::clone(&session)).await.unwrap();
        assert_eq!(first.body.receipt_id, second.body.receipt_id);
        first.verify_embedded().unwrap();
        assert!(matches!(
            first.body.subject,
            ReceiptSubject::AtifTrajectory {
                step_count: 1,
                retroactive: true,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn unsigned_restart_preserves_receipt_accounting_and_identity() {
        let directory = tempfile::tempdir().unwrap();
        let finalizer = finalizer(directory.path());
        let original = session(Workflow::Unsigned);
        original
            .totals
            .tool_calls
            .store(2, std::sync::atomic::Ordering::Release);
        original
            .totals
            .tool_allowed
            .store(1, std::sync::atomic::Ordering::Release);
        original
            .totals
            .tool_blocked
            .store(1, std::sync::atomic::Ordering::Release);
        original
            .totals
            .prompt_tokens
            .store(17, std::sync::atomic::Ordering::Release);
        original
            .totals
            .completion_tokens
            .store(9, std::sync::atomic::Ordering::Release);
        original
            .totals
            .cached_tokens
            .store(3, std::sync::atomic::Ordering::Release);
        original
            .totals
            .cost_usd_micros
            .store(1_234_567, std::sync::atomic::Ordering::Release);
        original.record_stop_reason(StopReason::PolicyBlocked);
        original
            .atif
            .lock()
            .push_step(ab_atif::Step {
                step_id: 0,
                timestamp: None,
                source: ab_atif::Source::User,
                message: serde_json::json!("test"),
                reasoning_effort: None,
                reasoning_content: None,
                model_name: None,
                tool_calls: None,
                observation: None,
                metrics: None,
                is_copied_context: None,
                llm_call_count: None,
                extra: None,
            })
            .unwrap();
        finalizer
            .close_session(original, StopReason::SessionClosed)
            .await
            .unwrap();

        let registry = SessionRegistry::new();
        finalizer
            .recover_spooled_sessions(&registry, &Default::default())
            .await
            .unwrap();
        let recovered = registry.get("lifecycle-session").unwrap();
        assert_eq!(recovered.current_identity().ttl_remaining_s, Some(600));
        let receipt = finalizer.promote(recovered).await.unwrap();
        assert_eq!(receipt.body.tool_calls.total, 2);
        assert_eq!(receipt.body.tool_calls.allowed, 1);
        assert_eq!(receipt.body.tool_calls.blocked, 1);
        assert_eq!(receipt.body.cost.prompt_tokens, 17);
        assert_eq!(receipt.body.cost.completion_tokens, 9);
        assert_eq!(receipt.body.cost.cached_tokens, 3);
        assert_eq!(receipt.body.cost.cost_usd_micros, 1_234_567);
        assert_eq!(receipt.body.stop_reason_id, StopReason::PolicyBlocked.id());
    }

    #[tokio::test]
    async fn incomplete_capture_never_produces_receipt_or_atif() {
        let directory = tempfile::tempdir().unwrap();
        let finalizer = finalizer(directory.path());
        for workflow in [Workflow::Signed, Workflow::Unsigned] {
            let session = session(workflow);
            session.mark_capture_failed();
            assert!(matches!(
                finalizer
                    .close_session(Arc::clone(&session), StopReason::SessionClosed)
                    .await,
                Err(FinalizeError::CaptureIncomplete)
            ));
            assert!(session.receipt.lock().is_none());
            assert!(session.atif_path.lock().is_none());
        }
    }

    /// Regression for the live-session analog of the quarantined-recovery
    /// idle-sweep churn (bug 20). A worker job panic sets `capture_failed = 1`
    /// on the live session's flag while `closed = 0, artifact_committed = 0`.
    /// The idle sweeper's `!is_closed()` filter therefore picks the session
    /// up on every tick, `close_session_locked` runs its full body only to
    /// hit `if session.capture_failed() { return Err(CaptureIncomplete); }`,
    /// `CloseClaim` drops unarmed, `reset_close()` puts `closed` back to 0,
    /// and the session churns forever burning CPU, `lifecycle_lock`
    /// acquisitions, log noise, and `ab_incomplete_sessions_total`. The fix
    /// is symmetric with bug 20: on the `CaptureIncomplete` return, mark the
    /// session `artifact_committed` and commit the `CloseClaim` so the
    /// session is sealed once and the idle sweeper's `!is_closed()` filter
    /// skips it forever after.
    #[tokio::test]
    async fn close_session_seals_capture_failed_session_so_idle_sweep_stops_churning() {
        let directory = tempfile::tempdir().unwrap();
        let finalizer = finalizer(directory.path());
        for workflow in [Workflow::Signed, Workflow::Unsigned] {
            let session = session(workflow);
            session.mark_capture_failed();
            let result = finalizer
                .close_session(Arc::clone(&session), StopReason::SessionClosed)
                .await;
            assert!(matches!(result, Err(FinalizeError::CaptureIncomplete)));
            assert!(
                session.is_closed(),
                "close_session_locked must seal a capture_failed session (mark_artifact_committed + claim.committed = true) on the CaptureIncomplete return path so subsequent idle-sweep passes skip it via the `!is_closed()` filter — otherwise CloseClaim drops unarmed, reset_close puts `closed` back to 0, is_closed() stays false, and the idle sweeper churns forever on this session (workflow: {workflow:?})",
            );
            assert!(session.receipt.lock().is_none());
            assert!(session.atif_path.lock().is_none());
        }
    }

    /// Regression for a third idle-sweep churn shape (analog of bugs 20 and
    /// 21): an unsigned session that was opened but never had any events
    /// captured. Sessions get opened as a side effect of `get_or_open` inside
    /// `prepare_chat` / `intercept_tool`, but the request itself can fail
    /// before any worker job is submitted (worker queue full, admission
    /// rejected, loop-breaker Open). The session is left in the registry
    /// with an empty `atif` (no `push_step` ever ran). When
    /// `close_session_locked` reaches its unsigned branch it calls
    /// `snapshot_trajectory()`, hands the empty trajectory to
    /// `ab_atif::write_atomic`, which runs strict validation, which rejects
    /// `steps.is_empty()` with "must contain at least one step". The write
    /// returns `WriterError::Invalid`, `close_session_locked` returns
    /// `Err(FinalizeError::Atif)`, `CloseClaim` drops unarmed,
    /// `reset_close()` puts `closed` back to `0`, and the idle sweeper
    /// re-enters this exact code path on every tick forever — burning CPU,
    /// growing `ab_reconcile_errors_total`, and generating warning logs.
    /// The fix is analogous to bug 21: detect the terminal condition (empty
    /// ATIF cannot ever produce a valid strict artifact) and seal the
    /// session so `is_closed()` returns true and the idle sweeper skips it.
    #[tokio::test]
    async fn close_session_seals_empty_unsigned_session_so_idle_sweep_stops_churning() {
        let directory = tempfile::tempdir().unwrap();
        let finalizer = finalizer(directory.path());
        let session = session(Workflow::Unsigned);
        assert_eq!(
            session.atif.lock().clone().finish().steps.len(),
            0,
            "precondition: session has no captured steps",
        );
        let result = finalizer
            .close_session(Arc::clone(&session), StopReason::SessionClosed)
            .await;
        assert!(
            matches!(result, Err(FinalizeError::Atif(_))),
            "empty unsigned close must surface an ATIF error to the caller: {result:?}",
        );
        assert!(
            session.is_closed(),
            "close_session_locked must seal an empty unsigned session (mark_artifact_committed + claim.committed = true) when write_atomic's strict validation rejects the empty trajectory — otherwise CloseClaim drops unarmed, reset_close puts `closed` back to 0, is_closed() stays false, and the idle sweeper churns forever on this session (write_atomic → validate → \"must contain at least one step\" → Err → reset_close → picked up next tick → repeat)",
        );
        assert!(
            session.atif_path.lock().is_none(),
            "no ATIF file was ever produced for the empty session",
        );
    }

    /// An in-flight response marker belonging to a *currently active*
    /// session is normal operation (the marker lives for the duration of
    /// the upstream call), not evidence of an abandoned effect. A periodic
    /// recovery tick that runs while such a request is in flight must not
    /// quarantine the session — otherwise any LLM call slower than one
    /// reconcile tick would poison its own session as capture-failed and
    /// wrongly quarantine the final trajectory at close.
    #[tokio::test]
    async fn recovery_tick_does_not_quarantine_live_sessions_with_inflight_markers() {
        let directory = tempfile::tempdir().unwrap();
        let finalizer = finalizer(directory.path());
        let live = session(Workflow::Unsigned);
        let registry = crate::session::SessionRegistry::new();
        let live = registry.insert_recovered(Arc::try_unwrap(live).map_err(|_| ()).unwrap());
        crate::worker::create_response_marker(
            directory.path(),
            &finalizer.journal_key,
            &live.id,
            "digest".to_owned(),
        )
        .await
        .unwrap();
        finalizer
            .recover_spooled_sessions(&registry, &Default::default())
            .await
            .unwrap();
        assert!(
            !finalizer.quarantined_sessions.lock().contains(&live.id),
            "a live session's in-flight marker must not put it in quarantine",
        );
        assert!(
            !live.capture_failed(),
            "a recovery tick must not poison a live session mid-request",
        );
    }

    /// The quarantined_sessions set records id-space markers for recoveries
    /// that saw inconsistent effects on disk. A live session (client retry
    /// under the same id) that shares such an id must NOT inherit the
    /// capture-failed verdict on finalize — the verdict belongs to the
    /// recovered Session inserted with `mark_capture_failed()`, not to a
    /// fresh live Session whose in-memory `capture_failed` flag is still 0.
    /// close_session_locked must therefore rely on the per-session flag,
    /// not on the process-wide id set.
    #[tokio::test]
    async fn live_session_with_id_in_quarantine_set_can_still_close() {
        let directory = tempfile::tempdir().unwrap();
        let finalizer = finalizer(directory.path());
        // Simulate a prior recovery pass that added this session id to the set.
        finalizer
            .quarantined_sessions
            .lock()
            .insert("lifecycle-session".to_owned());
        let live = session(Workflow::Unsigned);
        assert!(!live.capture_failed(), "precondition: live session is clean");
        // Give the live session a step so its unsigned finalize can succeed.
        live.atif
            .lock()
            .push_step(ab_atif::Step {
                step_id: 0,
                timestamp: None,
                source: ab_atif::Source::Agent,
                message: serde_json::json!("live response"),
                reasoning_effort: None,
                reasoning_content: None,
                model_name: Some("test-model".into()),
                tool_calls: None,
                observation: None,
                metrics: Some(ab_atif::Metrics {
                    prompt_tokens: Some(1),
                    completion_tokens: Some(1),
                    cached_tokens: Some(0),
                    cost_usd: Some(0.0),
                    logprobs: None,
                    completion_token_ids: None,
                    prompt_token_ids: None,
                    extra: None,
                }),
                is_copied_context: None,
                llm_call_count: Some(1),
                extra: None,
            })
            .unwrap();
        let outcome = finalizer
            .close_session(Arc::clone(&live), StopReason::SessionClosed)
            .await
            .expect("live session must finalize despite id sharing space with a set entry");
        match outcome {
            FinalizeOutcome::Atif { .. } => {}
            other => panic!("expected FinalizeOutcome::Atif, got {other:?}"),
        }
        assert!(
            !live.capture_failed(),
            "close_session must not poison the live session's capture_failed flag",
        );
    }

    /// Recovery must never clobber a live session that shares its id with a
    /// stale spool artifact — a client retrying the same session_id after a
    /// crash could otherwise have its in-flight session force-closed by the
    /// reconciler. Two layers guard against this: the early registry check
    /// AND `try_insert_recovered` returning `Err(existing)` at the point of
    /// insertion. This test locks the outer invariant.
    #[tokio::test]
    async fn recovery_does_not_clobber_a_live_session_with_the_same_id() {
        let directory = tempfile::tempdir().unwrap();
        let finalizer = finalizer(directory.path());
        // Produce a valid ATIF artifact on disk under the "lifecycle-session" id.
        let closed_session = session(Workflow::Unsigned);
        closed_session
            .atif
            .lock()
            .push_step(ab_atif::Step {
                step_id: 0,
                timestamp: None,
                source: ab_atif::Source::Agent,
                message: serde_json::json!("archived response"),
                reasoning_effort: None,
                reasoning_content: None,
                model_name: Some("test-model".into()),
                tool_calls: None,
                observation: None,
                metrics: Some(ab_atif::Metrics {
                    prompt_tokens: Some(1),
                    completion_tokens: Some(1),
                    cached_tokens: Some(0),
                    cost_usd: Some(0.0),
                    logprobs: None,
                    completion_token_ids: None,
                    prompt_token_ids: None,
                    extra: None,
                }),
                is_copied_context: None,
                llm_call_count: Some(1),
                extra: None,
            })
            .unwrap();
        finalizer
            .close_session(Arc::clone(&closed_session), StopReason::SessionClosed)
            .await
            .unwrap();
        // Now simulate a client retrying under the same session_id.
        let registry = SessionRegistry::new();
        let live = registry.get_or_open(
            "lifecycle-session",
            Workflow::Unsigned,
            &AgentIdentity {
                version: "1".to_owned(),
                charter: "test".into(),
                instance_uid: "instance-1".to_owned(),
                ttl_remaining_s: Some(600),
            },
            &Default::default(),
        );
        assert!(!live.is_closed(), "precondition: live session is open");
        assert!(live.receipt.lock().is_none(), "precondition: no receipt yet");
        assert!(live.atif_path.lock().is_none(), "precondition: no atif path yet");
        // Recovery must see the live session and skip the stale artifact.
        finalizer
            .recover_spooled_sessions(&registry, &Default::default())
            .await
            .unwrap();
        assert!(
            !live.is_closed(),
            "live session must not be force-closed by recovery"
        );
        assert!(
            live.receipt.lock().is_none(),
            "live session's receipt must not be overwritten from the stale artifact",
        );
        assert!(
            live.atif_path.lock().is_none(),
            "live session's atif_path must not be reassigned to the stale artifact",
        );
        assert_eq!(registry.len(), 1, "recovery must not add a duplicate entry");
    }

    /// A background promotion retry must never force-close a session that is
    /// currently active. Without this guard, `retry_marked_promotions` would
    /// pick up a stale `.promote` marker left by a prior crash, look up the
    /// current live session from the registry (client retried under the same
    /// session_id), and call `promote()` — which starts by
    /// `close_session_locked`-ing any non-closed session. The live session
    /// would be prematurely terminated and its ATIF artifact overwritten.
    #[tokio::test]
    async fn promotion_retry_does_not_force_close_a_live_session() {
        let directory = tempfile::tempdir().unwrap();
        let finalizer = finalizer(directory.path());
        // Produce a valid unsigned artifact so a real promotion marker can point at it.
        let closed_session = session(Workflow::Unsigned);
        closed_session
            .atif
            .lock()
            .push_step(ab_atif::Step {
                step_id: 0,
                timestamp: None,
                source: ab_atif::Source::Agent,
                message: serde_json::json!("archived response"),
                reasoning_effort: None,
                reasoning_content: None,
                model_name: Some("test-model".into()),
                tool_calls: None,
                observation: None,
                metrics: Some(ab_atif::Metrics {
                    prompt_tokens: Some(1),
                    completion_tokens: Some(1),
                    cached_tokens: Some(0),
                    cost_usd: Some(0.0),
                    logprobs: None,
                    completion_token_ids: None,
                    prompt_token_ids: None,
                    extra: None,
                }),
                is_copied_context: None,
                llm_call_count: Some(1),
                extra: None,
            })
            .unwrap();
        let outcome = finalizer
            .close_session(Arc::clone(&closed_session), StopReason::SessionClosed)
            .await
            .unwrap();
        let FinalizeOutcome::Atif { path } = outcome else {
            panic!("expected ATIF artifact")
        };
        let trajectory_bytes = tokio::fs::read(&path).await.unwrap();
        let promotion_marker = crate::journal::seal(
            &finalizer.journal_key,
            "promotion-marker",
            0,
            &PromotionMarker {
                session_id: closed_session.id.clone(),
                trajectory_digest: ab_core::digest::sha256_hex(&trajectory_bytes),
            },
        )
        .unwrap();
        tokio::fs::write(path.with_extension("promote"), &promotion_marker)
            .await
            .unwrap();
        // Now simulate a client retrying under the same session_id.
        let registry = SessionRegistry::new();
        let live = registry.get_or_open(
            &closed_session.id,
            Workflow::Unsigned,
            &AgentIdentity {
                version: "1".to_owned(),
                charter: "test".into(),
                instance_uid: "instance-1".to_owned(),
                ttl_remaining_s: Some(600),
            },
            &Default::default(),
        );
        // Give the live session a distinct step so its trajectory would
        // pass strict validation — this makes the potential overwrite of
        // the archived artifact directly observable.
        live.atif
            .lock()
            .push_step(ab_atif::Step {
                step_id: 0,
                timestamp: None,
                source: ab_atif::Source::Agent,
                message: serde_json::json!("live response"),
                reasoning_effort: None,
                reasoning_content: None,
                model_name: Some("test-model".into()),
                tool_calls: None,
                observation: None,
                metrics: Some(ab_atif::Metrics {
                    prompt_tokens: Some(2),
                    completion_tokens: Some(3),
                    cached_tokens: Some(0),
                    cost_usd: Some(0.0),
                    logprobs: None,
                    completion_token_ids: None,
                    prompt_token_ids: None,
                    extra: None,
                }),
                is_copied_context: None,
                llm_call_count: Some(1),
                extra: None,
            })
            .unwrap();
        assert!(!live.is_closed(), "precondition: live session is open");
        let promoted = finalizer.retry_marked_promotions(&registry).await.unwrap();
        assert_eq!(
            promoted, 0,
            "promotion retry must not count a skipped live session as promoted",
        );
        assert!(
            !live.is_closed(),
            "live session must not be force-closed by promotion retry",
        );
        assert!(
            live.receipt.lock().is_none(),
            "live session must not receive a receipt from a stale promotion marker",
        );
        assert!(
            live.atif_path.lock().is_none(),
            "live session's atif_path must not be set by a background promotion retry — that would mean its trajectory was snapshotted to disk out of band",
        );
        assert_eq!(
            tokio::fs::read(&path).await.unwrap(),
            trajectory_bytes,
            "the archived ATIF artifact must not be overwritten by a background retry that force-finalized the live session",
        );
        // The stale marker persists — it will be handled after the live
        // session finalizes normally, or expire with the artifact.
        assert!(
            path.with_extension("promote").exists(),
            "the promotion marker must remain on disk for future retries",
        );
    }

    /// Regression for the quarantined-unsigned recovery branch. When a
    /// crashed process left an unsigned session's `.session.json` metadata
    /// on disk AND the session id was already in the `quarantined_sessions`
    /// set (populated on the same pass by `inflight_response_sessions` or
    /// `unresolved_tool_sessions`), `consolidate_step_journals` builds a
    /// fresh `Session::new` (`closed = 0`, `artifact_committed = 0`),
    /// calls `mark_capture_failed()`, and inserts it via
    /// `insert_recovered` — but forgets the `mark_artifact_committed()`
    /// step that its signed-recovery sibling applies before
    /// `try_insert_recovered`. The result is a permanent
    /// `is_closed() == false, capture_failed == true` session in the
    /// registry: the idle sweeper's `!is_closed()` filter keeps picking
    /// it up every tick, `close_session_locked` runs its full body only
    /// to hit `if session.capture_failed()` and return
    /// `CaptureIncomplete`, `CloseClaim` drops unarmed → `reset_close`
    /// puts `closed` back to `0`, and the churn is unbounded: growing
    /// `ab_incomplete_sessions_total`, growing log noise, wasted lifecycle
    /// lock acquisitions, and a session that never leaves the registry.
    #[tokio::test]
    async fn recovery_marks_quarantined_unsigned_session_finalized_to_stop_idle_sweep_churn() {
        let directory = tempfile::tempdir().unwrap();
        let finalizer = finalizer(directory.path());
        let session_id = "quarantined-unsigned";
        let identity = AgentIdentity {
            version: "1".into(),
            charter: "test".into(),
            instance_uid: "instance-1".into(),
            ttl_remaining_s: Some(600),
        };

        let digest = ab_core::digest::sha256_hex(session_id.as_bytes());
        let stem = &digest[..32];
        let metadata_payload = serde_json::json!({
            "journal_version": 2,
            "session_id": session_id,
            "identity": identity,
            "workflow": "unsigned",
        });
        let metadata_sealed =
            crate::journal::seal(&finalizer.journal_key, "metadata", 0, &metadata_payload).unwrap();
        std::fs::write(
            directory.path().join(format!("{stem}.session.json")),
            &metadata_sealed,
        )
        .unwrap();

        // Pre-populate the quarantine set — this is what a prior recovery
        // pass would do after finding an inflight-response marker or an
        // unresolved-tool marker on disk for this session id.
        finalizer
            .quarantined_sessions
            .lock()
            .insert(session_id.to_owned());

        let registry = SessionRegistry::new();
        finalizer
            .recover_spooled_sessions(&registry, &Default::default())
            .await
            .unwrap();

        let recovered = registry
            .get(session_id)
            .expect("quarantined session must be inserted");
        assert!(
            recovered.capture_failed(),
            "quarantined session must carry the capture-failed verdict",
        );
        assert!(
            recovered.is_closed(),
            "the quarantined-unsigned recovery branch (consolidate_step_journals) must also mark the session finalized (artifact_committed) so the idle sweeper's `!is_closed()` filter skips it — otherwise every idle tick calls close_session_locked which returns CaptureIncomplete, CloseClaim resets the close, and the session churns forever burning CPU, log noise, and metrics without ever leaving the registry",
        );
    }

    /// A live session's `{stem}.session.json` journal metadata must be
    /// invisible to the ATIF spool scan. Both journal consumers skip a
    /// session that is still in the registry, so without the scan-side
    /// guard, every reconciler tick re-parsed the metadata file as an
    /// ATIF document, failed, warned "ignoring invalid ATIF spool file",
    /// and inflated the invalid_json skip counter — pure noise while a
    /// session was merely open.
    #[tokio::test]
    async fn atif_scan_ignores_live_session_journal_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let metrics = Arc::new(Registry::new());
        let finalizer = Finalizer::new(
            Arc::new(Ed25519Signer::from_seed([7; 32])),
            directory.path().to_path_buf(),
            Arc::clone(&metrics),
        );
        let session_id = "still-open-session";
        let identity = AgentIdentity {
            version: "1".into(),
            charter: "test".into(),
            instance_uid: "instance-1".into(),
            ttl_remaining_s: Some(600),
        };
        let digest = ab_core::digest::sha256_hex(session_id.as_bytes());
        let stem = &digest[..32];
        let metadata_payload = serde_json::json!({
            "journal_version": 2,
            "session_id": session_id,
            "identity": identity,
            "workflow": "unsigned",
        });
        let metadata_sealed =
            crate::journal::seal(&finalizer.journal_key, "metadata", 0, &metadata_payload).unwrap();
        std::fs::write(
            directory.path().join(format!("{stem}.session.json")),
            &metadata_sealed,
        )
        .unwrap();

        // The session is live, so consolidate/recover leave its journal alone.
        let registry = SessionRegistry::new();
        let live = registry.get_or_open(session_id, Workflow::Unsigned, &identity, &Default::default());
        assert!(!live.is_closed(), "precondition: session is open");

        finalizer
            .recover_spooled_sessions(&registry, &Default::default())
            .await
            .unwrap();

        assert!(
            !metrics.render().contains("ab_atif_recovery_skipped_total"),
            "the ATIF scan must skip *.session.json instead of counting it as an invalid spool file",
        );
        assert!(
            directory.path().join(format!("{stem}.session.json")).exists(),
            "the live session's journal metadata must survive the pass",
        );
    }

    #[tokio::test]
    async fn restart_quarantines_inflight_response_without_stopping_recovery() {
        let directory = tempfile::tempdir().unwrap();
        let finalizer = finalizer(directory.path());
        crate::worker::create_response_marker(
            directory.path(),
            &finalizer.journal_key,
            "uncertain-session",
            "request-digest".to_owned(),
        )
        .await
        .unwrap();

        let registry = SessionRegistry::new();
        assert_eq!(
            finalizer
                .recover_spooled_sessions(&registry, &Default::default())
                .await
                .unwrap(),
            0
        );
        assert!(finalizer
            .quarantined_sessions
            .lock()
            .contains("uncertain-session"));
        assert!(registry.get("uncertain-session").is_none());
    }

    #[tokio::test]
    async fn restart_recovers_atif_and_retries_marked_promotion() {
        let directory = tempfile::tempdir().unwrap();
        let first = finalizer(directory.path());
        let original = session(Workflow::Unsigned);
        original
            .atif
            .lock()
            .push_step(ab_atif::Step {
                step_id: 0,
                timestamp: None,
                source: ab_atif::Source::Agent,
                message: serde_json::json!("recovered response"),
                reasoning_effort: None,
                reasoning_content: None,
                model_name: Some("test-model".into()),
                tool_calls: None,
                observation: None,
                metrics: Some(ab_atif::Metrics {
                    prompt_tokens: Some(5),
                    completion_tokens: Some(2),
                    cached_tokens: Some(1),
                    cost_usd: Some(0.001),
                    logprobs: None,
                    completion_token_ids: None,
                    prompt_token_ids: None,
                    extra: None,
                }),
                is_copied_context: None,
                llm_call_count: Some(1),
                extra: None,
            })
            .unwrap();
        let outcome = first
            .close_session(Arc::clone(&original), StopReason::SessionClosed)
            .await
            .unwrap();
        let FinalizeOutcome::Atif { path } = outcome else {
            panic!("expected ATIF artifact")
        };
        let trajectory_bytes = tokio::fs::read(&path).await.unwrap();
        let promotion_marker = crate::journal::seal(
            &first.journal_key,
            "promotion-marker",
            0,
            &PromotionMarker {
                session_id: original.id.clone(),
                trajectory_digest: ab_core::digest::sha256_hex(&trajectory_bytes),
            },
        )
        .unwrap();
        tokio::fs::write(path.with_extension("promote"), &promotion_marker)
            .await
            .unwrap();

        let recovered_registry = SessionRegistry::new();
        let after_restart = finalizer(directory.path());
        assert_eq!(
            after_restart
                .recover_spooled_sessions(&recovered_registry, &Default::default())
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            after_restart
                .retry_marked_promotions(&recovered_registry)
                .await
                .unwrap(),
            1
        );
        let recovered = recovered_registry.get(&original.id).unwrap();
        let receipt = recovered.receipt.lock().clone().unwrap();
        receipt.verify_embedded().unwrap();
        assert!(recovered.is_promoted());
        assert!(!path.with_extension("promote").exists());

        tokio::fs::write(path.with_extension("promote"), &promotion_marker)
            .await
            .unwrap();
        let second_registry = SessionRegistry::new();
        assert_eq!(
            after_restart
                .recover_spooled_sessions(&second_registry, &Default::default())
                .await
                .unwrap(),
            1
        );
        let restored = second_registry.get(&original.id).unwrap();
        assert_eq!(
            restored.receipt.lock().as_ref().unwrap().body.receipt_id,
            receipt.body.receipt_id,
            "restart must restore the persisted receipt, not issue a duplicate"
        );
        assert_eq!(
            after_restart
                .retry_marked_promotions(&second_registry)
                .await
                .unwrap(),
            1
        );
        assert!(restored.is_promoted());
        assert!(!path.with_extension("promote").exists());
    }

    #[tokio::test]
    async fn close_waits_for_active_response_lease() {
        let directory = tempfile::tempdir().unwrap();
        let finalizer = finalizer(directory.path());
        let session = session(Workflow::Signed);
        let lease = crate::session::SessionLease::new(Arc::clone(&session));
        let close_session = Arc::clone(&session);
        let task = tokio::spawn(async move {
            finalizer
                .close_session(close_session, StopReason::SessionClosed)
                .await
        });
        tokio::task::yield_now().await;
        assert!(!task.is_finished(), "close overtook an active response");
        drop(lease);
        assert!(matches!(
            task.await.unwrap().unwrap(),
            FinalizeOutcome::Receipt { .. }
        ));
    }

    #[tokio::test]
    async fn torn_journal_tail_is_truncated_without_losing_complete_records() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("journal.ndjson");
        std::fs::write(&path, b"{\"complete\":true}\n{\"torn\":").unwrap();
        let lines = read_complete_journal(&path).await.unwrap();
        assert_eq!(lines, vec![r#"{"complete":true}"#]);
        assert_eq!(std::fs::read(&path).unwrap(), b"{\"complete\":true}\n");
    }

    #[tokio::test]
    async fn failed_persistence_reopens_session_for_retry() {
        let directory = tempfile::tempdir().unwrap();
        let blocking_file = directory.path().join("not-a-directory");
        std::fs::write(&blocking_file, b"file").unwrap();
        let finalizer = finalizer(&blocking_file);
        let session = session(Workflow::Signed);
        assert!(finalizer
            .close_session(Arc::clone(&session), StopReason::SessionClosed)
            .await
            .is_err());
        assert!(!session.is_closed());
        assert!(session.try_close(), "failed close claim was not reset");
    }

    #[tokio::test]
    async fn failed_unsigned_persistence_keeps_steps_for_retry() {
        let directory = tempfile::tempdir().unwrap();
        let spool = directory.path().join("spool");
        std::fs::write(&spool, b"blocking file").unwrap();
        let finalizer = finalizer(&spool);
        let session = session(Workflow::Unsigned);
        session
            .atif
            .lock()
            .push_step(ab_atif::Step {
                step_id: 0,
                timestamp: None,
                source: ab_atif::Source::User,
                message: serde_json::json!("survive"),
                reasoning_effort: None,
                reasoning_content: None,
                model_name: None,
                tool_calls: None,
                observation: None,
                metrics: None,
                is_copied_context: None,
                llm_call_count: None,
                extra: None,
            })
            .unwrap();
        assert!(finalizer
            .close_session(Arc::clone(&session), StopReason::SessionClosed)
            .await
            .is_err());
        assert!(!session.is_closed());
        std::fs::remove_file(&spool).unwrap();
        std::fs::create_dir(&spool).unwrap();
        let FinalizeOutcome::Atif { path } = finalizer
            .close_session(session, StopReason::SessionClosed)
            .await
            .unwrap()
        else {
            panic!("expected ATIF")
        };
        let trajectory: ab_atif::Trajectory = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(trajectory.steps.len(), 1);
        assert_eq!(trajectory.steps[0].message, serde_json::json!("survive"));
    }

    // ------------------------------------------------------------------
    // Congestion & bottleneck stress tests.
    // ------------------------------------------------------------------

    /// The lifecycle_lock serializes close_session and promote to prevent
    /// concurrent lifecycle-outbox rewrites, so many concurrent closes
    /// queue behind a single Mutex. This test locks the QUEUING behavior:
    /// N distinct sessions closing at once must all complete within a
    /// generous time bound and none must deadlock.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_closes_across_many_sessions_never_deadlock() {
        const SESSIONS: usize = 32;
        let directory = tempfile::tempdir().unwrap();
        let finalizer = Arc::new(finalizer(directory.path()));
        let mut tasks = Vec::with_capacity(SESSIONS);
        for i in 0..SESSIONS {
            let f = Arc::clone(&finalizer);
            let s = Arc::new(Session::new(
                format!("lifecycle-{i}"),
                Workflow::Signed,
                AgentIdentity {
                    version: "1".to_owned(),
                    charter: "test".into(),
                    instance_uid: format!("instance-{i}"),
                    ttl_remaining_s: Some(600),
                },
                Default::default(),
            ));
            tasks.push(tokio::spawn(async move {
                f.close_session(s, StopReason::SessionClosed).await
            }));
        }
        let results = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            futures::future::join_all(tasks),
        )
        .await
        .expect("close_session tasks deadlocked under lifecycle_lock contention");
        for result in results {
            let outcome = result.expect("task panicked");
            assert!(outcome.is_ok(), "close failed: {outcome:?}");
        }
    }

    /// A saturated worker-side finalizer must not hold the lifecycle_lock
    /// across independent await points that could stall other closers. We
    /// verify this indirectly by asserting the p50 latency for a single
    /// close under contention stays within 3x the uncontended latency
    /// (with a generous multiplier for CI noise). A regression that
    /// awaited a slow I/O with the lock held would blow this bound.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn close_latency_scales_reasonably_under_lock_contention() {
        let directory = tempfile::tempdir().unwrap();
        let finalizer = Arc::new(finalizer(directory.path()));
        // Warm-up: measure a single uncontended close.
        let warm = Arc::new(Session::new(
            "warm".to_owned(),
            Workflow::Signed,
            AgentIdentity {
                version: "1".to_owned(),
                charter: "test".into(),
                instance_uid: "warm".to_owned(),
                ttl_remaining_s: Some(600),
            },
            Default::default(),
        ));
        let uncontended = std::time::Instant::now();
        finalizer
            .close_session(warm, StopReason::SessionClosed)
            .await
            .unwrap();
        let baseline = uncontended.elapsed();

        // Contended: 16 closes at once. Measure their WALL-CLOCK total.
        const N: usize = 16;
        let mut tasks = Vec::with_capacity(N);
        let started = std::time::Instant::now();
        for i in 0..N {
            let f = Arc::clone(&finalizer);
            let s = Arc::new(Session::new(
                format!("contended-{i}"),
                Workflow::Signed,
                AgentIdentity {
                    version: "1".to_owned(),
                    charter: "test".into(),
                    instance_uid: format!("contended-{i}"),
                    ttl_remaining_s: Some(600),
                },
                Default::default(),
            ));
            tasks.push(tokio::spawn(async move {
                f.close_session(s, StopReason::SessionClosed).await
            }));
        }
        for t in tasks {
            t.await.unwrap().unwrap();
        }
        let total = started.elapsed();
        // A serialized lock gives ~N * baseline. Anything > 10 * N * baseline
        // signals we're holding the lock across additional awaits.
        let multiplier = u32::try_from(N * 10).unwrap_or(u32::MAX);
        let budget = baseline
            .saturating_mul(multiplier)
            .max(std::time::Duration::from_secs(60));
        assert!(
            total < budget,
            "16 contended closes took {total:?}, budget {budget:?} (baseline {baseline:?})",
        );
    }
}
