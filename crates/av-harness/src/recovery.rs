//! Recovery-pass seam for the reconciler.
//!
//! `recover_spooled_sessions` historically interleaved five recovery
//! concerns in one method on `Finalizer`; a bug in one silently
//! affected the others (several seal-before-insert races each
//! spanned two concerns). This module introduces the
//! `RecoveryPass` interface and hosts the first
//! extracted pass, the orphan-JSON quarantine. Subsequent
//! extractions move one concern at a time until
//! `recover_spooled_sessions` is a thin loop over `passes()`.

use std::collections::HashSet;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use av_core::metrics::Registry;

use crate::reconciler::FinalizeError;

/// The slice of reconciler state a recovery pass may touch. Passes
/// receive this instead of `&Finalizer` so the seam stays narrow:
/// a pass cannot reach lifecycle locks, the signer, or the bridge
/// unless a field is deliberately added here.
pub(crate) struct ReconcilerContext<'a> {
    /// The ATIF spool directory the recovery scan walks.
    pub spool_dir: &'a Path,
    pub metrics: &'a Registry,
    /// The live session registry. Passes snapshot what they need at
    /// run time (e.g. filename stems), so a pass observes the
    /// registry as of ITS position in the recovery order — earlier
    /// phases may have adopted sessions.
    pub sessions: &'a crate::session::SessionRegistry,
    /// Authenticates spool markers (in-flight responses, unresolved
    /// tool executions) so attacker-planted files cannot poison
    /// sessions into quarantine.
    pub journal_key: &'a [u8; 32],
    /// Session ids already warned about as incomplete-effect
    /// quarantines: markers stay on disk as evidence, so every tick
    /// rediscovers the same set and must not repeat the warning.
    pub quarantined_sessions: &'a parking_lot::Mutex<HashSet<String>>,
    /// The lifecycle event bus, when configured. `None` (tests,
    /// bridge-less deployments) makes bus-dependent passes no-ops.
    pub bridge: Option<&'a std::sync::Arc<dyn av_bridge::EventBus>>,
    /// Per-artifact warning dedupe (`Finalizer::warn_once`): a file
    /// left on disk as evidence must not repeat its warning every
    /// tick. Returns true when this is the first warn for the path
    /// in the current FIFO window.
    pub warn_once: &'a (dyn Fn(PathBuf) -> bool + Send + Sync),
}

impl ReconcilerContext<'_> {
    /// Filename stems (`sha256(session_id)[..32]`) of sessions that can
    /// legitimately be inside the §8.5 sidecar race window — the
    /// live-close guard: a sidecar-less `{stem}.json` whose stem is
    /// here belongs to an in-progress close (between `write_atomic`
    /// and the `.atif-auth` seal) and must not be quarantined out
    /// from under it. Only Open/Draining sessions qualify: the close
    /// flow marks the artifact committed strictly AFTER the provenance
    /// seal succeeded, so a Sealed/Complete session's artifact always
    /// has its sidecar — a sidecar-less `.json` under such a stem is a
    /// genuine orphan (e.g. a pre-provenance write abandoned by a close
    /// that later sealed terminally via the capture-failed branch).
    /// The previous every-registered-session guard protected those
    /// orphans forever: unsigned sessions stay registered for the
    /// process lifetime, so the file never converged to quarantine.
    fn known_stems(&self) -> HashSet<String> {
        self.sessions
            .open_sessions_including_closed()
            .iter()
            .filter(|session| !session.artifact_committed_flag())
            .map(|session| {
                let digest = av_core::digest::sha256_hex(session.id.as_bytes());
                digest.get(..32).unwrap_or(&digest).to_owned()
            })
            .collect()
    }
}

/// What a pass did this run, for tick-level observability.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct PassOutcome {
    /// Items (files or sessions) newly quarantined this run.
    pub quarantined: usize,
    /// Lifecycle outboxes published + acked this run.
    pub replayed: usize,
    /// Sessions adopted back into the registry this run.
    pub recovered: usize,
}

/// One self-contained concern of the recovery scan. Implementations
/// must be idempotent per tick (the reconciler re-runs every pass
/// every tick) and per-file fault-isolated: one unreadable or
/// hostile file warns and skips, it never aborts the pass.
pub(crate) trait RecoveryPass: Send + Sync {
    /// Stable name for logs and metrics.
    fn name(&self) -> &'static str;
    /// Run the pass once. Errors abort the current recovery tick
    /// (mirroring the historical inline behavior for directory-level
    /// failures); per-file problems must be absorbed internally.
    fn run<'a>(
        &'a self,
        ctx: &'a ReconcilerContext<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<PassOutcome, FinalizeError>> + Send + 'a>>;
}

/// Run one pass with tick-level observability.
/// `recover_spooled_sessions` is a flat ordered runner over these
/// (S1 step 4); the order encodes load-bearing constraints
/// documented at the runner.
pub(crate) async fn run_pass(
    pass: &dyn RecoveryPass,
    ctx: &ReconcilerContext<'_>,
) -> Result<PassOutcome, FinalizeError> {
    let outcome = pass.run(ctx).await?;
    if outcome.quarantined > 0 {
        tracing::info!(
            pass = pass.name(),
            quarantined = outcome.quarantined,
            "recovery pass quarantined items"
        );
    }
    if outcome.replayed > 0 {
        tracing::info!(
            pass = pass.name(),
            replayed = outcome.replayed,
            "recovery pass replayed lifecycle outboxes"
        );
    }
    Ok(outcome)
}

/// First phase of the recovery order: sessions with on-disk markers
/// proving an *abandoned* effect (an in-flight upstream response or
/// an unresolved tool execution at crash time) are quarantined by id
/// — their capture is incomplete, so closing them normally would
/// attest a trajectory missing effects that actually ran.
///
/// A marker only proves abandonment when its session is not
/// currently active: live sessions legitimately hold markers for
/// the duration of an upstream call, and a request that merely
/// straddles a periodic tick must not poison its session as
/// capture-failed forever. This pass therefore MUST run before the
/// journal-recovery phases adopt spooled sessions into the registry.
pub(crate) struct QuarantineIncompleteEffectsPass;

impl RecoveryPass for QuarantineIncompleteEffectsPass {
    fn name(&self) -> &'static str {
        "quarantine_incomplete_effects"
    }

    fn run<'a>(
        &'a self,
        ctx: &'a ReconcilerContext<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<PassOutcome, FinalizeError>> + Send + 'a>> {
        Box::pin(async move {
            let mut quarantined = crate::worker::inflight_response_sessions(ctx.spool_dir, ctx.journal_key)
                .await
                .map_err(FinalizeError::atif)?;
            quarantined.extend(
                crate::routes::unresolved_tool_sessions(ctx.spool_dir, ctx.journal_key)
                    .await
                    .map_err(FinalizeError::atif)?,
            );
            quarantined.retain(|id| ctx.sessions.get(id).is_none());
            let mut outcome = PassOutcome::default();
            if !quarantined.is_empty() {
                // The markers stay on disk as evidence, so every
                // periodic tick rediscovers the same set. Warn only
                // about ids not already known — otherwise a single
                // crash would repeat this warning every tick forever.
                let mut known = ctx.quarantined_sessions.lock();
                let new = quarantined.iter().filter(|id| !known.contains(*id)).count();
                if new > 0 {
                    outcome.quarantined = new;
                    tracing::warn!(sessions = new, "quarantining sessions with incomplete effects");
                }
                known.extend(quarantined.iter().cloned());
            }
            Ok(outcome)
        })
    }
}

/// Second phase of the recovery order: publish + ack every unacked
/// lifecycle outbox (durable intents persisted by close/promote
/// before their bus publish). Runs after the incomplete-effects scan
/// and before journal recovery, matching the historical order: a
/// replayed close event must precede re-adoption of its session so
/// downstream consumers observe close-then-recover, not the reverse.
/// The loop body lives in `reconciler::replay_lifecycle_outboxes_in`
/// with the rest of the outbox subsystem; this pass owns identity,
/// ordering and observability. Bridge-less deployments are a no-op.
pub(crate) struct ReplayLifecycleOutboxesPass;

impl RecoveryPass for ReplayLifecycleOutboxesPass {
    fn name(&self) -> &'static str {
        "replay_lifecycle_outboxes"
    }

    fn run<'a>(
        &'a self,
        ctx: &'a ReconcilerContext<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<PassOutcome, FinalizeError>> + Send + 'a>> {
        Box::pin(async move {
            let mut outcome = PassOutcome::default();
            let Some(bridge) = ctx.bridge else {
                return Ok(outcome);
            };
            outcome.replayed = crate::reconciler::replay_lifecycle_outboxes_in(
                ctx.spool_dir,
                ctx.journal_key,
                std::sync::Arc::clone(bridge),
            )
            .await?;
            Ok(outcome)
        })
    }
}

/// Signed-journal recovery: adopt crash-interrupted sessions whose
/// signed journals survived, folding their records through the
/// unified accounting rule. Carries `&Finalizer` — closing,
/// promoting and signing are the Finalizer's competency; the S1 plan
/// keeps its public API and delegates internally. Runs before
/// step-journal consolidation (signed candidates take precedence).
pub(crate) struct RecoverSignedJournalsPass<'f> {
    pub finalizer: &'f crate::reconciler::Finalizer,
    pub breaker: &'f av_loopdetect::BreakerConfig,
}

impl RecoveryPass for RecoverSignedJournalsPass<'_> {
    fn name(&self) -> &'static str {
        "recover_signed_journals"
    }

    fn run<'a>(
        &'a self,
        ctx: &'a ReconcilerContext<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<PassOutcome, FinalizeError>> + Send + 'a>> {
        Box::pin(async move {
            let recovered = self
                .finalizer
                .recover_signed_journals(ctx.sessions, self.breaker)
                .await?;
            Ok(PassOutcome {
                recovered,
                ..PassOutcome::default()
            })
        })
    }
}

/// Step-journal consolidation: fold unsigned per-step journals of
/// crash-interrupted sessions into recovered sessions via the
/// unified accounting rule. Finalizer-backed for the same reason as
/// `RecoverSignedJournalsPass`.
pub(crate) struct ConsolidateStepJournalsPass<'f> {
    pub finalizer: &'f crate::reconciler::Finalizer,
    pub breaker: &'f av_loopdetect::BreakerConfig,
}

impl RecoveryPass for ConsolidateStepJournalsPass<'_> {
    fn name(&self) -> &'static str {
        "consolidate_step_journals"
    }

    fn run<'a>(
        &'a self,
        ctx: &'a ReconcilerContext<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<PassOutcome, FinalizeError>> + Send + 'a>> {
        Box::pin(async move {
            self.finalizer
                .consolidate_step_journals(ctx.sessions, self.breaker)
                .await?;
            Ok(PassOutcome::default())
        })
    }
}

/// Strict-ATIF adoption: the tail of the recovery order — walk the
/// spool for sealed artifacts of closed unsigned sessions not in the
/// registry and re-adopt them. Finalizer-backed.
pub(crate) struct AdoptStrictAtifPass<'f> {
    pub finalizer: &'f crate::reconciler::Finalizer,
    pub breaker: &'f av_loopdetect::BreakerConfig,
}

impl RecoveryPass for AdoptStrictAtifPass<'_> {
    fn name(&self) -> &'static str {
        "adopt_strict_atif"
    }

    fn run<'a>(
        &'a self,
        ctx: &'a ReconcilerContext<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<PassOutcome, FinalizeError>> + Send + 'a>> {
        Box::pin(async move {
            let recovered = self
                .finalizer
                .adopt_strict_atif_artifacts(ctx.sessions, self.breaker)
                .await?;
            Ok(PassOutcome {
                recovered,
                ..PassOutcome::default()
            })
        })
    }
}

/// A fresh sidecar-less `{stem}.json` is
/// the normal transient state of an in-flight close (`write_atomic`
/// runs moments before `ensure_atif_provenance` seals `.atif-auth`).
/// Only files determinately older than this window are treated as
/// orphans; younger (or indeterminate-age) files are skipped this
/// tick at the cost of a single stat.
pub(crate) const MIN_ORPHAN_AGE: std::time::Duration = std::time::Duration::from_secs(60);

/// Quarantine sidecar-less `.json` spool files.
///
/// Data cannot be authenticated without a `journal_key`-signed
/// `.atif-auth` sidecar (generating one from bytes found on disk
/// would let an attacker-planted trajectory forge a session's audit
/// trail), so orphaned trajectories are unrecoverable by design.
/// Renaming to `<name>.corrupt-<uid>` moves them out of the recovery
/// scan glob while preserving the bytes for operator forensics, and
/// bounds the per-tick cost to one stat + one rename per file
/// regardless of how many an attacker plants.
pub(crate) struct QuarantineOrphanJsonPass;

impl RecoveryPass for QuarantineOrphanJsonPass {
    fn name(&self) -> &'static str {
        "quarantine_orphan_json"
    }

    fn run<'a>(
        &'a self,
        ctx: &'a ReconcilerContext<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<PassOutcome, FinalizeError>> + Send + 'a>> {
        Box::pin(async move {
            let mut outcome = PassOutcome::default();
            // Snapshot AFTER the journal-recovery phases have adopted
            // sessions (this pass runs late in the recovery order), so
            // freshly adopted sessions are covered by the live-close
            // guard. Sessions opened after this snapshot are handled
            // by the MIN_ORPHAN_AGE gate below.
            let known_stems = ctx.known_stems();
            let mut entries = match tokio::fs::read_dir(ctx.spool_dir).await {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(outcome);
                }
                Err(error) => return Err(FinalizeError::atif_source(error)),
            };
            while let Some(entry) = entries.next_entry().await.map_err(FinalizeError::atif_source)? {
                let path = entry.path();
                if path.extension().and_then(std::ffi::OsStr::to_str) != Some("json") {
                    continue;
                }
                // Live session journals ({hash}.session.json) belong to
                // consolidate_step_journals; they never carry a sidecar
                // and must not be quarantined while a session is open.
                if path
                    .file_name()
                    .and_then(std::ffi::OsStr::to_str)
                    .is_some_and(|name| name.ends_with(".session.json"))
                {
                    continue;
                }
                // Live-close guard (§8.5): see `known_stems` docs.
                if path
                    .file_stem()
                    .and_then(std::ffi::OsStr::to_str)
                    .is_some_and(|stem| known_stems.contains(stem))
                {
                    continue;
                }
                if path.with_extension("atif-auth").exists() {
                    continue;
                }
                let age = tokio::fs::metadata(&path)
                    .await
                    .ok()
                    .and_then(|meta| meta.modified().ok())
                    .and_then(|mtime| std::time::SystemTime::now().duration_since(mtime).ok());
                // Only quarantine when the age is DETERMINATELY past the
                // threshold. An indeterminate age (stat error, or a future
                // mtime after a backward clock step — NTP correction, VM
                // resume) must count as young: treating it as old would
                // quarantine a fresh in-flight-close artifact and recreate
                // the exact race MIN_ORPHAN_AGE exists to prevent.
                if !age.is_some_and(|age| age >= MIN_ORPHAN_AGE) {
                    continue;
                }
                ctx.metrics
                    .counter(
                        "av_atif_recovery_skipped_total{reason=\"unauthenticated\"}",
                        "ATIF spool files skipped during recovery",
                    )
                    .inc();
                let mut quarantine = path.clone();
                let stem = quarantine
                    .file_name()
                    .and_then(std::ffi::OsStr::to_str)
                    .unwrap_or("orphan-atif")
                    .to_owned();
                let new_name = format!("{stem}.corrupt-{}", av_core::new_event_uid());
                quarantine.set_file_name(new_name);
                match tokio::fs::rename(&path, &quarantine).await {
                    Ok(()) => {
                        outcome.quarantined += 1;
                        if (ctx.warn_once)(quarantine.clone()) {
                            tracing::warn!(
                                original = %av_core::fsutil::basename(&path),
                                quarantine = %av_core::fsutil::basename(&quarantine),
                                "quarantined ATIF spool file with no authenticated provenance"
                            );
                        }
                    }
                    Err(error) => {
                        if (ctx.warn_once)(path.clone()) {
                            tracing::warn!(
                                %error,
                                path = %av_core::fsutil::basename(&path),
                                "failed to quarantine ATIF spool file with no authenticated provenance; will retry next tick"
                            );
                        }
                    }
                }
            }
            Ok(outcome)
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use std::sync::Arc;

    struct CtxParts {
        metrics: Registry,
        sessions: crate::session::SessionRegistry,
        journal_key: [u8; 32],
        quarantined_sessions: parking_lot::Mutex<HashSet<String>>,
    }

    impl CtxParts {
        fn new() -> Self {
            Self {
                metrics: Registry::new(),
                sessions: crate::session::SessionRegistry::new(),
                journal_key: [7u8; 32],
                quarantined_sessions: parking_lot::Mutex::new(HashSet::new()),
            }
        }

        fn context<'a>(
            &'a self,
            spool_dir: &'a Path,
            warn_once: &'a (dyn Fn(PathBuf) -> bool + Send + Sync),
        ) -> ReconcilerContext<'a> {
            ReconcilerContext {
                spool_dir,
                metrics: &self.metrics,
                sessions: &self.sessions,
                journal_key: &self.journal_key,
                quarantined_sessions: &self.quarantined_sessions,
                bridge: None,
                warn_once,
            }
        }
    }

    fn age_past_threshold(path: &Path) {
        let old = std::time::SystemTime::now() - MIN_ORPHAN_AGE * 2;
        let file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
        file.set_times(std::fs::FileTimes::new().set_modified(old))
            .unwrap();
    }

    /// The pass-level contract, independent of the Finalizer wiring
    /// (which the reconciler regression tests pin):
    /// aged orphans are renamed, live-stem / young / sidecar'd /
    /// non-json files survive untouched.
    #[tokio::test]
    async fn quarantines_only_aged_unknown_sidecar_less_json() {
        let directory = tempfile::tempdir().unwrap();
        let spool = directory.path();

        let aged_orphan = spool.join("agedorphan.json");
        std::fs::write(&aged_orphan, b"{").unwrap();
        age_past_threshold(&aged_orphan);

        let young_orphan = spool.join("young.json");
        std::fs::write(&young_orphan, b"{").unwrap();

        let sealed = spool.join("sealed.json");
        std::fs::write(&sealed, b"{}").unwrap();
        std::fs::write(spool.join("sealed.atif-auth"), b"sig").unwrap();
        age_past_threshold(&sealed);

        let journal = spool.join("abc.session.json");
        std::fs::write(&journal, b"{}").unwrap();
        age_past_threshold(&journal);

        let parts = CtxParts::new();
        // A registered session whose artifact stem matches
        // `live_stem`'s filename engages the §8.5 live-close guard.
        // The pass snapshots stems from the registry at run time, so
        // the file to protect is derived from a REAL session id.
        let identity = av_events::AgentIdentity {
            version: "1".to_owned(),
            charter: "test".into(),
            instance_uid: "i".to_owned(),
            ttl_remaining_s: None,
        };
        let live = parts.sessions.get_or_open(
            "live-session",
            crate::session::Workflow::Unsigned,
            &identity,
            &av_loopdetect::BreakerConfig::default(),
        );
        let live_digest = av_core::digest::sha256_hex(live.id.as_bytes());
        let live_stem_name = live_digest.get(..32).unwrap().to_owned();
        let live_stem = spool.join(format!("{live_stem_name}.json"));
        std::fs::write(&live_stem, b"{").unwrap();
        age_past_threshold(&live_stem);
        let warned = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let warned_sink = Arc::clone(&warned);
        let warn_once = move |path: PathBuf| {
            warned_sink.lock().push(path);
            true
        };
        let ctx = parts.context(spool, &warn_once);
        let outcome = QuarantineOrphanJsonPass.run(&ctx).await.unwrap();

        assert_eq!(outcome.quarantined, 1, "exactly the aged orphan is renamed");
        assert!(!aged_orphan.exists(), "aged orphan must be renamed");
        assert!(live_stem.exists(), "live-close stem must survive");
        assert!(young_orphan.exists(), "young file must survive (age gate)");
        assert!(sealed.exists(), "sealed artifact must survive");
        assert!(journal.exists(), "step journal must survive");
        assert_eq!(warned.lock().len(), 1, "one warn for the one rename");
    }

    /// The §8.5 live-close guard must cover ONLY sessions still inside
    /// the sidecar race window (Open/Draining). A SEALED session's
    /// artifact always has its provenance sidecar (the close marks the
    /// artifact committed strictly after the seal succeeded), so an
    /// aged sidecar-less `.json` under a sealed session's stem is a
    /// genuine orphan — e.g. a pre-provenance write abandoned by a
    /// close that later sealed terminally via the capture-failed
    /// branch. Pre-fix the guard covered EVERY registered session, and
    /// unsigned sessions stay registered for the process lifetime, so
    /// such orphans never converged to quarantine.
    #[tokio::test]
    async fn sealed_session_stem_orphan_is_quarantined() {
        let directory = tempfile::tempdir().unwrap();
        let spool = directory.path();
        let parts = CtxParts::new();
        let identity = av_events::AgentIdentity {
            version: "1".to_owned(),
            charter: "test".into(),
            instance_uid: "i".to_owned(),
            ttl_remaining_s: None,
        };
        let sealed = parts.sessions.get_or_open(
            "sealed-session",
            crate::session::Workflow::Unsigned,
            &identity,
            &av_loopdetect::BreakerConfig::default(),
        );
        assert!(sealed.try_close());
        sealed.mark_artifact_committed();

        let digest = av_core::digest::sha256_hex(sealed.id.as_bytes());
        let stem = digest.get(..32).unwrap().to_owned();
        let orphan = spool.join(format!("{stem}.json"));
        std::fs::write(&orphan, b"{").unwrap();
        age_past_threshold(&orphan);

        let warn_once = |_: PathBuf| true;
        let ctx = parts.context(spool, &warn_once);
        let outcome = QuarantineOrphanJsonPass.run(&ctx).await.unwrap();

        assert_eq!(
            outcome.quarantined, 1,
            "an aged sidecar-less orphan under a SEALED session's stem must be quarantined"
        );
        assert!(!orphan.exists(), "the orphan must be renamed out of the scan");
    }

    /// Mutation-run hardening (round 10): the incomplete-effects pass
    /// counts only NEWLY quarantined sessions — the dedupe filter and
    /// the count itself had surviving mutants because no test planted
    /// a real inflight marker. First tick: one new quarantine.
    /// Second tick over the same marker: zero new (the marker stays on
    /// disk as evidence; without the dedupe every tick re-counts and
    /// re-warns the same crash forever).
    #[tokio::test]
    async fn incomplete_effects_pass_counts_only_new_sessions() {
        let directory = tempfile::tempdir().unwrap();
        let parts = CtxParts::new();
        let marker_dir = directory.path().join(crate::spool::INFLIGHT_RESPONSES);
        std::fs::create_dir_all(&marker_dir).unwrap();
        let sealed = crate::journal::seal(
            &parts.journal_key,
            "in-flight-response",
            0,
            &serde_json::json!({
                "session_id": "ghost-effects",
                "attempt_id": "attempt-1",
                "request_digest": "d",
            }),
        )
        .unwrap();
        let digest = av_core::digest::sha256_hex(b"ghost-effects:attempt-1");
        std::fs::write(
            marker_dir.join(format!("{}.json", &digest[..32])),
            &sealed,
        )
        .unwrap();

        let warn_once = |_: PathBuf| true;
        let ctx = parts.context(directory.path(), &warn_once);
        let first = QuarantineIncompleteEffectsPass.run(&ctx).await.unwrap();
        assert_eq!(first.quarantined, 1, "one NEW session on the first tick");
        assert!(parts.quarantined_sessions.lock().contains("ghost-effects"));

        let ctx = parts.context(directory.path(), &warn_once);
        let second = QuarantineIncompleteEffectsPass.run(&ctx).await.unwrap();
        assert_eq!(
            second.quarantined, 0,
            "the same marker must not re-count on subsequent ticks"
        );
    }

    /// A missing spool directory is a clean no-op, not an error —
    /// recovery runs before the first session may have spooled.
    #[tokio::test]
    async fn missing_spool_dir_is_a_noop() {
        let parts = CtxParts::new();
        let warn_once = |_: PathBuf| true;
        let ctx = parts.context(Path::new("/nonexistent/spool/dir"), &warn_once);
        let outcome = QuarantineOrphanJsonPass.run(&ctx).await.unwrap();
        assert_eq!(outcome, PassOutcome::default());
        let outcome = QuarantineIncompleteEffectsPass.run(&ctx).await.unwrap();
        assert_eq!(outcome, PassOutcome::default());
        // Bridge-less context: the outbox replay pass is a no-op.
        let outcome = ReplayLifecycleOutboxesPass.run(&ctx).await.unwrap();
        assert_eq!(outcome, PassOutcome::default());
    }

    /// The incomplete-effects pass counts (and warns about) only ids
    /// not already known from earlier ticks — a single crash must not
    /// repeat its warning every tick forever. Marker *creation* is
    /// covered by the reconciler regression tests
    /// (`recovery_tick_does_not_quarantine_live_sessions_with_inflight_markers`
    /// and friends); this pins the pass-level dedupe contract on an
    /// empty spool.
    #[tokio::test]
    async fn incomplete_effects_pass_is_idempotent_on_empty_spool() {
        let directory = tempfile::tempdir().unwrap();
        let parts = CtxParts::new();
        parts
            .quarantined_sessions
            .lock()
            .insert("previously-quarantined".to_owned());
        let warn_once = |_: PathBuf| true;
        let ctx = parts.context(directory.path(), &warn_once);
        let outcome = QuarantineIncompleteEffectsPass.run(&ctx).await.unwrap();
        assert_eq!(outcome.quarantined, 0, "no markers, nothing new to quarantine");
        assert!(
            parts
                .quarantined_sessions
                .lock()
                .contains("previously-quarantined"),
            "prior quarantines must be preserved"
        );
    }
}
