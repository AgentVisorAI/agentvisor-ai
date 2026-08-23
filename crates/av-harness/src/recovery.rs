//! Recovery-pass seam for the reconciler (round-51 §4.2, S1 step 2).
//!
//! `recover_spooled_sessions` historically interleaved five recovery
//! concerns in one method on `Finalizer`; a bug in one silently
//! affected the others (the round-42/44/51 seal-before-insert races
//! all spanned two concerns). This module introduces the
//! `RecoveryPass` interface from the S1 migration plan
//! (`docs/reference/STRUCTURAL-REFACTORS.md`) and hosts the first
//! extracted pass, the §8.5 orphan-JSON quarantine. Subsequent
//! extractions (step 3 of the plan) move one concern at a time until
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
    /// Filename stems (`sha256(session_id)[..32]`) of every
    /// registry-known session, snapshotted by the caller. Doubles as
    /// the §8.5 live-close guard: a sidecar-less `{stem}.json` whose
    /// stem is known belongs to an in-progress close (between
    /// `write_atomic` and the `.atif-auth` seal) and must not be
    /// quarantined out from under it.
    pub known_stems: &'a HashSet<String>,
    /// Per-artifact warning dedupe (`Finalizer::warn_once`): a file
    /// left on disk as evidence must not repeat its warning every
    /// tick. Returns true when this is the first warn for the path
    /// in the current FIFO window.
    pub warn_once: &'a (dyn Fn(PathBuf) -> bool + Send + Sync),
}

/// What a pass did this run, for tick-level observability.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct PassOutcome {
    /// Files renamed out of the recovery scan glob this run.
    pub quarantined: usize,
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

/// The ordered registry `recover_spooled_sessions` runs before its
/// adoption scan. Each S1 step-3 extraction appends one more pass
/// here instead of growing the god-method.
pub(crate) fn passes() -> &'static [&'static dyn RecoveryPass] {
    &[&QuarantineOrphanJsonPass]
}

/// Round-16 stress finding: a fresh sidecar-less `{stem}.json` is
/// the normal transient state of an in-flight close (`write_atomic`
/// runs moments before `ensure_atif_provenance` seals `.atif-auth`).
/// Only files determinately older than this window are treated as
/// orphans; younger (or indeterminate-age) files are skipped this
/// tick at the cost of a single stat.
pub(crate) const MIN_ORPHAN_AGE: std::time::Duration = std::time::Duration::from_secs(60);

/// §8.5 / round-44 F4: quarantine sidecar-less `.json` spool files.
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
            let mut entries = match tokio::fs::read_dir(ctx.spool_dir).await {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(outcome);
                }
                Err(error) => return Err(FinalizeError::Atif(error.to_string())),
            };
            while let Some(entry) = entries
                .next_entry()
                .await
                .map_err(|error| FinalizeError::Atif(error.to_string()))?
            {
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
                    .is_some_and(|stem| ctx.known_stems.contains(stem))
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

    fn context<'a>(
        spool_dir: &'a Path,
        metrics: &'a Registry,
        known_stems: &'a HashSet<String>,
        warn_once: &'a (dyn Fn(PathBuf) -> bool + Send + Sync),
    ) -> ReconcilerContext<'a> {
        ReconcilerContext {
            spool_dir,
            metrics,
            known_stems,
            warn_once,
        }
    }

    fn age_past_threshold(path: &Path) {
        let old = std::time::SystemTime::now() - MIN_ORPHAN_AGE * 2;
        let file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
        file.set_times(std::fs::FileTimes::new().set_modified(old))
            .unwrap();
    }

    /// The pass-level contract, independent of the Finalizer wiring
    /// (which the reconciler round-44/16 regression tests pin):
    /// aged orphans are renamed, live-stem / young / sidecar'd /
    /// non-json files survive untouched.
    #[tokio::test]
    async fn quarantines_only_aged_unknown_sidecar_less_json() {
        let directory = tempfile::tempdir().unwrap();
        let spool = directory.path();

        let aged_orphan = spool.join("agedorphan.json");
        std::fs::write(&aged_orphan, b"{").unwrap();
        age_past_threshold(&aged_orphan);

        let live_stem = spool.join("livestem.json");
        std::fs::write(&live_stem, b"{").unwrap();
        age_past_threshold(&live_stem);

        let young_orphan = spool.join("young.json");
        std::fs::write(&young_orphan, b"{").unwrap();

        let sealed = spool.join("sealed.json");
        std::fs::write(&sealed, b"{}").unwrap();
        std::fs::write(spool.join("sealed.atif-auth"), b"sig").unwrap();
        age_past_threshold(&sealed);

        let journal = spool.join("abc.session.json");
        std::fs::write(&journal, b"{}").unwrap();
        age_past_threshold(&journal);

        let metrics = Registry::new();
        let known_stems: HashSet<String> = std::iter::once("livestem".to_owned()).collect();
        let warned = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let warned_sink = Arc::clone(&warned);
        let warn_once = move |path: PathBuf| {
            warned_sink.lock().push(path);
            true
        };
        let ctx = context(spool, &metrics, &known_stems, &warn_once);
        let outcome = QuarantineOrphanJsonPass.run(&ctx).await.unwrap();

        assert_eq!(outcome.quarantined, 1, "exactly the aged orphan is renamed");
        assert!(!aged_orphan.exists(), "aged orphan must be renamed");
        assert!(live_stem.exists(), "live-close stem must survive (§8.5)");
        assert!(young_orphan.exists(), "young file must survive (round-16)");
        assert!(sealed.exists(), "sealed artifact must survive");
        assert!(journal.exists(), "step journal must survive");
        assert_eq!(warned.lock().len(), 1, "one warn for the one rename");
    }

    /// A missing spool directory is a clean no-op, not an error —
    /// recovery runs before the first session may have spooled.
    #[tokio::test]
    async fn missing_spool_dir_is_a_noop() {
        let metrics = Registry::new();
        let known_stems = HashSet::new();
        let warn_once = |_: PathBuf| true;
        let ctx = context(
            Path::new("/nonexistent/spool/dir"),
            &metrics,
            &known_stems,
            &warn_once,
        );
        let outcome = QuarantineOrphanJsonPass.run(&ctx).await.unwrap();
        assert_eq!(outcome, PassOutcome::default());
    }
}
