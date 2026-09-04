//! The embedded file-backed broker — the Bridge reference backend.
//!
//! Layout: `<data_dir>/manifest.yaml` + per partition under
//! `<data_dir>/topics/<topic>/`: `p<N>.jsonl` (the JSONL segment),
//! `p<N>.next-offset` (durable high-water mark), and `p<N>.event-uids.jsonl`
//! (idempotency sidecar). Offsets are stable logical positions: retention
//! rewrites keep surviving records under their original offsets, so after
//! expiry the first file line can carry an offset > 0. Segment appends are
//! serialized per partition; a crash can leave at most one torn trailing
//! line, which recovery detects, truncates, and *counts* (never silently
//! absorbs — D13.16). A torn sidecar tail is truncated without counting and
//! rebuilt from the recovered segment.
//!
//! Scope: single-process access (the harness embeds the broker or fronts it).
//! Cross-process multi-writer setups use the NATS/Kafka connectors.

use crate::bus::{partition_for, BusError, EventBus, PublishAck, StoredEvent};
use crate::manifest::BridgeManifest;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

struct Partition {
    path: PathBuf,
    watermark_path: PathBuf,
    idempotency_path: PathBuf,
    seen_event_uids: HashMap<String, u64>,
    next_offset: u64,
    writer: fs::File,
    /// Set when a failed append could not be repaired by truncating the
    /// segment back to its last known-good length. Every subsequent
    /// publish on this partition is refused (fail-closed) — appending
    /// after torn bytes would merge into the next record and make the
    /// whole partition unreadable to `fetch`. Cleared only by restart,
    /// where segment recovery re-establishes a consistent tail.
    poisoned: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EventUidOffset {
    event_uid: String,
    offset: u64,
}

/// File-backed broker instance.
pub struct EmbeddedBroker {
    data_dir: PathBuf,
    manifest: BridgeManifest,
    #[cfg(feature = "cold-store")]
    cold_archive: Option<crate::cold_store::ColdArchive>,
    // topic -> partitions
    partitions: HashMap<String, Vec<Mutex<Partition>>>,
    validators: HashMap<String, jsonschema::Validator>,
    /// Torn trailing lines dropped during recovery (public field asserted
    /// by the contract tests; not currently read by any caller or
    /// exported as a metric).
    pub recovered_torn_lines: u64,
}

impl EmbeddedBroker {
    /// Provision a fresh bridge in `data_dir` from `manifest` alone (R12).
    /// Fails if the directory already contains a bridge.
    pub fn provision(data_dir: &Path, manifest: &BridgeManifest) -> Result<Self, BusError> {
        manifest
            .validate()
            .map_err(|e| BusError::Backend(e.to_string()))?;
        // Reject a scheme-URI cold_uri BEFORE
        // any filesystem side effect. The prior check lived in
        // `open()` (after provision had already written manifest.yaml,
        // per-topic dirs, and schema copies to disk); when
        // provision-then-open failed here, the operator saw a "bridge
        // already provisioned" error on retry after fixing the
        // manifest, because the botched files still sat in data_dir.
        // Move the check to the top of provision so a failure leaves
        // data_dir untouched and retry-clean.
        #[cfg(not(feature = "cold-store"))]
        reject_cold_uri_without_feature(manifest)?;
        // Resolve and schema-validate every referenced schema BEFORE the
        // single-winner claim below: `manifest.validate()` does not check
        // schema refs, so an unresolvable/invalid ref must fail here —
        // side-effect-free and retry-clean — not after the claim has
        // already been taken (see the rollback note further down).
        let resolved_schemas = resolve_referenced_schemas(manifest)?;
        let manifest_path = data_dir.join("manifest.yaml");
        av_core::fsutil::create_dir_all_synced(data_dir)?;
        let yaml = manifest.to_yaml().map_err(|e| BusError::Backend(e.to_string()))?;
        // Atomic single-winner claim on a fresh provision: the
        // `hard_link(2)` below fails with EEXIST if the target already
        // exists — an OS-level
        // exclusion primitive, so N concurrent provisions race
        // on the same directory and exactly one wins. The old shape
        // (`exists()` check → separate write) had a TOCTOU: two racers
        // could both see "does not exist", both write, both succeed.
        //
        // Any error path — write_all, sync_all, hard_link, os signal —
        // must clean up the tmp file. TmpGuard's Drop covers the
        // early-return paths (ENOSPC, EIO on write, permission errors
        // on sync); the winner path explicitly disarms the guard just
        // before returning Ok so its finalised link is not deleted.
        use std::io::Write as _;
        let tmp = data_dir.join(format!("manifest.yaml.{}.tmp", av_core::new_event_uid()));
        struct TmpGuard {
            path: Option<std::path::PathBuf>,
        }
        impl TmpGuard {
            fn disarm(&mut self) {
                self.path = None;
            }
        }
        impl Drop for TmpGuard {
            fn drop(&mut self) {
                if let Some(path) = self.path.take() {
                    let _ = fs::remove_file(&path);
                }
            }
        }
        let mut guard = TmpGuard {
            path: Some(tmp.clone()),
        };
        {
            // Explicit 0o600 mode so the manifest doesn't inherit the
            // ambient umask. `hard_link` creates a second entry with
            // the SAME inode (and same mode), so the final manifest
            // path is 0o600 too. Bridge topology, schema refs, and
            // `cold_uri` are not per-session data, but the same
            // uniformity discipline the harness spool applies —
            // durability-critical control files should not ride on
            // the operator's umask.
            let mut tmp_options = fs::OpenOptions::new();
            tmp_options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                tmp_options.mode(0o600);
            }
            let mut file = tmp_options.open(&tmp)?;
            file.write_all(yaml.as_bytes())?;
            file.sync_all()?;
        }
        match fs::hard_link(&tmp, &manifest_path) {
            Ok(_) => {
                // The tmp file was successfully hard-linked to the
                // final path; the link itself is now the manifest.
                // Delete the tmp path entry (the inode stays alive
                // through the second link) and disarm the guard.
                let _ = fs::remove_file(&tmp);
                guard.disarm();
            }
            Err(error) => {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    // Loser arm: tmp is auto-removed by TmpGuard on Err.
                    // Use the basename to avoid leaking
                    // the absolute deployment dir if this BusError
                    // ever flows through a tracing::warn!(%error)
                    // path.
                    return Err(BusError::Backend(format!(
                        "bridge already provisioned at {}",
                        av_core::fsutil::basename(data_dir)
                    )));
                }
                return Err(BusError::Io(error));
            }
        }
        av_core::fsutil::sync_directory(data_dir).map_err(BusError::Io)?;
        // Schema copies and topic directories are written only AFTER the
        // hard-link claim above declared this provision the single
        // winner. Writing them before the claim (the old order) meant a
        // provision attempt against an ALREADY-provisioned bridge
        // overwrote the live bridge's schema files under
        // `data_dir/<schema_ref>` before erroring "bridge already
        // provisioned" — and `load_validators` falls back to those
        // copies for non-builtin refs, so the next open() silently
        // validated against the loser's schemas. It also let two racing
        // provisions cross-pollute each other's directories.
        //
        // The refs themselves were resolved and validated pre-claim, so
        // only environmental I/O errors (ENOSPC, permissions) can fail
        // here — and those must roll the claim back, or every retry
        // fails "bridge already provisioned" against a half-provisioned
        // directory (the retry-clean invariant).
        let post_claim = write_referenced_schemas(data_dir, &resolved_schemas).and_then(|()| {
            for t in &manifest.topics {
                av_core::fsutil::create_dir_all_synced(&data_dir.join("topics").join(&t.name))?;
            }
            Ok(())
        });
        if let Err(error) = post_claim {
            let _ = fs::remove_file(&manifest_path);
            let _ = av_core::fsutil::sync_directory(data_dir);
            return Err(error);
        }
        Self::open(data_dir)
    }

    /// Open an existing bridge, recovering offsets (and truncating at most one
    /// torn trailing line per partition) from the segment files.
    pub fn open(data_dir: &Path) -> Result<Self, BusError> {
        // Cap the bridge manifest read. A hostile plant of a
        // multi-GiB manifest.yaml would OOM the broker at startup before
        // the YAML parser could complain.
        let manifest_yaml = av_core::fsutil::read_capped_string(
            &data_dir.join("manifest.yaml"),
            av_core::fsutil::MAX_CONTROL_BYTES,
        )?;
        let manifest =
            BridgeManifest::from_yaml(&manifest_yaml).map_err(|e| BusError::Backend(e.to_string()))?;
        // NOTE: no orphaned-temp sweep here — the daemon performs the
        // sweep itself at boot (main.rs), where it is the single
        // writer. `open()` mutates on-disk state during recovery
        // (torn-tail truncate, sidecar rewrite, append handles), so it
        // must only ever run in the single-writer daemon; read-side
        // tooling running beside a live daemon uses
        // [`Self::fetch_read_only`] instead.
        let mut partitions = HashMap::new();
        let mut torn_total = 0u64;
        for t in &manifest.topics {
            let dir = data_dir.join("topics").join(&t.name);
            av_core::fsutil::create_dir_all_synced(&dir)?;
            let mut parts = Vec::with_capacity(t.partitions as usize);
            for p in 0..t.partitions {
                let path = dir.join(format!("p{p}.jsonl"));
                let watermark_path = dir.join(format!("p{p}.next-offset"));
                let idempotency_path = dir.join(format!("p{p}.event-uids.jsonl"));
                let (segment_offset, torn) = recover_segment(&path)?;
                let persisted_offset = read_high_water(&watermark_path)?;
                let mut seen_event_uids = recover_event_uids(&idempotency_path)?;
                recover_segment_event_uids(&path, &mut seen_event_uids)?;
                // Post-reconciliation drop: any UID whose offset does
                // not correspond to a record still present in the
                // segment (e.g., record purged by retention but the
                // sidecar rewrite lost the corresponding delete in a
                // crash between segment rename and sidecar rewrite)
                // must be evicted. Otherwise `publish_idempotent`
                // short-circuits to a stale offset and callers fetch
                // whatever event lives at that offset today, silently
                // returning the wrong record.
                //
                // Mirror `enforce_retention`'s policy for
                // unparseable-but-kept lines: any UID whose offset
                // falls in the [min, max] offset range of surviving
                // parseable records is kept, because it may correspond
                // to an unparseable-but-authentic line at that offset.
                // Without this parity, an unparseable segment record
                // after a crash would drop its sidecar entry, letting
                // the next publish_idempotent re-append a duplicate
                // that the following retention pass would choke on.
                if !seen_event_uids.is_empty() {
                    let mut live_uids =
                        std::collections::HashSet::<String>::with_capacity(seen_event_uids.len());
                    let mut min_offset = u64::MAX;
                    let mut max_offset = 0u64;
                    let mut have_parseable_line = false;
                    let mut unparseable_lines = 0u64;
                    if path.exists() {
                        for line in BufReader::new(fs::File::open(&path)?).lines() {
                            let Ok(line) = line else {
                                continue;
                            };
                            if line.is_empty() {
                                continue;
                            }
                            if let Ok(event) = serde_json::from_str::<StoredEvent>(&line) {
                                if let Some(uid) = event_uid_from_value(&event.value) {
                                    live_uids.insert(uid.to_owned());
                                }
                                min_offset = min_offset.min(event.offset);
                                max_offset = max_offset.max(event.offset);
                                have_parseable_line = true;
                            } else {
                                unparseable_lines = unparseable_lines.saturating_add(1);
                            }
                        }
                    }
                    // A TRAILING unparseable
                    // complete line occupies an offset ABOVE the max
                    // parseable one, so the previous [min, max]-of-
                    // parseable range dropped its UID — the exact
                    // duplicate-re-append case the range heuristic was
                    // added for, just at the other edge. Extend the
                    // upper bound by the count of unparseable lines
                    // (each occupies exactly one offset). When the
                    // segment has ONLY unparseable lines we have no
                    // offset information at all — keep every sidecar
                    // entry (conservative: at worst a stale ack that
                    // the fetch-side digest checks catch) rather than
                    // dropping evidence.
                    let offset_range = if have_parseable_line {
                        Some((min_offset, max_offset.saturating_add(unparseable_lines)))
                    } else if unparseable_lines > 0 {
                        tracing::warn!(
                            topic = %t.name,
                            partition = p,
                            unparseable_lines,
                            "segment has only unparseable lines; keeping all sidecar UID entries"
                        );
                        Some((0, u64::MAX))
                    } else {
                        None
                    };
                    let before = seen_event_uids.len();
                    seen_event_uids.retain(|uid, offset| {
                        if live_uids.contains(uid) {
                            return true;
                        }
                        match offset_range {
                            Some((lo, hi)) => *offset >= lo && *offset <= hi,
                            None => false,
                        }
                    });
                    if seen_event_uids.len() != before {
                        tracing::warn!(
                            topic = %t.name,
                            partition = p,
                            dropped = before - seen_event_uids.len(),
                            "sidecar UID→offset entries dropped: corresponding segment records \
                             absent (likely retention crash between segment rewrite and sidecar rewrite)"
                        );
                    }
                }
                torn_total += torn;
                // Track first-time creation so we can fsync the directory
                // after the file is materialised — `sync_data()` on the
                // append handle flushes bytes and size, but the directory
                // entry that names the inode is only durable after a
                // `sync_directory(parent)`. Without this, N successful
                // publishes → acked → power loss → boot back with the
                // segment file absent and every acked event lost until
                // another directory-fsyncing path runs (the retention
                // rewrite, or the sidecar-creation fsync in
                // `publish_with_uid`).
                let segment_created = std::fs::symlink_metadata(&path).is_err();
                // Same 0o600 + O_NOFOLLOW discipline the harness spool
                // applies. Segment JSONL carries full `StoredEvent`
                // records (instance_uid + event payload + tool/prompt
                // bytes + cost), which is the same "session-derived
                // data" class the harness-side R18/R19 fix protected.
                let mut open_options = fs::OpenOptions::new();
                open_options.create(true).append(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt as _;
                    open_options
                        .custom_flags(av_core::fsutil::unix_o_nofollow())
                        .mode(0o600);
                }
                let writer = open_options.open(&path)?;
                if segment_created {
                    av_core::fsutil::sync_directory(&dir).map_err(BusError::Io)?;
                }
                parts.push(Mutex::new(Partition {
                    path,
                    watermark_path,
                    idempotency_path,
                    seen_event_uids,
                    next_offset: segment_offset.max(persisted_offset),
                    writer,
                    poisoned: None,
                }));
            }
            partitions.insert(t.name.clone(), parts);
        }
        let validators = load_validators(data_dir, &manifest)?;
        #[cfg(feature = "cold-store")]
        let cold_archive = crate::cold_store::ColdArchive::from_manifest_with_pending_default(
            &manifest,
            Some(data_dir.join("cold-outbox")),
        )?;
        // Fail fast at boot on a scheme-URI `cold_uri` in a build without
        // the `cold-store` feature. Previously the error only surfaced
        // when the first record actually expired — up to `hot_hours`
        // (default 168 h) after boot — and, because `enforce_retention`
        // `?`-propagates out of the per-topic loop, halted retention for
        // every topic ordered after the misconfigured one. Boot-time
        // validation matches the fail-fast policy of every other
        // feature-gated backend (kafka/nats/redis/onnx/qdrant).
        #[cfg(not(feature = "cold-store"))]
        reject_cold_uri_without_feature(&manifest)?;
        Ok(Self {
            data_dir: data_dir.to_owned(),
            manifest,
            #[cfg(feature = "cold-store")]
            cold_archive,
            partitions,
            validators,
            recovered_torn_lines: torn_total,
        })
    }

    /// The manifest this bridge was provisioned from.
    pub fn manifest(&self) -> &BridgeManifest {
        &self.manifest
    }

    /// Data directory.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Read-only event fetch for tooling running BESIDE a live daemon
    /// (`avctl event-tail`). [`Self::open`] is NOT safe for that use:
    /// its recovery "repairs" a torn segment tail via `set_len` and
    /// atomically rewrites the idempotency sidecar — racing a daemon
    /// that is mid-append (between `write_all` of the record bytes and
    /// the trailing newline), a second process's repair truncates
    /// bytes the daemon goes on to ack as durable: a silently lost or
    /// corrupted acked audit event. There is no cross-process lock, so
    /// the only safe concurrent mode is one that mutates nothing.
    ///
    /// This path only reads: the manifest (capped, to validate the
    /// topic/partition and locate the segment), then a bounded
    /// streaming scan of the one segment file. An unparseable line is
    /// skipped (same policy as [`EventBus::fetch`]); an unterminated
    /// trailing line — an in-flight append or crash-torn tail — is
    /// ignored, never truncated; a record above the per-line bound
    /// stops the scan at that point (fail-stop, mutation-free).
    pub fn fetch_read_only(
        data_dir: &Path,
        topic: &str,
        partition: u32,
        offset: u64,
        max: usize,
    ) -> Result<Vec<StoredEvent>, BusError> {
        /// Same generous per-record bound as `recover_segment`.
        const MAX_SEGMENT_LINE_BYTES: u64 = 16 * 1024 * 1024;
        let manifest_yaml = av_core::fsutil::read_capped_string(
            &data_dir.join("manifest.yaml"),
            av_core::fsutil::MAX_CONTROL_BYTES,
        )?;
        let manifest =
            BridgeManifest::from_yaml(&manifest_yaml).map_err(|e| BusError::Backend(e.to_string()))?;
        let topic_spec = manifest
            .topics
            .iter()
            .find(|t| t.name == topic)
            .ok_or_else(|| BusError::UnknownTopic(topic.to_owned()))?;
        if partition >= topic_spec.partitions {
            return Err(BusError::Backend(format!("partition {partition} out of range")));
        }
        let path = data_dir
            .join("topics")
            .join(topic)
            .join(format!("p{partition}.jsonl"));
        let file = match fs::File::open(&path) {
            Ok(file) => file,
            // Provisioned topic whose segment has no events yet (the
            // daemon materialises it lazily at open/publish).
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(BusError::Io(error)),
        };
        let mut reader = std::io::BufReader::new(file);
        let mut out = Vec::with_capacity(max.min(1024));
        let mut buf: Vec<u8> = Vec::new();
        while out.len() < max {
            buf.clear();
            let read = {
                use std::io::Read as _;
                let mut limited = (&mut reader).take(MAX_SEGMENT_LINE_BYTES);
                use std::io::BufRead as _;
                limited.read_until(b'\n', &mut buf)?
            };
            if read == 0 {
                break;
            }
            if buf.last() != Some(&b'\n') {
                // In-flight append, crash-torn tail, or a record above
                // the line cap. A writer-side open() decides what to do
                // about those; a read-only tail just stops before them.
                break;
            }
            let line = buf.get(..buf.len().saturating_sub(1)).unwrap_or_default();
            if line.is_empty() {
                continue;
            }
            let ev: StoredEvent = match serde_json::from_slice(line) {
                Ok(ev) => ev,
                Err(error) => {
                    tracing::warn!(
                        %error,
                        path = %av_core::fsutil::basename(&path),
                        "skipping unparseable segment record during read-only fetch",
                    );
                    continue;
                }
            };
            if ev.offset < offset {
                continue;
            }
            out.push(ev);
        }
        Ok(out)
    }
}

/// Reject a manifest that names a scheme-URI `cold_uri` when this build
/// lacks the `cold-store` feature: retention would silently accept the
/// value at boot and only fail on the first tick that produced expired
/// records (up to `hot_hours` later), and — because `enforce_retention`
/// `?`-propagates out of the per-topic loop — halt retention for every
/// topic ordered after it. Boot-time refusal matches the fail-fast
/// policy of every other feature-gated backend.
#[cfg(not(feature = "cold-store"))]
fn reject_cold_uri_without_feature(manifest: &BridgeManifest) -> Result<(), BusError> {
    for topic in &manifest.topics {
        if let Some(cold) = topic.retention.cold_uri.as_deref() {
            if cold.contains("://") {
                return Err(BusError::Backend(format!(
                    "topic {:?} configures cold_uri {cold:?} which requires feature cold-store; \
                     rebuild av-bridge with `--features cold-store` (or `cold-store-aws`) or clear \
                     the field",
                    topic.name,
                )));
            }
        }
    }
    Ok(())
}

impl EmbeddedBroker {
    /// Enforce per-topic hot retention at time `now_ms`: when
    /// `retention.cold_uri` is set, each expired record
    /// is first exported to the cold tier as its own write-once object (via the
    /// authenticated `ColdArchive` for `scheme://` URIs, or
    /// `write_cold_event_once` for local directory paths) before being
    /// removed from the hot segment via atomic rewrite; with `cold_uri`
    /// unset, expired records are dropped from the hot segment without
    /// export. Returns the number of
    /// records expired.
    pub fn enforce_retention(&self, now_ms: u64) -> Result<u64, BusError> {
        let mut expired_total = 0u64;
        // Contain per-partition failures. A
        // persistent error class (divergent cold intent, cold-dir
        // permission error, content-mismatch) used to `?`-propagate out
        // of the whole two-level loop — starving retention for that
        // topic AND every topic after it in manifest order, forever,
        // until disk filled. Process every partition, then surface the
        // first error as an aggregate so the maintenance counter still
        // fires.
        let mut first_error: Option<(String, BusError)> = None;
        for t in &self.manifest.topics {
            let cutoff =
                now_ms.saturating_sub(u64::from(t.retention.hot_hours) * av_core::units::MS_PER_HOUR);
            let Some(parts) = self.partitions.get(&t.name) else {
                continue;
            };
            for p in parts {
                let mut part = p.lock();
                // A poisoned partition's segment may carry torn bytes from
                // an unrepaired append failure. Rewriting it here would
                // preserve the partial line WITH a trailing newline —
                // converting a restart-repairable torn tail (recover_segment
                // truncates a no-newline tail) into a permanent corrupt
                // line that breaks `fetch` forever. Skip until a restart
                // re-establishes a consistent tail.
                if let Some(reason) = &part.poisoned {
                    tracing::warn!(
                        topic = %t.name,
                        reason = %reason,
                        "skipping retention on a poisoned partition (restart to recover)"
                    );
                    continue;
                }
                let outcome: Result<u64, BusError> = (|| {
                    let (kept, expired) = split_by_time(&part.path, cutoff)?;
                    if expired.is_empty() {
                        return Ok(0);
                    }
                    let expired_count = expired.len() as u64;
                    // Cold export first (never destroy before the copy lands).
                    if let Some(cold) = &t.retention.cold_uri {
                        if cold.contains("://") {
                            #[cfg(feature = "cold-store")]
                            {
                                let archive = self.cold_archive.as_ref().ok_or_else(|| {
                                    BusError::Backend(format!("cold archive for {:?} is unavailable", t.name))
                                })?;
                                for line in &expired {
                                    let event: StoredEvent = serde_json::from_str(line)?;
                                    archive.put(&t.name, &event)?;
                                }
                            }
                            #[cfg(not(feature = "cold-store"))]
                            return Err(BusError::Backend(format!(
                                "cold_uri {cold:?} requires feature cold-store"
                            )));
                        } else {
                            let partition = part
                                .path
                                .file_stem()
                                .and_then(std::ffi::OsStr::to_str)
                                .unwrap_or("partition");
                            let cold_dir = Path::new(cold).join(&t.name).join(partition);
                            // Sync newly created ancestors too: the hot rewrite
                            // below destroys the only other copy, so the cold
                            // subtree's dirents must be durable before it runs.
                            av_core::fsutil::create_dir_all_synced(&cold_dir)?;
                            for line in &expired {
                                let event: StoredEvent = serde_json::from_str(line)?;
                                write_cold_event_once(&cold_dir, &event)?;
                            }
                            av_core::fsutil::sync_directory(&cold_dir)?;
                        }
                    }
                    persist_high_water(&part.watermark_path, part.next_offset)?;
                    // Atomic hot rewrite. Use a UUID-suffixed tmp name so a
                    // stale tmp from a prior crashed pass isn't reused (and
                    // an external backup/rsync tool can't grab an
                    // in-progress file thinking it's stable data).
                    let tmp = part
                        .path
                        .with_extension(format!("jsonl.{}.tmp", av_core::new_event_uid()));
                    // RAII guard cleans up the tmp on any early
                    // Err in the write/sync/rename path so a repeatedly-
                    // failing rewrite (ENOSPC/EIO) does not fill the inode
                    // table with UUID-suffixed orphan .tmp files.
                    let mut guard = av_core::fsutil::TempPathGuard::new(tmp.clone());
                    {
                        // Explicit 0o600 mode so the retention rewrite
                        // doesn't silently ratchet segment permissions
                        // back to 0o644 under the ambient umask — the
                        // previous `File::create` recipe would land at
                        // 0o644 on default-umask hosts and, because
                        // `rename` preserves the tmp's mode, every
                        // retention pass re-opened the confidentiality
                        // gap the initial 0o600 append open closes.
                        let mut tmp_options = fs::OpenOptions::new();
                        tmp_options.write(true).create_new(true);
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::OpenOptionsExt as _;
                            tmp_options.mode(0o600);
                        }
                        let mut f = tmp_options.open(&tmp)?;
                        for line in &kept {
                            f.write_all(line.as_bytes())?;
                            f.write_all(b"\n")?;
                        }
                        f.sync_all()?;
                    }
                    fs::rename(&tmp, &part.path)?;
                    guard.disarm();
                    // Everything between the rename above and a successful
                    // writer reopen below runs while `part.writer` still holds
                    // the fd of the pre-rewrite (now unlinked) inode. If any of
                    // it fails, propagating the error WITHOUT poisoning the
                    // partition would leave that stale handle live: every
                    // subsequent publish would append to the unlinked inode —
                    // acked as durable, invisible to `fetch`, and irrecoverably
                    // freed at process exit. Poison the partition on any
                    // post-rename failure so appends fail closed until a
                    // restart reopens the renamed segment (same fail-closed
                    // posture as an unrepaired append truncation).
                    let post_rename: Result<(), BusError> = (|| {
                        if let Some(parent) = part.path.parent() {
                            av_core::fsutil::sync_directory(parent)?;
                        }
                        // Prune the idempotency map + sidecar of any UID whose offset
                        // was expired: without this, a subsequent `publish_idempotent`
                        // with a still-cached UID returns an ack pointing at data that
                        // no longer exists, and the caller's follow-up `fetch(offset)`
                        // silently returns the wrong event or nothing.
                        //
                        // Expired lines are parseable
                        // BY CONSTRUCTION (`split_by_time` never expires an
                        // unparseable line), so we can remove exactly the
                        // expired offsets. The previous survivors+[min,max]
                        // range heuristic was unsound at both edges: a
                        // wall-clock regression could expire a MIDDLE-offset
                        // record whose UID then survived pruning (stale ack →
                        // wrong-record fetch), and a trailing unparseable
                        // kept line's offset fell OUTSIDE the range so its
                        // UID was dropped (duplicate re-append on the next
                        // publish_idempotent).
                        let expired_offsets: std::collections::HashSet<u64> = expired
                            .iter()
                            .filter_map(|line| serde_json::from_str::<StoredEvent>(line).ok())
                            .map(|event| event.offset)
                            .collect();
                        let before = part.seen_event_uids.len();
                        part.seen_event_uids
                            .retain(|_, offset| !expired_offsets.contains(offset));
                        if part.seen_event_uids.len() != before {
                            // Sidecar is now stale — rewrite it atomically with only
                            // the surviving mappings so recovery cannot resurrect a
                            // just-expired UID.
                            let mut lines: Vec<(String, u64)> = part
                                .seen_event_uids
                                .iter()
                                .map(|(uid, offset)| (uid.clone(), *offset))
                                .collect();
                            lines.sort_by_key(|(_, offset)| *offset);
                            let mut sidecar = Vec::new();
                            for (uid, offset) in lines {
                                let mapping = serde_json::to_string(&EventUidOffset {
                                    event_uid: uid,
                                    offset,
                                })?;
                                sidecar.extend_from_slice(mapping.as_bytes());
                                sidecar.push(b'\n');
                            }
                            rewrite_atomic(&part.idempotency_path, &sidecar)?;
                        }
                        // Segment reopen after retention rewrite. Use
                        // O_NOFOLLOW so a co-tenant that raced the
                        // rename window with a symlink plant cannot
                        // hijack the next authenticated append (a
                        // spool-plant confused-deputy). No create ⇒
                        // 0o600 mode is decorative but preserved for
                        // uniformity with the initial-open site.
                        let mut reopen = fs::OpenOptions::new();
                        reopen.append(true);
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::OpenOptionsExt as _;
                            reopen
                                .custom_flags(av_core::fsutil::unix_o_nofollow())
                                .mode(0o600);
                        }
                        part.writer = reopen.open(&part.path)?;
                        Ok(())
                    })();
                    if let Err(error) = post_rename {
                        part.poisoned = Some(format!(
                            "retention post-rename failure ({error}); the append handle may still \
                         reference the replaced segment inode (restart to recover)"
                        ));
                        return Err(error);
                    }
                    Ok(expired_count)
                })();
                match outcome {
                    Ok(count) => expired_total += count,
                    Err(error) => {
                        tracing::warn!(
                            topic = %t.name,
                            %error,
                            "retention failed for this partition; remaining topics/partitions continue"
                        );
                        if first_error.is_none() {
                            first_error = Some((t.name.clone(), error));
                        }
                    }
                }
            }
        }
        match first_error {
            Some((topic, error)) => Err(BusError::Backend(format!(
                "retention failed for topic {topic:?} (remaining topics were still processed, \
                 {expired_total} records expired): {error}"
            ))),
            None => Ok(expired_total),
        }
    }
}

fn write_cold_event_once(directory: &Path, event: &StoredEvent) -> Result<(), BusError> {
    let path = directory.join(format!("{:020}.json", event.offset));
    let bytes = serde_json::to_vec(event)?;
    if path.exists() {
        return if fs::read(&path)? == bytes {
            // Idempotent re-export (e.g. a retention pass that crashed
            // after the cold copy landed but before the hot rewrite).
            Ok(())
        } else {
            // Path-leak hazard: `write_cold_event_once`
            // errors bubble up through `enforce_retention` and can
            // reach a
            // tracing::warn!(%error) on the maintenance path.
            // Basename the absolute cold-destination path so a
            // duplicate-object collision doesn't ship the
            // deployment topology to OTLP.
            Err(BusError::Backend(format!(
                "cold object {} already exists with different content",
                av_core::fsutil::basename(&path)
            )))
        };
    }
    // Crash-atomic write-once. Writing directly at the final name
    // (create_new → write_all → sync_all) meant a crash/ENOSPC mid-write
    // left a torn file there, and every subsequent retention pass hit
    // AlreadyExists + content mismatch → enforce_retention aborted for
    // all topics, forever. Stage in a UUID-suffixed tmp, fsync, then
    // rename — the final path only ever holds complete objects (same
    // shape as `rewrite_atomic`; the caller fsyncs the directory after
    // the batch). True conflicts are still detected by the pre-existing
    // content comparison above.
    let tmp = path.with_extension(format!("json.{}.tmp", av_core::new_event_uid()));
    let mut guard = av_core::fsutil::TempPathGuard::new(tmp.clone());
    {
        // Explicit 0o600 mode — cold objects carry full `StoredEvent`
        // records (same session-data class as the hot segment). The
        // previous `File::create` recipe landed at 0o644 under the
        // ambient umask; `rename` preserves the tmp's mode, so cold
        // storage inherited world-readable posture without
        // announcement.
        let mut tmp_options = fs::OpenOptions::new();
        tmp_options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            tmp_options.mode(0o600);
        }
        let mut file = tmp_options.open(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, &path)?;
    guard.disarm();
    Ok(())
}

/// Pre-claim phase: resolve and schema-validate every referenced schema
/// without touching the filesystem, so a bad `schema_ref` fails provision
/// retry-clean (before the single-winner claim).
fn resolve_referenced_schemas(
    manifest: &BridgeManifest,
) -> Result<Vec<(String, serde_json::Value)>, BusError> {
    let mut resolved = Vec::new();
    for topic in &manifest.topics {
        let Some(reference) = &topic.schema_ref else {
            continue;
        };
        let value = crate::manifest::schema_document(reference)?;
        jsonschema::options()
            .should_validate_formats(true)
            .build(&value)
            .map_err(|error| BusError::Backend(format!("invalid schema {reference:?}: {error}")))?;
        resolved.push((reference.clone(), value));
    }
    Ok(resolved)
}

/// Post-claim phase: persist the pre-resolved schema copies.
fn write_referenced_schemas(
    data_dir: &Path,
    resolved: &[(String, serde_json::Value)],
) -> Result<(), BusError> {
    for (reference, value) in resolved {
        let destination = data_dir.join(reference);
        if let Some(parent) = destination.parent() {
            av_core::fsutil::create_dir_all_synced(parent)?;
        }
        // Fsync-safe atomic replace: a crash mid-`fs::write` (the old
        // shape) left torn JSON that made the `load_validators` disk
        // fallback fail `open()` permanently for non-builtin refs.
        rewrite_atomic(&destination, &serde_json::to_vec_pretty(value)?)?;
    }
    Ok(())
}

fn load_validators(
    data_dir: &Path,
    manifest: &BridgeManifest,
) -> Result<HashMap<String, jsonschema::Validator>, BusError> {
    let mut validators = HashMap::new();
    for topic in &manifest.topics {
        let Some(reference) = &topic.schema_ref else {
            continue;
        };
        let schema = crate::manifest::schema_document(reference).or_else(|_| {
            // Cap the schema file read. Schemas are control-
            // plane data (bounded well below 1 MiB in practice); a hostile
            // plant of a multi-GiB schema file would OOM the broker before
            // the JSON parser could complain.
            let bytes =
                av_core::fsutil::read_capped(&data_dir.join(reference), av_core::fsutil::MAX_CONTROL_BYTES)?;
            serde_json::from_slice(&bytes).map_err(BusError::from)
        })?;
        let validator = jsonschema::options()
            .should_validate_formats(true)
            .build(&schema)
            .map_err(|error| BusError::Backend(format!("invalid schema {reference:?}: {error}")))?;
        validators.insert(topic.name.clone(), validator);
    }
    Ok(validators)
}

/// Count complete lines; truncate a torn trailing line if present.
///
/// Streams the segment (same pattern as
/// `recover_event_uids`) instead of `fs::read`-ing it whole: segments
/// grow with accepted event traffic and are only time-bounded by
/// retention, so recovery of a large partition otherwise loaded an
/// arbitrarily large file fully into memory — the one unbounded
/// allocation left in startup recovery. Each line is capped; a line
/// above the cap fails the open loudly (fail closed, like a corrupt
/// watermark) rather than risking the allocation.
fn recover_segment(path: &Path) -> Result<(u64, u64), BusError> {
    /// Generous per-record bound: the harness caps request bodies at
    /// 16 MiB, so no legitimately published event line approaches this.
    const MAX_SEGMENT_LINE_BYTES: u64 = 16 * 1024 * 1024;
    use std::io::BufRead as _;
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok((0, 0)),
        Err(error) => return Err(BusError::Io(error)),
    };
    let mut reader = std::io::BufReader::new(file);
    let mut buf: Vec<u8> = Vec::new();
    let mut complete_len: u64 = 0;
    let mut next_offset = 0u64;
    let mut torn = false;
    loop {
        buf.clear();
        let read = {
            use std::io::Read as _;
            let mut limited = (&mut reader).take(MAX_SEGMENT_LINE_BYTES);
            limited.read_until(b'\n', &mut buf)?
        };
        if read == 0 {
            break;
        }
        if buf.last() != Some(&b'\n') {
            if read as u64 == MAX_SEGMENT_LINE_BYTES {
                return Err(BusError::Backend(format!(
                    "segment {} contains a record above {MAX_SEGMENT_LINE_BYTES} bytes; refusing to open the partition",
                    av_core::fsutil::basename(path)
                )));
            }
            // Torn trailing line (crash mid-append).
            torn = true;
            break;
        }
        complete_len = complete_len.saturating_add(read as u64);
        let line = buf.get(..buf.len().saturating_sub(1)).unwrap_or_default();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_slice::<StoredEvent>(line) {
            Ok(event) => next_offset = next_offset.max(event.offset.saturating_add(1)),
            // A single unparseable middle line must not brick the broker.
            // The corrupted bytes are left on disk as forensic evidence;
            // subsequent publishes append past the surviving max offset.
            // The line still occupies one logical offset (segment lines are
            // appended in offset order), so advance next_offset past it —
            // computing next_offset from parseable lines only let a corrupt
            // *trailing* line regress next_offset, and the next publish
            // reused that line's live offset (offset collision in the
            // audit stream).
            Err(error) => {
                next_offset = next_offset.saturating_add(1);
                tracing::warn!(
                    %error,
                    path = %av_core::fsutil::basename(path),
                    "skipping unparseable segment record during recovery",
                );
            }
        }
    }
    if torn {
        // In-place truncate + fsync: unlike the old whole-file
        // `rewrite_atomic` (which required buffering the entire segment),
        // `set_len` touches only file metadata — a crash mid-truncate
        // leaves either the torn or the truncated length, never an
        // empty/renamed-away segment, so the total-segment-loss hazard
        // the old comment guarded against cannot occur.
        //
        // O_NOFOLLOW: this reopens a path derived from a broker
        // partition name; a pre-planted symlink at that path would
        // otherwise let a co-tenant redirect the `set_len` +
        // `sync_all` to an arbitrary file the daemon UID can touch
        // (canonical confused-deputy).
        let mut reopen = fs::OpenOptions::new();
        reopen.write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            reopen.custom_flags(av_core::fsutil::unix_o_nofollow());
        }
        let file = reopen.open(path)?;
        file.set_len(complete_len)?;
        file.sync_all()?;
    }
    Ok((next_offset, u64::from(torn)))
}

fn recover_event_uids(path: &Path) -> Result<HashMap<String, u64>, BusError> {
    if !path.exists() {
        return Ok(HashMap::new());
    }
    // Stream the sidecar with BufReader rather than
    // reading it whole and capping at MAX_ATIF_BYTES. The sidecar grows
    // one line per idempotent publish, compacted only when retention
    // expires UIDs — at 30-day default hot retention, ~1M live events
    // per partition (≈0.4 ev/s) crosses 64 MiB. The previous hard cap
    // would then fail `open()` on every restart, permanently bricking
    // the broker even though the segment on disk is authoritative and
    // `recover_segment_event_uids` will fix the map either way. Bound
    // per-line via `read_line` (line length is only limited by
    // `EventUidOffset`'s JSON encoding at ~200 B); an oversize line is
    // treated as sidecar corruption and skipped, matching the parse
    // failure discipline just below.
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let mut seen = HashMap::new();
    let mut line_buffer = Vec::new();
    let mut valid_bytes: u64 = 0;
    let mut has_torn_tail = false;
    let mut logged_oversize_line = false;
    // Sibling once-per-file guards for the parse-failure and
    // duplicate-UID branches below. A crashed or hostile writer can
    // leave sidecars with millions of mangled-JSON lines (up to
    // hot-retention × events/partition, ≈ 1M per partition); without
    // per-branch guards the recovery pass would emit one warn per
    // corrupt line during the very restart it's diagnosing, bricking
    // the log pipeline. Same discipline as `logged_oversize_line`
    // above.
    let mut logged_parse_failure = false;
    let mut logged_duplicate_uid = false;
    // A single oversized-line hard cap: 4 KiB is 20x the fattest
    // sidecar record we produce. The reader is `take`-bounded to the
    // cap (+1 to detect overshoot) so a planted multi-GiB single line
    // cannot grow the buffer to file size; the overflow tail is
    // drained in cap-sized chunks and the whole line is skipped,
    // matching the parse-failure discipline below.
    const MAX_SIDECAR_LINE: usize = 4096;
    loop {
        line_buffer.clear();
        let bytes_read = {
            use std::io::Read as _;
            let mut limited = (&mut reader).take(MAX_SIDECAR_LINE as u64 + 1);
            match limited.read_until(b'\n', &mut line_buffer) {
                Ok(0) => break,
                Ok(bytes) => bytes,
                Err(error) => return Err(BusError::Io(error)),
            }
        };
        let terminated = line_buffer.last() == Some(&b'\n');
        if !terminated && bytes_read > MAX_SIDECAR_LINE {
            // Oversized line cut off by the `take` bound: drain the
            // rest of it in bounded chunks so the skip stays O(cap)
            // in memory whatever the line length on disk.
            let mut drained: u64 = bytes_read as u64;
            let mut found_newline = false;
            loop {
                line_buffer.clear();
                use std::io::Read as _;
                let mut limited = (&mut reader).take(MAX_SIDECAR_LINE as u64 + 1);
                match limited.read_until(b'\n', &mut line_buffer) {
                    Ok(0) => break,
                    Ok(bytes) => {
                        drained = drained.saturating_add(bytes as u64);
                        if line_buffer.last() == Some(&b'\n') {
                            found_newline = true;
                            break;
                        }
                    }
                    Err(error) => return Err(BusError::Io(error)),
                }
            }
            if !found_newline {
                // Oversized AND unterminated: the classic torn tail,
                // just fat. Truncate to the last complete line.
                has_torn_tail = true;
                break;
            }
            if !logged_oversize_line {
                tracing::warn!(
                    path = %av_core::fsutil::basename(path),
                    line_bytes = drained,
                    "oversized event-uid sidecar record skipped during recovery"
                );
                logged_oversize_line = true;
            }
            valid_bytes = valid_bytes.saturating_add(drained);
            continue;
        }
        if !terminated {
            // Trailing partial line (crash between newline appends);
            // the atomic-append discipline in `publish_with_uid`
            // guarantees any complete line is fully synced before the
            // next one starts, so this is the classic torn tail.
            has_torn_tail = true;
            break;
        }
        if bytes_read > MAX_SIDECAR_LINE {
            if !logged_oversize_line {
                tracing::warn!(
                    path = %av_core::fsutil::basename(path),
                    line_bytes = bytes_read,
                    "oversized event-uid sidecar record skipped during recovery"
                );
                logged_oversize_line = true;
            }
            valid_bytes = valid_bytes.saturating_add(bytes_read as u64);
            continue;
        }
        valid_bytes = valid_bytes.saturating_add(bytes_read as u64);
        let payload = line_buffer.strip_suffix(b"\n").unwrap_or(&line_buffer);
        if payload.is_empty() {
            continue;
        }
        let mapping: EventUidOffset = match serde_json::from_slice(payload) {
            Ok(mapping) => mapping,
            // Sidecar corruption skip-and-log: the segment is the
            // ground truth (see `recover_segment_event_uids` below), and
            // an unreadable idempotency line at most costs a duplicate
            // ack for the same UID.
            Err(error) => {
                if !logged_parse_failure {
                    tracing::warn!(
                        %error,
                        path = %av_core::fsutil::basename(path),
                        "skipping unparseable event-uid sidecar record during recovery; \
                         subsequent parse failures on this sidecar suppressed to avoid log storm"
                    );
                    logged_parse_failure = true;
                }
                continue;
            }
        };
        if let Some(existing) = seen.insert(mapping.event_uid.clone(), mapping.offset) {
            if existing != mapping.offset {
                // Sidecar (idempotency journal) can legitimately hold
                // stale UID→offset pairs after a partial retention
                // (segment rewritten atomically, sidecar rewrite lost
                // in a crash). The segment on disk is the source of
                // truth; log and let `recover_segment_event_uids` fix
                // the mapping. Refusing to open the broker here would
                // brick the whole tier over a benign inconsistency.
                if !logged_duplicate_uid {
                    tracing::warn!(
                        event_uid = %mapping.event_uid,
                        prior_offset = existing,
                        current_offset = mapping.offset,
                        path = %av_core::fsutil::basename(path),
                        "sidecar has duplicate UID entry; segment offset will win after \
                         full recovery. Subsequent duplicate-UID entries on this sidecar \
                         suppressed to avoid log storm"
                    );
                    logged_duplicate_uid = true;
                }
            }
        }
    }
    if has_torn_tail {
        // Truncate to the last complete line so future appends land
        // cleanly (the on-disk record set is unchanged). A transient
        // I/O error on `read_valid_prefix` (bit-rot, ENOENT race
        // with a concurrent unlink between the earlier BufReader
        // open and this reopen) must NOT collapse to an
        // `unwrap_or_default()` empty Vec — that atomically renames
        // a zero-byte file on top of the sidecar, permanently
        // destroying every persisted `EventUidOffset` mapping under
        // the guise of "torn-tail repair". Fail closed instead —
        // the caller retries recovery on the next daemon boot with
        // the sidecar bytes still intact. Same posture as
        // `read_high_water` (line 1132), which explicitly refused
        // its old "fail-open Ok(0)" for the identical rationale.
        let valid_prefix = read_valid_prefix(path, valid_bytes).map_err(BusError::Io)?;
        rewrite_atomic(path, &valid_prefix)?;
    }
    Ok(seen)
}

fn read_valid_prefix(path: &Path, len: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    let file = std::fs::File::open(path)?;
    let mut reader = file.take(len);
    let mut out = Vec::with_capacity(len.try_into().unwrap_or(usize::MAX));
    reader.read_to_end(&mut out)?;
    Ok(out)
}

fn recover_segment_event_uids(path: &Path, seen: &mut HashMap<String, u64>) -> Result<(), BusError> {
    if !path.exists() {
        return Ok(());
    }
    for line in BufReader::new(fs::File::open(path)?).lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }
        let event: StoredEvent = match serde_json::from_str(&line) {
            Ok(event) => event,
            // Same skip-and-log policy as `recover_segment`: an unreadable
            // segment record has already been flagged there; here it just
            // means we cannot reconstruct its UID → offset mapping.
            Err(error) => {
                tracing::warn!(
                    %error,
                    path = %av_core::fsutil::basename(path),
                    "skipping unparseable segment record while rebuilding UID index",
                );
                continue;
            }
        };
        let Some(uid) = event_uid_from_value(&event.value) else {
            continue;
        };
        if let Some(existing) = seen.insert(uid.to_owned(), event.offset) {
            if existing != event.offset {
                // Segment is authoritative — the sidecar was stale
                // (see recover_event_uids for the crash mode). Log
                // and keep the segment offset (the last write wins
                // via insert). Refusing to open would leave the
                // broker un-openable on a benign inconsistency.
                tracing::warn!(
                    event_uid = uid,
                    prior_offset = existing,
                    current_offset = event.offset,
                    "duplicate UID between sidecar and segment; segment offset wins"
                );
            }
        }
    }
    Ok(())
}

/// Fsync-safe replace. Do not hand-roll the atomic-write recipe here:
/// a hand-rolled copy diverged from the
/// canonical helper by using `File::create` instead of `create_new`.
/// Delegate to `av_core::fsutil::write_atomic` — one recipe, one set
/// of durability invariants (create_new tmp, sync_all, rename,
/// best-effort parent dirent fsync, RAII orphan cleanup).
fn rewrite_atomic(path: &Path, bytes: &[u8]) -> Result<(), BusError> {
    av_core::fsutil::write_atomic(path, bytes).map_err(BusError::from)
}

fn event_uid_from_value(value: &serde_json::Value) -> Option<&str> {
    value
        .get("metadata")
        .and_then(|metadata| metadata.get("uid"))
        .and_then(serde_json::Value::as_str)
}

fn read_high_water(path: &Path) -> Result<u64, BusError> {
    // A watermark is at most u64 in decimal (~20 chars). Cap
    // the read so a hostile plant of a giant p<N>.next-offset cannot OOM
    // the broker at startup. Use MAX_CONTROL_BYTES (1 MiB) for the
    // shared trust boundary; a real watermark is orders of magnitude
    // smaller.
    match av_core::fsutil::read_capped_string(path, av_core::fsutil::MAX_CONTROL_BYTES) {
        Ok(value) => match value.trim().parse::<u64>() {
            Ok(offset) => Ok(offset),
            // A corrupt watermark file IS fatal. The old fail-open
            // fallback (`Ok(0)`) claimed the segment is authoritative
            // and "the next successful publish rewrites the watermark
            // and self-heals" — both false: `persist_high_water` runs
            // only from `enforce_retention`, and the watermark exists
            // precisely for the case where retention has emptied the
            // segment. Falling back to 0 there restarts `next_offset`
            // at 0, reusing offsets of already-cold-exported records
            // (offset collisions in the audit stream, permanent
            // "cold object … already exists with different content"
            // conflicts). Fail closed like every other corrupt
            // control file in this crate; NotFound below stays Ok(0)
            // because a missing watermark is a legitimate fresh state.
            Err(error) => Err(BusError::Backend(format!(
                "high-watermark file {} is corrupt ({error}); refusing to open the partition",
                av_core::fsutil::basename(path)
            ))),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(BusError::Io(error)),
    }
}

fn persist_high_water(path: &Path, next_offset: u64) -> Result<(), BusError> {
    let parent = path
        .parent()
        .ok_or_else(|| BusError::Backend("high-watermark has no parent".to_owned()))?;
    let temporary = path.with_extension(format!("{}.tmp", av_core::new_event_uid()));
    // RAII cleanup on any early Err — same discipline as
    // `rewrite_atomic` above. On a bad-disk day, watermark writes fire
    // on every publish; orphan tmp accumulation would be fastest here.
    let mut guard = av_core::fsutil::TempPathGuard::new(temporary.clone());
    {
        // Explicit 0o600 mode — the watermark leaks throughput
        // pattern (a next-offset u64), which is minor per-file but
        // adds up over a busy broker. Cheap uniformity with the
        // segment/sidecar posture; removes umask-dependence from
        // the durability-critical control files.
        let mut tmp_options = fs::OpenOptions::new();
        tmp_options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            tmp_options.mode(0o600);
        }
        let mut file = tmp_options.open(&temporary)?;
        file.write_all(next_offset.to_string().as_bytes())?;
        file.sync_all()?;
    }
    fs::rename(&temporary, path)?;
    guard.disarm();
    av_core::fsutil::sync_directory(parent)?;
    Ok(())
}

/// Partition a segment's lines into (kept, expired) by `stored_at < cutoff`.
fn split_by_time(path: &Path, cutoff_ms: u64) -> Result<(Vec<String>, Vec<String>), BusError> {
    let mut kept = Vec::new();
    let mut expired = Vec::new();
    if !path.exists() {
        return Ok((kept, expired));
    }
    let reader = BufReader::new(fs::File::open(path)?);
    for line in reader.lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }
        let is_expired = serde_json::from_str::<StoredEvent>(&line)
            .map(|e| e.stored_at < cutoff_ms)
            .unwrap_or(false);
        if is_expired {
            expired.push(line);
        } else {
            kept.push(line);
        }
    }
    Ok((kept, expired))
}

impl EmbeddedBroker {
    fn publish_with_uid(
        &self,
        topic: &str,
        key: &str,
        value: &serde_json::Value,
        event_uid: Option<&str>,
    ) -> Result<PublishAck, BusError> {
        let parts = self
            .partitions
            .get(topic)
            .ok_or_else(|| BusError::UnknownTopic(topic.to_owned()))?;
        if let Some(validator) = self.validators.get(topic) {
            let errors: Vec<String> = validator
                .iter_errors(value)
                .take(3)
                .map(|error| error.to_string())
                .collect();
            if !errors.is_empty() {
                return Err(BusError::Backend(format!(
                    "event rejected by schema for topic {topic:?}: {}",
                    errors.join("; ")
                )));
            }
        }
        if let Some(expected) = event_uid {
            match event_uid_from_value(value) {
                Some(actual) if expected != actual => {
                    return Err(BusError::Backend(
                        "idempotency UID does not match event metadata UID".to_owned(),
                    ));
                }
                // A missing metadata.uid would make crash recovery lose the UID
                // → sidecar because recover_segment_event_uids scans metadata.uid;
                // require the UID to be embedded so recovery is deterministic.
                None => {
                    return Err(BusError::Backend(
                        "idempotent publish requires event metadata.uid to match the UID".to_owned(),
                    ));
                }
                _ => {}
            }
        }
        let partition = partition_for(key, u32::try_from(parts.len()).unwrap_or(u32::MAX));
        let slot = parts
            .get(partition as usize)
            .ok_or_else(|| BusError::Backend(format!("partition {partition} out of range")))?;
        let mut part = slot.lock();
        if let Some(reason) = &part.poisoned {
            return Err(BusError::Backend(format!(
                "partition {partition} of topic {topic:?} is poisoned by an unrepaired append failure \
                 (restart to recover): {reason}"
            )));
        }
        if let Some(uid) = event_uid {
            if let Some(offset) = part.seen_event_uids.get(uid).copied() {
                return Ok(PublishAck {
                    topic: topic.to_owned(),
                    partition,
                    offset,
                });
            }
        }
        let offset = part.next_offset;
        let record = StoredEvent {
            partition,
            offset,
            key: key.to_owned(),
            value: value.clone(),
            stored_at: av_core::time::now_ms(),
        };
        let line = serde_json::to_string(&record)?;
        // Capture the durable length before appending so a failed append can
        // be repaired. Without the truncate-on-error below, two failure
        // modes leave the partition permanently inconsistent while the same
        // writer stays live:
        //   1. a torn write (ENOSPC/EIO mid-`write_all`) leaves partial
        //      bytes that the NEXT publish appends after, merging both into
        //      one unparseable line that ends in '\n' — `fetch` then errors
        //      on every read, and startup recovery only repairs torn
        //      *trailing* lines (no newline at EOF), not mid-file ones;
        //   2. a failed `sync_data` after a complete write leaves the
        //      record durable while `next_offset` was never advanced, so
        //      the next publish stamps a different record with the same
        //      offset (duplicate offsets hidden by max(offset)+1 recovery).
        let known_good = part.writer.metadata()?.len();
        let append = (|| {
            part.writer.write_all(line.as_bytes())?;
            part.writer.write_all(b"\n")?;
            part.writer.flush()?;
            part.writer.sync_data()
        })();
        if let Err(error) = append {
            if let Err(repair) = part
                .writer
                .set_len(known_good)
                .and_then(|()| part.writer.sync_data())
            {
                // The segment may still carry torn bytes; refuse further
                // appends (fail-closed) rather than corrupt the next record.
                part.poisoned = Some(format!("append failed ({error}); truncation failed ({repair})"));
            }
            return Err(BusError::Io(error));
        }
        part.next_offset = part
            .next_offset
            .checked_add(1)
            .ok_or_else(|| BusError::Backend("embedded offset overflow".to_owned()))?;
        if let Some(uid) = event_uid {
            part.seen_event_uids.insert(uid.to_owned(), offset);
            // The sidecar is a rebuildable cache: `open()` reconciles it
            // from the segment itself (`recover_segment_event_uids` —
            // idempotent publishes are required to embed metadata.uid),
            // and the in-memory map updated above already serves
            // same-process retries. The record is durable (fsynced append
            // above), so a sidecar failure must NOT fail the publish:
            // reporting an error for an operation whose primary effect
            // succeeded invites the caller to re-mint the event under a
            // fresh UID — a genuine duplicate. Log loudly and return the
            // ack instead.
            let sidecar_write = (|| -> Result<(), BusError> {
                let mapping = serde_json::to_string(&EventUidOffset {
                    event_uid: uid.to_owned(),
                    offset,
                })?;
                // Directory entry for a first-time-created sidecar is only
                // durable after sync_directory(parent). Sync the parent when
                // we discover we're creating the file so a subsequent power
                // loss cannot lose the whole sidecar (which would silently
                // convert future publish_idempotent calls into duplicate
                // appends).
                let sidecar_created = std::fs::symlink_metadata(&part.idempotency_path).is_err();
                // Same 0o600 + O_NOFOLLOW discipline the segment append
                // gets — sidecar entries are (event_uid, offset) pairs,
                // and event_uids are session-derived identifiers.
                let mut sidecar_options = fs::OpenOptions::new();
                sidecar_options.create(true).append(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt as _;
                    sidecar_options
                        .custom_flags(av_core::fsutil::unix_o_nofollow())
                        .mode(0o600);
                }
                let mut idempotency = sidecar_options.open(&part.idempotency_path)?;
                idempotency.write_all(mapping.as_bytes())?;
                idempotency.write_all(b"\n")?;
                idempotency.sync_data()?;
                if sidecar_created {
                    if let Some(parent) = part.idempotency_path.parent() {
                        av_core::fsutil::sync_directory(parent)?;
                    }
                }
                Ok(())
            })();
            if let Err(error) = sidecar_write {
                tracing::warn!(
                    %error,
                    topic,
                    partition,
                    offset,
                    "idempotency sidecar append failed; the publish is durable and the \
                     UID index will be rebuilt from the segment at the next open"
                );
            }
        }
        Ok(PublishAck {
            topic: topic.to_owned(),
            partition,
            offset,
        })
    }
}

impl EventBus for EmbeddedBroker {
    fn set_control_key(&self, _key: [u8; 32]) -> Result<(), BusError> {
        #[cfg(feature = "cold-store")]
        if let Some(archive) = &self.cold_archive {
            archive.set_control_key(_key)?;
        }
        Ok(())
    }

    fn publish(&self, topic: &str, key: &str, value: &serde_json::Value) -> Result<PublishAck, BusError> {
        self.publish_with_uid(topic, key, value, event_uid_from_value(value))
    }

    fn publish_idempotent(
        &self,
        topic: &str,
        key: &str,
        value: &serde_json::Value,
        event_uid: &str,
    ) -> Result<PublishAck, BusError> {
        self.publish_with_uid(topic, key, value, Some(event_uid))
    }

    /// O(1) event-UID lookup via the partition's in-memory
    /// `seen_event_uids` map. The default trait impl at
    /// `bus.rs::find_event_by_uid` linearly scans the segment from
    /// offset 0 with `fetch`, which for `EmbeddedBroker` re-opens
    /// the segment file each call and streams from the head with
    /// a `BufReader` — so each fetch page for offset > 0 also walks
    /// the whole prefix. `resolve_lifecycle_ack` in the harness
    /// calls this on EVERY `emit_bridge_event` (twice per session
    /// close — RECEIPT + SESSION_CLOSE), which meant close latency
    /// grew O(total events per partition²) amortised. The Kafka
    /// and NATS bus implementations both override with O(1) lookups;
    /// only the embedded broker was still on the trait default.
    fn find_event_by_uid(
        &self,
        topic: &str,
        key: &str,
        event_uid: &str,
    ) -> Result<Option<PublishAck>, BusError> {
        let parts = self
            .partitions
            .get(topic)
            .ok_or_else(|| BusError::UnknownTopic(topic.to_owned()))?;
        let partition = partition_for(key, u32::try_from(parts.len()).unwrap_or(u32::MAX));
        let slot = parts
            .get(partition as usize)
            .ok_or_else(|| BusError::Backend(format!("partition {partition} out of range")))?;
        let part = slot.lock();
        Ok(part
            .seen_event_uids
            .get(event_uid)
            .copied()
            .map(|offset| PublishAck {
                topic: topic.to_owned(),
                partition,
                offset,
            }))
    }

    fn fetch(
        &self,
        topic: &str,
        partition: u32,
        offset: u64,
        max: usize,
    ) -> Result<Vec<StoredEvent>, BusError> {
        let parts = self
            .partitions
            .get(topic)
            .ok_or_else(|| BusError::UnknownTopic(topic.to_owned()))?;
        let slot = parts
            .get(partition as usize)
            .ok_or_else(|| BusError::Backend(format!("partition {partition} out of range")))?;
        // Hold the partition lock across the entire read so a concurrent
        // enforce_retention rename cannot swap the segment mid-read.
        let part = slot.lock();
        if max == 0 || !part.path.exists() {
            return Ok(Vec::new());
        }
        let reader = BufReader::new(fs::File::open(&part.path)?);
        let mut out = Vec::with_capacity(max.min(1024));
        for line in reader.lines() {
            let line = line?;
            if line.is_empty() {
                continue;
            }
            let ev: StoredEvent = match serde_json::from_str(&line) {
                Ok(ev) => ev,
                // Same policy as `recover_segment`: a single unparseable
                // complete line (bit-rot, tamper, a crash mode recovery
                // does not repair) must not brick the read side. Retention
                // keeps unparseable lines forever (`split_by_time` treats
                // them as non-expired), so erroring here made every fetch
                // spanning the line fail permanently while publishes kept
                // acking events that could never be delivered.
                Err(error) => {
                    tracing::warn!(
                        %error,
                        path = %av_core::fsutil::basename(&part.path),
                        "skipping unparseable segment record during fetch",
                    );
                    continue;
                }
            };
            if ev.offset < offset {
                continue;
            }
            out.push(ev);
            if out.len() >= max {
                break;
            }
        }
        Ok(out)
    }

    fn partitions(&self, topic: &str) -> Result<u32, BusError> {
        self.partitions
            .get(topic)
            .map(|p| u32::try_from(p.len()).unwrap_or(u32::MAX))
            .ok_or_else(|| BusError::UnknownTopic(topic.to_owned()))
    }

    fn topics(&self) -> Vec<String> {
        let mut t: Vec<String> = self.partitions.keys().cloned().collect();
        t.sort();
        t
    }

    fn maintenance(&self, now_ms: u64) -> Result<u64, BusError> {
        let expired = EmbeddedBroker::enforce_retention(self, now_ms)?;
        // Drain cold-export intents that a previous `ColdArchive::commit`
        // converted from a transient remote failure into a durable
        // "queued for retry" file. Only the Kafka/NATS maintenance paths
        // used to drain the queue; the embedded broker never did, so the
        // retry promise was never fulfilled — a silent permanent
        // cold-tier gap after the record left the hot segment.
        #[cfg(feature = "cold-store")]
        if let Some(archive) = &self.cold_archive {
            archive.retry_pending_with(|pending| {
                // Embedded intents are staged and committed inside one
                // `put()` call during retention, so a surviving
                // offset-None intent means a crash landed between stage
                // and commit while the record was still hot (the segment
                // rewrite only happens after export). Resolve the offset
                // from the partition's idempotency map instead of
                // re-publishing, which would append a duplicate record.
                let parts = self
                    .partitions
                    .get(&pending.topic)
                    .ok_or_else(|| BusError::UnknownTopic(pending.topic.clone()))?;
                let slot = parts.get(pending.partition as usize).ok_or_else(|| {
                    BusError::Backend(format!("partition {} out of range", pending.partition))
                })?;
                let offset = slot
                    .lock()
                    .seen_event_uids
                    .get(&pending.event_uid)
                    .copied()
                    .ok_or_else(|| {
                        BusError::Backend(format!(
                            "cold intent {:?} has no broker offset and no live segment \
                             record to resolve it from; refusing to fabricate one",
                            pending.event_uid
                        ))
                    })?;
                Ok(PublishAck {
                    topic: pending.topic.clone(),
                    partition: pending.partition,
                    offset,
                })
            })?;
        }
        Ok(expired)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn stored(offset: u64) -> StoredEvent {
        StoredEvent {
            partition: 0,
            offset,
            key: "inst".to_owned(),
            value: serde_json::json!({"n": offset}),
            stored_at: 1,
        }
    }

    /// A corrupt complete line occupies one logical offset. If it is the
    /// *last* line, next_offset must not regress below it — computing
    /// next_offset from parseable lines only made the next publish reuse
    /// the corrupt line's live offset.
    #[test]
    fn recover_segment_counts_a_corrupt_trailing_line_as_one_offset() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p0.jsonl");
        let mut lines = String::new();
        for offset in 0..2u64 {
            lines.push_str(&serde_json::to_string(&stored(offset)).unwrap());
            lines.push('\n');
        }
        lines.push_str("{corrupt-but-complete\n");
        fs::write(&path, &lines).unwrap();
        let (next_offset, torn) = recover_segment(&path).unwrap();
        assert_eq!(torn, 0, "a complete corrupt line is kept, not a torn tail");
        assert_eq!(next_offset, 3, "the corrupt line at offset 2 must be counted");
    }

    /// A corrupt *middle* line must not overshoot: the running counter
    /// advances by one for the corrupt line and the trailing parseable
    /// line still governs.
    #[test]
    fn recover_segment_keeps_next_offset_exact_with_a_corrupt_middle_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p0.jsonl");
        let mut lines = String::new();
        lines.push_str(&serde_json::to_string(&stored(0)).unwrap());
        lines.push_str("\n{corrupt-but-complete\n");
        lines.push_str(&serde_json::to_string(&stored(2)).unwrap());
        lines.push('\n');
        fs::write(&path, &lines).unwrap();
        let (next_offset, torn) = recover_segment(&path).unwrap();
        assert_eq!(torn, 0);
        assert_eq!(next_offset, 3);
    }

    /// The sidecar recovery's oversized-line skip must stay O(cap) in
    /// memory: the reader is `take`-bounded, the overflow tail is
    /// drained in chunks, and a well-formed record after the giant
    /// line is still recovered. An oversized UNTERMINATED tail is the
    /// classic torn tail and truncates back to the last complete line.
    #[test]
    fn recover_event_uids_skips_oversized_lines_with_bounded_reads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p0.event-uids.jsonl");
        let good_before = "{\"event_uid\":\"uid-before\",\"offset\":1}\n";
        // Well above the 4 KiB cap (and above cap+1 so the drain loop runs).
        let oversized = format!("{{\"event_uid\":\"{}\",\"offset\":2}}\n", "x".repeat(20 * 1024));
        let good_after = "{\"event_uid\":\"uid-after\",\"offset\":3}\n";
        fs::write(&path, format!("{good_before}{oversized}{good_after}")).unwrap();
        let seen = recover_event_uids(&path).unwrap();
        assert_eq!(seen.get("uid-before"), Some(&1));
        assert_eq!(
            seen.get("uid-after"),
            Some(&3),
            "records after the giant line must survive"
        );
        assert_eq!(seen.len(), 2, "the oversized record itself is skipped");
        // Complete lines are never rewritten by a skip-only pass.
        assert!(
            fs::read_to_string(&path).unwrap().ends_with(good_after),
            "no truncation without a torn tail"
        );

        // Oversized AND unterminated: torn tail — truncate to the last
        // complete line, exactly like a small torn tail.
        let torn_path = dir.path().join("p1.event-uids.jsonl");
        let torn_tail = format!("{{\"event_uid\":\"{}\",\"off", "y".repeat(20 * 1024));
        fs::write(&torn_path, format!("{good_before}{torn_tail}")).unwrap();
        let seen = recover_event_uids(&torn_path).unwrap();
        assert_eq!(seen.get("uid-before"), Some(&1));
        assert_eq!(seen.len(), 1);
        assert_eq!(
            fs::read_to_string(&torn_path).unwrap(),
            good_before,
            "torn oversized tail must truncate to the valid prefix"
        );
    }

    /// Crash-atomic write-once contract: identical re-export is
    /// idempotent, divergent content is refused loudly, and no tmp
    /// staging file survives either path (a torn own-write can therefore
    /// never appear at the final name and poison retention forever).
    #[test]
    fn write_cold_event_once_is_idempotent_and_refuses_divergent_content() {
        let dir = tempfile::tempdir().unwrap();
        let event = stored(7);
        write_cold_event_once(dir.path(), &event).unwrap();
        // Identical re-export: idempotent.
        write_cold_event_once(dir.path(), &event).unwrap();
        // Divergent content at the same offset: refused, original kept.
        let mut divergent = stored(7);
        divergent.value = serde_json::json!({"tampered": true});
        let err = write_cold_event_once(dir.path(), &divergent).unwrap_err();
        assert!(
            err.to_string().contains("already exists with different content"),
            "{err}"
        );
        let kept: StoredEvent =
            serde_json::from_slice(&fs::read(dir.path().join("00000000000000000007.json")).unwrap()).unwrap();
        assert_eq!(kept.value, event.value, "conflict must not overwrite");
        // No staging residue: exactly the one final object remains.
        let names: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["00000000000000000007.json".to_owned()], "{names:?}");
    }
}
