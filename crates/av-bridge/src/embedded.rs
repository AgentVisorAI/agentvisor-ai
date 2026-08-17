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
        let manifest_path = data_dir.join("manifest.yaml");
        fs::create_dir_all(data_dir)?;
        copy_referenced_schemas(data_dir, manifest)?;
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
            let mut file = fs::File::create(&tmp)?;
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
                    // Round-37 F1/F2 class: basename to avoid leaking
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
        for t in &manifest.topics {
            fs::create_dir_all(data_dir.join("topics").join(&t.name))?;
        }
        Self::open(data_dir)
    }

    /// Open an existing bridge, recovering offsets (and truncating at most one
    /// torn trailing line per partition) from the segment files.
    pub fn open(data_dir: &Path) -> Result<Self, BusError> {
        // Round-22 F4: cap the bridge manifest read. A hostile plant of a
        // multi-GiB manifest.yaml would OOM the broker at startup before
        // the YAML parser could complain.
        let manifest_yaml = av_core::fsutil::read_capped_string(
            &data_dir.join("manifest.yaml"),
            av_core::fsutil::MAX_CONTROL_BYTES,
        )?;
        let manifest =
            BridgeManifest::from_yaml(&manifest_yaml).map_err(|e| BusError::Backend(e.to_string()))?;
        let mut partitions = HashMap::new();
        let mut torn_total = 0u64;
        for t in &manifest.topics {
            let dir = data_dir.join("topics").join(&t.name);
            fs::create_dir_all(&dir)?;
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
                            }
                        }
                    }
                    let offset_range = if have_parseable_line {
                        Some((min_offset, max_offset))
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
                let segment_created = !path.exists();
                let writer = fs::OpenOptions::new().create(true).append(true).open(&path)?;
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
        for t in &self.manifest.topics {
            let cutoff =
                now_ms.saturating_sub(u64::from(t.retention.hot_hours) * av_core::units::MS_PER_HOUR);
            let Some(parts) = self.partitions.get(&t.name) else {
                continue;
            };
            for p in parts {
                let mut part = p.lock();
                let (kept, expired) = split_by_time(&part.path, cutoff)?;
                if expired.is_empty() {
                    continue;
                }
                expired_total += expired.len() as u64;
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
                        fs::create_dir_all(&cold_dir)?;
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
                // Round-22 F3: RAII guard cleans up the tmp on any early
                // Err in the write/sync/rename path so a repeatedly-
                // failing rewrite (ENOSPC/EIO) does not fill the inode
                // table with UUID-suffixed orphan .tmp files.
                let mut guard = av_core::fsutil::TempPathGuard::new(tmp.clone());
                {
                    let mut f = fs::File::create(&tmp)?;
                    for line in &kept {
                        f.write_all(line.as_bytes())?;
                        f.write_all(b"\n")?;
                    }
                    f.sync_all()?;
                }
                fs::rename(&tmp, &part.path)?;
                guard.disarm();
                if let Some(parent) = part.path.parent() {
                    av_core::fsutil::sync_directory(parent)?;
                }
                // Prune the idempotency map + sidecar of any UID whose offset
                // was expired: without this, a subsequent `publish_idempotent`
                // with a still-cached UID returns an ack pointing at data that
                // no longer exists, and the caller's follow-up `fetch(offset)`
                // silently returns the wrong event or nothing.
                //
                // We compute survivors from parseable lines, but ALSO keep
                // the range [min_kept_offset, max_kept_offset]: any UID
                // whose offset falls in that range is potentially attached
                // to an unparseable-but-kept line, and dropping it would
                // let the next publish_idempotent re-append a duplicate
                // record (which retention would then choke on next pass).
                let survivors: std::collections::HashSet<u64> = kept
                    .iter()
                    .filter_map(|line| serde_json::from_str::<StoredEvent>(line).ok())
                    .map(|event| event.offset)
                    .collect();
                let range = if survivors.is_empty() {
                    None
                } else {
                    // A single manual pass gives min/max and avoids
                    // expect() on the guaranteed-non-empty iterator.
                    let (mut lo, mut hi) = (u64::MAX, 0u64);
                    for offset in &survivors {
                        lo = lo.min(*offset);
                        hi = hi.max(*offset);
                    }
                    Some((lo, hi))
                };
                let before = part.seen_event_uids.len();
                part.seen_event_uids.retain(|_, offset| {
                    if survivors.contains(offset) {
                        return true;
                    }
                    match range {
                        Some((lo, hi)) => *offset >= lo && *offset <= hi,
                        None => false,
                    }
                });
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
                part.writer = fs::OpenOptions::new().append(true).open(&part.path)?;
            }
        }
        Ok(expired_total)
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
            // Round-37 F1/F2 class: `write_cold_event_once`
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
        let mut file = fs::File::create(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, &path)?;
    guard.disarm();
    Ok(())
}

fn copy_referenced_schemas(data_dir: &Path, manifest: &BridgeManifest) -> Result<(), BusError> {
    for topic in &manifest.topics {
        let Some(reference) = &topic.schema_ref else {
            continue;
        };
        let value = crate::manifest::schema_document(reference)?;
        jsonschema::validator_for(&value)
            .map_err(|error| BusError::Backend(format!("invalid schema {reference:?}: {error}")))?;
        let destination = data_dir.join(reference);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(destination, serde_json::to_vec_pretty(&value)?)?;
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
            // Round-22 F4: cap the schema file read. Schemas are control-
            // plane data (bounded well below 1 MiB in practice); a hostile
            // plant of a multi-GiB schema file would OOM the broker before
            // the JSON parser could complain.
            let bytes =
                av_core::fsutil::read_capped(&data_dir.join(reference), av_core::fsutil::MAX_CONTROL_BYTES)?;
            serde_json::from_slice(&bytes).map_err(BusError::from)
        })?;
        let validator = jsonschema::validator_for(&schema)
            .map_err(|error| BusError::Backend(format!("invalid schema {reference:?}: {error}")))?;
        validators.insert(topic.name.clone(), validator);
    }
    Ok(validators)
}

/// Count complete lines; truncate a torn trailing line if present.
fn recover_segment(path: &Path) -> Result<(u64, u64), BusError> {
    if !path.exists() {
        return Ok((0, 0));
    }
    let bytes = fs::read(path)?;
    if bytes.is_empty() {
        return Ok((0, 0));
    }
    let complete_len = match bytes.iter().rposition(|b| *b == b'\n') {
        Some(pos) => pos + 1,
        None => 0, // single torn line, no newline at all
    };
    let torn = usize::from(complete_len < bytes.len());
    if torn == 1 {
        // Same fsync-safe rewrite pattern as `persist_high_water`: without
        // sync_all()+sync_directory a crash during recovery could turn a
        // torn-tail single-record loss into total-segment loss on
        // non-ext4 filesystems.
        rewrite_atomic(path, bytes.get(..complete_len).unwrap_or_default())?;
    }
    let complete = bytes.get(..complete_len).unwrap_or_default();
    let mut next_offset = 0u64;
    for line in complete
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
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
    Ok((next_offset, torn as u64))
}

fn recover_event_uids(path: &Path) -> Result<HashMap<String, u64>, BusError> {
    if !path.exists() {
        return Ok(HashMap::new());
    }
    // Round-22 F4: cap the idempotency sidecar read. The sidecar grows
    // proportionally to live UIDs (bounded by retention) so MAX_ATIF_BYTES
    // (64 MiB) is the operationally-sized ceiling; a hostile plant of a
    // multi-GiB sidecar file would OOM the broker at startup.
    let bytes = av_core::fsutil::read_capped(path, av_core::fsutil::MAX_ATIF_BYTES)?;
    let complete_len = bytes
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |position| position + 1);
    if complete_len < bytes.len() {
        rewrite_atomic(path, bytes.get(..complete_len).unwrap_or_default())?;
    }
    let mut seen = HashMap::new();
    for line in bytes
        .get(..complete_len)
        .unwrap_or_default()
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let mapping: EventUidOffset = match serde_json::from_slice(line) {
            Ok(mapping) => mapping,
            // Sidecar corruption also skip-and-log: the segment is the
            // ground truth (see `recover_segment_event_uids` below), and
            // an unreadable idempotency line at most costs a duplicate
            // ack for the same UID.
            Err(error) => {
                tracing::warn!(
                    %error,
                    path = %av_core::fsutil::basename(path),
                    "skipping unparseable event-uid sidecar record during recovery",
                );
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
                tracing::warn!(
                    event_uid = %mapping.event_uid,
                    prior_offset = existing,
                    current_offset = mapping.offset,
                    "sidecar has duplicate UID entry; segment offset will win after full recovery"
                );
            }
        }
    }
    Ok(seen)
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

/// Fsync-safe replace: `File::create` → `write_all` → `sync_all` → rename
/// → `sync_directory(parent)`. Same shape as `persist_high_water` and the
/// hot-segment rewrite in `enforce_retention`.
fn rewrite_atomic(path: &Path, bytes: &[u8]) -> Result<(), BusError> {
    let parent = path
        .parent()
        .ok_or_else(|| BusError::Backend("atomic rewrite has no parent".to_owned()))?;
    let tmp = path.with_extension(format!("jsonl.{}.tmp", av_core::new_event_uid()));
    // Round-22 F3: RAII cleanup on any early Err. Without this, a
    // failing sync/rename leaves a UUID-suffixed orphan .tmp behind
    // and repeated retries can exhaust ext4/xfs inodes.
    let mut guard = av_core::fsutil::TempPathGuard::new(tmp.clone());
    {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    guard.disarm();
    av_core::fsutil::sync_directory(parent)?;
    Ok(())
}

fn event_uid_from_value(value: &serde_json::Value) -> Option<&str> {
    value
        .get("metadata")
        .and_then(|metadata| metadata.get("uid"))
        .and_then(serde_json::Value::as_str)
}

fn read_high_water(path: &Path) -> Result<u64, BusError> {
    // Round-22 F4: a watermark is at most u64 in decimal (~20 chars). Cap
    // the read so a hostile plant of a giant p<N>.next-offset cannot OOM
    // the broker at startup. Use MAX_CONTROL_BYTES (1 MiB) for the
    // shared trust boundary; a real watermark is orders of magnitude
    // smaller.
    match av_core::fsutil::read_capped_string(path, av_core::fsutil::MAX_CONTROL_BYTES) {
        Ok(value) => match value.trim().parse::<u64>() {
            Ok(offset) => Ok(offset),
            // A corrupt watermark file is not fatal: `next_offset` is
            // recomputed as `segment_offset.max(persisted_offset)` in
            // `open()`, so falling back to 0 lets the segment be
            // authoritative. The next successful publish rewrites the
            // watermark via `persist_high_water` and self-heals.
            Err(error) => {
                tracing::warn!(
                    %error,
                    path = %av_core::fsutil::basename(path),
                    "high-watermark file is corrupt; falling back to segment-derived next_offset",
                );
                Ok(0)
            }
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
    // Round-22 F3: RAII cleanup on any early Err — same discipline as
    // `rewrite_atomic` above. On a bad-disk day, watermark writes fire
    // on every publish; orphan tmp accumulation would be fastest here.
    let mut guard = av_core::fsutil::TempPathGuard::new(temporary.clone());
    {
        let mut file = fs::File::create(&temporary)?;
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
        part.writer.write_all(line.as_bytes())?;
        part.writer.write_all(b"\n")?;
        part.writer.flush()?;
        part.writer.sync_data()?;
        part.next_offset = part
            .next_offset
            .checked_add(1)
            .ok_or_else(|| BusError::Backend("embedded offset overflow".to_owned()))?;
        if let Some(uid) = event_uid {
            part.seen_event_uids.insert(uid.to_owned(), offset);
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
            let sidecar_created = !part.idempotency_path.exists();
            let mut idempotency = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&part.idempotency_path)?;
            idempotency.write_all(mapping.as_bytes())?;
            idempotency.write_all(b"\n")?;
            idempotency.sync_data()?;
            if sidecar_created {
                if let Some(parent) = part.idempotency_path.parent() {
                    av_core::fsutil::sync_directory(parent)?;
                }
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
            let ev: StoredEvent = serde_json::from_str(&line)?;
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
