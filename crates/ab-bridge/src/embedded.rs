//! The embedded file-backed broker — the Bridge reference backend.
//!
//! Layout: `<data_dir>/manifest.yaml` + `<data_dir>/topics/<topic>/p<N>.jsonl`
//! (one JSONL segment per partition; offset = record index). Appends are
//! serialized per partition; a crash can leave at most one torn trailing line,
//! which recovery detects, truncates, and *counts* (never silently absorbs —
//! D13.16).
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
    /// Torn trailing lines dropped during recovery (exposed to metrics).
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
        if manifest_path.exists() {
            return Err(BusError::Backend(format!(
                "bridge already provisioned at {}",
                data_dir.display()
            )));
        }
        fs::create_dir_all(data_dir)?;
        copy_referenced_schemas(data_dir, manifest)?;
        let yaml = manifest.to_yaml().map_err(|e| BusError::Backend(e.to_string()))?;
        // Manifest write is atomic: tmp + rename.
        let tmp = data_dir.join("manifest.yaml.tmp");
        fs::write(&tmp, &yaml)?;
        fs::rename(&tmp, &manifest_path)?;
        for t in &manifest.topics {
            fs::create_dir_all(data_dir.join("topics").join(&t.name))?;
        }
        Self::open(data_dir)
    }

    /// Open an existing bridge, recovering offsets (and truncating at most one
    /// torn trailing line per partition) from the segment files.
    pub fn open(data_dir: &Path) -> Result<Self, BusError> {
        let manifest_yaml = fs::read_to_string(data_dir.join("manifest.yaml"))?;
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
                torn_total += torn;
                let writer = fs::OpenOptions::new().create(true).append(true).open(&path)?;
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
        let cold_archive = crate::cold_store::ColdArchive::from_manifest(&manifest)?;
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

    /// Enforce per-topic hot retention at time `now_ms`: expired records are
    /// appended to the cold file (when `cold_uri` is a directory path) and
    /// removed from the hot segment via atomic rewrite. Returns the number of
    /// records expired.
    pub fn enforce_retention(&self, now_ms: u64) -> Result<u64, BusError> {
        let mut expired_total = 0u64;
        for t in &self.manifest.topics {
            let cutoff =
                now_ms.saturating_sub(u64::from(t.retention.hot_hours) * ab_core::units::MS_PER_HOUR);
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
                        ab_core::fsutil::sync_directory(&cold_dir)?;
                    }
                }
                persist_high_water(&part.watermark_path, part.next_offset)?;
                // Atomic hot rewrite.
                let tmp = part.path.with_extension("jsonl.tmp");
                {
                    let mut f = fs::File::create(&tmp)?;
                    for line in &kept {
                        f.write_all(line.as_bytes())?;
                        f.write_all(b"\n")?;
                    }
                    f.sync_all()?;
                }
                fs::rename(&tmp, &part.path)?;
                if let Some(parent) = part.path.parent() {
                    ab_core::fsutil::sync_directory(parent)?;
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
    match fs::OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(mut file) => {
            file.write_all(&bytes)?;
            file.sync_all()?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if fs::read(&path)? == bytes {
                Ok(())
            } else {
                Err(BusError::Backend(format!(
                    "cold object {} already exists with different content",
                    path.display()
                )))
            }
        }
        Err(error) => Err(BusError::Io(error)),
    }
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
            let bytes = fs::read(data_dir.join(reference))?;
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
        // Truncate to the last complete record (atomic rewrite).
        let tmp = path.with_extension("jsonl.tmp");
        fs::write(&tmp, bytes.get(..complete_len).unwrap_or_default())?;
        fs::rename(&tmp, path)?;
    }
    let complete = bytes.get(..complete_len).unwrap_or_default();
    let mut next_offset = 0u64;
    for line in complete
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let event: StoredEvent = serde_json::from_slice(line)?;
        next_offset = next_offset.max(event.offset.saturating_add(1));
    }
    Ok((next_offset, torn as u64))
}

fn recover_event_uids(path: &Path) -> Result<HashMap<String, u64>, BusError> {
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let bytes = fs::read(path)?;
    let complete_len = bytes
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |position| position + 1);
    if complete_len < bytes.len() {
        let temporary = path.with_extension("jsonl.tmp");
        fs::write(&temporary, bytes.get(..complete_len).unwrap_or_default())?;
        fs::rename(&temporary, path)?;
    }
    let mut seen = HashMap::new();
    for line in bytes
        .get(..complete_len)
        .unwrap_or_default()
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let mapping: EventUidOffset = serde_json::from_slice(line)?;
        if seen
            .insert(mapping.event_uid.clone(), mapping.offset)
            .is_some_and(|existing| existing != mapping.offset)
        {
            return Err(BusError::Backend(format!(
                "event UID {:?} maps to multiple offsets",
                mapping.event_uid
            )));
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
        let event: StoredEvent = serde_json::from_str(&line)?;
        let Some(uid) = event_uid_from_value(&event.value) else {
            continue;
        };
        if seen
            .insert(uid.to_owned(), event.offset)
            .is_some_and(|existing| existing != event.offset)
        {
            return Err(BusError::Backend(format!(
                "event UID {uid:?} maps to multiple offsets"
            )));
        }
    }
    Ok(())
}

fn event_uid_from_value(value: &serde_json::Value) -> Option<&str> {
    value
        .get("metadata")
        .and_then(|metadata| metadata.get("uid"))
        .and_then(serde_json::Value::as_str)
}

fn read_high_water(path: &Path) -> Result<u64, BusError> {
    match fs::read_to_string(path) {
        Ok(value) => value
            .trim()
            .parse::<u64>()
            .map_err(|error| BusError::Backend(format!("invalid high-watermark: {error}"))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(BusError::Io(error)),
    }
}

fn persist_high_water(path: &Path, next_offset: u64) -> Result<(), BusError> {
    let parent = path
        .parent()
        .ok_or_else(|| BusError::Backend("high-watermark has no parent".to_owned()))?;
    let temporary = path.with_extension(format!("{}.tmp", ab_core::new_event_uid()));
    {
        let mut file = fs::File::create(&temporary)?;
        file.write_all(next_offset.to_string().as_bytes())?;
        file.sync_all()?;
    }
    fs::rename(temporary, path)?;
    ab_core::fsutil::sync_directory(parent)?;
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
            stored_at: ab_core::time::now_ms(),
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
            let mut idempotency = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&part.idempotency_path)?;
            idempotency.write_all(mapping.as_bytes())?;
            idempotency.write_all(b"\n")?;
            idempotency.sync_data()?;
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
            archive.set_control_key(_key);
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
        if !part.path.exists() {
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
        EmbeddedBroker::enforce_retention(self, now_ms)
    }
}
