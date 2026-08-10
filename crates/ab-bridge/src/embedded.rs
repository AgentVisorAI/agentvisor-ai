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
    next_offset: u64,
    writer: fs::File,
}

/// File-backed broker instance.
pub struct EmbeddedBroker {
    data_dir: PathBuf,
    manifest: BridgeManifest,
    // topic -> partitions
    partitions: HashMap<String, Vec<Mutex<Partition>>>,
    /// Torn trailing lines dropped during recovery (exposed to metrics).
    pub recovered_torn_lines: u64,
}

impl EmbeddedBroker {
    /// Provision a fresh bridge in `data_dir` from `manifest` alone (R12).
    /// Fails if the directory already contains a bridge.
    pub fn provision(data_dir: &Path, manifest: &BridgeManifest) -> Result<Self, BusError> {
        manifest.validate().map_err(|e| BusError::Backend(e.to_string()))?;
        let manifest_path = data_dir.join("manifest.yaml");
        if manifest_path.exists() {
            return Err(BusError::Backend(format!(
                "bridge already provisioned at {}",
                data_dir.display()
            )));
        }
        fs::create_dir_all(data_dir)?;
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
                let (count, torn) = recover_segment(&path)?;
                torn_total += torn;
                let writer = fs::OpenOptions::new().create(true).append(true).open(&path)?;
                parts.push(Mutex::new(Partition { path, next_offset: count, writer }));
            }
            partitions.insert(t.name.clone(), parts);
        }
        Ok(Self { data_dir: data_dir.to_owned(), manifest, partitions, recovered_torn_lines: torn_total })
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
            let cutoff = now_ms.saturating_sub(u64::from(t.retention.hot_hours) * 3_600_000);
            let Some(parts) = self.partitions.get(&t.name) else { continue };
            for p in parts {
                let mut part = p.lock();
                let (kept, expired) = split_by_time(&part.path, cutoff)?;
                if expired.is_empty() {
                    continue;
                }
                expired_total += expired.len() as u64;
                // Cold export first (never destroy before the copy lands).
                if let Some(cold) = &t.retention.cold_uri {
                    let cold_dir = Path::new(cold).join(&t.name);
                    fs::create_dir_all(&cold_dir)?;
                    let cold_path = cold_dir.join(
                        part.path.file_name().map(|f| f.to_string_lossy().to_string())
                            .unwrap_or_else(|| "p.jsonl".to_owned()),
                    );
                    let mut cold_file = fs::OpenOptions::new().create(true).append(true).open(cold_path)?;
                    for line in &expired {
                        cold_file.write_all(line.as_bytes())?;
                        cold_file.write_all(b"\n")?;
                    }
                    cold_file.sync_all()?;
                }
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
                part.writer = fs::OpenOptions::new().append(true).open(&part.path)?;
            }
        }
        Ok(expired_total)
    }
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
    let count = bytes.get(..complete_len).unwrap_or_default().iter().filter(|b| **b == b'\n').count();
    Ok((count as u64, torn as u64))
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

impl EventBus for EmbeddedBroker {
    fn publish(&self, topic: &str, key: &str, value: &serde_json::Value) -> Result<PublishAck, BusError> {
        let parts = self.partitions.get(topic).ok_or_else(|| BusError::UnknownTopic(topic.to_owned()))?;
        let partition = partition_for(key, u32::try_from(parts.len()).unwrap_or(u32::MAX));
        let slot = parts
            .get(partition as usize)
            .ok_or_else(|| BusError::Backend(format!("partition {partition} out of range")))?;
        let mut part = slot.lock();
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
        part.next_offset += 1;
        Ok(PublishAck { topic: topic.to_owned(), partition, offset })
    }

    fn fetch(
        &self,
        topic: &str,
        partition: u32,
        offset: u64,
        max: usize,
    ) -> Result<Vec<StoredEvent>, BusError> {
        let parts = self.partitions.get(topic).ok_or_else(|| BusError::UnknownTopic(topic.to_owned()))?;
        let slot = parts
            .get(partition as usize)
            .ok_or_else(|| BusError::Backend(format!("partition {partition} out of range")))?;
        let path = {
            let part = slot.lock();
            part.path.clone()
        };
        if !path.exists() {
            return Ok(Vec::new());
        }
        let reader = BufReader::new(fs::File::open(path)?);
        let mut out = Vec::new();
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
}
