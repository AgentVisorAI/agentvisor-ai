//! Customer-owned cold-tier object storage for acknowledged bridge events.

use crate::{BridgeManifest, BusError, StoredEvent};
use object_store::path::Path;
use object_store::{ObjectStore, ObjectStoreExt as _};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone)]
struct ColdTarget {
    store: Arc<dyn ObjectStore>,
    prefix: Path,
}

pub(crate) struct ColdArchive {
    targets: HashMap<String, ColdTarget>,
    executor: crate::bus::ConnectorExecutor,
    pending_dir: std::path::PathBuf,
    control_key: parking_lot::RwLock<[u8; 32]>,
    /// Serializes pending-intent file read/modify/remove between
    /// publishers (`stage`/`commit`) and the maintenance retry scan, so
    /// neither side observes (or clobbers) an intent mid-update. Never
    /// held across a remote put or a broker resolve: those run up to the
    /// 10 s `ConnectorExecutor` timeout, and the embedded resolver takes
    /// a partition lock that retention holds while staging (ABBA).
    intent_lock: parking_lot::Mutex<()>,
}

/// Grace age below which an offset-None intent is presumed to be a
/// publisher's in-flight stage → produce → commit window and is skipped
/// by the maintenance retry scan. Publishers set `stored_at` to "now"
/// immediately before staging and the `ConnectorExecutor` caps the
/// produce at 10 s, so 60 s comfortably exceeds the longest possible
/// stage→commit window. Resolving a younger intent would re-publish the
/// event mid-produce (duplicate) and make the racing `commit()` fail
/// with NotFound or a conflicting offset (typically triggering a caller
/// retry — a third copy). A genuine crash leftover ages past the grace
/// and is resolved on a later scan.
const RETRY_GRACE_MS: u64 = 60_000;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct PendingColdEvent {
    pub(crate) topic: String,
    pub(crate) event_uid: String,
    pub(crate) partition: u32,
    pub(crate) key: String,
    pub(crate) value: serde_json::Value,
    pub(crate) stored_at: u64,
    pub(crate) offset: Option<u64>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PendingEnvelope {
    payload: PendingColdEvent,
    mac: String,
}

impl ColdArchive {
    // Only called from the kafka/nats bus arms; benign dead code in
    // feature combinations that enable cold-store without either bus.
    #[cfg_attr(not(any(feature = "kafka", feature = "nats")), allow(dead_code))]
    pub(crate) fn from_manifest(manifest: &BridgeManifest) -> Result<Option<Self>, BusError> {
        Self::from_manifest_with_pending_default(manifest, None)
    }

    /// Same as [`Self::from_manifest`] but uses `pending_default` when the
    /// operator-set `AV_COLD_OUTBOX_DIR` env var is absent (falling back to
    /// `data/cold-outbox` when the caller passes no default either).
    /// Callers with a natural data directory (e.g. the embedded
    /// broker) pass `data_dir.join("cold-outbox")` so two brokers in the
    /// same process do not cross-consume each other's intents via the
    /// CWD-relative fallback.
    pub(crate) fn from_manifest_with_pending_default(
        manifest: &BridgeManifest,
        pending_default: Option<std::path::PathBuf>,
    ) -> Result<Option<Self>, BusError> {
        let mut targets = HashMap::new();
        for topic in &manifest.topics {
            let Some(uri) = topic.retention.cold_uri.as_deref() else {
                continue;
            };
            let url = cold_url(uri)?;
            let options = aws_env_options(std::env::vars());
            let (store, prefix) = object_store::parse_url_opts(&url, options).map_err(|error| {
                // Round-6 (hunt5 portability F3): object_store's
                // "feature for AmazonS3 not enabled" names an internal
                // feature the operator cannot act on; map it to the
                // cargo feature that actually fixes the build.
                let detail = error.to_string();
                if detail.contains("not enabled") && url.scheme() == "s3" {
                    BusError::Backend(format!(
                        "cold store {uri:?}: this build has no S3 support — rebuild with \
                         `--features cold-store-aws` (or `full`)"
                    ))
                } else {
                    BusError::Backend(format!("cold store {uri:?}: {detail}"))
                }
            })?;
            targets.insert(
                topic.name.clone(),
                ColdTarget {
                    store: Arc::from(store),
                    prefix,
                },
            );
        }
        if targets.is_empty() {
            return Ok(None);
        }
        let pending_dir = std::env::var_os("AV_COLD_OUTBOX_DIR")
            .map(std::path::PathBuf::from)
            .or(pending_default)
            .unwrap_or_else(|| std::path::PathBuf::from("data/cold-outbox"));
        Ok(Some(Self {
            targets,
            executor: crate::bus::ConnectorExecutor::new("agentvisor-ai-cold-store")?,
            pending_dir,
            control_key: parking_lot::RwLock::new([0; 32]),
            intent_lock: parking_lot::Mutex::new(()),
        }))
    }

    pub(crate) fn set_control_key(&self, key: [u8; 32]) -> Result<(), BusError> {
        // Round-21 F3: refuse known-weak keys. The default init at
        // construction is `[0; 32]` (round-14 and round-20 F5
        // banned both patterns for the primary signing seed;
        // parity here closes the last legal surface for the
        // pattern). Silently accepting a weak key would let a
        // startup-order wiring bug (bus impl forgets to plumb
        // through set_control_key, or a caller passes an
        // uninitialized array) produce a cold-outbox whose
        // authentication tag is forgeable by anyone who guessed
        // the pattern.
        if key == [0u8; 32] || key == [0xFFu8; 32] {
            return Err(BusError::Backend(
                "cold-outbox control key is all-zero or all-0xFF; refusing (known-weak pattern)".to_owned(),
            ));
        }
        *self.control_key.write() = key;
        Ok(())
    }

    pub(crate) fn put(&self, topic: &str, event: &StoredEvent) -> Result<(), BusError> {
        if !self.targets.contains_key(topic) {
            return Ok(());
        }
        let event_uid = event
            .value
            .get("metadata")
            .and_then(|metadata| metadata.get("uid"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| {
                av_core::digest::sha256_hex(
                    format!("{topic}:{}:{}", event.partition, event.offset).as_bytes(),
                )
            });
        self.stage(topic, event, &event_uid)?;
        self.commit(topic, &event_uid, event.offset)
    }

    pub(crate) fn stage(&self, topic: &str, event: &StoredEvent, event_uid: &str) -> Result<(), BusError> {
        if !self.targets.contains_key(topic) {
            return Ok(());
        }
        let pending = PendingColdEvent {
            topic: topic.to_owned(),
            event_uid: event_uid.to_owned(),
            partition: event.partition,
            key: event.key.clone(),
            value: event.value.clone(),
            stored_at: event.stored_at,
            offset: None,
        };
        let pending_path = self.pending_path(topic, event_uid);
        // Existence-check + persist is a read-modify-write on the intent
        // file; hold the intent lock so the retry scan cannot interleave.
        let _guard = self.intent_lock.lock();
        if pending_path.exists() {
            let existing = read_pending(&pending_path, &self.control_key.read())?;
            validate_same_intent(&existing, &pending)?;
            return Ok(());
        }
        persist_pending(&pending_path, &pending, &self.control_key.read())
    }

    pub(crate) fn commit(&self, topic: &str, event_uid: &str, offset: u64) -> Result<(), BusError> {
        if !self.targets.contains_key(topic) {
            return Ok(());
        }
        let pending_path = self.pending_path(topic, event_uid);
        // Read-check-persist under the intent lock so the maintenance
        // retry scan can never observe (or rewrite) the intent mid-update;
        // the remote put runs outside the lock (it is idempotent — a
        // concurrent retry of the same resolved intent writes identical
        // bytes and both removals tolerate NotFound).
        let pending = {
            let _guard = self.intent_lock.lock();
            let mut pending = match read_pending(&pending_path, &self.control_key.read()) {
                Ok(pending) => pending,
                // A racing maintenance pass may have resolved, exported, and
                // removed this intent while the publisher sat between
                // `stage` and `commit` (stalled thread or wall-clock jump
                // past RETRY_GRACE_MS). The export already happened, so the
                // publish as a whole succeeded — mirror the NotFound
                // tolerance of `retry_pending_with` instead of failing a
                // fully-successful publish.
                Err(BusError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            if pending.topic != topic || pending.event_uid != event_uid {
                return Err(BusError::Backend(
                    "cold intent does not match broker acknowledgment".to_owned(),
                ));
            }
            if pending.offset.is_some_and(|existing| existing != offset) {
                return Err(BusError::Backend(
                    "cold intent received conflicting broker offsets".to_owned(),
                ));
            }
            pending.offset = Some(offset);
            persist_pending(&pending_path, &pending, &self.control_key.read())?;
            pending
        };
        match self.put_remote(&pending) {
            Ok(()) => remove_pending(&pending_path),
            Err(error) => {
                tracing::warn!(
                    %error,
                    topic,
                    event_uid,
                    offset,
                    "cold export intent is durable and queued for retry"
                );
                Ok(())
            }
        }
    }

    pub(crate) fn retry_pending_with<F>(&self, mut resolve: F) -> Result<u64, BusError>
    where
        F: FnMut(&PendingColdEvent) -> Result<crate::PublishAck, BusError>,
    {
        let entries = match std::fs::read_dir(&self.pending_dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(BusError::Io(error)),
        };
        let mut completed = 0u64;
        for entry in entries {
            let path = entry?.path();
            if path.extension().and_then(std::ffi::OsStr::to_str) != Some("json") {
                continue;
            }
            // Round-6 (hunt3 F6): isolate per-file failures so ONE
            // corrupt intent does not head-of-line-block cold export
            // for every other durable intent forever. Any error class
            // that would abort the loop (unverifiable MAC, decode
            // failure, filename↔payload mismatch, unavailable target,
            // remote put failure) is now downgraded to warn + quarantine
            // + continue.
            if let Err(error) = self.retry_pending_one(&path, &mut resolve) {
                self.quarantine_cold_intent(&path, &error);
                continue;
            }
            completed = completed.saturating_add(1);
        }
        Ok(completed)
    }

    fn retry_pending_one<F>(&self, path: &std::path::Path, resolve: &mut F) -> Result<(), BusError>
    where
        F: FnMut(&PendingColdEvent) -> Result<crate::PublishAck, BusError>,
    {
        // Read under the intent lock so a concurrent stage/commit
        // rewrite is never observed mid-swap; NotFound means a racing
        // commit already exported and removed the intent.
        let mut pending = {
            let _guard = self.intent_lock.lock();
            match read_pending(path, &self.control_key.read()) {
                Ok(pending) => pending,
                Err(BusError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(());
                }
                Err(error) => return Err(error),
            }
        };
        if path != self.pending_path(&pending.topic, &pending.event_uid) {
            return Err(BusError::Backend(
                "cold outbox path does not match its payload".to_owned(),
            ));
        }
        if pending.offset.is_none() {
            // In-flight publisher window: skip young offset-None
            // intents entirely (see RETRY_GRACE_MS). `stored_at` is
            // MAC-authenticated, so a filesystem tamperer cannot park
            // an intent in the grace window forever.
            if av_core::time::now_ms().saturating_sub(pending.stored_at) < RETRY_GRACE_MS {
                return Ok(());
            }
            let ack = resolve(&pending)?;
            if ack.topic != pending.topic || ack.partition != pending.partition {
                return Err(BusError::Backend(
                    "broker resolver returned an acknowledgment for another cold intent".to_owned(),
                ));
            }
            // Re-read after the (unlocked) resolve: a racing commit may
            // have exported+removed the intent (skip it) or persisted
            // the broker-acked offset (which wins over ours).
            let _guard = self.intent_lock.lock();
            match read_pending(path, &self.control_key.read()) {
                Ok(current) if current.offset.is_some() => pending = current,
                Ok(_) => {
                    pending.offset = Some(ack.offset);
                    persist_pending(path, &pending, &self.control_key.read())?;
                }
                Err(BusError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(());
                }
                Err(error) => return Err(error),
            }
        }
        self.put_remote(&pending)?;
        remove_pending(path)?;
        Ok(())
    }

    fn quarantine_cold_intent(&self, path: &std::path::Path, error: &BusError) {
        let uid = av_core::new_event_uid();
        let quarantine = path.with_extension(format!("json.corrupt-{uid}"));
        if let Err(rename_err) = std::fs::rename(path, &quarantine) {
            tracing::warn!(
                %error,
                %rename_err,
                path = %av_core::fsutil::basename(path),
                "cold outbox intent failed and could not be quarantined — leaving in place"
            );
        } else {
            tracing::warn!(
                %error,
                path = %av_core::fsutil::basename(path),
                quarantine = %av_core::fsutil::basename(&quarantine),
                "cold outbox intent quarantined so remaining exports can proceed"
            );
        }
    }

    fn put_remote(&self, pending: &PendingColdEvent) -> Result<(), BusError> {
        let Some(target) = self.targets.get(&pending.topic).cloned() else {
            return Err(BusError::Backend(format!(
                "cold target for topic {:?} is unavailable",
                pending.topic
            )));
        };
        let location = target
            .prefix
            .clone()
            .join(pending.topic.as_str())
            .join(format!("p{}", pending.partition))
            .join(format!(
                "{:020}.json",
                pending
                    .offset
                    .ok_or_else(|| BusError::Backend("cold intent has no broker offset".to_owned()))?
            ));
        let location_display = location.to_string();
        let payload = serde_json::to_vec(&StoredEvent {
            partition: pending.partition,
            offset: pending.offset.unwrap_or(0),
            key: pending.key.clone(),
            value: pending.value.clone(),
            stored_at: pending.stored_at,
        })?;
        self.executor
            .run(move || async move {
                match target
                    .store
                    .put_opts(
                        &location,
                        payload.clone().into(),
                        object_store::PutMode::Create.into(),
                    )
                    .await
                {
                    Ok(_) => Ok(()),
                    Err(object_store::Error::AlreadyExists { .. }) => {
                        let existing = target
                            .store
                            .get(&location)
                            .await
                            .map_err(|error| error.to_string())?
                            .bytes()
                            .await
                            .map_err(|error| error.to_string())?;
                        if existing.as_ref() == payload.as_slice() {
                            Ok(())
                        } else {
                            Err("existing cold object has different content".to_owned())
                        }
                    }
                    Err(error) => Err(error.to_string()),
                }
            })?
            .map_err(|error| BusError::Backend(format!("cold export {location_display}: {error}")))
    }

    fn pending_path(&self, topic: &str, event_uid: &str) -> std::path::PathBuf {
        self.pending_dir.join(format!(
            "{}.json",
            av_core::digest::sha256_hex(format!("{topic}:{event_uid}").as_bytes())
        ))
    }
}

fn persist_pending(
    path: &std::path::Path,
    pending: &PendingColdEvent,
    control_key: &[u8; 32],
) -> Result<(), BusError> {
    use std::io::Write as _;
    let parent = path
        .parent()
        .ok_or_else(|| BusError::Backend("cold outbox has no parent".to_owned()))?;
    // Sync newly created ancestors too: the intent this file records is
    // the only durable trace of a staged cold export, and an unsynced
    // ancestor dirent can drop the whole outbox subtree on power loss.
    av_core::fsutil::create_dir_all_synced(parent)?;
    let temporary = path.with_extension(format!("{}.tmp", av_core::new_event_uid()));
    // Round-22 F3: arm the RAII guard immediately after choosing the
    // temp path so that any Err on mac/serialize/write/sync/rename
    // cleans up the tmp instead of leaving an orphan. Repeated
    // ENOSPC/EIO on a bad-disk day would otherwise unboundedly
    // consume inodes (UUIDv7-suffixed .tmp names never collide).
    let mut guard = av_core::fsutil::TempPathGuard::new(temporary.clone());
    let mut file = std::fs::File::create(&temporary)?;
    let mac = pending_mac(control_key, pending)?;
    file.write_all(&serde_json::to_vec(&PendingEnvelope {
        payload: pending.clone(),
        mac,
    })?)?;
    file.sync_all()?;
    std::fs::rename(&temporary, path)?;
    guard.disarm();
    av_core::fsutil::sync_directory(parent)?;
    Ok(())
}

fn read_pending(path: &std::path::Path, control_key: &[u8; 32]) -> Result<PendingColdEvent, BusError> {
    let envelope: PendingEnvelope = serde_json::from_slice(&std::fs::read(path)?)?;
    verify_pending_mac(control_key, &envelope.payload, &envelope.mac)?;
    Ok(envelope.payload)
}

fn pending_mac(control_key: &[u8; 32], pending: &PendingColdEvent) -> Result<String, BusError> {
    // Round-22 F2: refuse to sign under a known-weak key. Round-21 F3
    // blocked *installing* [0; 32] / [0xFF; 32] through set_control_key,
    // but the archive is *constructed* with [0; 32] and a bus impl that
    // publishes before an operator installs a real key (or that forgets
    // set_control_key entirely) would sign under the weak default. Fail
    // closed at the sign site so the default-init window can never
    // produce a forgeable envelope.
    if control_key == &[0u8; 32] || control_key == &[0xFFu8; 32] {
        return Err(BusError::Backend(
            "cold-outbox control key is uninitialized/known-weak; refusing to sign".to_owned(),
        ));
    }
    use hmac::{Hmac, KeyInit as _, Mac as _};
    use sha2::Sha256;
    let value = serde_json::to_value(pending)?;
    let canonical =
        av_receipts::canonicalize(&value).map_err(|error| BusError::Backend(error.to_string()))?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(control_key).map_err(|error| BusError::Backend(error.to_string()))?;
    mac.update(b"agentvisor-cold-outbox-v1\0");
    mac.update(canonical.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Verify the MAC in constant time (`hmac::Mac::verify_slice`), which
/// eliminates the timing side-channel that a variable-time `String != String`
/// comparison would expose (CWE-208 class).
fn verify_pending_mac(
    control_key: &[u8; 32],
    pending: &PendingColdEvent,
    presented_hex: &str,
) -> Result<(), BusError> {
    // Round-22 F2: refuse to verify under a known-weak key. Mirrors the
    // sign-time check in `pending_mac`. If the archive is still holding
    // its default [0; 32] key when a stale envelope is read back on
    // startup, we do NOT want to accept it as authentic — a
    // filesystem-tamper attacker knows the weak key too.
    if control_key == &[0u8; 32] || control_key == &[0xFFu8; 32] {
        return Err(BusError::Backend("cold outbox authentication failed".to_owned()));
    }
    use hmac::{Hmac, KeyInit as _, Mac as _};
    use sha2::Sha256;
    let value = serde_json::to_value(pending)?;
    let canonical =
        av_receipts::canonicalize(&value).map_err(|error| BusError::Backend(error.to_string()))?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(control_key).map_err(|error| BusError::Backend(error.to_string()))?;
    mac.update(b"agentvisor-cold-outbox-v1\0");
    mac.update(canonical.as_bytes());
    // Round-17 F9: same 128-char cap as journal.rs — HMAC-SHA256 is
    // 64 hex chars; refuse a giant `presented_hex` so a fs-tamper
    // attacker cannot force a huge hex::decode allocation before
    // verify_slice fails.
    if presented_hex.len() > 128 {
        return Err(BusError::Backend("cold outbox authentication failed".to_owned()));
    }
    let presented_bytes = hex::decode(presented_hex)
        .map_err(|_| BusError::Backend("cold outbox authentication failed".to_owned()))?;
    mac.verify_slice(&presented_bytes)
        .map_err(|_| BusError::Backend("cold outbox authentication failed".to_owned()))
}

fn validate_same_intent(existing: &PendingColdEvent, pending: &PendingColdEvent) -> Result<(), BusError> {
    if existing.topic != pending.topic
        || existing.event_uid != pending.event_uid
        || existing.partition != pending.partition
        || existing.key != pending.key
        || existing.value != pending.value
    {
        return Err(BusError::Backend(
            "cold outbox UID is bound to a different event".to_owned(),
        ));
    }
    Ok(())
}

fn remove_pending(path: &std::path::Path) -> Result<(), BusError> {
    let parent = path
        .parent()
        .ok_or_else(|| BusError::Backend("cold outbox has no parent".to_owned()))?;
    match std::fs::remove_file(path) {
        Ok(()) => av_core::fsutil::sync_directory(parent).map_err(BusError::Io),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(BusError::Io(error)),
    }
}

/// Honor only `AWS_*`-prefixed env vars (credentials plus AWS-scoped
/// configuration like `AWS_ENDPOINT`), lowercased for
/// `parse_url_opts` (its config-key parser accepts lowercase names only).
/// Passing the whole environment would let generic variable names —
/// `ENDPOINT`, `REGION`, `TIMEOUT`, `TOKEN`, `PROXY_URL` — silently
/// reconfigure the cold-store client; standard AWS tooling scopes
/// credential discovery to `AWS_*`.
fn aws_env_options(vars: impl Iterator<Item = (String, String)>) -> Vec<(String, String)> {
    vars.filter_map(|(key, value)| key.starts_with("AWS_").then(|| (key.to_ascii_lowercase(), value)))
        .collect()
}

fn cold_url(value: &str) -> Result<url::Url, BusError> {
    if value.contains("://") {
        return url::Url::parse(value)
            .map_err(|error| BusError::Backend(format!("invalid cold_uri {value:?}: {error}")));
    }
    std::fs::create_dir_all(value)?;
    // `Url::from_directory_path` rejects relative paths outright, so a
    // portable manifest entry like `cold_uri: "data/cold"` used to create
    // the directory and then fail provisioning. Canonicalize against the
    // CWD first (same resolution rule as the cold-outbox default).
    let absolute = std::fs::canonicalize(value)?;
    url::Url::from_directory_path(&absolute)
        .map_err(|()| BusError::Backend(format!("invalid cold directory {value:?}")))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::unwrap_used)]

    use super::*;

    /// Generic env names must never leak into the object-store client
    /// config; only `AWS_*` names pass, lowercased for the options parser.
    #[test]
    fn only_aws_prefixed_env_reaches_the_object_store_config() {
        let vars = [
            ("AWS_ACCESS_KEY_ID", "id"),
            ("AWS_ENDPOINT", "http://127.0.0.1:9000"),
            ("AWS_ALLOW_HTTP", "true"),
            ("ENDPOINT", "http://evil.example"),
            ("REGION", "hijack"),
            ("TIMEOUT", "1ns"),
            ("TOKEN", "stolen"),
            ("PROXY_URL", "http://mitm.example"),
            ("PATH", "/usr/bin"),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value.to_owned()));
        let options = aws_env_options(vars);
        assert_eq!(
            options,
            vec![
                ("aws_access_key_id".to_owned(), "id".to_owned()),
                ("aws_endpoint".to_owned(), "http://127.0.0.1:9000".to_owned()),
                ("aws_allow_http".to_owned(), "true".to_owned()),
            ]
        );
    }

    /// Mutation-run hardening (round 14): the READ-side twin of the
    /// weak-key sign guard. `verify_pending_mac` refuses envelopes while
    /// the archive still holds a known-weak key ([0;32]/[0xFF;32]); the
    /// surviving `||` -> `&&` mutant only refuses a key that is BOTH
    /// patterns (impossible), so a filesystem attacker who forges an
    /// envelope MAC'd with the all-zero default would have it accepted
    /// during the pre-set_control_key startup window. Forge exactly that
    /// envelope and require rejection.
    #[test]
    fn envelope_forged_with_the_weak_default_key_is_refused_on_read() {
        use hmac::{Hmac, KeyInit as _, Mac as _};
        use sha2::Sha256;
        let directory = tempfile::tempdir().unwrap();
        let uri = url::Url::from_directory_path(directory.path())
            .unwrap()
            .to_string();
        let outbox = tempfile::tempdir().unwrap();
        let mut manifest = BridgeManifest::default_for("cold-forged");
        let topic = &mut manifest.topics[0];
        topic.retention.cold_uri = Some(uri);
        let topic_name = topic.name.clone();
        let archive =
            ColdArchive::from_manifest_with_pending_default(&manifest, Some(outbox.path().to_path_buf()))
                .unwrap()
                .unwrap();
        // No set_control_key: the archive holds the [0; 32] default,
        // exactly the startup window the read guard protects.
        let payload = PendingColdEvent {
            topic: topic_name.clone(),
            event_uid: "uid-forged".to_owned(),
            partition: 0,
            key: "instance".to_owned(),
            value: serde_json::json!({"metadata": {"uid": "uid-forged"}}),
            stored_at: 1,
            offset: Some(0),
        };
        let canonical = av_receipts::canonicalize(&serde_json::to_value(&payload).unwrap()).unwrap();
        let mut mac = Hmac::<Sha256>::new_from_slice(&[0u8; 32]).unwrap();
        mac.update(b"agentvisor-cold-outbox-v1\0");
        mac.update(canonical.as_bytes());
        let forged = PendingEnvelope {
            payload,
            mac: hex::encode(mac.finalize().into_bytes()),
        };
        let forged_path = archive.pending_path(&topic_name, "uid-forged");
        std::fs::create_dir_all(forged_path.parent().unwrap()).unwrap();
        std::fs::write(&forged_path, serde_json::to_vec(&forged).unwrap()).unwrap();
        let outcome = archive.retry_pending_with(|_| {
            Err(BusError::Backend(
                "resolver must not run for a forged envelope".to_owned(),
            ))
        });
        assert!(
            matches!(outcome, Err(BusError::Backend(ref m)) if m.contains("authentication failed")),
            "weak-key forged envelope must be refused, got {outcome:?}"
        );
    }

    /// A racing maintenance pass can resolve, export, and remove an intent
    /// while the publisher sits between `stage` and `commit` (stalled
    /// thread or wall-clock jump past the retry grace). The export already
    /// happened, so `commit` must treat the missing intent as success —
    /// mirroring `retry_pending_with`'s NotFound tolerance — instead of
    /// failing a fully-successful publish (which would push callers into a
    /// retry that duplicates the event on backends without local dedup).
    #[test]
    fn commit_tolerates_an_intent_already_exported_by_maintenance() {
        let directory = tempfile::tempdir().unwrap();
        let uri = url::Url::from_directory_path(directory.path())
            .unwrap()
            .to_string();
        let outbox = tempfile::tempdir().unwrap();
        let mut manifest = BridgeManifest::default_for("cold-race");
        let topic = &mut manifest.topics[0];
        topic.retention.cold_uri = Some(uri);
        let topic_name = topic.name.clone();
        let archive =
            ColdArchive::from_manifest_with_pending_default(&manifest, Some(outbox.path().to_path_buf()))
                .unwrap()
                .unwrap();
        archive.set_control_key([17u8; 32]).unwrap();
        let event = StoredEvent {
            partition: 0,
            offset: 5,
            key: "instance".to_owned(),
            value: serde_json::json!({"metadata": {"uid": "uid-race"}}),
            stored_at: 1,
        };
        archive.stage(&topic_name, &event, "uid-race").unwrap();
        // Simulate the racing maintenance export+removal.
        std::fs::remove_file(archive.pending_path(&topic_name, "uid-race")).unwrap();
        archive.commit(&topic_name, "uid-race", 5).unwrap(); // commit after a racing export must succeed
    }

    /// Mutation-run hardening (round 14): `validate_same_intent` binds a
    /// cold-outbox UID to one exact event — nine surviving mutants could
    /// each let a UID be re-staged over a DIFFERENT event's payload
    /// (silent audit-trail substitution). Pin every field of the identity
    /// individually, plus the identical-restage acceptance.
    #[test]
    fn restaging_a_uid_with_any_field_changed_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let uri = url::Url::from_directory_path(directory.path())
            .unwrap()
            .to_string();
        let outbox = tempfile::tempdir().unwrap();
        let mut manifest = BridgeManifest::default_for("cold-bind");
        for topic in &mut manifest.topics {
            topic.retention.cold_uri = Some(uri.clone());
        }
        let topic_a = manifest.topics[0].name.clone();
        let topic_b = manifest.topics[1].name.clone();
        let archive =
            ColdArchive::from_manifest_with_pending_default(&manifest, Some(outbox.path().to_path_buf()))
                .unwrap()
                .unwrap();
        archive.set_control_key([9u8; 32]).unwrap();
        let base = StoredEvent {
            partition: 1,
            offset: 0,
            key: "instance-a".to_owned(),
            value: serde_json::json!({"n": 1}),
            stored_at: 42,
        };
        archive.stage(&topic_a, &base, "uid-bind").unwrap();
        // Identical restage: idempotent.
        archive.stage(&topic_a, &base, "uid-bind").unwrap();
        // Each field mutation individually must be refused. (The topic is
        // part of the pending path, so a different topic writes a distinct
        // intent instead — covered by the path-mismatch check elsewhere.)
        let mut other_partition = base.clone();
        other_partition.partition = 2;
        let mut other_key = base.clone();
        other_key.key = "instance-b".to_owned();
        let mut other_value = base.clone();
        other_value.value = serde_json::json!({"n": 2});
        for (label, mutated) in [
            ("partition", other_partition),
            ("key", other_key),
            ("value", other_value),
        ] {
            let outcome = archive.stage(&topic_a, &mutated, "uid-bind");
            assert!(
                matches!(outcome, Err(BusError::Backend(ref m)) if m.contains("different event")),
                "changed {label} must be refused, got {outcome:?}"
            );
        }
        // Same uid staged under another topic is a separate intent file and
        // must succeed (per-topic namespacing, not a rebinding).
        archive.stage(&topic_b, &base, "uid-bind").unwrap();
    }

    /// Mutation-run hardening (round 13): the AlreadyExists tolerance in
    /// `put_remote` compares existing object bytes against the new payload —
    /// an `==` -> `!=` mutant would silently accept a DIFFERENT object at
    /// the same deterministic key (an integrity violation) and reject
    /// legitimate idempotent re-puts. `commit` deliberately converts remote
    /// failures into durable retry intents (a broker-acked event must not
    /// fail client-side), so the conflict surfaces on the retry path: the
    /// intent stays on disk and every retry refuses loudly (feeding the
    /// maintenance error counter) instead of overwriting or vanishing.
    #[test]
    fn same_content_reput_is_idempotent_and_conflicts_poison_loudly() {
        let directory = tempfile::tempdir().unwrap();
        let uri = url::Url::from_directory_path(directory.path())
            .unwrap()
            .to_string();
        let outbox = tempfile::tempdir().unwrap();
        std::env::remove_var("AV_COLD_OUTBOX_DIR");
        let mut manifest = BridgeManifest::default_for("cold-conflict");
        let topic = &mut manifest.topics[0];
        topic.retention.cold_uri = Some(uri);
        let topic_name = topic.name.clone();
        let archive =
            ColdArchive::from_manifest_with_pending_default(&manifest, Some(outbox.path().to_path_buf()))
                .unwrap()
                .unwrap();
        archive.set_control_key([7u8; 32]).unwrap();
        let event = StoredEvent {
            partition: 1,
            offset: 3,
            key: "instance".to_owned(),
            value: serde_json::json!({"metadata": {"uid": "uid-c"}, "n": 1}),
            stored_at: 42,
        };
        archive.put(&topic_name, &event).unwrap();
        // Identical re-put: idempotent success, no pending residue.
        archive.put(&topic_name, &event).unwrap();
        assert_eq!(std::fs::read_dir(outbox.path()).unwrap().count(), 0);
        // Same key, different content: put() keeps the durability contract
        // (Ok), but the intent must persist for retry…
        let conflicting = StoredEvent {
            value: serde_json::json!({"metadata": {"uid": "uid-c"}, "n": 2}),
            ..event
        };
        archive.put(&topic_name, &conflicting).unwrap();
        assert_eq!(
            std::fs::read_dir(outbox.path()).unwrap().count(),
            1,
            "conflicting intent must stay durable, not vanish"
        );
        // …and the retry path must refuse loudly, never overwrite. The
        // resolver must not be consulted (the intent already carries an
        // offset); if a regression calls it anyway, this error propagates
        // and fails the content-conflict assertion below.
        let outcome = archive.retry_pending_with(|_| {
            Err(BusError::Backend(
                "resolver must not be called: the intent already has an offset".to_owned(),
            ))
        });
        assert!(
            matches!(outcome, Err(BusError::Backend(ref m)) if m.contains("different content")),
            "conflicting retry must be refused, got {outcome:?}"
        );
    }

    #[test]
    fn file_uri_uses_the_object_store_contract() {
        let directory = tempfile::tempdir().unwrap();
        let uri = url::Url::from_directory_path(directory.path())
            .unwrap()
            .to_string();
        let mut manifest = BridgeManifest::default_for("cold-contract");
        let topic = &mut manifest.topics[0];
        topic.retention.cold_uri = Some(uri);
        let topic_name = topic.name.clone();
        let archive = ColdArchive::from_manifest(&manifest).unwrap().unwrap();
        archive.set_control_key([7u8; 32]).unwrap();
        archive
            .put(
                &topic_name,
                &StoredEvent {
                    partition: 2,
                    offset: 7,
                    key: "instance".to_owned(),
                    value: serde_json::json!({"ok": true}),
                    stored_at: 1,
                },
            )
            .unwrap();
        let path = directory
            .path()
            .join(topic_name)
            .join("p2")
            .join("00000000000000000007.json");
        let stored: StoredEvent = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(stored.offset, 7);
    }

    #[test]
    fn unresolved_intent_is_resolved_and_exported_after_restart() {
        let directory = tempfile::tempdir().unwrap();
        let outbox = tempfile::tempdir().unwrap();
        let uri = url::Url::from_directory_path(directory.path())
            .unwrap()
            .to_string();
        let mut manifest = BridgeManifest::default_for("cold-recovery");
        let topic = &mut manifest.topics[0];
        topic.retention.cold_uri = Some(uri);
        let topic_name = topic.name.clone();
        let mut archive = ColdArchive::from_manifest(&manifest).unwrap().unwrap();
        archive.pending_dir = outbox.path().to_path_buf();
        archive.set_control_key([7u8; 32]).unwrap();
        let event = StoredEvent {
            partition: 2,
            offset: 0,
            key: "instance".to_owned(),
            value: serde_json::json!({"metadata": {"uid": "cold-event-1"}}),
            stored_at: 1,
        };
        archive.stage(&topic_name, &event, "cold-event-1").unwrap();
        assert_eq!(std::fs::read_dir(outbox.path()).unwrap().count(), 1);

        let resolved = archive
            .retry_pending_with(|pending| {
                assert_eq!(pending.event_uid, "cold-event-1");
                Ok(crate::PublishAck {
                    topic: pending.topic.clone(),
                    partition: pending.partition,
                    offset: 7,
                })
            })
            .unwrap();
        assert_eq!(resolved, 1);
        assert_eq!(std::fs::read_dir(outbox.path()).unwrap().count(), 0);
        let path = directory
            .path()
            .join(topic_name)
            .join("p2")
            .join("00000000000000000007.json");
        let stored: StoredEvent = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(stored.offset, 7);
        assert_eq!(stored.value["metadata"]["uid"], "cold-event-1");
    }

    /// The maintenance retry scan runs concurrently with publishers, which
    /// stage an offset-None intent, produce to the broker (up to the 10 s
    /// executor timeout), then commit. A scan that resolved such an
    /// in-flight intent would re-publish the event (duplicate), persist its
    /// own offset, and make the racing commit fail with
    /// NotFound/conflicting-offset. Fresh offset-None intents must be
    /// skipped; only intents older than RETRY_GRACE_MS reach the resolver.
    #[test]
    fn retry_scan_skips_in_flight_offset_none_intents_within_the_grace_window() {
        let directory = tempfile::tempdir().unwrap();
        let outbox = tempfile::tempdir().unwrap();
        let uri = url::Url::from_directory_path(directory.path())
            .unwrap()
            .to_string();
        let mut manifest = BridgeManifest::default_for("cold-grace");
        let topic = &mut manifest.topics[0];
        topic.retention.cold_uri = Some(uri);
        let topic_name = topic.name.clone();
        let archive =
            ColdArchive::from_manifest_with_pending_default(&manifest, Some(outbox.path().to_path_buf()))
                .unwrap()
                .unwrap();
        archive.set_control_key([7u8; 32]).unwrap();
        // In-flight shape: stored_at is "now", exactly what publish_with_uid
        // stamps immediately before staging.
        let in_flight = StoredEvent {
            partition: 0,
            offset: 0,
            key: "instance".to_owned(),
            value: serde_json::json!({"metadata": {"uid": "uid-in-flight"}}),
            stored_at: av_core::time::now_ms(),
        };
        archive.stage(&topic_name, &in_flight, "uid-in-flight").unwrap();
        // Crash-leftover shape: an ancient stored_at, well past the grace.
        let leftover = StoredEvent {
            partition: 0,
            offset: 0,
            key: "instance".to_owned(),
            value: serde_json::json!({"metadata": {"uid": "uid-leftover"}}),
            stored_at: 1,
        };
        archive.stage(&topic_name, &leftover, "uid-leftover").unwrap();
        let resolved = archive
            .retry_pending_with(|pending| {
                assert_eq!(
                    pending.event_uid, "uid-leftover",
                    "the resolver must never see an in-flight (young offset-None) intent"
                );
                Ok(crate::PublishAck {
                    topic: pending.topic.clone(),
                    partition: pending.partition,
                    offset: 9,
                })
            })
            .unwrap();
        assert_eq!(resolved, 1, "only the aged leftover intent is exported");
        assert_eq!(
            std::fs::read_dir(outbox.path()).unwrap().count(),
            1,
            "the in-flight intent must stay queued for its publisher's commit"
        );
    }

    #[test]
    fn tampered_cold_intent_fails_authentication() {
        let directory = tempfile::tempdir().unwrap();
        let outbox = tempfile::tempdir().unwrap();
        let uri = url::Url::from_directory_path(directory.path())
            .unwrap()
            .to_string();
        let mut manifest = BridgeManifest::default_for("cold-auth");
        let topic = &mut manifest.topics[0];
        topic.retention.cold_uri = Some(uri);
        let topic_name = topic.name.clone();
        let mut archive = ColdArchive::from_manifest(&manifest).unwrap().unwrap();
        archive.pending_dir = outbox.path().to_path_buf();
        archive.set_control_key([41; 32]).unwrap();
        archive
            .stage(
                &topic_name,
                &StoredEvent {
                    partition: 0,
                    offset: 0,
                    key: "instance".to_owned(),
                    value: serde_json::json!({"metadata": {"uid": "cold-auth-1"}}),
                    stored_at: 1,
                },
                "cold-auth-1",
            )
            .unwrap();
        let path = std::fs::read_dir(outbox.path())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let mut envelope: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        envelope["payload"]["value"] = serde_json::json!({"forged": true});
        std::fs::write(path, serde_json::to_vec(&envelope).unwrap()).unwrap();
        let resolver_called = std::sync::atomic::AtomicBool::new(false);
        assert!(archive
            .retry_pending_with(|_| {
                resolver_called.store(true, std::sync::atomic::Ordering::Release);
                Err(BusError::Backend("unexpected resolver call".to_owned()))
            })
            .unwrap_err()
            .to_string()
            .contains("authentication failed"));
        assert!(!resolver_called.load(std::sync::atomic::Ordering::Acquire));
    }

    /// Adversarial: a non-hex MAC field must fail authentication with the same
    /// error message as a wrong MAC (no oracle leaking format vs. value).
    #[test]
    fn corrupt_hex_mac_field_fails_authentication() {
        let directory = tempfile::tempdir().unwrap();
        let outbox = tempfile::tempdir().unwrap();
        let uri = url::Url::from_directory_path(directory.path())
            .unwrap()
            .to_string();
        let mut manifest = BridgeManifest::default_for("cold-hex");
        let topic = &mut manifest.topics[0];
        topic.retention.cold_uri = Some(uri);
        let topic_name = topic.name.clone();
        let mut archive = ColdArchive::from_manifest(&manifest).unwrap().unwrap();
        archive.pending_dir = outbox.path().to_path_buf();
        archive.set_control_key([73; 32]).unwrap();
        archive
            .stage(
                &topic_name,
                &StoredEvent {
                    partition: 0,
                    offset: 0,
                    key: "instance".to_owned(),
                    value: serde_json::json!({"metadata": {"uid": "cold-hex-1"}}),
                    stored_at: 1,
                },
                "cold-hex-1",
            )
            .unwrap();
        let path = std::fs::read_dir(outbox.path())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let mut envelope: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        envelope["mac"] = serde_json::json!("not-hexadecimal-!!!");
        std::fs::write(path, serde_json::to_vec(&envelope).unwrap()).unwrap();
        let err = archive
            .retry_pending_with(|_| Err(BusError::Backend("unexpected".to_owned())))
            .unwrap_err()
            .to_string();
        assert!(err.contains("authentication failed"), "{err}");
    }

    /// Adversarial: an attacker who guessed the payload but not the key must
    /// still fail authentication. A wrong control key MUST NOT verify a
    /// previously valid MAC.
    #[test]
    fn wrong_control_key_fails_authentication() {
        let directory = tempfile::tempdir().unwrap();
        let outbox = tempfile::tempdir().unwrap();
        let uri = url::Url::from_directory_path(directory.path())
            .unwrap()
            .to_string();
        let mut manifest = BridgeManifest::default_for("cold-key");
        let topic = &mut manifest.topics[0];
        topic.retention.cold_uri = Some(uri);
        let topic_name = topic.name.clone();
        let mut archive = ColdArchive::from_manifest(&manifest).unwrap().unwrap();
        archive.pending_dir = outbox.path().to_path_buf();
        archive.set_control_key([11; 32]).unwrap();
        archive
            .stage(
                &topic_name,
                &StoredEvent {
                    partition: 0,
                    offset: 0,
                    key: "instance".to_owned(),
                    value: serde_json::json!({"metadata": {"uid": "cold-key-1"}}),
                    stored_at: 1,
                },
                "cold-key-1",
            )
            .unwrap();
        // The staged file was authenticated with key [11; 32]. Rotate to a
        // different key and demand authentication of the same file.
        archive.set_control_key([22; 32]).unwrap();
        let err = archive
            .retry_pending_with(|_| Err(BusError::Backend("unexpected".to_owned())))
            .unwrap_err()
            .to_string();
        assert!(err.contains("authentication failed"), "{err}");
    }

    /// Byte-level tamper uniformity: mutating any single nibble of the MAC
    /// field must yield the same "authentication failed" error text. A
    /// short-circuit comparator would either fail earlier (leaking via
    /// timing) or emit a different error for a "wrong-format" MAC vs a
    /// "wrong-value" MAC — either would form a CWE-208 oracle.
    #[test]
    fn cold_outbox_mac_tamper_at_any_nibble_returns_the_same_error() {
        let directory = tempfile::tempdir().unwrap();
        let outbox = tempfile::tempdir().unwrap();
        let uri = url::Url::from_directory_path(directory.path())
            .unwrap()
            .to_string();
        let mut manifest = BridgeManifest::default_for("cold-uniform");
        let topic = &mut manifest.topics[0];
        topic.retention.cold_uri = Some(uri);
        let topic_name = topic.name.clone();
        let mut archive = ColdArchive::from_manifest(&manifest).unwrap().unwrap();
        archive.pending_dir = outbox.path().to_path_buf();
        archive.set_control_key([99; 32]).unwrap();
        archive
            .stage(
                &topic_name,
                &StoredEvent {
                    partition: 0,
                    offset: 0,
                    key: "instance".to_owned(),
                    value: serde_json::json!({"metadata": {"uid": "cold-uniform-1"}}),
                    stored_at: 1,
                },
                "cold-uniform-1",
            )
            .unwrap();
        let path = std::fs::read_dir(outbox.path())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let envelope: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let mac_hex = envelope["mac"].as_str().unwrap().to_owned();

        let mut errors = std::collections::HashSet::new();
        for i in 0..mac_hex.len() {
            let mut bytes: Vec<u8> = mac_hex.as_bytes().to_vec();
            bytes[i] = if bytes[i] == b'0' { b'f' } else { b'0' };
            let tampered_hex = String::from_utf8(bytes).unwrap();
            let mut tampered_envelope = envelope.clone();
            tampered_envelope["mac"] = serde_json::json!(tampered_hex);
            std::fs::write(&path, serde_json::to_vec(&tampered_envelope).unwrap()).unwrap();
            let err = archive
                .retry_pending_with(|_| Err(BusError::Backend("unexpected".to_owned())))
                .unwrap_err()
                .to_string();
            errors.insert(err);
        }
        assert_eq!(
            errors.len(),
            1,
            "cold-outbox MAC verification must return a single error text regardless of which \
             nibble failed; got {} distinct texts (i.e. a timing/oracle side channel): {errors:?}",
            errors.len()
        );
    }

    /// Round-21 F3: refuse known-weak control keys — parity with
    /// round-14 and round-20 F5 for the primary signing seed.
    /// Silently accepting [0; 32] or [0xFF; 32] would let a
    /// startup-order wiring bug produce a cold-outbox whose
    /// authentication tag is forgeable by anyone who guessed
    /// the pattern.
    #[test]
    fn set_control_key_refuses_all_zero_and_all_ff() {
        let manifest = {
            let mut m = BridgeManifest::default_for("cold-weak");
            let topic = &mut m.topics[0];
            let outbox = tempfile::tempdir().unwrap();
            let uri = url::Url::from_directory_path(outbox.path()).unwrap().to_string();
            topic.retention.cold_uri = Some(uri);
            m
        };
        let archive = ColdArchive::from_manifest(&manifest).unwrap().unwrap();
        let err = archive.set_control_key([0u8; 32]).unwrap_err();
        assert!(
            format!("{err:?}").contains("known-weak"),
            "expected known-weak rejection for all-zero, got {err:?}"
        );
        let err = archive.set_control_key([0xFFu8; 32]).unwrap_err();
        assert!(
            format!("{err:?}").contains("known-weak"),
            "expected known-weak rejection for all-0xFF, got {err:?}"
        );
        // A legit key still installs cleanly.
        archive.set_control_key([7u8; 32]).unwrap();
    }

    /// Round-22 F2: sign-time refusal of known-weak keys. Round-21 F3
    /// only guarded `set_control_key`. If a bus impl publishes before
    /// (or without) installing a real key, the archive is still holding
    /// its default `[0; 32]` — and would previously have signed
    /// envelopes under an all-zero MAC key any attacker could forge.
    /// `stage()` (which calls `persist_pending` → `pending_mac`) must
    /// fail closed in that state.
    #[test]
    fn stage_refuses_to_sign_under_default_weak_key() {
        let directory = tempfile::tempdir().unwrap();
        let outbox = tempfile::tempdir().unwrap();
        let uri = url::Url::from_directory_path(directory.path())
            .unwrap()
            .to_string();
        let mut manifest = BridgeManifest::default_for("cold-default-weak");
        let topic = &mut manifest.topics[0];
        topic.retention.cold_uri = Some(uri);
        let topic_name = topic.name.clone();
        let mut archive = ColdArchive::from_manifest(&manifest).unwrap().unwrap();
        archive.pending_dir = outbox.path().to_path_buf();
        // NOTE: no set_control_key call — the archive is still holding
        // its constructor default of [0; 32].
        let event = StoredEvent {
            partition: 0,
            offset: 0,
            key: "instance".to_owned(),
            value: serde_json::json!({"metadata": {"uid": "cold-default-1"}}),
            stored_at: 1,
        };
        let err = archive.stage(&topic_name, &event, "cold-default-1").unwrap_err();
        assert!(
            format!("{err:?}").contains("uninitialized") || format!("{err:?}").contains("known-weak"),
            "expected weak-key rejection at sign time, got {err:?}"
        );
        // The pending dir must remain empty — a rejected sign attempt
        // must not leave orphan `.tmp` (round-22 F3 guard) or a
        // committed pending file.
        let leftover = std::fs::read_dir(outbox.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .count();
        assert_eq!(
            leftover, 0,
            "sign refusal must not leave any file behind in the pending dir"
        );
    }
}
