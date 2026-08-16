//! Customer-owned cold-tier object storage for acknowledged bridge events.

use crate::{BridgeManifest, BusError, StoredEvent};
use object_store::path::Path;
use object_store::ObjectStore;
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
}

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
    pub(crate) fn from_manifest(manifest: &BridgeManifest) -> Result<Option<Self>, BusError> {
        Self::from_manifest_with_pending_default(manifest, None)
    }

    /// Same as [`Self::from_manifest`] but uses `pending_default` when neither
    /// the operator-set `AV_COLD_OUTBOX_DIR` env var nor a manifest override
    /// is present. Callers with a natural data directory (e.g. the embedded
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
            let (store, prefix) = object_store::parse_url_opts(&url, options)
                .map_err(|error| BusError::Backend(format!("cold store {uri:?}: {error}")))?;
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
        let mut pending = read_pending(&pending_path, &self.control_key.read())?;
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
            let mut pending = read_pending(&path, &self.control_key.read())?;
            if path != self.pending_path(&pending.topic, &pending.event_uid) {
                return Err(BusError::Backend(
                    "cold outbox path does not match its payload".to_owned(),
                ));
            }
            if pending.offset.is_none() {
                let ack = resolve(&pending)?;
                if ack.topic != pending.topic || ack.partition != pending.partition {
                    return Err(BusError::Backend(
                        "broker resolver returned an acknowledgment for another cold intent".to_owned(),
                    ));
                }
                pending.offset = Some(ack.offset);
                persist_pending(&path, &pending, &self.control_key.read())?;
            }
            self.put_remote(&pending)?;
            remove_pending(&path)?;
            completed = completed.saturating_add(1);
        }
        Ok(completed)
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
            .child(pending.topic.as_str())
            .child(format!("p{}", pending.partition))
            .child(format!(
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
    std::fs::create_dir_all(parent)?;
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
    use hmac::{Hmac, Mac as _};
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
    use hmac::{Hmac, Mac as _};
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

/// Honor only `AWS_*`-prefixed env credentials, lowercased for
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
    url::Url::from_directory_path(value)
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
