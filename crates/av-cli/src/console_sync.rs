use anyhow::{Context, Result};
use base64::Engine as _;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

const INGEST_PREFIX: &str = "/api/v1/ingest";
const MAX_EXTERNAL_ID_UNITS: usize = 128;
const MAX_AGENT_UNITS: usize = 80;
const MAX_TAG_UNITS: usize = 32;
const MAX_BODY_UNITS: usize = 8_000;
const MAX_SUB_UNITS: usize = 2_000;
const MAX_BATCH_EVENTS: usize = 500;
const MAX_SEQ: u64 = 100_000_000;
const FALLBACK_OCCURRED_AT: &str = "2000-01-01T00:00:00Z";
const INGEST_MIN_OCCURRED_AT_MS: u64 = 946_684_800_000;
const INGEST_FUTURE_SKEW_MS: u64 = 5 * 60 * 1_000;
const BRIDGE_SEQ_STRIDE: u64 = 1_000_000;
const BRIDGE_FETCH_PAGE: usize = 1_024;
const BRIDGE_TOPICS: [&str; 6] = [
    "agent.session",
    "agent.tool_call",
    "agent.stop_reason",
    "agent.compression",
    "agent.identity",
    "agent.receipt",
];

pub(super) struct ConsoleSyncArgs {
    pub(super) spool_dir: PathBuf,
    pub(super) console_url: Option<String>,
    pub(super) deployment: Option<String>,
    pub(super) token_file: Option<PathBuf>,
    pub(super) bridge_dir: Option<PathBuf>,
    pub(super) watch: bool,
    pub(super) interval: u64,
    pub(super) state_file: Option<PathBuf>,
    pub(super) dry_run: bool,
}

pub(super) async fn run(args: ConsoleSyncArgs) -> Result<()> {
    if args.watch && args.interval == 0 {
        anyhow::bail!("--interval must be at least 1 second");
    }
    let config = ResolvedSyncConfig::resolve(&args)?;
    if args.watch {
        loop {
            if let Err(error) = run_once(&config, args.dry_run).await {
                eprintln!("warning: console-sync pass failed: {error:#}");
            }
            tokio::select! {
                () = tokio::time::sleep(Duration::from_secs(args.interval)) => {}
                interrupt = tokio::signal::ctrl_c() => {
                    if let Err(error) = interrupt {
                        eprintln!("warning: failed to listen for Ctrl-C: {error}");
                    }
                    break;
                }
            }
        }
        Ok(())
    } else {
        run_once(&config, args.dry_run).await.map(|_| ())
    }
}

async fn run_once(config: &ResolvedSyncConfig, dry_run: bool) -> Result<SyncSummary> {
    let mut state = SyncState::load(&config.state_file)?;
    let trajectories = scan_trajectories(&config.spool_dir);
    let receipts = scan_receipts(&config.spool_dir);
    let atif_session_ids: BTreeSet<String> = trajectories
        .iter()
        .map(|candidate| candidate.session.external_id.clone())
        .collect();
    let bridge_candidates = match config.bridge_dir.as_ref() {
        Some(bridge_dir) => scan_bridge_candidates(bridge_dir, &state, &atif_session_ids),
        None => BridgeScan::default(),
    };

    if dry_run {
        let event_count: usize = trajectories.iter().map(|candidate| candidate.events.len()).sum();
        println!(
            "{}",
            serde_json::json!({
                "dryRun": true,
                "spoolDir": config.spool_dir.display().to_string(),
                "stateFile": config.state_file.display().to_string(),
                "bridgeDir": config.bridge_dir.as_ref().map(|path| path.display().to_string()),
                "sessions": trajectories.len(),
                "events": event_count,
                "bridgeSessions": bridge_candidates.candidates.len(),
                "bridgeEvents": bridge_candidates.candidates.iter().map(|candidate| candidate.events.len()).sum::<usize>(),
                "bridgeEventsOutsideWindow": bridge_candidates.events_outside_window,
                "receipts": receipts.len(),
            })
        );
        return Ok(SyncSummary::default());
    }

    // Refuse a destination switch under an existing state file: the
    // watermarks/receipt flags in it describe what THAT console already
    // has, not the new one. This runs AFTER the dry-run branch —
    // `resolve()` deliberately allows a missing URL/deployment in
    // dry-run mode, and comparing the empty config against a bound
    // state file broke `--dry-run` in any spool that had ever really
    // synced. URLs compare trailing-slash-normalized: the same console
    // spelled `https://c.example` vs `https://c.example/` (arg vs env
    // vs config-file convention) is one destination, and a spurious
    // bail here sends the operator to a fresh state file — a full
    // re-upload whose sealed sessions then defer their receipts
    // forever.
    let config_url = config.console_url.trim_end_matches('/');
    if let (Some(stored_url), Some(stored_dep)) = (state.console_url.as_deref(), state.deployment.as_deref())
    {
        if stored_url.trim_end_matches('/') != config_url || stored_dep != config.deployment {
            anyhow::bail!(
                "state file {} was accumulated for {stored_url} / deployment {stored_dep}; \
                 refusing to reuse it against {} / {} — pass a fresh --state-file per destination",
                config.state_file.display(),
                config.console_url,
                config.deployment,
            );
        }
    }
    let binding_added = state.console_url.is_none() || state.deployment.is_none();
    state.console_url = Some(config_url.to_owned());
    state.deployment = Some(config.deployment.clone());

    let client = ConsoleClient::new(config)?;
    let mut summary = SyncSummary {
        sessions_seen: trajectories.len(),
        receipts_seen: receipts.len(),
        bridge_sessions_seen: bridge_candidates.candidates.len(),
        bridge_events_outside_window: bridge_candidates.events_outside_window,
        ..SyncSummary::default()
    };
    // Also save when the destination binding was just added to a
    // pre-existing (or fresh) state file.
    let mut changed = binding_added;

    // Receipt gate bookkeeping: sealing a session is IRREVERSIBLE on
    // the console (events for sealed sessions are refused), so a
    // receipt must only be posted once every event this pass could see
    // for that session has been acknowledged. Without this, a
    // transient event-upload failure followed by a successful receipt
    // post permanently locked the missing events out.
    let mut failed_sessions: std::collections::HashSet<String> = std::collections::HashSet::new();
    let bridge_max_seen_offsets = bridge_candidates.max_seen_offsets.clone();
    let mut pending_max_seq: std::collections::HashMap<String, u64> = trajectories
        .iter()
        .filter_map(|candidate| {
            candidate
                .events
                .iter()
                .map(|event| event.seq)
                .max()
                .map(|max_seq| (candidate.session.external_id.clone(), max_seq))
        })
        .collect();
    let mut bridge_pending_max_seq: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for candidate in &bridge_candidates.candidates {
        if let Some(max_seq) = candidate.events.iter().map(|event| event.seq).max() {
            bridge_pending_max_seq.insert(candidate.session.external_id.clone(), max_seq);
            pending_max_seq
                .entry(candidate.session.external_id.clone())
                .and_modify(|existing| *existing = (*existing).max(max_seq))
                .or_insert(max_seq);
        }
    }

    for candidate in trajectories {
        summary.attempted += 1;
        let session_id = candidate.session.external_id.clone();
        match sync_trajectory(&client, &mut state, candidate).await {
            Ok(did_change) => {
                summary.succeeded += 1;
                changed |= did_change;
            }
            Err(error) => {
                summary.failed += 1;
                failed_sessions.insert(session_id);
                eprintln!("warning: skipped session sync: {error:#}");
            }
        }
    }

    let mut bridge_failed = false;
    let mut bridge_incomplete = false;
    for candidate in bridge_candidates.candidates {
        summary.attempted += 1;
        let session_id = candidate.session.external_id.clone();
        match sync_bridge_candidate(&client, &mut state, candidate).await {
            Ok(did_change) => {
                summary.succeeded += 1;
                changed |= did_change;
                // A console-sealed session's remaining bridge records are
                // terminally unconsumable — banking their offsets is
                // correct and must not hold the global advance hostage.
                let sealed = state
                    .sessions
                    .get(&session_id)
                    .is_some_and(|session| session.receipt_synced);
                if !sealed {
                    if let Some(max_seq) = bridge_pending_max_seq.get(&session_id) {
                        let (acknowledged, _, _) = acknowledged_through(&state, &session_id, *max_seq);
                        bridge_incomplete |= !acknowledged;
                    }
                }
            }
            Err(error) => {
                summary.failed += 1;
                bridge_failed = true;
                failed_sessions.insert(session_id);
                eprintln!("warning: skipped bridge session sync: {error:#}");
            }
        }
    }
    if !bridge_failed && !bridge_incomplete {
        changed |= update_bridge_offsets(&mut state, &bridge_max_seen_offsets);
    }

    for candidate in receipts {
        if state
            .sessions
            .get(&candidate.session_external_id)
            .is_some_and(|session| session.receipt_synced)
        {
            summary.receipts_skipped += 1;
            continue;
        }
        if failed_sessions.contains(&candidate.session_external_id) {
            summary.receipts_skipped += 1;
            eprintln!(
                "warning: deferring receipt for {} — its event sync failed this pass and \
                 sealing would lock the missing events out permanently",
                sanitize_for_terminal(&candidate.session_external_id)
            );
            continue;
        }
        if let Some(max_seq) = pending_max_seq.get(&candidate.session_external_id) {
            let (acknowledged, synced_through, synced_any) =
                acknowledged_through(&state, &candidate.session_external_id, *max_seq);
            if !acknowledged {
                summary.receipts_skipped += 1;
                let synced_label = if synced_any {
                    synced_through.to_string()
                } else {
                    "nothing".to_owned()
                };
                eprintln!(
                    "warning: deferring receipt for {} — events through seq {max_seq} are not yet \
                     acknowledged (synced through {})",
                    sanitize_for_terminal(&candidate.session_external_id),
                    synced_label,
                );
                continue;
            }
        }
        summary.attempted += 1;
        match sync_receipt(&client, &mut state, candidate).await {
            Ok(()) => {
                summary.succeeded += 1;
                changed = true;
            }
            Err(error) => {
                summary.failed += 1;
                eprintln!("warning: skipped receipt sync: {error:#}");
            }
        }
    }

    if changed {
        state.save(&config.state_file)?;
    }
    println!(
        "{}",
        serde_json::json!({
            "sessionsSeen": summary.sessions_seen,
            "receiptsSeen": summary.receipts_seen,
            "attempted": summary.attempted,
            "succeeded": summary.succeeded,
            "failed": summary.failed,
            "receiptsSkipped": summary.receipts_skipped,
            "bridgeSessionsSeen": summary.bridge_sessions_seen,
            "bridgeEventsOutsideWindow": summary.bridge_events_outside_window,
        })
    );
    if summary.attempted > 0 && summary.succeeded == 0 && summary.failed > 0 {
        anyhow::bail!("console-sync failed for every attempted item");
    }
    Ok(summary)
}

#[derive(Debug, Default)]
struct SyncSummary {
    sessions_seen: usize,
    receipts_seen: usize,
    bridge_sessions_seen: usize,
    bridge_events_outside_window: usize,
    attempted: usize,
    succeeded: usize,
    failed: usize,
    receipts_skipped: usize,
}

async fn sync_trajectory(
    client: &ConsoleClient,
    state: &mut SyncState,
    candidate: TrajectoryCandidate,
) -> Result<bool> {
    // Console-side seal is terminal: nothing more can be sent for this
    // session (events are refused, the receipt row is immutable). Skip
    // BEFORE the session upsert so a sealed historical session costs
    // zero round trips per pass.
    if state
        .sessions
        .get(&candidate.session.external_id)
        .is_some_and(|session| session.receipt_synced)
    {
        return Ok(false);
    }
    let _: serde_json::Value = client.post_json("sessions", &candidate.session).await?;
    let session_state = state
        .sessions
        .entry(candidate.session.external_id.clone())
        .or_default();
    let newly_marked_atif = !session_state.atif_synced;
    session_state.atif_synced = true;
    let last_synced = session_state.last_synced_seq;
    let synced_any = session_state.synced_any;
    let mut events: Vec<IngestEvent> = candidate
        .events
        .into_iter()
        // `synced_any` distinguishes a fresh session (nothing
        // acknowledged — include the seq-0 `open` event) from a
        // watermark that genuinely sits at 0.
        .filter(|event| event.seq > last_synced || (!synced_any && event.seq == 0))
        .collect();
    events.sort_by_key(|event| event.seq);
    events.dedup_by_key(|event| event.seq);
    if events.is_empty() {
        return Ok(newly_marked_atif);
    }

    let mut changed = newly_marked_atif;
    for batch in event_batches(&events) {
        let response: EventBatchResponse = client.post_json("events", &batch).await?;
        if response
            .rejected_sealed
            .as_ref()
            .is_some_and(|sealed| sealed.iter().any(|id| id == &candidate.session.external_id))
        {
            eprintln!(
                "warning: console already sealed session {}; marking it done locally",
                sanitize_for_terminal(&candidate.session.external_id)
            );
            // Sealed is TERMINAL on the console — no event for this
            // session can ever insert again. Record that instead of
            // "leaving state unchanged": a state file that lagged the
            // seal (fresh state against a populated console, or the
            // pre-`synced_any` upgrade path) otherwise re-posted the
            // same refused batch on every pass forever. Also stop
            // instead of letting a later batch advance the watermark.
            let session_state = state
                .sessions
                .entry(candidate.session.external_id.clone())
                .or_default();
            session_state.receipt_synced = true;
            session_state.synced_any = true;
            changed = true;
            break;
        }
        if response.dropped_future.unwrap_or(0) > 0 || response.dropped_ancient.unwrap_or(0) > 0 {
            eprintln!(
                "warning: console dropped timestamp-skewed events for {}; leaving that batch retryable",
                sanitize_for_terminal(&candidate.session.external_id)
            );
            // MUST stop here: continuing let the NEXT batch's success
            // bump last_synced_seq past the dropped events, excluding
            // them from every future pass — permanently missing
            // evidence with only a one-line warning.
            break;
        }
        if response.inserted > 0 || !batch.is_empty() {
            if let Some(max_seq) = batch.iter().map(|event| event.seq).max() {
                let session_state = state
                    .sessions
                    .entry(candidate.session.external_id.clone())
                    .or_default();
                session_state.last_synced_seq = session_state.last_synced_seq.max(max_seq);
                session_state.synced_any = true;
                changed = true;
            }
        }
    }
    Ok(changed)
}

async fn sync_receipt(
    client: &ConsoleClient,
    state: &mut SyncState,
    candidate: ReceiptCandidate,
) -> Result<()> {
    if let Some(public_key_hex) = &candidate.public_key_hex {
        if state.pubkey_hex_synced.as_deref() != Some(public_key_hex) {
            let _: serde_json::Value = client
                .post_json(
                    "pubkey",
                    &serde_json::json!({
                        "publicKeyHex": public_key_hex,
                        // Display metadata for the console's fleet view;
                        // never part of the server's trust decision.
                        "daemonVersion": env!("CARGO_PKG_VERSION"),
                    }),
                )
                .await?;
            state.pubkey_hex_synced = Some(public_key_hex.clone());
        }
    }
    let _: serde_json::Value = client.post_json("sessions", &candidate.session).await?;
    let _: serde_json::Value = client.post_json("receipts", &candidate.payload).await?;
    state
        .sessions
        .entry(candidate.session_external_id)
        .or_default()
        .receipt_synced = true;
    Ok(())
}

async fn sync_bridge_candidate(
    client: &ConsoleClient,
    state: &mut SyncState,
    candidate: BridgeSessionCandidate,
) -> Result<bool> {
    // Console-side seal is terminal — mirror the ATIF path's skip so a
    // post-seal bridge record can't make this session churn (and, via
    // the global bridge_incomplete flag, wedge offset progress for
    // every other topic/partition forever).
    if state
        .sessions
        .get(&candidate.session.external_id)
        .is_some_and(|session| session.receipt_synced)
    {
        return Ok(false);
    }
    let _: serde_json::Value = client.post_json("sessions", &candidate.session).await?;
    let mut events: Vec<IngestEvent> = candidate.events;
    // NO seq-watermark filter here, unlike the ATIF path: bridge seqs
    // are `topic_idx × 1e6 + offset` — NOT chronological — so one
    // high-base event (e.g. agent.compression at 3e6) raised the
    // session watermark above every later low-base event (a session
    // close at seq 1, tool calls at 1e6+x) and silently discarded them
    // while the offset cursor advanced past their records: permanently
    // missing evidence, then sealed by the receipt gate. The
    // per-(topic,partition) OFFSET cursor is the bridge watermark;
    // re-posts inside an unadvanced window are deduped server-side by
    // (sessionId, seq).
    events.sort_by_key(|event| event.seq);
    events.dedup_by_key(|event| event.seq);
    if events.is_empty() {
        return Ok(false);
    }

    let mut changed = false;
    for batch in event_batches(&events) {
        let response: EventBatchResponse = client.post_json("events", &batch).await?;
        if response
            .rejected_sealed
            .as_ref()
            .is_some_and(|sealed| sealed.iter().any(|id| id == &candidate.session.external_id))
        {
            eprintln!(
                "warning: console already sealed bridge session {}; marking it done locally",
                sanitize_for_terminal(&candidate.session.external_id)
            );
            // Terminal on the console — record it (mirrors the ATIF
            // path) so this session stops being rebuilt and stops
            // holding the global offset advance hostage.
            let session_state = state
                .sessions
                .entry(candidate.session.external_id.clone())
                .or_default();
            session_state.receipt_synced = true;
            session_state.synced_any = true;
            changed = true;
            break;
        }
        if response.dropped_future.unwrap_or(0) > 0 || response.dropped_ancient.unwrap_or(0) > 0 {
            eprintln!(
                "warning: console dropped timestamp-skewed bridge events for {}; leaving that batch retryable",
                sanitize_for_terminal(&candidate.session.external_id)
            );
            // MUST stop here: continuing let the NEXT batch's success
            // bump last_synced_seq past the dropped events, excluding
            // them from every future pass — permanently missing
            // evidence with only a one-line warning.
            break;
        }
        if let Some(max_seq) = batch.iter().map(|event| event.seq).max() {
            let session_state = state
                .sessions
                .entry(candidate.session.external_id.clone())
                .or_default();
            session_state.last_synced_seq = session_state.last_synced_seq.max(max_seq);
            session_state.synced_any = true;
            changed = true;
        }
    }
    Ok(changed)
}

fn update_bridge_offsets(state: &mut SyncState, offsets: &BTreeMap<String, u64>) -> bool {
    let mut changed = false;
    for (key, offset) in offsets {
        let entry = state.bridge_topic_offsets.entry(key.clone()).or_insert(0);
        if *entry < *offset {
            *entry = *offset;
            changed = true;
        }
    }
    changed
}

fn acknowledged_through(state: &SyncState, session_id: &str, max_seq: u64) -> (bool, u64, bool) {
    let synced_through = state
        .sessions
        .get(session_id)
        .map(|session| session.last_synced_seq)
        .unwrap_or(0);
    let synced_any = state
        .sessions
        .get(session_id)
        .is_some_and(|session| session.synced_any);
    (
        synced_any && synced_through >= max_seq,
        synced_through,
        synced_any,
    )
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct SyncState {
    sessions: BTreeMap<String, SessionSyncState>,
    pubkey_hex_synced: Option<String>,
    /// Destination binding: state is meaningful only against the
    /// console+deployment it was accumulated for. Without this, a rerun
    /// against a different deployment reused watermarks/receipt flags
    /// and silently delivered incomplete evidence to the new target.
    console_url: Option<String>,
    deployment: Option<String>,
    bridge_topic_offsets: BTreeMap<String, u64>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct SessionSyncState {
    last_synced_seq: u64,
    receipt_synced: bool,
    /// Distinguishes "never acknowledged anything" from "acknowledged
    /// up to seq 0": the generated `open` event carries seq 0, and the
    /// `seq > last_synced_seq` filter with the default watermark of 0
    /// silently discarded it forever on every fresh session.
    #[serde(alias = "events_synced")]
    synced_any: bool,
    atif_synced: bool,
}

/// The state file grows with one entry per session and is never pruned;
/// reading it back through the generic 1 MiB control-file cap meant the
/// writer eventually produced a file its own reader refused — watch mode
/// then failed every pass before scanning anything. 16 MiB ≈ hundreds of
/// thousands of sessions while still bounding a hostile plant.
const MAX_STATE_BYTES: u64 = 16 * 1024 * 1024;

impl SyncState {
    fn load(path: &Path) -> Result<Self> {
        match av_core::fsutil::read_capped(path, MAX_STATE_BYTES) {
            Ok(bytes) => {
                let mut state: Self = serde_json::from_slice(&bytes)
                    .with_context(|| format!("parse console-sync state {}", path.display()))?;
                // Upgrade migration for pre-`synced_any` state files
                // (serde default = false): any session with prior
                // acknowledgements HAS synced — without this, every
                // already-sealed historical session re-included its
                // seq-0 open event on each pass, the server's sealed
                // guard rejected the batch before its seq-dedupe could
                // no-op it, and watch mode burned two HTTP round trips
                // + a warning per sealed session per interval forever.
                for session in state.sessions.values_mut() {
                    if session.last_synced_seq > 0 || session.receipt_synced {
                        session.synced_any = true;
                    }
                }
                Ok(state)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error).with_context(|| format!("read console-sync state {}", path.display())),
        }
    }

    fn save(&self, path: &Path) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(self).context("serialize console-sync state")?;
        av_core::fsutil::write_atomic(path, &bytes)
            .with_context(|| format!("write console-sync state {}", path.display()))
    }
}

#[derive(Debug)]
struct ResolvedSyncConfig {
    spool_dir: PathBuf,
    bridge_dir: Option<PathBuf>,
    state_file: PathBuf,
    console_url: String,
    deployment: String,
    token: String,
}

impl ResolvedSyncConfig {
    fn resolve(args: &ConsoleSyncArgs) -> Result<Self> {
        let file_config = read_console_file_config()?;
        let console_url = args
            .console_url
            .clone()
            .or_else(|| std::env::var("AV_CONSOLE_URL").ok())
            .or(file_config.url);
        let deployment = args
            .deployment
            .clone()
            .or_else(|| std::env::var("AV_CONSOLE_DEPLOYMENT").ok())
            .or(file_config.deployment);
        let bridge_dir = args
            .bridge_dir
            .clone()
            .or_else(|| std::env::var_os("AV_CONSOLE_BRIDGE_DIR").map(PathBuf::from))
            .or(file_config.bridge_dir);
        let env_token = std::env::var("AV_CONSOLE_TOKEN")
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        let token = if let Some(path) = args.token_file.as_ref() {
            let raw = av_core::fsutil::read_capped_string(path, av_core::fsutil::MAX_CONTROL_BYTES)
                .with_context(|| format!("read console ingest token file {}", path.display()))?;
            Some(raw.trim().to_owned())
        } else if env_token.is_some() {
            env_token
        } else if let Some(path) = file_config.token_file.as_ref() {
            let raw = av_core::fsutil::read_capped_string(path, av_core::fsutil::MAX_CONTROL_BYTES)
                .with_context(|| format!("read console ingest token file {}", path.display()))?;
            Some(raw.trim().to_owned())
        } else {
            None
        };

        let console_url = console_url.unwrap_or_default();
        let deployment = deployment.unwrap_or_default();
        let token = token.unwrap_or_default();
        if !args.dry_run {
            if console_url.is_empty() {
                anyhow::bail!(
                    "missing console URL; pass --console-url, set AV_CONSOLE_URL, or add [console].url"
                );
            }
            if deployment.is_empty() {
                anyhow::bail!(
                    "missing console deployment; pass --deployment, set AV_CONSOLE_DEPLOYMENT, or add [console].deployment"
                );
            }
            if token.is_empty() {
                anyhow::bail!(
                    "missing console ingest token; pass --token-file, set AV_CONSOLE_TOKEN, or add [console].token_file"
                );
            }
            let url = reqwest::Url::parse(&console_url).context("parse console URL")?;
            match url.scheme() {
                "http" | "https" => {}
                scheme => anyhow::bail!("console URL must use http or https, got {scheme:?}"),
            }
        }
        let state_file = args
            .state_file
            .clone()
            .unwrap_or_else(|| args.spool_dir.join(".console-sync-state.json"));
        Ok(Self {
            spool_dir: args.spool_dir.clone(),
            bridge_dir,
            state_file,
            console_url,
            deployment,
            token,
        })
    }
}

#[derive(Default)]
struct ConsoleFileConfig {
    url: Option<String>,
    deployment: Option<String>,
    token_file: Option<PathBuf>,
    bridge_dir: Option<PathBuf>,
}

fn read_console_file_config() -> Result<ConsoleFileConfig> {
    let mut config = read_user_console_file_config()?;
    let source = av_harness::config::resolve_config_source().map_err(anyhow::Error::msg)?;
    let av_harness::config::ConfigSource::File(path) = source else {
        return Ok(config);
    };
    let text = av_core::fsutil::read_capped_string(&path, av_core::fsutil::MAX_CONTROL_BYTES)
        .with_context(|| format!("read config {}", path.display()))?;
    let value: toml::Value =
        toml::from_str(&text).with_context(|| format!("parse config {}", path.display()))?;
    let Some(console) = value.get("console").and_then(toml::Value::as_table) else {
        return Ok(config);
    };
    config.url = console
        .get("url")
        .and_then(toml::Value::as_str)
        .map(str::to_owned)
        .or(config.url);
    config.deployment = console
        .get("deployment")
        .and_then(toml::Value::as_str)
        .map(str::to_owned)
        .or(config.deployment);
    config.token_file = console
        .get("token_file")
        .and_then(toml::Value::as_str)
        .map(PathBuf::from)
        .or(config.token_file);
    config.bridge_dir = console
        .get("bridge_dir")
        .and_then(toml::Value::as_str)
        .map(PathBuf::from)
        .or(config.bridge_dir);
    Ok(config)
}

fn read_user_console_file_config() -> Result<ConsoleFileConfig> {
    let Some(path) = user_console_config_path() else {
        return Ok(ConsoleFileConfig::default());
    };
    let text = match av_core::fsutil::read_capped_string(&path, av_core::fsutil::MAX_CONTROL_BYTES) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ConsoleFileConfig::default());
        }
        Err(error) => return Err(error).with_context(|| format!("read console config {}", path.display())),
    };
    let value: toml::Value =
        toml::from_str(&text).with_context(|| format!("parse console config {}", path.display()))?;
    let Some(console) = value.get("console").and_then(toml::Value::as_table) else {
        return Ok(ConsoleFileConfig::default());
    };
    Ok(ConsoleFileConfig {
        url: console
            .get("url")
            .and_then(toml::Value::as_str)
            .map(str::to_owned),
        deployment: console
            .get("deployment")
            .and_then(toml::Value::as_str)
            .map(str::to_owned),
        token_file: console
            .get("token_file")
            .and_then(toml::Value::as_str)
            .map(PathBuf::from),
        bridge_dir: console
            .get("bridge_dir")
            .and_then(toml::Value::as_str)
            .map(PathBuf::from),
    })
}

fn user_console_config_path() -> Option<PathBuf> {
    #[allow(deprecated)]
    std::env::home_dir().map(|home| home.join(".agentvisor").join("console.toml"))
}

struct ConsoleClient {
    client: reqwest::Client,
    ingest_base: String,
    deployment: String,
    token: String,
}

impl ConsoleClient {
    fn new(config: &ResolvedSyncConfig) -> Result<Self> {
        let mut base = config.console_url.trim_end_matches('/').to_owned();
        if !base.ends_with(INGEST_PREFIX) {
            base.push_str(INGEST_PREFIX);
        }
        Ok(Self {
            // Deadlines are load-bearing in --watch mode: with no
            // request timeout, one server that accepts a connection and
            // never completes a response wedged the sync loop forever
            // (Ctrl-C only ran between passes) and blocked the
            // end-of-pass state save.
            client: reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(10))
                .timeout(Duration::from_secs(120))
                .build()
                .context("build HTTP client")?,
            ingest_base: base,
            deployment: config.deployment.clone(),
            token: config.token.clone(),
        })
    }

    async fn post_json<T, R>(&self, endpoint: &str, payload: &T) -> Result<R>
    where
        T: Serialize + ?Sized,
        R: for<'de> Deserialize<'de>,
    {
        let url = format!("{}/{}", self.ingest_base, endpoint.trim_start_matches('/'));
        let mut backoff = Duration::from_secs(1);
        for _attempt in 0..5 {
            let response = self
                .client
                .post(&url)
                .bearer_auth(&self.token)
                .header("X-AV-Deployment", &self.deployment)
                .json(payload)
                .send()
                .await
                .with_context(|| format!("POST {endpoint}"))?;
            if response.status() == StatusCode::UNAUTHORIZED {
                anyhow::bail!(
                    "console returned 401 unauthenticated; check --deployment and the console ingest token"
                );
            }
            if response.status() == StatusCode::TOO_MANY_REQUESTS {
                let retry_after = response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<u64>().ok())
                    // Clamp: a hostile/misconfigured server must not be
                    // able to park the sync for hours with one header.
                    .map(|seconds| Duration::from_secs(seconds.min(300)))
                    .unwrap_or(backoff);
                tokio::time::sleep(retry_after).await;
                backoff = (backoff * 2).min(Duration::from_secs(30));
                continue;
            }
            if !response.status().is_success() {
                let status = response.status();
                let body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "<unreadable body>".to_owned());
                anyhow::bail!(
                    "POST {endpoint} failed with HTTP {status}: {}",
                    sanitize_for_terminal(&body)
                );
            }
            return response
                .json::<R>()
                .await
                .with_context(|| format!("decode POST {endpoint} response"));
        }
        anyhow::bail!("POST {endpoint} was rate-limited after repeated 429 responses")
    }
}

#[derive(Debug)]
struct TrajectoryCandidate {
    session: SessionUpsert,
    events: Vec<IngestEvent>,
}

fn scan_trajectories(spool_dir: &Path) -> Vec<TrajectoryCandidate> {
    let mut out = Vec::new();
    let entries = match sorted_dir_entries(spool_dir) {
        Ok(entries) => entries,
        Err(error) => {
            eprintln!(
                "warning: cannot read spool directory {}: {error}",
                spool_dir.display()
            );
            return out;
        }
    };
    for path in entries {
        if !is_primary_json(&path)
            || is_symlink(&path)
            || is_session_sidecar(&path)
            || !path.with_extension("atif-auth").exists()
        {
            continue;
        }
        match read_trajectory_candidate(&path) {
            Ok(candidate) => out.push(candidate),
            Err(error) => eprintln!(
                "warning: skipping ATIF trajectory {}: {error:#}",
                sanitize_for_terminal(&path.display().to_string())
            ),
        }
    }
    out
}

#[derive(Default)]
struct BridgeScan {
    candidates: Vec<BridgeSessionCandidate>,
    events_outside_window: usize,
    max_seen_offsets: BTreeMap<String, u64>,
}

#[derive(Debug)]
struct BridgeSessionCandidate {
    session: SessionUpsert,
    events: Vec<IngestEvent>,
}

struct BridgeSessionAccumulator {
    external_id: String,
    agent: String,
    workflow: Workflow,
    opened_at: Option<String>,
    closed_at: Option<String>,
    first_at: Option<String>,
    events: Vec<IngestEvent>,
}

struct BridgeMappedEvent {
    session_external_id: String,
    agent: String,
    workflow: Option<Workflow>,
    opened_at: Option<String>,
    closed_at: Option<String>,
    event: IngestEvent,
}

fn scan_bridge_candidates(
    bridge_dir: &Path,
    state: &SyncState,
    atif_session_ids: &BTreeSet<String>,
) -> BridgeScan {
    let partitions = match bridge_topic_partitions(bridge_dir) {
        Ok(partitions) => partitions,
        Err(error) => {
            eprintln!(
                "warning: cannot read bridge manifest under {}: {error:#}",
                bridge_dir.display()
            );
            return BridgeScan::default();
        }
    };
    let mut scan = BridgeScan::default();
    // Cursors halted at a clock-skewed record this pass (see the
    // OutsideWindow arm): no offset past the freeze point is banked.
    let mut frozen_cursors: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut sessions: BTreeMap<String, BridgeSessionAccumulator> = BTreeMap::new();
    let now_ms = av_core::time::now_ms();

    for (topic_idx, topic) in BRIDGE_TOPICS.iter().enumerate() {
        let Some(partition_count) = partitions.get(*topic).copied() else {
            continue;
        };
        for partition in 0..partition_count {
            let cursor_key = bridge_offset_key(topic, partition);
            let mut cursor = state
                .bridge_topic_offsets
                .get(&cursor_key)
                .and_then(|offset| offset.checked_add(1))
                .unwrap_or(0);
            loop {
                let page = match av_bridge::EmbeddedBroker::fetch_read_only(
                    bridge_dir,
                    topic,
                    partition,
                    cursor,
                    BRIDGE_FETCH_PAGE,
                ) {
                    Ok(page) => page,
                    Err(error) => {
                        eprintln!(
                            "warning: cannot read bridge topic {} partition {}: {error}",
                            sanitize_for_terminal(topic),
                            partition
                        );
                        break;
                    }
                };
                if page.is_empty() {
                    break;
                }
                for stored in &page {
                    // Offset banking is deferred until we know the record
                    // is consumable: for clock-skewed records (see the
                    // OutsideWindow arm) the cursor must FREEZE before
                    // them so a corrected clock re-delivers — banking
                    // unconditionally consumed them permanently with only
                    // a counter bump. Once a cursor is frozen, nothing
                    // later in that (topic, partition) banks either
                    // (banking a later mapped offset would skip the
                    // frozen record on the next pass).
                    if frozen_cursors.contains(&cursor_key) {
                        continue;
                    }
                    let mut bank = |offset: u64| {
                        scan.max_seen_offsets
                            .entry(cursor_key.clone())
                            .and_modify(|current| *current = (*current).max(offset))
                            .or_insert(offset);
                    };
                    if *topic == "agent.receipt" {
                        bank(stored.offset);
                        continue;
                    }
                    let Some(session_id) = bridge_session_id(&stored.value) else {
                        bank(stored.offset);
                        continue;
                    };
                    if atif_session_ids.contains(&session_id)
                        || state
                            .sessions
                            .get(&session_id)
                            .is_some_and(|session| session.atif_synced)
                    {
                        bank(stored.offset);
                        continue;
                    }
                    match bridge_record_to_event(topic_idx, topic, stored, now_ms) {
                        BridgeRecordMapping::Mapped(mapped) => {
                            bank(stored.offset);
                            let entry =
                                sessions
                                    .entry(mapped.session_external_id.clone())
                                    .or_insert_with(|| BridgeSessionAccumulator {
                                        external_id: mapped.session_external_id.clone(),
                                        agent: mapped.agent.clone(),
                                        workflow: mapped.workflow.unwrap_or(Workflow::Signed),
                                        opened_at: None,
                                        closed_at: None,
                                        first_at: None,
                                        events: Vec::new(),
                                    });
                            entry.agent = mapped.agent;
                            if let Some(workflow) = mapped.workflow {
                                entry.workflow = workflow;
                            }
                            if let Some(opened_at) = mapped.opened_at {
                                entry.opened_at = Some(opened_at);
                            }
                            if let Some(closed_at) = mapped.closed_at {
                                entry.closed_at = Some(closed_at);
                            }
                            if entry.first_at.is_none() {
                                entry.first_at = Some(mapped.event.occurred_at.clone());
                            }
                            entry.events.push(mapped.event);
                        }
                        BridgeRecordMapping::OutsideWindow => {
                            scan.events_outside_window = scan.events_outside_window.saturating_add(1);
                            // Freeze this cursor (do NOT bank): the record
                            // stays unread so a later pass with a sane
                            // clock window can deliver it.
                            frozen_cursors.insert(cursor_key.clone());
                            eprintln!(
                                "warning: bridge record at {} offset {} has a timestamp outside \
                                 the ingest window; cursor frozen before it so it stays retryable \
                                 (check clock skew between daemon and sync hosts)",
                                sanitize_for_terminal(&cursor_key),
                                stored.offset
                            );
                        }
                        BridgeRecordMapping::Skipped => bank(stored.offset),
                    }
                }
                let next = page
                    .last()
                    .and_then(|event| event.offset.checked_add(1))
                    .unwrap_or(cursor);
                if next <= cursor {
                    break;
                }
                cursor = next;
            }
        }
    }

    scan.candidates = sessions
        .into_values()
        .filter_map(|mut session| {
            session.events.sort_by_key(|event| event.seq);
            session.events.dedup_by_key(|event| event.seq);
            if session.events.is_empty() {
                return None;
            }
            let opened_at = session
                .opened_at
                .clone()
                .or_else(|| session.first_at.clone())
                .unwrap_or_else(|| FALLBACK_OCCURRED_AT.to_owned());
            Some(BridgeSessionCandidate {
                session: SessionUpsert {
                    external_id: session.external_id,
                    agent: bounded_nonempty(&session.agent, MAX_AGENT_UNITS, "agent"),
                    workflow: session.workflow,
                    status: SessionStatus::Live,
                    policy_version: 1,
                    opened_at,
                    closed_at: session.closed_at,
                },
                events: session.events,
            })
        })
        .collect();
    scan
}

fn bridge_topic_partitions(bridge_dir: &Path) -> Result<BTreeMap<String, u32>> {
    let manifest_yaml = av_core::fsutil::read_capped_string(
        &bridge_dir.join("manifest.yaml"),
        av_core::fsutil::MAX_CONTROL_BYTES,
    )?;
    let manifest = av_bridge::BridgeManifest::from_yaml(&manifest_yaml).map_err(anyhow::Error::new)?;
    let wanted: BTreeSet<&str> = BRIDGE_TOPICS.iter().copied().collect();
    Ok(manifest
        .topics
        .iter()
        .filter(|topic| wanted.contains(topic.name.as_str()))
        .map(|topic| (topic.name.clone(), topic.partitions))
        .collect())
}

fn bridge_offset_key(topic: &str, partition: u32) -> String {
    format!("{topic}/p{partition}")
}

enum BridgeRecordMapping {
    Mapped(Box<BridgeMappedEvent>),
    OutsideWindow,
    Skipped,
}

fn bridge_record_to_event(
    topic_idx: usize,
    topic: &str,
    stored: &av_bridge::StoredEvent,
    now_ms: u64,
) -> BridgeRecordMapping {
    let value = &stored.value;
    let Some(session_external_id) = bridge_session_id(value) else {
        return BridgeRecordMapping::Skipped;
    };
    let Some((occurred_ms, occurred_at)) = bridge_occurred_at(value, stored.stored_at) else {
        return BridgeRecordMapping::OutsideWindow;
    };
    if occurred_ms < INGEST_MIN_OCCURRED_AT_MS || occurred_ms > now_ms.saturating_add(INGEST_FUTURE_SKEW_MS) {
        return BridgeRecordMapping::OutsideWindow;
    }
    let seq = bridge_seq(topic_idx, stored.offset);
    let agent = bounded_nonempty(
        value
            .pointer("/ai_agent/charter/name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("agent"),
        MAX_AGENT_UNITS,
        "agent",
    );
    let payload = value.get("payload").unwrap_or(&serde_json::Value::Null);
    let body = bridge_body(topic, value);
    let mut workflow = payload
        .get("workflow")
        .and_then(serde_json::Value::as_str)
        .and_then(workflow_from_str);
    let mut opened_at = None;
    let mut closed_at = None;

    let mut event = match topic {
        "agent.session" => {
            let action = payload
                .get("action")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("session");
            if action == "opened" {
                opened_at = Some(occurred_at.clone());
            } else if action == "closed" {
                closed_at = Some(occurred_at.clone());
            }
            if workflow.is_none() && action == "closed" {
                workflow = Some(Workflow::Signed);
            }
            bridge_ingest_event(
                &session_external_id,
                seq,
                EventKind::Sys,
                if action == "opened" {
                    "open"
                } else if action == "closed" {
                    "close"
                } else {
                    "session"
                },
                None,
                body,
                occurred_at.clone(),
            )
        }
        "agent.tool_call" => {
            let blocked = bridge_tool_blocked(value);
            let tag = bridge_tool_tag(payload);
            let mut event = bridge_ingest_event(
                &session_external_id,
                seq,
                if blocked {
                    EventKind::Block
                } else {
                    EventKind::Tool
                },
                &tag,
                Some(tag.clone()),
                body,
                occurred_at.clone(),
            );
            if blocked {
                event.add_tools_blocked = 1;
                event.add_blocked_payout_usd_micros = extract_payout_micros(payload);
            } else {
                event.add_tools_allowed = 1;
            }
            // Per-policy attribution when the daemon names the policy in
            // the OCSF payload. Absent today for the built-in verdict
            // shapes ({stage, reason}); forward-wired so a policy-aware
            // daemon build lights the console counters with no CLI change.
            event.policy_name = payload
                .get("policy")
                .or_else(|| payload.get("policy_name"))
                .and_then(serde_json::Value::as_str)
                .map(|name| bounded_nonempty(name, MAX_AGENT_UNITS, "policy"));
            event
        }
        "agent.stop_reason" => bridge_ingest_event(
            &session_external_id,
            seq,
            EventKind::Guard,
            bridge_stop_reason_tag(value).as_str(),
            None,
            body,
            occurred_at.clone(),
        ),
        "agent.compression" => bridge_ingest_event(
            &session_external_id,
            seq,
            EventKind::Audit,
            "compression",
            None,
            body,
            occurred_at.clone(),
        ),
        "agent.identity" => bridge_ingest_event(
            &session_external_id,
            seq,
            EventKind::Audit,
            "identity",
            None,
            body,
            occurred_at.clone(),
        ),
        _ => return BridgeRecordMapping::Skipped,
    };
    apply_bridge_metrics(value, &mut event);
    BridgeRecordMapping::Mapped(Box::new(BridgeMappedEvent {
        session_external_id,
        agent,
        workflow,
        opened_at,
        closed_at,
        event,
    }))
}

fn bridge_ingest_event(
    session_external_id: &str,
    seq: u64,
    kind: EventKind,
    tag: &str,
    sub: Option<String>,
    body: String,
    occurred_at: String,
) -> IngestEvent {
    IngestEvent {
        session_external_id: bounded_nonempty(session_external_id, MAX_EXTERNAL_ID_UNITS, "unknown-session"),
        seq,
        kind,
        tag: bounded_nonempty(tag, MAX_TAG_UNITS, "event"),
        body: bounded_text(&body, MAX_BODY_UNITS),
        sub: sub.map(|value| bounded_text(&value, MAX_SUB_UNITS)),
        policy_name: None,
        occurred_at,
        journal_count: 1,
        add_prompt_tokens: 0,
        add_completion_tokens: 0,
        add_cost_usd_micros: 0,
        add_payout_usd_micros: 0,
        add_blocked_payout_usd_micros: 0,
        add_tools_allowed: 0,
        add_tools_blocked: 0,
    }
}

fn bridge_session_id(value: &serde_json::Value) -> Option<String> {
    value
        .get("session_uid")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            value
                .pointer("/payload/session_id")
                .and_then(serde_json::Value::as_str)
        })
        .or_else(|| {
            value
                .pointer("/payload/session_uid")
                .and_then(serde_json::Value::as_str)
        })
        .map(|value| bounded_nonempty(value, MAX_EXTERNAL_ID_UNITS, "unknown-session"))
}

fn bridge_occurred_at(value: &serde_json::Value, stored_at: u64) -> Option<(u64, String)> {
    let ms = value
        .get("time")
        .and_then(serde_json::Value::as_u64)
        .or_else(|| (stored_at > 0).then_some(stored_at))?;
    let iso = value
        .get("time_iso")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| av_core::time::iso8601_ms(ms));
    Some((ms, iso))
}

fn bridge_seq(topic_idx: usize, offset: u64) -> u64 {
    let base = u64::try_from(topic_idx)
        .unwrap_or(u64::MAX)
        .saturating_mul(BRIDGE_SEQ_STRIDE);
    base.saturating_add(offset).min(MAX_SEQ)
}

fn workflow_from_str(value: &str) -> Option<Workflow> {
    match value {
        "signed" => Some(Workflow::Signed),
        "unsigned" => Some(Workflow::Unsigned),
        _ => None,
    }
}

fn bridge_body(topic: &str, value: &serde_json::Value) -> String {
    let mut body = serde_json::json!({
        "topic": topic,
        "metadataUid": value.pointer("/metadata/uid"),
        "payload": value.get("payload"),
        "metrics": value.get("metrics"),
        "stopReasonId": value.get("stop_reason_id"),
        "stopReason": value.get("stop_reason"),
    });
    if topic == "agent.compression" {
        if let Some(pruned) = value
            .pointer("/metrics/pruned_tokens")
            .and_then(serde_json::Value::as_u64)
            .or_else(|| {
                value
                    .pointer("/payload/pruned_tokens")
                    .and_then(serde_json::Value::as_u64)
            })
        {
            if let Some(object) = body.as_object_mut() {
                object.insert("prunedTokens".to_owned(), serde_json::json!(pruned));
            }
        }
    }
    serde_json::to_string(&body).unwrap_or_else(|_| "{}".to_owned())
}

fn bridge_tool_blocked(value: &serde_json::Value) -> bool {
    let payload = value.get("payload").unwrap_or(&serde_json::Value::Null);
    if payload.get("allowed").and_then(serde_json::Value::as_bool) == Some(false) {
        return true;
    }
    if value.get("status_id").and_then(serde_json::Value::as_u64) == Some(2) {
        return true;
    }
    for key in ["verdict", "status", "decision", "outcome"] {
        if payload
            .get(key)
            .and_then(serde_json::Value::as_str)
            .is_some_and(|text| {
                let text = text.to_ascii_lowercase();
                text.contains("block") || text.contains("deny") || text.contains("fail")
            })
        {
            return true;
        }
    }
    false
}

fn bridge_tool_tag(payload: &serde_json::Value) -> String {
    for pointer in ["/tool", "/tool_name", "/name", "/function/name", "/function_name"] {
        if let Some(value) = payload.pointer(pointer).and_then(serde_json::Value::as_str) {
            return bounded_nonempty(value, MAX_TAG_UNITS, "tool");
        }
    }
    "tool".to_owned()
}

fn bridge_stop_reason_tag(value: &serde_json::Value) -> String {
    value
        .get("stop_reason")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            value
                .pointer("/payload/reason")
                .and_then(serde_json::Value::as_str)
        })
        .map(|value| bounded_nonempty(value, MAX_TAG_UNITS, "stop_reason"))
        .unwrap_or_else(|| "stop_reason".to_owned())
}

fn apply_bridge_metrics(value: &serde_json::Value, event: &mut IngestEvent) {
    if let Some(metrics) = value.get("metrics") {
        event.add_prompt_tokens = cap_u64_to_u32(
            metrics
                .get("prompt_tokens")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
            1_000_000,
        );
        event.add_completion_tokens = cap_u64_to_u32(
            metrics
                .get("completion_tokens")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
            1_000_000,
        );
    }
    event.add_cost_usd_micros = value
        .pointer("/payload/cost_usd_micros")
        .and_then(serde_json::Value::as_u64)
        .or_else(|| value.get("cost_usd_micros").and_then(serde_json::Value::as_u64))
        .unwrap_or(0)
        .min(100_000_000_000);
}

fn extract_payout_micros(value: &serde_json::Value) -> u64 {
    for pointer in [
        "/payout_usd_micros",
        "/payoutUsdMicros",
        "/payout_micros",
        "/payout/micros",
        "/payout/usd_micros",
    ] {
        if let Some(micros) = value.pointer(pointer).and_then(serde_json::Value::as_u64) {
            return micros.min(100_000_000_000);
        }
    }
    for pointer in ["/payout_usd", "/amount_usd", "/payout/usd", "/payout/amount_usd"] {
        if let Some(usd) = value.pointer(pointer).and_then(serde_json::Value::as_f64) {
            return cost_usd_to_micros(usd);
        }
    }
    0
}

fn read_trajectory_candidate(path: &Path) -> Result<TrajectoryCandidate> {
    let bytes = av_core::fsutil::read_capped(path, av_core::fsutil::MAX_ATIF_BYTES)
        .with_context(|| format!("read ATIF {}", path.display()))?;
    let issues = av_atif::validate_bytes(&bytes, av_atif::Mode::Strict)
        .map_err(|reason| anyhow::anyhow!("ATIF JSON rejected: {reason}"))?;
    if !issues.is_empty() {
        anyhow::bail!("ATIF validation failed: {:?}", issues);
    }
    let trajectory: av_atif::Trajectory =
        serde_json::from_slice(&bytes).with_context(|| format!("parse ATIF {}", path.display()))?;
    let issues = av_atif::validate_trajectory(&trajectory, av_atif::Mode::Strict);
    if !issues.is_empty() {
        anyhow::bail!("ATIF validation failed: {:?}", issues);
    }
    Ok(trajectory_to_candidate(&trajectory, path))
}

fn trajectory_to_candidate(trajectory: &av_atif::Trajectory, path: &Path) -> TrajectoryCandidate {
    let fallback_id = path
        .file_stem()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or("unknown-session");
    let external_id = bounded_nonempty(
        trajectory.session_id.as_deref().unwrap_or(fallback_id),
        MAX_EXTERNAL_ID_UNITS,
        "unknown-session",
    );
    let opened_at = trajectory
        .steps
        .iter()
        .find_map(|step| step.timestamp.as_deref())
        .unwrap_or(FALLBACK_OCCURRED_AT)
        .to_owned();
    let close_marker = path.with_extension("close-complete").exists();
    let closed_at = close_marker.then(|| {
        trajectory
            .steps
            .iter()
            .rev()
            .find_map(|step| step.timestamp.as_deref())
            .unwrap_or(opened_at.as_str())
            .to_owned()
    });
    let policy_version = policy_version_from_extra(trajectory.extra.as_ref());
    let session = SessionUpsert {
        external_id: external_id.clone(),
        agent: bounded_nonempty(&trajectory.agent.name, MAX_AGENT_UNITS, "agent"),
        workflow: Workflow::Unsigned,
        status: SessionStatus::Live,
        policy_version,
        opened_at: opened_at.clone(),
        closed_at,
    };

    let mut events = Vec::with_capacity(trajectory.steps.len().saturating_add(2));
    events.push(IngestEvent::sys(
        &external_id,
        0,
        "open",
        serde_json::json!({
            "action": "opened",
            "schemaVersion": trajectory.schema_version,
            "trajectoryId": trajectory.trajectory_id,
        }),
        opened_at,
    ));
    for step in &trajectory.steps {
        if step.step_id > MAX_SEQ {
            continue;
        }
        events.push(step_to_event(&external_id, step.step_id, step));
    }
    if close_marker {
        let close_seq = trajectory
            .steps
            .last()
            .and_then(|step| step.step_id.checked_add(1))
            .unwrap_or(1);
        if close_seq <= MAX_SEQ {
            let occurred_at = trajectory
                .steps
                .iter()
                .rev()
                .find_map(|step| step.timestamp.as_deref())
                .unwrap_or(FALLBACK_OCCURRED_AT)
                .to_owned();
            events.push(IngestEvent::sys(
                &external_id,
                close_seq,
                "close",
                serde_json::json!({
                    "action": "closed",
                    "workflow": "unsigned",
                }),
                occurred_at,
            ));
        }
    }
    TrajectoryCandidate { session, events }
}

fn step_to_event(session_external_id: &str, seq: u64, step: &av_atif::Step) -> IngestEvent {
    let (kind, tag, sub) = classify_step(step);
    let body_value = serde_json::json!({
        "stepId": step.step_id,
        "source": step.source,
        "message": step.message,
        "reasoningEffort": step.reasoning_effort,
        "reasoningContent": step.reasoning_content,
        "modelName": step.model_name,
        "toolCalls": step.tool_calls,
        "observation": step.observation,
        "metrics": step.metrics,
        "llmCallCount": step.llm_call_count,
        "extra": step.extra,
    });
    let mut event = IngestEvent {
        session_external_id: bounded_nonempty(session_external_id, MAX_EXTERNAL_ID_UNITS, "unknown-session"),
        seq,
        kind,
        tag: bounded_nonempty(&tag, MAX_TAG_UNITS, "step"),
        body: bounded_text(
            &serde_json::to_string(&body_value).unwrap_or_else(|_| "{}".to_owned()),
            MAX_BODY_UNITS,
        ),
        policy_name: policy_from_step(step),
        sub: sub.map(|value| bounded_text(&value, MAX_SUB_UNITS)),
        occurred_at: step
            .timestamp
            .clone()
            .unwrap_or_else(|| FALLBACK_OCCURRED_AT.to_owned()),
        journal_count: 1,
        add_prompt_tokens: 0,
        add_completion_tokens: 0,
        add_cost_usd_micros: 0,
        add_payout_usd_micros: 0,
        add_blocked_payout_usd_micros: 0,
        add_tools_allowed: 0,
        add_tools_blocked: 0,
    };
    if let Some(metrics) = &step.metrics {
        event.add_prompt_tokens = cap_u64_to_u32(metrics.prompt_tokens.unwrap_or(0), 1_000_000);
        event.add_completion_tokens = cap_u64_to_u32(metrics.completion_tokens.unwrap_or(0), 1_000_000);
        event.add_cost_usd_micros = cost_usd_to_micros(metrics.cost_usd.unwrap_or(0.0));
    }
    let tool_count = step
        .tool_calls
        .as_ref()
        .map_or(0, |calls| cap_usize_to_u32(calls.len(), 1_000));
    if event.kind == EventKind::Block {
        event.add_tools_blocked = tool_count.max(1);
    } else if event.kind == EventKind::Tool {
        event.add_tools_allowed = tool_count;
    }
    event
}

fn classify_step(step: &av_atif::Step) -> (EventKind, String, Option<String>) {
    match step.source {
        av_atif::Source::User => (EventKind::User, "user".to_owned(), None),
        av_atif::Source::System => (EventKind::Sys, "system".to_owned(), None),
        av_atif::Source::Agent => {
            if contains_block_signal(step) {
                return (EventKind::Block, "policy_block".to_owned(), first_tool_name(step));
            }
            if step.tool_calls.as_ref().is_some_and(|calls| !calls.is_empty()) || step.observation.is_some() {
                let tag = first_tool_name(step).unwrap_or_else(|| "tool".to_owned());
                return (EventKind::Tool, tag.clone(), Some(tag));
            }
            (
                EventKind::Llm,
                step.model_name.clone().unwrap_or_else(|| "llm".to_owned()),
                step.model_name.clone(),
            )
        }
        _ => (EventKind::Sys, "step".to_owned(), None),
    }
}

fn first_tool_name(step: &av_atif::Step) -> Option<String> {
    step.tool_calls
        .as_ref()
        .and_then(|calls| calls.first())
        .map(|call| bounded_text(&call.function_name, MAX_TAG_UNITS))
}

/// Extract a named-policy attribution from an ATIF step. The harness
/// embeds its tool-authorization payload (the same JSON that reaches
/// the OCSF `agent.tool_call` event, including `"policy"` for named
/// policy-chain denials) as observation-result content — either as a
/// JSON object or as a serialized JSON string. Absent or unnamed gates
/// (parse/schema/budget) yield `None`; attribution must never invent a
/// policy the operator can't find in the console inventory.
fn policy_from_step(step: &av_atif::Step) -> Option<String> {
    let results = &step.observation.as_ref()?.results;
    for result in results {
        let Some(content) = result.content.as_ref() else {
            continue;
        };
        let payload: Option<serde_json::Value> = match content {
            serde_json::Value::String(text) => serde_json::from_str(text).ok(),
            other => Some(other.clone()),
        };
        if let Some(name) = payload
            .as_ref()
            .and_then(|value| value.get("policy"))
            .and_then(serde_json::Value::as_str)
        {
            return Some(bounded_nonempty(name, MAX_AGENT_UNITS, "policy"));
        }
    }
    None
}

fn contains_block_signal(step: &av_atif::Step) -> bool {
    let text = serde_json::to_string(step)
        .unwrap_or_default()
        .to_ascii_lowercase();
    text.contains("blocked") || text.contains("forbidden") || text.contains("policy")
}

fn policy_version_from_extra(extra: Option<&serde_json::Value>) -> u32 {
    extra
        .and_then(|value| value.get("policyVersion").or_else(|| value.get("policy_version")))
        .and_then(serde_json::Value::as_u64)
        .map_or(1, |value| cap_u64_to_u32(value, 1_000_000))
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn cost_usd_to_micros(cost_usd: f64) -> u64 {
    if !cost_usd.is_finite() || cost_usd <= 0.0 {
        return 0;
    }
    let micros = (cost_usd * 1_000_000.0).round();
    if micros >= 100_000_000_000.0 {
        100_000_000_000
    } else {
        micros as u64
    }
}

fn cap_u64_to_u32(value: u64, cap: u32) -> u32 {
    u32::try_from(value.min(u64::from(cap))).unwrap_or(cap)
}

fn cap_usize_to_u32(value: usize, cap: u32) -> u32 {
    let cap_usize = usize::try_from(cap).unwrap_or(usize::MAX);
    u32::try_from(value.min(cap_usize)).unwrap_or(cap)
}

#[derive(Debug)]
struct ReceiptCandidate {
    session_external_id: String,
    session: SessionUpsert,
    payload: ReceiptIngestPayload,
    public_key_hex: Option<String>,
}

fn scan_receipts(spool_dir: &Path) -> Vec<ReceiptCandidate> {
    let receipts_dir = spool_dir.join("receipts");
    let mut out = Vec::new();
    let entries = match sorted_dir_entries(&receipts_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return out,
        Err(error) => {
            eprintln!(
                "warning: cannot read receipt directory {}: {error}",
                receipts_dir.display()
            );
            return out;
        }
    };
    for path in entries {
        if !is_primary_json(&path) || is_symlink(&path) {
            continue;
        }
        match read_receipt_candidate(&path) {
            Ok(candidate) => out.push(candidate),
            Err(error) => eprintln!(
                "warning: skipping receipt {}: {error:#}",
                sanitize_for_terminal(&path.display().to_string())
            ),
        }
    }
    out
}

fn read_receipt_candidate(path: &Path) -> Result<ReceiptCandidate> {
    let bytes = av_core::fsutil::read_capped(path, av_core::fsutil::MAX_RECEIPT_BYTES)
        .with_context(|| format!("read receipt {}", path.display()))?;
    let receipt = av_receipts::Receipt::from_json_slice(&bytes)
        .with_context(|| format!("parse receipt {}", path.display()))?;
    let body_value = serde_json::to_value(&receipt.body).context("serialize receipt body")?;
    let canonical_body = av_receipts::canonicalize(&body_value).context("canonicalize receipt body")?;
    let (event_count, workflow) = match &receipt.body.subject {
        av_receipts::ReceiptSubject::EventChain { event_count, .. } => (*event_count, Workflow::Signed),
        av_receipts::ReceiptSubject::AtifTrajectory { step_count, .. } => (*step_count, Workflow::Unsigned),
        _ => anyhow::bail!("unsupported future receipt subject"),
    };
    let event_count = event_count.min(MAX_SEQ);
    let session_external_id =
        bounded_nonempty(&receipt.body.session_id, MAX_EXTERNAL_ID_UNITS, "unknown-session");
    let session = SessionUpsert {
        external_id: session_external_id.clone(),
        agent: bounded_nonempty(&receipt.body.ai_agent.charter.name, MAX_AGENT_UNITS, "agent"),
        workflow,
        status: SessionStatus::Live,
        policy_version: 1,
        opened_at: receipt.body.issued_at_iso.clone(),
        closed_at: Some(receipt.body.issued_at_iso.clone()),
    };
    let payload = ReceiptIngestPayload {
        session_external_id: session_external_id.clone(),
        receipt_id: bounded_nonempty(&receipt.body.receipt_id, MAX_EXTERNAL_ID_UNITS, "receipt"),
        body: canonical_body,
        sig_b64: receipt.signature_b64.clone(),
        key_id_hex: receipt.body.key_id.clone(),
        event_count,
        issued_at: receipt.body.issued_at_iso.clone(),
        stop_reason_id: Some(u64::from(receipt.body.stop_reason_id)),
        stop_reason: Some(bounded_text(&receipt.body.stop_reason, 80)),
    };
    Ok(ReceiptCandidate {
        session_external_id,
        session,
        payload,
        public_key_hex: public_key_hex_from_receipt(&receipt)?,
    })
}

fn public_key_hex_from_receipt(receipt: &av_receipts::Receipt) -> Result<Option<String>> {
    if receipt.body.public_key_b64.is_empty() {
        return Ok(None);
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(receipt.body.public_key_b64.trim())
        .context("decode receipt public_key_b64")?;
    if decoded.len() != 32 {
        anyhow::bail!(
            "receipt public_key_b64 decoded to {} bytes, expected 32",
            decoded.len()
        );
    }
    Ok(Some(hex::encode(decoded)))
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionUpsert {
    external_id: String,
    agent: String,
    workflow: Workflow,
    status: SessionStatus,
    policy_version: u32,
    opened_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    closed_at: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum Workflow {
    Signed,
    Unsigned,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
enum SessionStatus {
    Live,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct IngestEvent {
    session_external_id: String,
    seq: u64,
    kind: EventKind,
    tag: String,
    body: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sub: Option<String>,
    /// Policy the event fired under, when the OCSF payload attributes
    /// one (`payload.policy` / `payload.policy_name`). Powers the
    /// console's per-policy 24h hit/block counters.
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_name: Option<String>,
    occurred_at: String,
    #[serde(skip_serializing_if = "is_default_u32")]
    journal_count: u32,
    #[serde(skip_serializing_if = "is_default_u32")]
    add_prompt_tokens: u32,
    #[serde(skip_serializing_if = "is_default_u32")]
    add_completion_tokens: u32,
    #[serde(skip_serializing_if = "is_default_u64")]
    add_cost_usd_micros: u64,
    #[serde(skip_serializing_if = "is_default_u64")]
    add_payout_usd_micros: u64,
    #[serde(skip_serializing_if = "is_default_u64")]
    add_blocked_payout_usd_micros: u64,
    #[serde(skip_serializing_if = "is_default_u32")]
    add_tools_allowed: u32,
    #[serde(skip_serializing_if = "is_default_u32")]
    add_tools_blocked: u32,
}

impl IngestEvent {
    fn sys(
        session_external_id: &str,
        seq: u64,
        tag: &str,
        body: serde_json::Value,
        occurred_at: String,
    ) -> Self {
        Self {
            session_external_id: bounded_nonempty(
                session_external_id,
                MAX_EXTERNAL_ID_UNITS,
                "unknown-session",
            ),
            seq,
            kind: EventKind::Sys,
            tag: bounded_nonempty(tag, MAX_TAG_UNITS, "sys"),
            body: bounded_text(
                &serde_json::to_string(&body).unwrap_or_else(|_| "{}".to_owned()),
                MAX_BODY_UNITS,
            ),
            sub: None,
            policy_name: None,
            occurred_at,
            journal_count: 1,
            add_prompt_tokens: 0,
            add_completion_tokens: 0,
            add_cost_usd_micros: 0,
            add_payout_usd_micros: 0,
            add_blocked_payout_usd_micros: 0,
            add_tools_allowed: 0,
            add_tools_blocked: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum EventKind {
    Sys,
    User,
    Llm,
    Tool,
    Block,
    Guard,
    Audit,
}

fn is_default_u32(value: &u32) -> bool {
    *value == 0
}

fn is_default_u64(value: &u64) -> bool {
    *value == 0
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EventBatchResponse {
    inserted: u64,
    rejected_sealed: Option<Vec<String>>,
    dropped_future: Option<u64>,
    dropped_ancient: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptIngestPayload {
    session_external_id: String,
    receipt_id: String,
    body: String,
    #[serde(rename = "sigB64")]
    sig_b64: String,
    #[serde(rename = "keyIdHex")]
    key_id_hex: String,
    event_count: u64,
    issued_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    stop_reason_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stop_reason: Option<String>,
}

/// Cap batches by BOTH event count and serialized size: field caps are
/// UTF-16-unit based, so 500 CJK-heavy events serialize to ~12 MB of
/// UTF-8 JSON — far past the server's 4 MiB body limit, and the 413
/// reply made the same oversized batch rebuild forever. 3 MiB leaves
/// room for JSON escaping + envelope overhead.
const MAX_BATCH_BYTES: usize = 3 * 1024 * 1024;

fn event_batches(events: &[IngestEvent]) -> Vec<Vec<IngestEvent>> {
    let mut batches = Vec::new();
    let mut current: Vec<IngestEvent> = Vec::new();
    let mut current_bytes = 0usize;
    for event in events {
        let event_bytes = serde_json::to_string(event).map(|s| s.len()).unwrap_or(0);
        let would_overflow = !current.is_empty()
            && (current.len() >= MAX_BATCH_EVENTS
                || current_bytes.saturating_add(event_bytes) > MAX_BATCH_BYTES);
        if would_overflow {
            batches.push(std::mem::take(&mut current));
            current_bytes = 0;
        }
        current_bytes = current_bytes.saturating_add(event_bytes);
        current.push(event.clone());
    }
    if !current.is_empty() {
        batches.push(current);
    }
    batches
}

/// Symlink refusal for spool scans: the daemon writes only regular
/// files here; a planted symlink would otherwise let `read_capped`
/// (which follows links) exfiltrate an arbitrary readable file into the
/// console upload. Same O_NOFOLLOW-equivalent posture as the harness's
/// own spool readers. Unreadable metadata counts as a symlink
/// (fail-closed — the read would fail anyway).
fn is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(true)
}

fn sorted_dir_entries(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        entries.push(entry?.path());
    }
    entries.sort();
    Ok(entries)
}

fn is_primary_json(path: &Path) -> bool {
    let is_json = path.extension().and_then(std::ffi::OsStr::to_str) == Some("json");
    if !is_json {
        return false;
    }
    let Some(name) = path.file_name().and_then(std::ffi::OsStr::to_str) else {
        return false;
    };
    !name.contains(".archived-") && !name.starts_with(".archived-")
}

fn is_session_sidecar(path: &Path) -> bool {
    path.file_name()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|name| name.ends_with(".session.json"))
}

fn bounded_nonempty(value: &str, max_units: usize, fallback: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        fallback.to_owned()
    } else {
        bounded_text(trimmed, max_units)
    }
}

fn bounded_text(value: &str, max_units: usize) -> String {
    let mut out = String::new();
    let mut used = 0usize;
    for c in value.chars() {
        let units = c.len_utf16();
        if used.saturating_add(units) > max_units {
            break;
        }
        used = used.saturating_add(units);
        out.push(c);
    }
    out
}

fn sanitize_for_terminal(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            let cp = c as u32;
            if cp == 0x09 {
                c
            } else if cp < 0x20
                || cp == 0x7f
                || (0x80..=0x9f).contains(&cp)
                || av_core::text::is_bidi_or_zero_width(c)
            {
                '\u{FFFD}'
            } else {
                c
            }
        })
        .collect()
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
    use av_receipts::Signer as _;
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode as AxumStatusCode};
    use axum::routing::post;
    use axum::{Json, Router};
    use serde_json::{json, Value};
    use std::sync::{Arc, Mutex};
    use tokio::sync::oneshot;

    #[test]
    fn unicode_truncation_does_not_split_utf8_or_exceed_utf16_cap() {
        let input = "😀".repeat(4_001);
        let truncated = bounded_text(&input, MAX_BODY_UNITS);
        assert_eq!(truncated.chars().count(), 4_000);
        assert_eq!(truncated.encode_utf16().count(), MAX_BODY_UNITS);
        assert!(truncated.ends_with('😀'));
    }

    #[test]
    fn event_chunking_is_capped_at_five_hundred() {
        let events: Vec<_> = (0..1_001)
            .map(|seq| {
                IngestEvent::sys(
                    "session",
                    seq,
                    "sys",
                    json!({"seq": seq}),
                    FALLBACK_OCCURRED_AT.to_owned(),
                )
            })
            .collect();
        let batches = event_batches(&events);
        assert_eq!(batches.len(), 3);
        assert_eq!(batches[0].len(), 500);
        assert_eq!(batches[1].len(), 500);
        assert_eq!(batches[2].len(), 1);
    }

    #[test]
    fn state_file_round_trips() {
        let dir = test_tempdir("state");
        let path = dir.path().join("state.json");
        let mut state = SyncState::default();
        state.sessions.insert(
            "s1".to_owned(),
            SessionSyncState {
                last_synced_seq: 42,
                receipt_synced: true,
                synced_any: true,
                atif_synced: true,
            },
        );
        state.pubkey_hex_synced = Some("ab".repeat(32));
        state.console_url = Some("https://console.example".to_owned());
        state.deployment = Some("dep-1".to_owned());
        state
            .bridge_topic_offsets
            .insert("agent.session/p0".to_owned(), 7);
        state.save(&path).unwrap();
        let restored = SyncState::load(&path).unwrap();
        let session = restored.sessions.get("s1").unwrap();
        assert_eq!(session.last_synced_seq, 42);
        assert!(session.synced_any);
        assert!(session.receipt_synced);
        assert!(session.atif_synced);
        assert_eq!(restored.pubkey_hex_synced, Some("ab".repeat(32)));
        assert_eq!(restored.console_url.as_deref(), Some("https://console.example"));
        assert_eq!(restored.deployment.as_deref(), Some("dep-1"));
        assert_eq!(restored.bridge_topic_offsets.get("agent.session/p0"), Some(&7));
    }

    #[test]
    fn bridge_seq_is_deterministic_and_capped() {
        assert_eq!(bridge_seq(1, 7), 1_000_007);
        assert_eq!(bridge_seq(1, 7), bridge_seq(1, 7));
        assert_eq!(bridge_seq(200, 1), MAX_SEQ);
    }

    #[test]
    fn bridge_ocsf_tool_and_session_events_map_to_ingest_shape() {
        let tool = stored_bridge_event(
            "agent.tool_call",
            7,
            json!({
                "metadata": {"uid": "evt-tool", "sequence": 3},
                "class_name": "agent.tool_call",
                "time": 1767225600000u64,
                "time_iso": "2026-01-01T00:00:00.000Z",
                "status_id": 2,
                "session_uid": "signed-s",
                "ai_agent": {
                    "version": "1.0.0",
                    "charter": {"name": "signed-agent", "type_id": 1},
                    "instance_uid": "inst-1"
                },
                "payload": {
                    "tool": "deploy-production",
                    "allowed": false,
                    "stage": "policy",
                    "reason": "denied by policy",
                    "payout_usd_micros": 8400
                }
            }),
        );
        let BridgeRecordMapping::Mapped(mapped) =
            bridge_record_to_event(1, "agent.tool_call", &tool, 1_800_000_000_000)
        else {
            panic!("tool event should map");
        };
        assert_eq!(mapped.session_external_id, "signed-s");
        assert_eq!(mapped.agent, "signed-agent");
        assert_eq!(mapped.event.seq, 1_000_007);
        assert_eq!(mapped.event.kind, EventKind::Block);
        assert_eq!(mapped.event.tag, "deploy-production");
        assert_eq!(mapped.event.add_tools_blocked, 1);
        assert_eq!(mapped.event.add_tools_allowed, 0);
        assert_eq!(mapped.event.add_blocked_payout_usd_micros, 8400);

        let opened = stored_bridge_event(
            "agent.session",
            0,
            json!({
                "metadata": {"uid": "evt-open", "sequence": 0},
                "class_name": "agent.session",
                "time": 1767225600000u64,
                "time_iso": "2026-01-01T00:00:00.000Z",
                "status_id": 1,
                "session_uid": "signed-s",
                "ai_agent": {
                    "version": "1.0.0",
                    "charter": {"name": "signed-agent", "type_id": 1},
                    "instance_uid": "inst-1"
                },
                "payload": {"action": "opened", "workflow": "signed"}
            }),
        );
        let BridgeRecordMapping::Mapped(mapped) =
            bridge_record_to_event(0, "agent.session", &opened, 1_800_000_000_000)
        else {
            panic!("session event should map");
        };
        assert_eq!(mapped.workflow, Some(Workflow::Signed));
        assert_eq!(mapped.opened_at.as_deref(), Some("2026-01-01T00:00:00.000Z"));
        assert_eq!(mapped.event.kind, EventKind::Sys);
        assert_eq!(mapped.event.tag, "open");
    }

    #[test]
    fn bridge_scan_skips_atif_synced_sessions_and_tracks_offsets() {
        let dir = test_tempdir("bridge-dedupe");
        write_bridge_manifest(dir.path());
        append_bridge_event(
            dir.path(),
            "agent.session",
            stored_bridge_event(
                "agent.session",
                0,
                json!({
                    "metadata": {"uid": "evt-unsigned", "sequence": 0},
                    "class_name": "agent.session",
                    "time": 1767225600000u64,
                    "time_iso": "2026-01-01T00:00:00.000Z",
                    "status_id": 1,
                    "session_uid": "unsigned-s",
                    "ai_agent": {
                        "version": "1.0.0",
                        "charter": {"name": "unsigned-agent", "type_id": 1},
                        "instance_uid": "inst-u"
                    },
                    "payload": {"action": "opened", "workflow": "unsigned"}
                }),
            ),
        );
        append_bridge_event(
            dir.path(),
            "agent.session",
            stored_bridge_event(
                "agent.session",
                2,
                json!({
                    "metadata": {"uid": "evt-old-unsigned", "sequence": 0},
                    "class_name": "agent.session",
                    "time": 1767225600000u64,
                    "time_iso": "2026-01-01T00:00:00.000Z",
                    "status_id": 1,
                    "session_uid": "old-unsigned",
                    "ai_agent": {
                        "version": "1.0.0",
                        "charter": {"name": "old-unsigned-agent", "type_id": 1},
                        "instance_uid": "inst-ou"
                    },
                    "payload": {"action": "opened", "workflow": "unsigned"}
                }),
            ),
        );
        append_bridge_event(
            dir.path(),
            "agent.session",
            stored_bridge_event(
                "agent.session",
                1,
                json!({
                    "metadata": {"uid": "evt-signed", "sequence": 0},
                    "class_name": "agent.session",
                    "time": 1767225600000u64,
                    "time_iso": "2026-01-01T00:00:00.000Z",
                    "status_id": 1,
                    "session_uid": "signed-s",
                    "ai_agent": {
                        "version": "1.0.0",
                        "charter": {"name": "signed-agent", "type_id": 1},
                        "instance_uid": "inst-s"
                    },
                    "payload": {"action": "opened", "workflow": "signed"}
                }),
            ),
        );

        let mut state = SyncState::default();
        state.sessions.insert(
            "old-unsigned".to_owned(),
            SessionSyncState {
                last_synced_seq: 0,
                receipt_synced: false,
                synced_any: true,
                atif_synced: true,
            },
        );
        let atif_ids = BTreeSet::from(["unsigned-s".to_owned()]);
        let scan = scan_bridge_candidates(dir.path(), &state, &atif_ids);
        assert_eq!(scan.candidates.len(), 1);
        assert_eq!(scan.candidates[0].session.external_id, "signed-s");
        assert_eq!(scan.max_seen_offsets.get("agent.session/p0"), Some(&2));
    }

    #[test]
    fn atif_mapping_uses_public_writer_shape_and_truncates_fields() {
        let dir = test_tempdir("atif-map");
        let path = dir.path().join("trajectory.json");
        let mut builder = av_atif::TrajectoryBuilder::new(
            av_atif::Agent {
                name: format!("agent-{}", "x".repeat(90)),
                version: "1.0.0".to_owned(),
                model_name: Some(format!("model-{}", "y".repeat(100))),
                tool_definitions: None,
                extra: None,
            },
            Some("session-1".to_owned()),
        );
        builder
            .push_step(av_atif::Step {
                step_id: 999,
                timestamp: Some("2026-01-01T00:00:00Z".to_owned()),
                source: av_atif::Source::Agent,
                message: json!("hello"),
                reasoning_effort: None,
                reasoning_content: None,
                model_name: Some("gpt-test".to_owned()),
                tool_calls: None,
                observation: None,
                metrics: Some(av_atif::writer::metrics(10, 5, 0, 0.000123)),
                is_copied_context: None,
                llm_call_count: Some(1),
                extra: None,
            })
            .unwrap();
        av_atif::write_atomic(&builder.finish(), &path).unwrap();
        std::fs::write(path.with_extension("atif-auth"), b"test-sidecar").unwrap();

        let candidate = read_trajectory_candidate(&path).unwrap();
        assert_eq!(candidate.session.external_id, "session-1");
        assert_eq!(candidate.session.agent.encode_utf16().count(), MAX_AGENT_UNITS);
        assert_eq!(candidate.events.len(), 2);
        let llm = &candidate.events[1];
        assert_eq!(llm.kind, EventKind::Llm);
        assert_eq!(llm.add_prompt_tokens, 10);
        assert_eq!(llm.add_completion_tokens, 5);
        assert_eq!(llm.add_cost_usd_micros, 123);
    }

    #[tokio::test]
    async fn sync_posts_to_ingest_api_and_uses_state_on_rerun() {
        let dir = test_tempdir("http-sync");
        let spool = dir.path().join("spool");
        std::fs::create_dir_all(spool.join("receipts")).unwrap();
        let atif_path = spool.join("session.json");
        write_test_trajectory(&atif_path);
        std::fs::write(atif_path.with_extension("atif-auth"), b"sidecar").unwrap();
        std::fs::write(atif_path.with_extension("close-complete"), b"closed").unwrap();
        let receipt_path = spool.join("receipts").join("session.json");
        write_test_receipt(&receipt_path);

        let seen = Arc::new(Mutex::new(Vec::new()));
        let (base_url, shutdown) = start_mock_console(Arc::clone(&seen)).await;
        let token_path = dir.path().join("token");
        std::fs::write(&token_path, b"secret\n").unwrap();
        let config = ResolvedSyncConfig::resolve(&ConsoleSyncArgs {
            spool_dir: spool.clone(),
            console_url: Some(base_url),
            deployment: Some("dep-1".to_owned()),
            token_file: Some(token_path),
            bridge_dir: None,
            watch: false,
            interval: 30,
            state_file: Some(dir.path().join("state.json")),
            dry_run: false,
        })
        .unwrap();

        run_once(&config, false).await.unwrap();
        run_once(&config, false).await.unwrap();
        let seen = seen.lock().unwrap();
        let events_posts = seen.iter().filter(|entry| entry.as_str() == "events").count();
        let receipts_posts = seen.iter().filter(|entry| entry.as_str() == "receipts").count();
        let pubkey_posts = seen.iter().filter(|entry| entry.as_str() == "pubkey").count();
        assert_eq!(events_posts, 1, "second run must not repost synced event seqs");
        assert_eq!(receipts_posts, 1, "second run must not repost synced receipt");
        assert_eq!(pubkey_posts, 1, "public key should be posted once");
        drop(seen);
        let _ = shutdown.send(());
    }

    fn test_tempdir(name: &str) -> tempfile::TempDir {
        let base = std::env::current_dir()
            .unwrap()
            .join("target")
            .join("av-cli-console-sync-tests");
        std::fs::create_dir_all(&base).unwrap();
        tempfile::Builder::new().prefix(name).tempdir_in(base).unwrap()
    }

    fn write_test_trajectory(path: &Path) {
        let mut builder = av_atif::TrajectoryBuilder::new(
            av_atif::Agent {
                name: "test-agent".to_owned(),
                version: "1.0.0".to_owned(),
                model_name: Some("gpt-test".to_owned()),
                tool_definitions: None,
                extra: None,
            },
            Some("session-1".to_owned()),
        );
        builder
            .push_step(av_atif::Step {
                step_id: 0,
                timestamp: Some("2026-01-01T00:00:00Z".to_owned()),
                source: av_atif::Source::User,
                message: json!("hello"),
                reasoning_effort: None,
                reasoning_content: None,
                model_name: None,
                tool_calls: None,
                observation: None,
                metrics: None,
                is_copied_context: None,
                llm_call_count: Some(0),
                extra: None,
            })
            .unwrap();
        av_atif::write_atomic(&builder.finish(), path).unwrap();
    }

    fn write_test_receipt(path: &Path) {
        let signer = av_receipts::Ed25519Signer::from_seed(&[9; 32]);
        let value = json!({
            "receipt_version": 2,
            "receipt_id": "receipt-1",
            "session_id": "session-1",
            "issued_at": 1767225600000u64,
            "issued_at_iso": "2026-01-01T00:00:00Z",
            "ai_agent": {
                "version": "1.0.0",
                "charter": {"name": "test-agent", "type_id": 1},
                "instance_uid": "instance-1"
            },
            "subject": {
                "kind": "atif_trajectory",
                "trajectory_digest": "ab".repeat(32),
                "step_count": 1,
                "retroactive": true
            },
            "tool_calls": {"total": 0, "allowed": 0, "blocked": 0},
            "cost": {"prompt_tokens": 0, "completion_tokens": 0, "cached_tokens": 0, "cost_usd_micros": 0},
            "stop_reason_id": 1,
            "stop_reason": "complete",
            "key_id": signer.key_id(),
            "public_key_b64": base64::engine::general_purpose::STANDARD.encode(signer.public_key_bytes()),
            "signature_b64": base64::engine::general_purpose::STANDARD.encode([7u8; 64])
        });
        std::fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    }

    fn write_bridge_manifest(path: &Path) {
        let topics = BRIDGE_TOPICS
            .iter()
            .map(|topic| format!("  - name: {topic}\n    partitions: 1\n    retention: {{hot_hours: 24}}\n"))
            .collect::<String>();
        std::fs::write(
            path.join("manifest.yaml"),
            format!("manifest_version: 1\nname: test-bridge\ntopics:\n{topics}"),
        )
        .unwrap();
    }

    fn stored_bridge_event(_topic: &str, offset: u64, value: Value) -> av_bridge::StoredEvent {
        av_bridge::StoredEvent {
            partition: 0,
            offset,
            key: value
                .pointer("/ai_agent/instance_uid")
                .and_then(Value::as_str)
                .unwrap_or("inst")
                .to_owned(),
            value,
            stored_at: 1_767_225_600_000,
        }
    }

    fn append_bridge_event(path: &Path, topic: &str, event: av_bridge::StoredEvent) {
        let topic_dir = path.join("topics").join(topic);
        std::fs::create_dir_all(&topic_dir).unwrap();
        let segment = topic_dir.join("p0.jsonl");
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(segment)
            .unwrap();
        writeln!(file, "{}", serde_json::to_string(&event).unwrap()).unwrap();
    }

    async fn start_mock_console(seen: Arc<Mutex<Vec<String>>>) -> (String, oneshot::Sender<()>) {
        async fn handler(
            State((seen, name)): State<(Arc<Mutex<Vec<String>>>, &'static str)>,
            headers: HeaderMap,
            Json(_body): Json<Value>,
        ) -> (AxumStatusCode, Json<Value>) {
            assert_eq!(
                headers.get("authorization").and_then(|value| value.to_str().ok()),
                Some("Bearer secret")
            );
            assert_eq!(
                headers
                    .get("x-av-deployment")
                    .and_then(|value| value.to_str().ok()),
                Some("dep-1")
            );
            seen.lock().unwrap().push(name.to_owned());
            let body = if name == "events" {
                json!({"inserted": 1})
            } else {
                json!({"ok": true})
            };
            (AxumStatusCode::OK, Json(body))
        }

        let app = Router::new()
            .route(
                "/api/v1/ingest/pubkey",
                post(handler).with_state((Arc::clone(&seen), "pubkey")),
            )
            .route(
                "/api/v1/ingest/sessions",
                post(handler).with_state((Arc::clone(&seen), "sessions")),
            )
            .route(
                "/api/v1/ingest/events",
                post(handler).with_state((Arc::clone(&seen), "events")),
            )
            .route(
                "/api/v1/ingest/receipts",
                post(handler).with_state((seen, "receipts")),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await
                .unwrap();
        });
        (format!("http://{address}"), tx)
    }
}
