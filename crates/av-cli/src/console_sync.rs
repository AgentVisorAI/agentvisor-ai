use anyhow::{Context, Result};
use base64::Engine as _;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
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

pub(super) struct ConsoleSyncArgs {
    pub(super) spool_dir: PathBuf,
    pub(super) console_url: Option<String>,
    pub(super) deployment: Option<String>,
    pub(super) token_file: Option<PathBuf>,
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

    if dry_run {
        let event_count: usize = trajectories.iter().map(|candidate| candidate.events.len()).sum();
        println!(
            "{}",
            serde_json::json!({
                "dryRun": true,
                "spoolDir": config.spool_dir.display().to_string(),
                "stateFile": config.state_file.display().to_string(),
                "sessions": trajectories.len(),
                "events": event_count,
                "receipts": receipts.len(),
            })
        );
        return Ok(SyncSummary::default());
    }

    let client = ConsoleClient::new(config)?;
    let mut summary = SyncSummary {
        sessions_seen: trajectories.len(),
        receipts_seen: receipts.len(),
        ..SyncSummary::default()
    };
    let mut changed = false;

    for candidate in trajectories {
        summary.attempted += 1;
        match sync_trajectory(&client, &mut state, candidate).await {
            Ok(did_change) => {
                summary.succeeded += 1;
                changed |= did_change;
            }
            Err(error) => {
                summary.failed += 1;
                eprintln!("warning: skipped session sync: {error:#}");
            }
        }
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
    let _: serde_json::Value = client.post_json("sessions", &candidate.session).await?;
    let session_state = state
        .sessions
        .entry(candidate.session.external_id.clone())
        .or_default();
    let last_synced = session_state.last_synced_seq;
    let mut events: Vec<IngestEvent> = candidate
        .events
        .into_iter()
        .filter(|event| event.seq > last_synced)
        .collect();
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
                "warning: console rejected sealed session {}; leaving state unchanged",
                sanitize_for_terminal(&candidate.session.external_id)
            );
            continue;
        }
        if response.dropped_future.unwrap_or(0) > 0 || response.dropped_ancient.unwrap_or(0) > 0 {
            eprintln!(
                "warning: console dropped timestamp-skewed events for {}; leaving that batch retryable",
                sanitize_for_terminal(&candidate.session.external_id)
            );
            continue;
        }
        if response.inserted > 0 || !batch.is_empty() {
            if let Some(max_seq) = batch.iter().map(|event| event.seq).max() {
                let session_state = state
                    .sessions
                    .entry(candidate.session.external_id.clone())
                    .or_default();
                session_state.last_synced_seq = session_state.last_synced_seq.max(max_seq);
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

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct SyncState {
    sessions: BTreeMap<String, SessionSyncState>,
    pubkey_hex_synced: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct SessionSyncState {
    last_synced_seq: u64,
    receipt_synced: bool,
}

impl SyncState {
    fn load(path: &Path) -> Result<Self> {
        match av_core::fsutil::read_capped(path, av_core::fsutil::MAX_CONTROL_BYTES) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("parse console-sync state {}", path.display())),
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
}

fn read_console_file_config() -> Result<ConsoleFileConfig> {
    let source = av_harness::config::resolve_config_source().map_err(anyhow::Error::msg)?;
    let av_harness::config::ConfigSource::File(path) = source else {
        return Ok(ConsoleFileConfig::default());
    };
    let text = av_core::fsutil::read_capped_string(&path, av_core::fsutil::MAX_CONTROL_BYTES)
        .with_context(|| format!("read config {}", path.display()))?;
    let value: toml::Value =
        toml::from_str(&text).with_context(|| format!("parse config {}", path.display()))?;
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
    })
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
            client: reqwest::Client::builder().build().context("build HTTP client")?,
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
                    .map(Duration::from_secs)
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
        if !is_primary_json(&path) || is_session_sidecar(&path) || !path.with_extension("atif-auth").exists()
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
        if !is_primary_json(&path) {
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

#[derive(Debug, Clone, Copy, Serialize)]
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

fn event_batches(events: &[IngestEvent]) -> Vec<Vec<IngestEvent>> {
    events
        .chunks(MAX_BATCH_EVENTS)
        .map(<[IngestEvent]>::to_vec)
        .collect()
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
            },
        );
        state.pubkey_hex_synced = Some("ab".repeat(32));
        state.save(&path).unwrap();
        let restored = SyncState::load(&path).unwrap();
        let session = restored.sessions.get("s1").unwrap();
        assert_eq!(session.last_synced_seq, 42);
        assert!(session.receipt_synced);
        assert_eq!(restored.pubkey_hex_synced, Some("ab".repeat(32)));
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
