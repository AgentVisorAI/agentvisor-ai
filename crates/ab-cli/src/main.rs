//! `abctl` operations for keys, receipts, ATIF, Bridge, sessions, and load.

mod setup;

use ab_bridge::{BridgeManifest, EmbeddedBroker, EventBus};
use ab_receipts::{Ed25519Signer, Keyring, Receipt, Signer};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use futures::{stream, StreamExt};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Parser)]
#[command(
    name = "abctl",
    version,
    about = "AgentBridge operations CLI. Run with no arguments for guided setup."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Guided setup: answer two questions, get a working proxy (default).
    Setup,
    /// Start AgentBridge and print where to point your AI app.
    Start,
    /// Create a provider-specific agentbridge.toml (start here).
    Init {
        /// Provider preset.
        #[arg(long, value_enum, default_value_t = setup::Preset::Openai)]
        preset: setup::Preset,
        /// Destination file (the harness finds agentbridge.toml automatically).
        #[arg(long, default_value = "agentbridge.toml")]
        output: PathBuf,
        /// Overwrite an existing file.
        #[arg(long)]
        force: bool,
        /// Override the preset's upstream base URL (required for --preset custom).
        #[arg(long)]
        upstream_url: Option<String>,
        /// Override the environment variable the API key is read from.
        #[arg(long)]
        key_env: Option<String>,
    },
    /// Diagnose the environment: config, keys, upstream, backends.
    Doctor {
        /// Skip network reachability probes.
        #[arg(long)]
        offline: bool,
    },
    /// Probe a running harness /health endpoint (for container healthchecks).
    Health {
        /// Harness base URL.
        #[arg(long, default_value = "http://127.0.0.1:8484")]
        url: String,
    },
    /// Generate and persist an Ed25519 signing seed.
    Keygen {
        /// Destination seed file.
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify a receipt offline using an independently trusted public key.
    ReceiptVerify {
        /// Receipt JSON file.
        path: PathBuf,
        /// Trusted Ed25519 public key as 64 hexadecimal characters.
        #[arg(long)]
        public_key_hex: String,
    },
    /// Validate an ATIF trajectory.
    AtifValidate {
        /// ATIF JSON file.
        path: PathBuf,
        /// Validation mode.
        #[arg(long, value_enum, default_value_t = ValidationMode::Strict)]
        mode: ValidationMode,
    },
    /// Validate a Bridge manifest.
    ManifestValidate {
        /// Manifest YAML file.
        path: PathBuf,
    },
    /// Provision an embedded Bridge from a manifest alone.
    BridgeProvision {
        /// Manifest YAML file.
        #[arg(long)]
        manifest: PathBuf,
        /// Fresh Bridge data directory.
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Tail ordered events from an embedded Bridge partition.
    EventTail {
        /// Bridge data directory.
        #[arg(long)]
        data_dir: PathBuf,
        /// Topic name.
        #[arg(long)]
        topic: String,
        /// Partition index.
        #[arg(long, default_value_t = 0)]
        partition: u32,
        /// Starting offset.
        #[arg(long, default_value_t = 0)]
        offset: u64,
        /// Maximum events to print.
        #[arg(long, default_value_t = 100)]
        max: usize,
    },
    /// Promote an unsigned session through the Harness API.
    SessionPromote {
        /// Harness base URL.
        #[arg(long, default_value = "http://127.0.0.1:8484")]
        url: String,
        /// Session id.
        id: String,
        /// File containing the NHI bearer token (or AB_BEARER_TOKEN_FILE).
        #[arg(long)]
        bearer_token_file: Option<PathBuf>,
    },
    /// Validate a harness TOML configuration.
    ConfigValidate {
        /// Configuration file.
        path: PathBuf,
    },
    /// Generate concurrent OpenAI-compatible chat traffic and report latency.
    Loadgen {
        /// Harness base URL.
        #[arg(long, default_value = "http://127.0.0.1:8484")]
        url: String,
        /// Simultaneous requests. Use 10000 for the deployment SLA.
        #[arg(long, default_value_t = 500)]
        connections: usize,
        /// Signed or unsigned workflow header.
        #[arg(long, default_value = "signed")]
        workflow: String,
        /// File containing the NHI bearer token (or AB_BEARER_TOKEN_FILE).
        #[arg(long)]
        bearer_token_file: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ValidationMode {
    Strict,
    Compat,
}

#[tokio::main]
async fn main() -> Result<()> {
    run(Cli::parse()).await
}

async fn run(cli: Cli) -> Result<()> {
    let Some(command) = cli.command else {
        return wizard_then_maybe_start().await;
    };
    match command {
        Command::Setup => wizard_then_maybe_start().await,
        Command::Start => setup::start().await,
        Command::Init {
            preset,
            output,
            force,
            upstream_url,
            key_env,
        } => setup::init(
            preset,
            &output,
            force,
            upstream_url.as_deref(),
            key_env.as_deref(),
        ),
        Command::Doctor { offline } => setup::doctor(offline).await,
        Command::Health { url } => setup::health(&url).await,
        Command::Keygen { output } => keygen(&output),
        Command::ReceiptVerify { path, public_key_hex } => receipt_verify(&path, &public_key_hex),
        Command::AtifValidate { path, mode } => atif_validate(&path, mode),
        Command::ManifestValidate { path } => manifest_validate(&path),
        Command::BridgeProvision { manifest, data_dir } => bridge_provision(&manifest, &data_dir),
        Command::EventTail {
            data_dir,
            topic,
            partition,
            offset,
            max,
        } => event_tail(&data_dir, &topic, partition, offset, max),
        Command::SessionPromote {
            url,
            id,
            bearer_token_file,
        } => session_promote(&url, &id, bearer_token_file.as_deref()).await,
        Command::ConfigValidate { path } => config_validate(&path),
        Command::Loadgen {
            url,
            connections,
            workflow,
            bearer_token_file,
        } => loadgen(&url, connections, &workflow, bearer_token_file.as_deref()).await,
    }
}

/// The wizard reads answers from stdin; secrets come from the terminal
/// with echo off when interactive, or from the same stream when piped
/// (scripts and tests).
async fn wizard_then_maybe_start() -> Result<()> {
    let outcome = {
        use std::io::IsTerminal as _;
        #[allow(deprecated)] // undeprecated in Rust 1.86; MSRV is 1.88
        let home = std::env::home_dir().context("could not find your home folder")?;
        let stdin = std::io::stdin();
        let secrets = if stdin.is_terminal() {
            setup::SecretInput::Hidden
        } else {
            setup::SecretInput::Plain
        };
        let mut input = stdin.lock();
        setup::wizard(&home, &mut input, &secrets)?
    };
    if outcome.start_now {
        setup::start().await
    } else {
        println!("\nYour settings are saved at {}.", outcome.config_path.display());
        println!("When you're ready: abctl start");
        Ok(())
    }
}

fn keygen(path: &Path) -> Result<()> {
    let signer = Ed25519Signer::generate();
    if !install_seed_exclusive(path, &hex::encode(signer.seed()))? {
        anyhow::bail!("refusing to overwrite existing key {}", path.display());
    }
    println!(
        "{}",
        serde_json::json!({
            "key_id": signer.key_id(),
            "public_key_hex": hex::encode(signer.public_key_bytes()),
            "seed_file": path,
        })
    );
    Ok(())
}

fn install_seed_exclusive(path: &Path, encoded: &str) -> Result<bool> {
    use std::io::Write as _;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).with_context(|| format!("create key directory {}", parent.display()))?;
    let temporary = parent.join(format!(".abctl-key-{}.tmp", ab_core::new_event_uid()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .with_context(|| format!("create key temporary file {}", temporary.display()))?;
    file.write_all(encoded.as_bytes())
        .with_context(|| format!("write key temporary file {}", temporary.display()))?;
    file.sync_all()
        .with_context(|| format!("sync key temporary file {}", temporary.display()))?;
    match std::fs::hard_link(&temporary, path) {
        Ok(()) => {
            std::fs::remove_file(&temporary)
                .with_context(|| format!("remove key temporary file {}", temporary.display()))?;
            ab_core::fsutil::sync_directory(parent)
                .with_context(|| format!("sync key directory {}", parent.display()))?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = std::fs::remove_file(&temporary);
            Ok(false)
        }
        Err(error) => {
            let _ = std::fs::remove_file(&temporary);
            Err(error).with_context(|| format!("install key {}", path.display()))
        }
    }
}

fn receipt_verify(path: &Path, public_key_hex: &str) -> Result<()> {
    let receipt: Receipt = read_json(path)?;
    let public_key: [u8; 32] = hex::decode(public_key_hex)
        .context("trusted public key is not hexadecimal")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("trusted public key must contain exactly 32 bytes"))?;
    let mut keyring = Keyring::new();
    keyring
        .add_key_bytes(&public_key)
        .context("trusted public key is invalid")?;
    receipt.verify(&keyring).context("receipt verification failed")?;
    println!("verified {}", receipt.body.receipt_id);
    Ok(())
}

fn atif_validate(path: &Path, mode: ValidationMode) -> Result<()> {
    let value: Value = read_json(path)?;
    let mode = match mode {
        ValidationMode::Strict => ab_atif::Mode::Strict,
        ValidationMode::Compat => ab_atif::Mode::Compat,
    };
    let issues = ab_atif::validate_value(&value, mode);
    if !issues.is_empty() {
        for issue in &issues {
            eprintln!("{}: {}", issue.path, issue.message);
        }
        anyhow::bail!("ATIF validation failed with {} issue(s)", issues.len());
    }
    println!("valid {}", path.display());
    Ok(())
}

fn manifest_validate(path: &Path) -> Result<()> {
    let yaml = std::fs::read_to_string(path).with_context(|| format!("read manifest {}", path.display()))?;
    let manifest = BridgeManifest::from_yaml(&yaml).map_err(anyhow::Error::new)?;
    println!("valid {} topics={}", manifest.name, manifest.topics.len());
    Ok(())
}

fn bridge_provision(manifest_path: &Path, data_dir: &Path) -> Result<()> {
    let yaml = std::fs::read_to_string(manifest_path)
        .with_context(|| format!("read manifest {}", manifest_path.display()))?;
    let manifest = BridgeManifest::from_yaml(&yaml).map_err(anyhow::Error::new)?;
    let started = Instant::now();
    EmbeddedBroker::provision(data_dir, &manifest).context("provision Bridge")?;
    println!(
        "provisioned {} topics={} elapsed_ms={}",
        manifest.name,
        manifest.topics.len(),
        started.elapsed().as_millis()
    );
    Ok(())
}

fn event_tail(data_dir: &Path, topic: &str, partition: u32, offset: u64, max: usize) -> Result<()> {
    let bridge = EmbeddedBroker::open(data_dir).context("open Bridge")?;
    for event in bridge
        .fetch(topic, partition, offset, max)
        .context("fetch events")?
    {
        println!("{}", serde_json::to_string(&event)?);
    }
    Ok(())
}

async fn session_promote(base_url: &str, id: &str, token_file: Option<&Path>) -> Result<()> {
    let url = format!("{}/v1/sessions/{}/promote", base_url.trim_end_matches('/'), id);
    let token = bearer_token(token_file)?;
    // Every other CLI probe bounds its wait (see `doctor` and `probe_endpoint`
    // at 3 s); without an explicit timeout, a hung harness leaves this call
    // waiting forever.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .connect_timeout(std::time::Duration::from_secs(5))
        .build()
        .context("build promotion client")?;
    let mut request = client.post(url);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    let response = request.send().await.context("promote session")?;
    let status = response.status();
    let body = response.text().await.context("read promotion response")?;
    if !status.is_success() {
        anyhow::bail!("promotion failed ({status}): {body}");
    }
    println!("{body}");
    Ok(())
}

fn config_validate(path: &Path) -> Result<()> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read config {}", path.display()))?;
    let config = ab_harness::HarnessConfig::from_toml(&text).map_err(anyhow::Error::msg)?;
    println!(
        "valid config_version={} listen={}",
        config.config_version, config.listen
    );
    Ok(())
}

async fn loadgen(
    base_url: &str,
    connections: usize,
    workflow: &str,
    token_file: Option<&Path>,
) -> Result<()> {
    if connections == 0 {
        anyhow::bail!("connections must be greater than zero");
    }
    // Cap the requested concurrency: at multi-hundred-thousand
    // connections the loadgen exhausts source ports / FDs / RAM on the
    // operator's own host before any latency numbers land, and the load
    // *test* becomes the very thing it was supposed to measure. 10k is
    // the stated SLA gate (round-11 F6) — the previous 100k cap
    // encouraged runs that a single host cannot sustain: default Linux
    // `net.ipv4.ip_local_port_range` (~28k) exhausts before hyper can
    // dial, and `RLIMIT_NOFILE` (1024–65536) trips producing thousands
    // of `Address not available` failures that look like the harness
    // is broken.
    const MAX_CONNECTIONS: usize = 10_000;
    if connections > MAX_CONNECTIONS {
        anyhow::bail!(
            "connections must be <= {MAX_CONNECTIONS} — larger values \
             exhaust source ports / FDs before producing usable results"
        );
    }
    if ab_harness::session::Workflow::parse(workflow).is_none() {
        anyhow::bail!("workflow must be signed or unsigned");
    }
    // A hung upstream must not turn `loadgen --connections 10000` into an
    // unbounded resource consumer that never fails — the load *test* would
    // otherwise mask the failure it is supposed to expose. Per-request
    // timeout bounds each in-flight probe; connect_timeout catches
    // upstream unreachable faster than TCP retransmit does. Idle pool
    // capped at 1024 — more than that is never useful and just wastes
    // FDs after the burst ends.
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(connections.min(1024))
        .timeout(std::time::Duration::from_secs(30))
        .connect_timeout(std::time::Duration::from_secs(5))
        .build()
        .context("build loadgen client")?;
    let url = format!("{}/v1/chat/completions", base_url.trim_end_matches('/'));
    let token = bearer_token(token_file)?.map(Arc::<str>::from);
    // Unique per run: reusing ids like `load-0` across runs would bind to
    // sessions a previous run left behind — sealed ones refuse reuse with
    // 400 "session is already closed".
    let run_id = ab_core::new_event_uid();
    let started = Instant::now();
    let results: Vec<Result<u64, String>> = stream::iter(0..connections)
        .map(|index| {
            let client = client.clone();
            let url = url.clone();
            let workflow = workflow.to_owned();
            let token = token.clone();
            let run_id = run_id.clone();
            async move {
                let request_started = Instant::now();
                let mut request = client
                    .post(url)
                    .header("x-ab-session", format!("load-{run_id}-{index}"))
                    .header("x-ab-workflow", workflow)
                    .json(&serde_json::json!({
                        "model": "loadgen",
                        "stream": true,
                        "messages": [{"role": "user", "content": "health check"}],
                    }));
                if let Some(token) = token {
                    request = request.bearer_auth(token);
                }
                let response = request.send().await.map_err(|error| error.to_string())?;
                let status = response.status();
                let _ = response.bytes().await.map_err(|error| error.to_string())?;
                if !status.is_success() {
                    return Err(format!("HTTP {status}"));
                }
                Ok(u64::try_from(request_started.elapsed().as_micros()).unwrap_or(u64::MAX))
            }
        })
        .buffer_unordered(connections)
        .collect()
        .await;
    let mut latencies = Vec::with_capacity(connections);
    let mut failures = Vec::new();
    for result in results {
        match result {
            Ok(latency) => latencies.push(latency),
            Err(error) => failures.push(error),
        }
    }
    latencies.sort_unstable();
    println!(
        "connections={} success={} failed={} wall_ms={} p50_us={} p95_us={} p99_us={}",
        connections,
        latencies.len(),
        failures.len(),
        started.elapsed().as_millis(),
        percentile(&latencies, 50),
        percentile(&latencies, 95),
        percentile(&latencies, 99),
    );
    if !failures.is_empty() {
        anyhow::bail!(
            "{} load requests failed; first: {}",
            failures.len(),
            failures.first().map(String::as_str).unwrap_or("unknown")
        );
    }
    Ok(())
}

fn bearer_token(path: Option<&Path>) -> Result<Option<String>> {
    let path = path
        .map(Path::to_path_buf)
        .or_else(|| std::env::var_os("AB_BEARER_TOKEN_FILE").map(PathBuf::from));
    path.map(|path| {
        let token = std::fs::read_to_string(&path)
            .with_context(|| format!("read bearer token {}", path.display()))?;
        let token = token.trim().to_owned();
        if token.is_empty() {
            anyhow::bail!("bearer token file {} is empty", path.display());
        }
        Ok(token)
    })
    .transpose()
}

fn percentile(sorted: &[u64], percentile: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let index = sorted.len().saturating_mul(percentile).saturating_add(99) / 100;
    sorted.get(index.saturating_sub(1)).copied().unwrap_or(0)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse JSON {}", path.display()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn cli_covers_required_commands() {
        for args in [
            vec!["abctl", "init", "--preset", "ollama"],
            vec!["abctl", "doctor", "--offline"],
            vec!["abctl", "health"],
            vec!["abctl", "keygen", "--output", "key.seed"],
            vec![
                "abctl",
                "receipt-verify",
                "receipt.json",
                "--public-key-hex",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ],
            vec!["abctl", "atif-validate", "trajectory.json"],
            vec!["abctl", "manifest-validate", "bridge.yaml"],
            vec!["abctl", "config-validate", "harness.toml"],
            vec!["abctl", "loadgen", "--connections", "10000"],
        ] {
            Cli::try_parse_from(args).unwrap();
        }
    }

    #[test]
    fn percentile_uses_nearest_rank() {
        let values: Vec<u64> = (1..=100).collect();
        assert_eq!(percentile(&values, 50), 50);
        assert_eq!(percentile(&values, 95), 95);
        assert_eq!(percentile(&values, 99), 99);
        assert_eq!(percentile(&[], 99), 0);
    }
}
