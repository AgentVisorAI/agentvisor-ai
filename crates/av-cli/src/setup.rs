//! `avctl init` / `avctl doctor` / `avctl health` — first-run setup and
//! environment diagnosis.
//!
//! `init` writes a provider-specific `agentvisor.toml` that the harness
//! picks up automatically (it is first in the config search path), then
//! prints copy-paste next steps. `doctor` re-resolves configuration the
//! exact same way the server does and checks every runtime prerequisite
//! without printing a single secret value. `health` probes a running
//! harness and is intended for container HEALTHCHECK directives.

use anyhow::{Context, Result};
use clap::ValueEnum;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Supported provider presets for `avctl init`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Preset {
    /// OpenAI (api.openai.com).
    Openai,
    /// Azure OpenAI (custom deployment path + `api-key` header).
    Azure,
    /// Anthropic's OpenAI-compatible endpoint (api.anthropic.com).
    Anthropic,
    /// Google Gemini's OpenAI-compatible endpoint.
    Gemini,
    /// Groq (api.groq.com/openai).
    Groq,
    /// Mistral (api.mistral.ai).
    Mistral,
    /// OpenRouter (openrouter.ai/api).
    Openrouter,
    /// Together AI (api.together.xyz).
    Together,
    /// DeepSeek (api.deepseek.com).
    Deepseek,
    /// xAI Grok (api.x.ai).
    Xai,
    /// Local Ollama (127.0.0.1:11434, no key).
    Ollama,
    /// Local LM Studio (127.0.0.1:1234, no key).
    Lmstudio,
    /// Local vLLM OpenAI server (127.0.0.1:8000, no key).
    Vllm,
    /// Local llama.cpp server (127.0.0.1:8080, no key).
    Llamacpp,
    /// LiteLLM gateway (127.0.0.1:4000).
    Litellm,
    /// Custom endpoint: supply --upstream-url yourself.
    Custom,
}

struct PresetSpec {
    upstream_url: &'static str,
    chat_path: Option<&'static str>,
    key_env: Option<&'static str>,
    auth_header: Option<&'static str>,
    /// `Some("")` means "raw key, no scheme prefix".
    auth_scheme: Option<&'static str>,
    notes: &'static [&'static str],
}

fn spec(preset: Preset) -> PresetSpec {
    let plain = |url, env| PresetSpec {
        upstream_url: url,
        chat_path: None,
        key_env: env,
        auth_header: None,
        auth_scheme: None,
        notes: &[],
    };
    match preset {
        Preset::Openai => plain("https://api.openai.com", Some("OPENAI_API_KEY")),
        Preset::Azure => PresetSpec {
            upstream_url: "https://YOUR-RESOURCE.openai.azure.com",
            chat_path: Some("/openai/deployments/YOUR-DEPLOYMENT/chat/completions?api-version=2024-10-21"),
            key_env: Some("AZURE_OPENAI_API_KEY"),
            auth_header: Some("api-key"),
            auth_scheme: Some(""),
            notes: &[
                "Replace YOUR-RESOURCE with your Azure OpenAI resource name.",
                "Replace YOUR-DEPLOYMENT with your model deployment name.",
            ],
        },
        Preset::Anthropic => plain("https://api.anthropic.com", Some("ANTHROPIC_API_KEY")),
        Preset::Gemini => PresetSpec {
            upstream_url: "https://generativelanguage.googleapis.com/v1beta/openai",
            chat_path: Some("/chat/completions"),
            key_env: Some("GEMINI_API_KEY"),
            auth_header: None,
            auth_scheme: None,
            notes: &[],
        },
        Preset::Groq => plain("https://api.groq.com/openai", Some("GROQ_API_KEY")),
        Preset::Mistral => plain("https://api.mistral.ai", Some("MISTRAL_API_KEY")),
        Preset::Openrouter => plain("https://openrouter.ai/api", Some("OPENROUTER_API_KEY")),
        Preset::Together => plain("https://api.together.xyz", Some("TOGETHER_API_KEY")),
        Preset::Deepseek => plain("https://api.deepseek.com", Some("DEEPSEEK_API_KEY")),
        Preset::Xai => plain("https://api.x.ai", Some("XAI_API_KEY")),
        Preset::Ollama => plain("http://127.0.0.1:11434", None),
        Preset::Lmstudio => plain("http://127.0.0.1:1234", None),
        Preset::Vllm => plain("http://127.0.0.1:8000", None),
        Preset::Llamacpp => plain("http://127.0.0.1:8080", None),
        Preset::Litellm => plain("http://127.0.0.1:4000", Some("LITELLM_MASTER_KEY")),
        Preset::Custom => PresetSpec {
            upstream_url: "",
            chat_path: None,
            key_env: None,
            auth_header: None,
            auth_scheme: None,
            notes: &["Pass --key-env NAME if the endpoint needs an API key."],
        },
    }
}

/// Where the generated config reads the provider API key from.
enum KeySpec {
    /// `upstream_api_key_env = "NAME"` — key exported by the user.
    Env(String),
    /// `upstream_api_key_file = "PATH"` — key stored by the wizard (0600).
    File(String),
    /// Endpoint needs no key (local runtimes).
    NoKey,
}

/// Everything that ends up interpolated into the generated TOML.
struct ConfigPlan {
    preset: Preset,
    upstream_url: String,
    /// `None` uses the preset's default chat path.
    chat_path: Option<String>,
    key: KeySpec,
    /// `None` keeps the relative `data/` layout; the wizard passes an
    /// absolute per-user directory so data never scatters across cwds.
    data_root: Option<String>,
}

/// Why a candidate upstream URL cannot be accepted, if anything.
/// (Also guards the TOML interpolation: quote/backslash/control are out.)
fn upstream_url_error(url: &str) -> Option<&'static str> {
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Some("must start with http:// or https://");
    }
    if url
        .chars()
        .any(|c| c == '"' || c == '\\' || c.is_control() || c == ' ')
    {
        return Some("contains characters not allowed in a URL");
    }
    None
}

/// Reject values that could escape a TOML string literal.
fn assert_toml_safe(label: &str, value: &str) -> Result<()> {
    if value.chars().any(|c| c == '"' || c == '\\' || c.is_control()) {
        anyhow::bail!("{label} contains characters that cannot be stored in the config file");
    }
    Ok(())
}

/// Split a pasted upstream URL that already embeds a chat-completions path.
///
/// The harness joins `upstream_url` + `upstream_chat_path`, so storing a full
/// endpoint URL (which "paste your endpoint" naturally invites) would produce
/// `/v1/chat/completions/v1/chat/completions` and a confusing provider 404.
/// Returns `(base_url, chat_path_override)`; the override is `None` when the
/// embedded path is exactly the default that the harness appends anyway.
fn split_embedded_chat_path(url: String) -> (String, Option<String>) {
    const DEFAULT_CHAT_PATH: &str = "/v1/chat/completions";
    let path_start = match url.find("://").and_then(|scheme| {
        let host = scheme + 3;
        url[host..].find('/').map(|slash| host + slash)
    }) {
        Some(index) => index,
        None => return (url, None),
    };
    let path = &url[path_start..];
    let embeds_chat = path.ends_with("/chat/completions") || path.contains("/chat/completions?");
    if !embeds_chat {
        return (url, None);
    }
    let base = url[..path_start].to_owned();
    if path == DEFAULT_CHAT_PATH {
        return (base, None);
    }
    let path = path.to_owned();
    (base, Some(path))
}

/// Render the annotated TOML for a plan.
fn render_config(plan: &ConfigPlan) -> String {
    let spec = spec(plan.preset);
    let chat_path = plan.chat_path.as_deref().or(spec.chat_path);
    let upstream_url = &plan.upstream_url;
    let mut out = String::new();
    out.push_str("# AgentVisor AI harness configuration (generated by `avctl init`).\n");
    out.push_str("# Every omitted field keeps a safe default; see config/harness.example.toml\n");
    out.push_str("# in the AgentVisor AI repository for the full annotated reference.\n\n");
    out.push_str("config_version = 1\n\n");
    out.push_str("# Address the proxy listens on. Use \"0.0.0.0:8484\" inside containers.\n");
    out.push_str("listen = \"127.0.0.1:8484\"\n\n");
    out.push_str("# OpenAI-compatible provider base URL.\n");
    out.push_str(&format!("upstream_url = \"{upstream_url}\"\n"));
    if let Some(path) = chat_path {
        out.push_str("# Provider-specific chat completions path.\n");
        out.push_str(&format!("upstream_chat_path = \"{path}\"\n"));
    }
    match &plan.key {
        KeySpec::Env(env) => {
            out.push_str("\n# API key is read from this environment variable at startup.\n");
            out.push_str("# (Alternative: upstream_api_key_file = \"/path/to/key\" with mode 0600.)\n");
            out.push_str(&format!("upstream_api_key_env = \"{env}\"\n"));
        }
        KeySpec::File(path) => {
            out.push_str("\n# API key is read from this file at startup. Keep it private:\n");
            out.push_str("# the server refuses group- or world-readable key files.\n");
            out.push_str(&format!("upstream_api_key_file = \"{path}\"\n"));
        }
        KeySpec::NoKey => {
            out.push_str("\n# No API key needed for this endpoint. To add one later:\n");
            out.push_str("#   upstream_api_key_env = \"PROVIDER_API_KEY\"\n");
        }
    }
    if let Some(header) = spec.auth_header {
        out.push_str(&format!("upstream_auth_header = \"{header}\"\n"));
    }
    if let Some(scheme) = spec.auth_scheme {
        out.push_str("# Empty scheme sends the key raw (no \"Bearer \" prefix).\n");
        out.push_str(&format!("upstream_auth_scheme = \"{scheme}\"\n"));
    }
    out.push_str("\n# OpenAI SDKs require an api_key and always send an Authorization header.\n");
    out.push_str("# This dev-mode flag accepts and DISCARDS that header (it is never\n");
    out.push_str("# forwarded upstream; the key above is injected instead), so the\n");
    out.push_str("# one-line quickstart works with any stock SDK. Remove it when you\n");
    out.push_str("# turn on require_identity.\n");
    out.push_str("ignore_client_authorization = true\n\n");
    out.push_str("# Sign every session close with an Ed25519 receipt (the product's\n");
    out.push_str("# core promise). \"unsigned\" produces ATIF trajectories without\n");
    out.push_str("# signatures; clients can override per request via X-AV-Workflow.\n");
    out.push_str("default_workflow = \"signed\"\n");
    out.push_str("\n# Signed receipts, OCSF events, and ATIF trajectories are written here.\n");
    match &plan.data_root {
        Some(root) => {
            // These paths mirror the harness `default_spool` / `default_bridge`
            // shapes (see crates/av-harness/src/config.rs) so that removing a
            // key from the generated config leaves the runtime pointing at the
            // same directory the generated config named. Diverging silently
            // relocates the spool the moment an operator edits the file.
            out.push_str(&format!("atif_spool_dir = \"{root}/spool/atif\"\n"));
            out.push_str(&format!("bridge_data_dir = \"{root}/data/bridge\"\n"));
        }
        None => {
            out.push_str("atif_spool_dir = \"spool/atif\"\n");
            out.push_str("bridge_data_dir = \"data/bridge\"\n");
        }
    }
    out
}

/// `avctl init` — write a provider-specific config and print next steps.
pub fn init(
    preset: Preset,
    output: &Path,
    force: bool,
    upstream_url: Option<&str>,
    key_env: Option<&str>,
) -> Result<()> {
    let spec_defaults = spec(preset);
    let upstream_url = match (upstream_url, spec_defaults.upstream_url) {
        (Some(url), _) => url.to_owned(),
        (None, "") => anyhow::bail!("--preset custom requires --upstream-url"),
        (None, default) => default.to_owned(),
    };
    // The values are interpolated into TOML below: reject anything that
    // could escape the string literal (quote, backslash, control bytes)
    // instead of silently writing a config that means something else.
    if let Some(reason) = upstream_url_error(&upstream_url) {
        anyhow::bail!("--upstream-url {reason}");
    }
    let key_env = key_env
        .map(str::to_owned)
        .or_else(|| spec_defaults.key_env.map(str::to_owned));
    if let Some(env) = &key_env {
        let valid = !env.is_empty()
            && !env.starts_with(|c: char| c.is_ascii_digit())
            && env.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid {
            anyhow::bail!("--key-env must be a valid environment variable name, got {env:?}");
        }
    }
    let plan = ConfigPlan {
        preset,
        upstream_url,
        chat_path: None,
        key: match &key_env {
            Some(env) => KeySpec::Env(env.clone()),
            None => KeySpec::NoKey,
        },
        data_root: None,
    };
    // Same footgun as the wizard: a full endpoint URL passed via
    // --upstream-url would double the chat path once the harness joins them.
    let (upstream_url, chat_path) = split_embedded_chat_path(plan.upstream_url);
    let plan = ConfigPlan {
        upstream_url,
        chat_path: chat_path.or(plan.chat_path),
        ..plan
    };
    let rendered = render_config(&plan);
    // Refuse to write anything the harness itself would reject.
    av_harness::HarnessConfig::from_toml(&rendered)
        .map_err(|error| anyhow::anyhow!("generated config failed validation (bug): {error}"))?;
    if output.exists() && !force {
        anyhow::bail!("{} already exists; pass --force to overwrite", output.display());
    }
    // Round-15 F2: refuse to follow a pre-planted symlink at
    // `output`. The wizard path is protected by `write_atomic`'s
    // rename-over semantics
    // (see `wizard_replaces_config_symlink_instead_of_following_it`);
    // `init --force` used to differ, so an attacker who could plant
    // ~/.agentvisor/agentvisor.toml as a symlink to
    // ~/.bashrc or /etc/nginx/conf.d/upstream.conf could redirect
    // the TOML write into the target when the operator ran
    // `avctl init --force`. Unlink the symlink first so the
    // subsequent std::fs::write hits a fresh regular file at
    // `output`.
    if let Ok(metadata) = std::fs::symlink_metadata(output) {
        if metadata.file_type().is_symlink() {
            std::fs::remove_file(output)
                .with_context(|| format!("remove pre-existing symlink at {}", output.display()))?;
        }
    }
    if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).with_context(|| format!("create directory {}", parent.display()))?;
    }
    // Round-51 §3.5: `std::fs::write` after the symlink check above was
    // a TOCTOU — an attacker replanting the symlink in the
    // check→write window redirected the TOML into the target (and
    // created it 0666&~umask before the post-hoc chmod).
    // `write_atomic`'s rename-over semantics replace the link ITSELF
    // rather than following it, closing the race the same way the
    // wizard path does.
    av_core::fsutil::write_atomic(output, rendered.as_bytes())
        .with_context(|| format!("write {}", output.display()))?;
    // Round-43 F3: match the key-file installer
    // (`write_private_key_file`) which explicitly opens with
    // mode(0o600). The rendered config carries
    // upstream_url / upstream_api_key_env / upstream_auth_header hints
    // — capability-sensitive metadata that a co-tenant on a shared
    // workstation could otherwise read via the default umask=022
    // world-readable bits. Silently no-op on non-Unix (Windows ACLs
    // are inherited from the parent dir and 0o600 has no analog).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if let Err(error) = std::fs::set_permissions(output, std::fs::Permissions::from_mode(0o600)) {
            eprintln!(
                "warning: failed to chmod 0600 on {}: {error}; contents may be world-readable",
                output.display(),
            );
        }
    }
    println!("wrote {}", output.display());
    for note in spec_defaults.notes {
        println!("note: {note}");
    }
    println!();
    println!("Next steps:");
    let mut step = 1;
    if let Some(env) = &key_env {
        println!("  {step}. export {env}=<your api key>");
        step += 1;
    }
    if preset == Preset::Azure {
        println!(
            "  {step}. edit {} and fill in your resource + deployment",
            output.display()
        );
        step += 1;
    }
    println!("  {step}. agentvisord       # starts on 127.0.0.1:8484");
    step += 1;
    println!("  {step}. point your OpenAI-compatible client at http://127.0.0.1:8484/v1");
    println!();
    println!("Check the environment any time with: avctl doctor");
    Ok(())
}

// ---------------------------------------------------------------------------
// Guided setup (bare `avctl`) and `avctl start` — the no-experience path.
// ---------------------------------------------------------------------------

/// How the wizard reads pasted secrets.
pub enum SecretInput {
    /// Read from the terminal with echo disabled (interactive use).
    Hidden,
    /// Read a plain line from the same input stream (pipes and tests).
    Plain,
}

/// What the wizard produced and whether the user asked to start now.
#[derive(Debug)]
pub struct WizardOutcome {
    pub config_path: PathBuf,
    pub start_now: bool,
}

/// Provider menu in plain language, most common first. Power-user presets
/// (vllm, llamacpp, litellm) stay available through `avctl init`.
const WIZARD_MENU: [(&str, Preset); 13] = [
    ("OpenAI (GPT models)", Preset::Openai),
    ("Anthropic (Claude)", Preset::Anthropic),
    ("Google (Gemini)", Preset::Gemini),
    ("Azure OpenAI", Preset::Azure),
    ("Groq", Preset::Groq),
    ("Mistral", Preset::Mistral),
    ("OpenRouter", Preset::Openrouter),
    ("Together AI", Preset::Together),
    ("DeepSeek", Preset::Deepseek),
    ("xAI (Grok)", Preset::Xai),
    ("Ollama on this computer (free, no key needed)", Preset::Ollama),
    (
        "LM Studio on this computer (free, no key needed)",
        Preset::Lmstudio,
    ),
    ("Somewhere else (I have a URL)", Preset::Custom),
];

fn slug(preset: Preset) -> &'static str {
    match preset {
        Preset::Openai => "openai",
        Preset::Azure => "azure",
        Preset::Anthropic => "anthropic",
        Preset::Gemini => "gemini",
        Preset::Groq => "groq",
        Preset::Mistral => "mistral",
        Preset::Openrouter => "openrouter",
        Preset::Together => "together",
        Preset::Deepseek => "deepseek",
        Preset::Xai => "xai",
        Preset::Ollama => "ollama",
        Preset::Lmstudio => "lmstudio",
        Preset::Vllm => "vllm",
        Preset::Llamacpp => "llamacpp",
        Preset::Litellm => "litellm",
        Preset::Custom => "custom",
    }
}

fn friendly_name(preset: Preset) -> &'static str {
    match preset {
        Preset::Openai => "OpenAI",
        Preset::Azure => "Azure OpenAI",
        Preset::Anthropic => "Anthropic",
        Preset::Gemini => "Google Gemini",
        Preset::Groq => "Groq",
        Preset::Mistral => "Mistral",
        Preset::Openrouter => "OpenRouter",
        Preset::Together => "Together AI",
        Preset::Deepseek => "DeepSeek",
        Preset::Xai => "xAI",
        Preset::Ollama => "Ollama",
        Preset::Lmstudio => "LM Studio",
        Preset::Vllm => "vLLM",
        Preset::Llamacpp => "llama.cpp",
        Preset::Litellm => "LiteLLM",
        Preset::Custom => "endpoint",
    }
}

/// Print a prompt and read one trimmed line; EOF is a hard error so a
/// closed pipe can never spin the ask-again loops.
fn ask_line(prompt: &str, input: &mut dyn std::io::BufRead) -> Result<String> {
    use std::io::Write as _;
    print!("{prompt}");
    std::io::stdout().flush().context("flush prompt")?;
    let mut line = String::new();
    if input.read_line(&mut line).context("read answer")? == 0 {
        anyhow::bail!("setup input ended unexpectedly");
    }
    Ok(line.trim().to_owned())
}

/// Round-39 F1: read one line into a `Zeroizing<String>` from the
/// very first allocation, so the pasted secret + trailing `\n` are
/// zeroed on drop. `ask_line` above stores the line in a plain
/// `String` and returns a fresh `.trim().to_owned()` — both the
/// original buffer and the trimmed copy sit un-zeroed in the
/// allocator when the piped-stdin (non-TTY) Plain path fed the
/// wizard a real API key. Round-38 F2 wrapped only the outer
/// return; this closes the intermediate copies. The caller trims
/// via `line.trim()` (a `&str` borrow into the Zeroizing buffer),
/// so no additional un-zeroed intermediate is created.
fn ask_secret_line(prompt: &str, input: &mut dyn std::io::BufRead) -> Result<zeroize::Zeroizing<String>> {
    use std::io::Write as _;
    print!("{prompt}");
    std::io::stdout().flush().context("flush prompt")?;
    let mut line = zeroize::Zeroizing::new(String::new());
    if input.read_line(&mut line).context("read answer")? == 0 {
        anyhow::bail!("setup input ended unexpectedly");
    }
    Ok(line)
}

/// Round-38 F2 + round-39 F1: `Zeroizing<String>` end-to-end so
/// every intermediate copy of the pasted secret zeroes its heap
/// allocation on drop.
///
/// * Hidden (TTY) branch: `rpassword::prompt_password` returns a
///   plain `String`; wrap it immediately at the boundary so the
///   raw allocation never outlives this function.
/// * Plain (non-TTY / piped stdin) branch: use `ask_secret_line`
///   which allocates the line buffer INSIDE `Zeroizing` from the
///   start. `ask_line` (used for non-secret prompts) still returns
///   plain `String` — cheaper, but MUST NOT be reached from
///   secret-carrying paths. Rejected retries in the caller's loop
///   then drop-zero the previous attempt's buffer as well.
///
/// Residual: `StdinLock`'s internal `BufReader` buffer is outside
/// our control (std/kernel-owned); we cannot zero that copy. All
/// intermediates we ourselves allocate are zeroed.
fn ask_secret(
    prompt: &str,
    input: &mut dyn std::io::BufRead,
    mode: &SecretInput,
) -> Result<zeroize::Zeroizing<String>> {
    match mode {
        SecretInput::Hidden => {
            let raw =
                rpassword::prompt_password(format!("{prompt} (typing is hidden): ")).context("read key")?;
            Ok(zeroize::Zeroizing::new(raw))
        }
        SecretInput::Plain => ask_secret_line(&format!("{prompt}: "), input),
    }
}

fn ask_yes_no(prompt: &str, input: &mut dyn std::io::BufRead, default: bool) -> Result<bool> {
    for _ in 0..5 {
        let answer = ask_line(prompt, input)?.to_ascii_lowercase();
        match answer.as_str() {
            "" => return Ok(default),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("Please answer y or n."),
        }
    }
    anyhow::bail!("no valid answer given");
}

/// Ask until `error_for` accepts the answer (or five attempts pass).
fn ask_validated(
    prompt: &str,
    input: &mut dyn std::io::BufRead,
    error_for: impl Fn(&str) -> Option<String>,
) -> Result<String> {
    for _ in 0..5 {
        let answer = ask_line(prompt, input)?;
        match error_for(&answer) {
            None => return Ok(answer),
            Some(reason) => println!("{reason}"),
        }
    }
    anyhow::bail!("no valid answer given");
}

/// Azure resource/deployment names: URL- and TOML-safe by construction.
fn azure_name_error(value: &str) -> Option<String> {
    if value.is_empty() {
        return Some("The name cannot be empty — it is shown in your Azure portal.".to_owned());
    }
    if value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        None
    } else {
        Some("Use only letters, numbers, dots, dashes, and underscores.".to_owned())
    }
}

/// Write `key` to `path` with owner-only permissions, replacing any
/// previous file (including a symlink, which the server would refuse).
///
/// Atomic install (tmp file + hard-link + parent sync) so a crash between
/// remove and sync cannot leave the final path empty or truncated. Same
/// posture as the server's signing-seed installer in av-harness/main.rs.
fn write_private_key_file(path: &Path, key: &str) -> Result<()> {
    use std::io::Write as _;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).with_context(|| format!("create key directory {}", parent.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }
    let temporary = parent.join(format!(".agentvisor-key-{}.tmp", av_core::new_event_uid()));
    // Round-13: sibling of round-12 F4 (harness `install_seed_exclusive`).
    // Without the RAII guard, an early `?` return from write_all /
    // sync_all leaves a zero-byte `.agentvisor-key-*.tmp` behind
    // that only cargoes up on next boot as a confused operator
    // symptom ("two key files?"). Use the shared TempPathGuard so
    // every failure path unlinks.
    let mut guard = av_core::fsutil::TempPathGuard::new(temporary.clone());
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .with_context(|| format!("create key file {}", temporary.display()))?;
    file.write_all(key.as_bytes())
        .with_context(|| format!("write key file {}", temporary.display()))?;
    file.sync_all()
        .with_context(|| format!("sync key file {}", temporary.display()))?;
    // Only unlink the previous key once the replacement is durably on
    // disk. Removing it before the temp write (the old order) meant a
    // write/sync failure — ENOSPC, EIO — destroyed the only copy of the
    // existing key with nothing to install in its place. The old file may
    // be a symlink; unlink it so hard_link below fails cleanly on a
    // pre-planted target rather than following the link and overwriting
    // whatever it points at.
    let _ = std::fs::remove_file(path);
    // hard_link installs the final path atomically and refuses to follow a
    // pre-existing symlink at `path`; none exists at this point because
    // we removed it above.
    let result =
        std::fs::hard_link(&temporary, path).with_context(|| format!("install key file {}", path.display()));
    // The hard_link created a second inode name for the tmp file;
    // unlink the tmp name (the final path keeps the data). Guard is
    // then disarmed so its Drop is a no-op — we already unlinked.
    let _ = std::fs::remove_file(&temporary);
    guard.disarm();
    result?;
    // Round-14 F4: mirror of round-13 F4 (harness install_seed_
    // exclusive) and round-12 F5 (fsutil::write_atomic). Once
    // hard_link commits, the key IS at `path` — a subsequent
    // sync_directory failure means the dirent may not survive an
    // immediate power loss, but every observer running now sees the
    // key. Returning Err here made `avctl init` report failure; the
    // operator re-runs, the `remove_file` at the top of this function
    // unlinks the good key, and the whole install cycle retries.
    // Downgrade to warn+Ok so this last-stanza fsync is best-effort.
    if let Err(error) = av_core::fsutil::sync_directory(parent) {
        eprintln!(
            "warning: key installed at {}, but parent directory fsync failed: {error}; \
             dirent may not survive an immediate power loss",
            parent.display()
        );
    }
    Ok(())
}

/// Convert a path for TOML interpolation, refusing the rare hostile cases.
fn path_for_config(label: &str, path: &Path) -> Result<String> {
    let text = path
        .to_str()
        .with_context(|| format!("{label} is not valid UTF-8"))?;
    assert_toml_safe(label, text)?;
    Ok(text.to_owned())
}

/// A relative home (odd `$HOME`) would bake relative key/data paths into
/// the config, which silently break as soon as the server runs from a
/// different directory. Anchor everything to an absolute path up front.
fn absolute_home(home: &Path) -> Result<PathBuf> {
    if home.is_absolute() {
        return Ok(home.to_path_buf());
    }
    Ok(std::env::current_dir()
        .context("resolve current directory")?
        .join(home))
}

/// The guided setup: a few quick prompts (provider, key, start-now),
/// everything stored
/// under `home/.agentvisor/` so no environment variables, exports, or
/// file editing are ever needed. Drive `input` with scripted answers and
/// `SecretInput::Plain` in tests.
pub fn wizard(home: &Path, input: &mut dyn std::io::BufRead, secrets: &SecretInput) -> Result<WizardOutcome> {
    let home = absolute_home(home)?;
    let home = home.as_path();
    println!("Welcome to AgentVisor AI! A couple of quick questions and you're done.");
    println!();
    println!("Where do your AI models come from?");
    println!();
    for (index, (label, _)) in WIZARD_MENU.iter().enumerate() {
        println!("  {:>2}) {label}", index + 1);
    }
    let mut preset = None;
    for _ in 0..5 {
        let answer = ask_line("\nType a number and press Enter [1]: ", input)?;
        if answer.is_empty() {
            preset = WIZARD_MENU.first().map(|entry| entry.1);
            break;
        }
        if let Ok(choice) = answer.parse::<usize>() {
            if let Some(entry) = choice.checked_sub(1).and_then(|index| WIZARD_MENU.get(index)) {
                preset = Some(entry.1);
                break;
            }
        }
        println!("Please type a number between 1 and {}.", WIZARD_MENU.len());
    }
    let Some(preset) = preset else {
        anyhow::bail!("no valid choice made");
    };

    // Provider-specific follow-ups.
    let (upstream_url, chat_path, needs_key) = match preset {
        Preset::Azure => {
            println!("\nFrom your Azure OpenAI resource (shown in the Azure portal):");
            let resource = ask_validated("  Resource name: ", input, azure_name_error)?;
            let deployment = ask_validated("  Deployment name: ", input, azure_name_error)?;
            (
                format!("https://{resource}.openai.azure.com"),
                Some(format!(
                    "/openai/deployments/{deployment}/chat/completions?api-version=2024-10-21"
                )),
                true,
            )
        }
        Preset::Custom => {
            let url = ask_validated(
                "\nFull URL of your OpenAI-compatible endpoint (e.g. http://10.0.0.5:8000): ",
                input,
                |value| upstream_url_error(value).map(|reason| format!("That URL {reason}.")),
            )?;
            let needs_key = ask_yes_no("Does it need an API key? [y/N]: ", input, false)?;
            // Pasting the complete endpoint URL must work: split any embedded
            // chat path so base + upstream_chat_path join back to what was
            // pasted instead of doubling the path.
            let (url, chat_path) = split_embedded_chat_path(url);
            (url, chat_path, needs_key)
        }
        other => {
            let spec = spec(other);
            (
                spec.upstream_url.to_owned(),
                spec.chat_path.map(str::to_owned),
                spec.key_env.is_some(),
            )
        }
    };
    if let Some(reason) = upstream_url_error(&upstream_url) {
        anyhow::bail!("upstream URL {reason}");
    }

    // Key: pasted once, stored privately — no export step, ever.
    let root = home.join(".agentvisor");
    std::fs::create_dir_all(&root)
        .with_context(|| format!("create settings directory {}", root.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700));
    }
    let key_file = if needs_key {
        let name = friendly_name(preset);
        // Round-38 F2: `key` holds the accepted secret wrapped in
        // Zeroizing so the heap allocation is zeroed on drop. Each
        // failed retry's `pasted` binding drops-zeros before the
        // next iteration reaches the reader.
        let mut key: Option<zeroize::Zeroizing<String>> = None;
        for _ in 0..5 {
            let pasted = ask_secret(&format!("\nPaste your {name} API key"), input, secrets)?;
            // `pasted.trim()` returns a &str borrowed from the
            // zeroing buffer; we validate against the borrow and
            // only take ownership of a zeroing copy after all
            // checks pass, so a rejected paste never spawns a
            // second un-zeroed String on the heap.
            let trimmed = pasted.trim();
            if trimmed.is_empty() {
                println!("The key looked empty — please paste it again.");
                continue;
            }
            if trimmed.chars().any(char::is_control) {
                println!("That key contains characters that don't belong — please try again.");
                continue;
            }
            // Real API keys are plain ASCII; anything else (emoji, accents,
            // smart quotes from a rich-text paste) would only fail later
            // with a cryptic HTTP-header error, so catch it here.
            if !trimmed.is_ascii() {
                println!(
                    "That key contains non-ASCII characters (accents, emoji, or smart quotes) — API keys never do. Please paste it again."
                );
                continue;
            }
            if trimmed.len() > 8192 {
                println!(
                    "That looks far too long to be an API key — it may be the wrong clipboard content. Please paste just the key."
                );
                continue;
            }
            // Round-38 F2: build the accepted-key buffer directly
            // from the trimmed slice into a fresh Zeroizing so the
            // stored copy is minimal and zero-on-drop.
            key = Some(zeroize::Zeroizing::new(trimmed.to_owned()));
            break;
        }
        let Some(key) = key else {
            anyhow::bail!("no API key provided");
        };
        let path = root.join("keys").join(format!("{}.key", slug(preset)));
        // Round-38 F2: pass by `&str` borrow so the write path
        // never allocates a plain String copy of the secret.
        write_private_key_file(&path, key.as_str())?;
        Some(path)
    } else {
        None
    };

    // Assemble, self-validate, and save the config.
    let data_root = root.join("data");
    let key = match &key_file {
        Some(path) => KeySpec::File(path_for_config("your key file location", path)?),
        None => KeySpec::NoKey,
    };
    let plan = ConfigPlan {
        preset,
        upstream_url,
        chat_path,
        key,
        data_root: Some(path_for_config("your home folder", &data_root)?),
    };
    let rendered = render_config(&plan);
    av_harness::HarnessConfig::from_toml(&rendered)
        .map_err(|error| anyhow::anyhow!("generated config failed validation (bug): {error}"))?;
    let config_path = av_harness::config::user_config_path_from(home);
    if config_path.exists() {
        let backup = config_path.with_extension("toml.bak");
        std::fs::copy(&config_path, &backup).with_context(|| format!("back up {}", config_path.display()))?;
        println!("\n(Your previous settings were saved to {})", backup.display());
    }
    // Two concurrent wizards on the same $HOME must not interleave into a
    // fixed `.toml.tmp` name — `write_atomic` uses a UUID-suffixed tmp file
    // and rename semantics that replace any pre-existing symlink at the
    // destination without following it.
    av_core::fsutil::write_atomic(&config_path, rendered.as_bytes())
        .with_context(|| format!("install {}", config_path.display()))?;
    // Round-43 F3: chmod 0600 to match the key-file installer
    // (`write_private_key_file`) and prevent co-tenants on a shared
    // workstation from reading
    // upstream_url / upstream_api_key_env metadata via default umask
    // 022 world-readable bits. `write_atomic` opens with default mode
    // via `OpenOptions::create_new`; setting the perm post-rename
    // covers the final path atomically since rename is what makes the
    // dst visible.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if let Err(error) = std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600)) {
            eprintln!(
                "warning: failed to chmod 0600 on {}: {error}; contents may be world-readable",
                config_path.display(),
            );
        }
    }

    println!("\nAll set!");
    println!();
    println!("  Settings: {}", config_path.display());
    if let Some(path) = &key_file {
        println!("  API key:  {} (private to your user account)", path.display());
    }
    if matches!(preset, Preset::Ollama | Preset::Lmstudio) {
        println!(
            "\n  Reminder: make sure {} is running on this computer.",
            friendly_name(preset)
        );
    }
    // Setup already succeeded and the config is on disk, so a closed
    // stdin here (e.g. `printf '11\n' | avctl`) must not turn into a
    // scary error — it just means "don't start now".
    let start_now = ask_yes_no("\nStart AgentVisor AI now? [Y/n]: ", input, true).unwrap_or(false);
    Ok(WizardOutcome {
        config_path,
        start_now,
    })
}

/// Is an actual AgentVisor AI answering at `base` right now? Requires the
/// `/health` body to self-identify (`"service": "agentvisor"`) so an
/// unrelated app that happens to answer 200 on the port is not mistaken
/// for a running AgentVisor AI — that would silently point the user's
/// tools at the wrong service.
async fn health_ok(base: &str) -> bool {
    let Ok(client) = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(1))
        .build()
    else {
        return false;
    };
    let Ok(response) = client.get(format!("{base}/health")).send().await else {
        return false;
    };
    if !response.status().is_success() {
        return false;
    }
    matches!(
        response.json::<serde_json::Value>().await,
        Ok(body) if body.get("service").and_then(serde_json::Value::as_str) == Some("agentvisor")
    )
}

/// Prefer the server binary installed next to avctl; fall back to PATH.
///
/// Naming history: prior to v0.1.0 the binary was `agent-bridge`; it was
/// renamed to `agentbridged` (the `agent-bridge` name on crates.io is
/// taken by an unrelated project) and then to `agentvisord` as part of
/// the AgentVisor AI rebrand. We look for the current name first, then
/// fall back to the legacy names so operators upgrading from a
/// source-built older install keep working.
fn find_server_binary() -> PathBuf {
    let candidates: &[&str] = if cfg!(windows) {
        &["agentvisord.exe", "agentbridged.exe", "agent-bridge.exe"]
    } else {
        &["agentvisord", "agentbridged", "agent-bridge"]
    };
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for candidate in candidates {
                let sibling = dir.join(candidate);
                if sibling.is_file() {
                    return sibling;
                }
            }
        }
    }
    PathBuf::from(candidates.first().copied().unwrap_or("agentvisord"))
}

/// Print the last `count` log lines, unwrapping the JSON envelope when
/// possible so failures read like sentences instead of telemetry.
///
/// Round-6 (hunt4 F15): JSON-decoding the tracing envelope RESURRECTS
/// escaped control bytes (tracing writes `\u001b`; `serde_json` decodes
/// it back to live ESC). An attacker who can influence a logged string
/// (any upstream/tool response payload that got captured into an error
/// message) could then paint spoofed diagnostics on the operator's
/// terminal via CSI sequences. Route both the JSON-decoded message and
/// the raw-line fallback through the same terminal sanitizer used
/// everywhere else in this crate.
fn print_log_tail(path: &Path, count: usize) {
    // Bounded read: the log is opened append-only with no rotation, so
    // it grows without bound across runs; slurping the whole file (the
    // old `read_to_string`) risked a multi-GB allocation at exactly the
    // moment the operator is diagnosing a failure. Read only a fixed
    // suffix — generous for `count` lines of tracing JSON.
    const TAIL_BYTES: u64 = 256 * 1024;
    let Ok(mut file) = std::fs::File::open(path) else {
        return;
    };
    let Ok(len) = file.metadata().map(|m| m.len()) else {
        return;
    };
    use std::io::{Read as _, Seek as _};
    let start = len.saturating_sub(TAIL_BYTES);
    if start > 0 && file.seek(std::io::SeekFrom::Start(start)).is_err() {
        return;
    }
    let mut bytes = Vec::with_capacity(usize::try_from(len - start).unwrap_or(0));
    if file.take(TAIL_BYTES).read_to_end(&mut bytes).is_err() {
        return;
    }
    let text = String::from_utf8_lossy(&bytes);
    // Drop the first (possibly truncated) line when we started mid-file.
    let text = if start > 0 {
        text.split_once('\n').map_or("", |(_, rest)| rest)
    } else {
        &text
    };
    let mut tail: Vec<&str> = text.lines().rev().take(count).collect();
    tail.reverse();
    for line in tail {
        let friendly = serde_json::from_str::<serde_json::Value>(line)
            .ok()
            .and_then(|value| {
                let level = value.get("level")?.as_str()?.to_owned();
                let message = value.get("fields")?.get("message")?.as_str()?.to_owned();
                Some(format!("{level:<5} {message}"))
            })
            .unwrap_or_else(|| line.to_owned());
        eprintln!("    {}", crate::sanitize_for_terminal(&friendly));
    }
}

fn print_usage_banner(base: &str) {
    println!();
    println!("  Use it from any OpenAI-compatible app:");
    println!("    Base URL: {base}/v1");
    println!("    API key:  anything (your real key stays on this machine)");
    println!();
}

/// `avctl start` — run the server in the foreground with friendly output.
/// Logs go to a file so the terminal stays readable; Ctrl-C stops both
/// processes gracefully (the server flushes trajectories on shutdown).
pub async fn start() -> Result<()> {
    // Friendly pre-checks with the exact resolution the server uses.
    let not_set_up = matches!(
        av_harness::config::resolve_config_source(),
        Ok(av_harness::config::ConfigSource::BuiltIn)
    ) && std::env::var_os("AV_UPSTREAM_URL").is_none_or(|value| value.is_empty());
    if not_set_up {
        anyhow::bail!(
            "AgentVisor AI is not set up yet.\nRun `avctl` (no arguments) and answer a couple of quick questions, then try again."
        );
    }
    let (config, source) = av_harness::config::load_config().map_err(|error| {
        anyhow::anyhow!("configuration problem: {error}\nRun `avctl doctor` for a full diagnosis.")
    })?;
    // Round-21 F6 + round-40 F2: rewrite the listen address to a
    // loopback probe URL. The prior implementation was a pair of
    // string replacements (`0.0.0.0`->`127.0.0.1`, `[::]`->`[::1]`)
    // which missed three real forms:
    //   1. IPv6 link-local with a zone identifier
    //      (`[fe80::1%eth0]:8484`) — the raw `%` in the URL fails
    //      RFC 3986 parsing and every probe URL-parses to `Err`,
    //      so `avctl start` blocks the full 20 s deadline and
    //      kills a healthy child.
    //   2. Fully expanded unspecified `[0:0:0:0:0:0:0:0]:8484`
    //      (Rust `SocketAddr::to_string()` for `::` may emit
    //      the shortened form, but operator-typed configs can be
    //      expanded).
    //   3. Non-`0.0.0.0` / `[::]` listen literals that happen to
    //      resolve to an unspecified address.
    // Parse via `SocketAddr` so the address family drives the
    // loopback rewrite, and drop any zone identifier since a
    // loopback connect never needs it.
    let base = build_probe_base(&config.listen);

    if health_ok(&base).await {
        println!("AgentVisor AI is already running at {base}");
        print_usage_banner(&base);
        return Ok(());
    }

    let binary = find_server_binary();
    let log_path = av_harness::config::user_config_path()
        .and_then(|path| Some(path.parent()?.join("agentvisor-ai.log")))
        .unwrap_or_else(|| PathBuf::from("agentvisor-ai.log"));
    if let Some(parent) = log_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("open log file {}", log_path.display()))?;
    let log_err = log.try_clone().context("clone log handle")?;

    println!("Starting AgentVisor AI (settings: {source})...");
    let mut command = tokio::process::Command::new(&binary);
    command
        .stdout(std::process::Stdio::from(log))
        .stderr(std::process::Stdio::from(log_err));
    // When running from the per-user config, keep every file the server
    // creates (signing seed included) inside ~/.agentvisor/ instead of
    // scattering a config/ directory into whatever folder we run from.
    if std::env::var_os("AV_SIGNING_SEED_FILE").is_none() {
        if let av_harness::config::ConfigSource::File(config_path) = &source {
            if Some(config_path) == av_harness::config::user_config_path().as_ref() {
                if let Some(root) = config_path.parent() {
                    command.env("AV_SIGNING_SEED_FILE", root.join("signing.seed"));
                }
            }
        }
    }
    let mut child = command.spawn().map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            anyhow::anyhow!(
                "could not find the AgentVisor AI server program ({}).\n\
                 It normally lives next to avctl. To install it:\n\
                 cargo install av-harness   # or: cargo install --path crates/av-harness",
                binary.display()
            )
        } else {
            anyhow::Error::new(error).context(format!("could not run {}", binary.display()))
        }
    })?;

    // Wait until healthy — or explain why it died. Stop requests during
    // startup must reach the child too: without polling the signal
    // streams here, a SIGTERM/SIGINT in this window would kill avctl at
    // the default disposition and orphan the server mid-boot.
    let mut interrupt = std::pin::pin!(tokio::signal::ctrl_c());
    let mut terminate = std::pin::pin!(terminate_signal());
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = child.try_wait().context("check server status")? {
            eprintln!("AgentVisor AI stopped right away ({status}). Last log lines:");
            print_log_tail(&log_path, 12);
            anyhow::bail!("startup failed — run `avctl doctor` for a diagnosis");
        }
        if health_ok(&base).await {
            break;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.start_kill();
            let _ = child.wait().await;
            print_log_tail(&log_path, 12);
            anyhow::bail!("the server did not become ready within 20 seconds");
        }
        tokio::select! {
            () = tokio::time::sleep(Duration::from_millis(250)) => {}
            _ = &mut interrupt => {
                println!("\nStopping AgentVisor AI...");
                forward_signal(&child, "-INT");
                wait_for_graceful_exit(&mut child).await;
                return Ok(());
            }
            () = &mut terminate => {
                println!("\nStopping AgentVisor AI...");
                forward_signal(&child, "-TERM");
                wait_for_graceful_exit(&mut child).await;
                return Ok(());
            }
        }
    }

    println!("✓ AgentVisor AI is running at {base}");
    print_usage_banner(&base);
    println!("  Log file: {}", log_path.display());
    println!("  Press Ctrl-C to stop.");

    tokio::select! {
        status = child.wait() => {
            let status = status.context("wait for server")?;
            if status.success() {
                println!("AgentVisor AI stopped.");
            } else {
                eprintln!("AgentVisor AI exited unexpectedly ({status}). Last log lines:");
                print_log_tail(&log_path, 12);
                anyhow::bail!("server exited unexpectedly");
            }
        }
        _ = &mut interrupt => {
            println!("\nStopping AgentVisor AI...");
            // Terminal Ctrl-C reaches the child through the foreground
            // process group, but a direct `kill -INT <avctl>` does not —
            // forward to be sure. A duplicate SIGINT is harmless: the
            // server's signal stream is already registered, so it can't
            // fall back to the abrupt default disposition.
            forward_signal(&child, "-INT");
            wait_for_graceful_exit(&mut child).await;
        }
        () = &mut terminate => {
            // SIGTERM (Activity Monitor "Quit", plain `kill`, service
            // managers) only reaches avctl — without forwarding it the
            // server would keep running unsupervised as an orphan.
            println!("\nStopping AgentVisor AI...");
            forward_signal(&child, "-TERM");
            wait_for_graceful_exit(&mut child).await;
        }
    }
    Ok(())
}

/// Resolves when the process receives SIGTERM; never resolves where
/// SIGTERM does not exist (or the handler cannot be installed) so the
/// other `select!` arms keep working.
#[cfg(unix)]
async fn terminate_signal() {
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(mut stream) => {
            stream.recv().await;
        }
        Err(_) => std::future::pending().await,
    }
}

#[cfg(not(unix))]
async fn terminate_signal() {
    std::future::pending::<()>().await;
}

/// Forward `signal` (e.g. "-INT") to the server child so it shuts down
/// gracefully even when only avctl was signalled. Uses the `kill`
/// program because the workspace forbids unsafe code (no raw libc).
#[cfg(unix)]
fn forward_signal(child: &tokio::process::Child, signal: &str) {
    if let Some(pid) = child.id() {
        let _ = std::process::Command::new("kill")
            .arg(signal)
            .arg(pid.to_string())
            .status();
    }
}

#[cfg(not(unix))]
fn forward_signal(_child: &tokio::process::Child, _signal: &str) {}

/// Wait for the server's four-phase graceful shutdown, then force-kill
/// only if it truly hangs.
///
/// Round-6 (hunt4 ops F6): the harness's documented shutdown budget is
/// up to 95 s (30 s HTTP drain + 30 s worker wait_idle + 30 s
/// finalize_sessions + 5 s telemetry flush) — the systemd unit and
/// compose files are tuned to 120–125 s for exactly this reason. The
/// prior 10 s SIGKILL here dropped receipts and truncated trajectories
/// mid-finalize on the desktop path while printing "Your data is
/// saved." Print progress so a long flush doesn't look like a hang.
async fn wait_for_graceful_exit(child: &mut tokio::process::Child) {
    const GRACEFUL_BUDGET_S: u64 = 100;
    match tokio::time::timeout(Duration::from_secs(10), child.wait()).await {
        Ok(_) => {
            println!("Stopped. Your data is saved.");
            return;
        }
        Err(_) => {
            println!("Waiting for the server to flush sessions and receipts (up to {GRACEFUL_BUDGET_S}s)...");
        }
    }
    match tokio::time::timeout(Duration::from_secs(GRACEFUL_BUDGET_S - 10), child.wait()).await {
        Ok(_) => println!("Stopped. Your data is saved."),
        Err(_) => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            // Do NOT claim data safety: a SIGKILL mid-finalize can
            // leave receipts unminted and trajectories truncated —
            // recovery will quarantine them on next start.
            println!("Stopped (forced). Some sessions may need recovery on next start.");
        }
    }
}

/// One diagnostic line: pass/warn/fail plus a short explanation.
enum Check {
    Pass(String),
    Warn(String),
    Fail(String),
}

fn report(checks: &[Check]) -> (usize, usize) {
    let mut warnings = 0;
    let mut failures = 0;
    for check in checks {
        match check {
            Check::Pass(message) => println!("  ok    {message}"),
            Check::Warn(message) => {
                warnings += 1;
                println!("  warn  {message}");
            }
            Check::Fail(message) => {
                failures += 1;
                println!("  FAIL  {message}");
            }
        }
    }
    (warnings, failures)
}

/// `avctl doctor` — resolve config exactly like the server and verify every
/// runtime prerequisite. Never prints secret values or URL userinfo —
/// key sources by name only, endpoints with credentials redacted.
pub async fn doctor(offline: bool) -> Result<()> {
    let mut checks = Vec::new();

    // 1. Config resolution (same search order as the server).
    let resolved = av_harness::config::load_config();
    let (config, source) = match resolved {
        Ok((config, source)) => {
            checks.push(Check::Pass(format!("config: {source}")));
            (Some(config), Some(source))
        }
        Err(error) => {
            checks.push(Check::Fail(format!("config: {error}")));
            (None, None)
        }
    };

    if let Some(config) = &config {
        // 2. Common URL footgun: base URL already contains the chat path
        // prefix (e.g. ".../v1" + "/v1/chat/completions").
        if let Some(segment) = config.duplicated_chat_path_segment() {
            checks.push(Check::Warn(format!(
                "upstream_url ends with \"/{segment}\" and upstream_chat_path repeats it; \
                 the joined URL will contain \"/{segment}/{segment}/\" — drop the suffix from upstream_url"
            )));
        }

        // 3. Upstream auth source (names only, never values).
        let auth = av_harness::pipeline::describe_upstream_auth(config);
        if let Some(env) = &config.upstream_api_key_env {
            match std::env::var(env) {
                Ok(value) if !value.trim().is_empty() => {
                    checks.push(Check::Pass(format!("upstream auth: {auth} (set)")));
                }
                _ => checks.push(Check::Fail(format!(
                    "upstream auth: {auth} — environment variable {env} is unset or empty"
                ))),
            }
        } else if let Some(file) = &config.upstream_api_key_file {
            // Round-42 F1: mirror `av_harness::pipeline::require_owner_only_secret`
            // exactly — the runtime refuses symlinks, non-regular files,
            // group/other-readable modes, and empty content. Doctor used to
            // only `metadata(file).ok()`-check existence, so an operator
            // whose key file was chmod 644 or a dangling symlink would see
            // `avctl doctor` PASS and `avctl start`/harness startup FAIL.
            match check_owner_only_secret(std::path::Path::new(file)) {
                Ok(()) => checks.push(Check::Pass(format!("upstream auth: {auth}"))),
                Err(reason) => checks.push(Check::Fail(format!("upstream auth: {auth} — {reason}"))),
            }
        } else {
            checks.push(Check::Pass(format!("upstream auth: {auth}")));
        }

        // Round-29 F1 (avctl doctor): parity with the upstream API key
        // check above. `tool_upstream_bearer_env/_file` is the MCP
        // path's bearer token; the runtime applies the SAME
        // `require_owner_only_secret` posture at first tool call,
        // but doctor used to check neither.
        if let Some(env) = &config.tool_upstream_bearer_env {
            match std::env::var(env) {
                Ok(value) if !value.trim().is_empty() => {
                    checks.push(Check::Pass(format!("tool bearer: env {env} (set)")));
                }
                _ => checks.push(Check::Fail(format!(
                    "tool bearer: environment variable {env} is unset or empty"
                ))),
            }
        } else if let Some(file) = &config.tool_upstream_bearer_file {
            match check_owner_only_secret(std::path::Path::new(file)) {
                Ok(()) => checks.push(Check::Pass(format!("tool bearer: {file}"))),
                Err(reason) => {
                    checks.push(Check::Fail(format!("tool bearer: {file} — {reason}")));
                }
            }
        } else if config.tool_upstream_url.is_some() {
            checks.push(Check::Warn(
                "tool bearer: none configured (MCP calls will proxy unauthenticated)".to_owned(),
            ));
        }

        // 4. Upstream reachability (TCP + HTTP; any HTTP status counts).
        if offline {
            checks.push(Check::Warn("upstream: skipped (--offline)".to_owned()));
        } else {
            let url = config.upstream_url.trim_end_matches('/').to_owned();
            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(3))
                .build()
                .context("build probe client")?;
            match client.get(&url).send().await {
                Ok(response) => checks.push(Check::Pass(format!(
                    "upstream: {} reachable (HTTP {})",
                    redact_userinfo(&url),
                    response.status().as_u16()
                ))),
                Err(error) => {
                    // Round-34 S1: redact userinfo here too — this failure
                    // line was the missing half of the round-28 F5 pair.
                    // `without_url()` strips reqwest's own embedded copy of
                    // the URL from the error Display as well.
                    checks.push(Check::Fail(format!(
                        "upstream: {} unreachable ({})",
                        redact_userinfo(&url),
                        error.without_url()
                    )));
                }
            }
        }

        // 5. Bridge manifest. Same MAX_CONTROL_BYTES cap as
        // `manifest-validate` and the daemon's own load, so all three
        // reach the same verdict on the same file.
        match av_core::fsutil::read_capped_string(
            Path::new(&config.bridge_manifest_path),
            av_core::fsutil::MAX_CONTROL_BYTES,
        ) {
            Ok(text) => match av_bridge::BridgeManifest::from_yaml(&text) {
                Ok(manifest) => checks.push(Check::Pass(format!(
                    "manifest: {} ({} topics)",
                    config.bridge_manifest_path,
                    manifest.topics.len()
                ))),
                Err(error) => checks.push(Check::Fail(format!(
                    "manifest: {} invalid: {error}",
                    config.bridge_manifest_path
                ))),
            },
            Err(_) if config.uses_default_manifest_path() => checks.push(Check::Pass(
                "manifest: using embedded built-in (no file on disk)".to_owned(),
            )),
            Err(error) => checks.push(Check::Fail(format!(
                "manifest: {}: {error}",
                config.bridge_manifest_path
            ))),
        }

        // 6. WASM policies.
        for path in &config.wasm_policy_paths {
            if Path::new(path).is_file() {
                checks.push(Check::Pass(format!("policy: {path}")));
            } else if av_harness::HarnessConfig::is_default_policy_path(path) {
                checks.push(Check::Pass(format!("policy: {path} (embedded built-in)")));
            } else {
                checks.push(Check::Fail(format!("policy: {path} not found")));
            }
        }

        // 7. Tool schemas. The consequence differs by posture:
        // require_tool_schema = true (default) rejects schema-less tool
        // calls; false lets them through the schema gate unvalidated.
        let no_schema_consequence = if config.require_tool_schema {
            "tool calls will be rejected"
        } else {
            "require_tool_schema = false, so tool arguments will skip schema validation (policy and budget gates still apply)"
        };
        match config.tool_schema_dir.as_deref() {
            Some(dir) => match std::fs::read_dir(dir) {
                Ok(entries) => {
                    let count = entries
                        .filter_map(Result::ok)
                        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
                        .count();
                    if count > 0 {
                        checks.push(Check::Pass(format!("tool schemas: {count} in {dir}")));
                    } else if config.tool_upstream_url.is_some() {
                        checks.push(Check::Fail(format!(
                            "tool schemas: none in {dir} but tool_upstream_url is set"
                        )));
                    } else {
                        checks.push(Check::Warn(format!(
                            "tool schemas: none in {dir}; {no_schema_consequence}"
                        )));
                    }
                }
                Err(_) if config.uses_default_tool_schema_dir() => checks.push(Check::Warn(format!(
                    "tool schemas: default directory missing; {no_schema_consequence}"
                ))),
                Err(error) => checks.push(Check::Fail(format!("tool schemas: {dir}: {error}"))),
            },
            None => checks.push(Check::Warn(format!(
                "tool schemas: no directory configured; {no_schema_consequence}"
            ))),
        }

        // 8. Signing seed (created on first run if absent). Round-42 F2:
        // pick the same path `avctl start` will actually pass to the
        // harness — when the user config is at `user_config_path()`,
        // start overrides `AV_SIGNING_SEED_FILE` to
        // `<user_config_dir>/signing.seed` (see main.rs
        // `avctl_start`, "Starting AgentVisor AI"). Doctor used to
        // probe `config/signing.seed` regardless, so a bad seed in
        // the user directory would pass doctor and fail startup.
        // Additionally, verify the seed content (hex, 32 bytes, not
        // known-weak) so a corrupt seed cannot survive doctor —
        // `av_harness::main::read_signer` refuses those at startup.
        let seed_path = seed_path_for(source.as_ref());
        if seed_path.is_file() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt as _;
                match std::fs::symlink_metadata(&seed_path) {
                    Ok(meta) if meta.file_type().is_symlink() => checks.push(Check::Fail(format!(
                        "signing seed: {} is a symbolic link",
                        seed_path.display()
                    ))),
                    Ok(meta) if meta.mode() & 0o077 != 0 => checks.push(Check::Fail(format!(
                        "signing seed: {} is group/world accessible (chmod 600 it)",
                        seed_path.display()
                    ))),
                    Ok(_) => match check_signing_seed_content(&seed_path) {
                        Ok(()) => checks.push(Check::Pass(format!("signing seed: {}", seed_path.display()))),
                        Err(reason) => checks.push(Check::Fail(format!(
                            "signing seed: {}: {reason}",
                            seed_path.display()
                        ))),
                    },
                    Err(error) => {
                        checks.push(Check::Fail(format!(
                            "signing seed: {}: {error}",
                            seed_path.display()
                        )));
                    }
                }
            }
            #[cfg(not(unix))]
            match check_signing_seed_content(&seed_path) {
                Ok(()) => checks.push(Check::Pass(format!("signing seed: {}", seed_path.display()))),
                Err(reason) => checks.push(Check::Fail(format!(
                    "signing seed: {}: {reason}",
                    seed_path.display()
                ))),
            }
        } else {
            checks.push(Check::Pass(format!(
                "signing seed: {} will be generated on first run",
                seed_path.display()
            )));
        }

        // 9. Data directories writable (created on demand by the server).
        for (label, dir) in [
            ("spool dir", config.atif_spool_dir.as_str()),
            ("bridge dir", config.bridge_data_dir.as_str()),
        ] {
            let path = Path::new(dir);
            let probe_parent = if path.exists() {
                path.to_path_buf()
            } else {
                // Find the nearest existing ancestor to test writability.
                let mut ancestor = path.to_path_buf();
                while !ancestor.exists() {
                    match ancestor.parent() {
                        Some(parent) if !parent.as_os_str().is_empty() => {
                            ancestor = parent.to_path_buf();
                        }
                        _ => {
                            ancestor = PathBuf::from(".");
                            break;
                        }
                    }
                }
                ancestor
            };
            // A real create+delete probe: permission bits alone lie about
            // ownership, ACLs, and read-only mounts. Round-51 §8.10:
            // write actual DATA bytes, not just a dirent — a filesystem
            // out of data blocks (the most likely spool outage) can
            // still create zero-byte files from reserved inode space,
            // so a bare create_new passed while every request 503'd.
            let probe = probe_parent.join(format!(".avctl-doctor-{}", std::process::id()));
            let write_outcome = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&probe)
                .and_then(|mut file| {
                    use std::io::Write as _;
                    file.write_all(&[0u8; 4096])?;
                    file.sync_all()
                });
            match write_outcome {
                Ok(()) => {
                    let _ = std::fs::remove_file(&probe);
                    checks.push(Check::Pass(format!("{label}: {dir}")));
                }
                Err(error) => {
                    let _ = std::fs::remove_file(&probe);
                    checks.push(Check::Fail(format!(
                        "{label}: cannot write 4 KiB in {} ({error})",
                        probe_parent.display()
                    )));
                }
            }
            // Surface the spool's current footprint so an operator can
            // see growth (there is no automatic pruning without
            // atif_retention_days).
            if *label == *"spool dir" && path.exists() {
                let (bytes, files) = std::fs::read_dir(path)
                    .map(|entries| {
                        entries
                            .flatten()
                            .filter_map(|entry| entry.metadata().ok())
                            .filter(std::fs::Metadata::is_file)
                            .fold((0u64, 0u64), |(bytes, files), metadata| {
                                (bytes.saturating_add(metadata.len()), files + 1)
                            })
                    })
                    .unwrap_or((0, 0));
                checks.push(Check::Pass(format!(
                    "spool footprint: {files} files, {} KiB (top level)",
                    bytes / 1024
                )));
            }
        }

        // 9b. Round-51 §8.10: backends the config selects that THIS
        // build cannot run. Previously doctor passed every check while
        // the daemon was guaranteed to hard-fail at boot on a
        // compiled-out backend.
        for problem in config.unsupported_backend_requirements() {
            checks.push(Check::Fail(problem));
        }

        // 9c. Round-51 §9.4: the three checkout-path footguns doctor
        // used to miss entirely.
        if !config.listen.starts_with("127.0.0.1") && !config.listen.starts_with("localhost") {
            checks.push(Check::Warn(format!(
                "listen = {:?} is not loopback: anyone who can reach this address gets a \
                 fully-authenticated proxy to your provider account (the key is injected \
                 server-side). Keep 127.0.0.1 unless an outer network layer controls access",
                config.listen
            )));
        }
        if config.default_workflow == "unsigned" {
            checks.push(Check::Warn(
                "default_workflow = \"unsigned\": sessions produce ATIF trajectories but NO \
                 signed receipts. Set default_workflow = \"signed\" (or send \
                 X-AV-Workflow: signed per request) if you need verifiable receipts"
                    .to_owned(),
            ));
        }
        if config.dashboard_enabled
            && !config.listen.starts_with("127.0.0.1")
            && !config.listen.starts_with("localhost")
        {
            checks.push(Check::Warn(format!(
                "dashboard_enabled = true with non-loopback listen {:?}: /dashboard and \
                 /api/v1/dashboard/* are UNAUTHENTICATED and expose per-session identity, \
                 token and cost metadata to anyone who can reach the port",
                config.listen
            )));
        }

        // 10. Backend endpoints (TCP probe only; skipped offline).
        if !offline {
            for (label, endpoint) in [
                ("state (redis)", config.state_endpoint.as_deref()),
                ("bridge endpoint", config.bridge_endpoint.as_deref()),
                ("qdrant", config.qdrant_url.as_deref()),
            ] {
                let Some(endpoint) = endpoint.filter(|e| !e.is_empty()) else {
                    continue;
                };
                match probe_endpoint_any(endpoint).await {
                    Ok(()) => checks.push(Check::Pass(format!(
                        // Round-28 F5 partner fix: the success line must
                        // redact userinfo too, not just the failure line.
                        "{label}: {} reachable",
                        redact_userinfo(endpoint)
                    ))),
                    Err(error) => {
                        // Round-28 F5: DO NOT echo `endpoint` verbatim
                        // in the failure line — a redis/qdrant URL may
                        // embed userinfo (`redis://user:pass@host/0`)
                        // and this text lands on stderr, which CI
                        // pipelines routinely capture. Report the
                        // label + probe error only.
                        checks.push(Check::Fail(format!("{label}: unreachable ({error})")));
                    }
                }
            }
        }

        // 11. Identity posture.
        if config.require_identity {
            checks.push(Check::Pass("identity: required (production posture)".to_owned()));
        } else {
            checks.push(Check::Warn(
                "identity: optional (dev mode; set require_identity=true in production)".to_owned(),
            ));
        }
    }

    println!("avctl doctor");
    let (warnings, failures) = report(&checks);
    println!();
    if failures > 0 {
        anyhow::bail!("{failures} check(s) failed, {warnings} warning(s)");
    }
    println!("all checks passed ({warnings} warning(s))");
    Ok(())
}

/// Strip URL userinfo (`user:pass@`) for safe display. Handles
/// comma-separated endpoint lists (Redis Cluster) AND passwords
/// containing `,`. Display-only — never used for connecting.
///
/// Round-6: delegate to `av_core::url_redact::redact_userinfo` so the
/// harness startup logs and the CLI doctor use identical semantics.
fn redact_userinfo(endpoints: &str) -> String {
    av_core::url_redact::redact_userinfo(endpoints)
}

/// TCP-connect to `host:port` extracted from a URL or bare `host:port`.
async fn probe_endpoint(endpoint: &str) -> Result<()> {
    let target = probe_target(endpoint)?;
    tokio::time::timeout(Duration::from_secs(3), tokio::net::TcpStream::connect(&target))
        .await
        .map_err(|_| anyhow::anyhow!("timeout"))?
        .map(|_| ())
        .map_err(anyhow::Error::from)
}

/// Round-42 F3: probe a config-shaped endpoint. Two forms that
/// `probe_endpoint` alone cannot handle without emitting a spurious
/// "unreachable" for a perfectly valid config:
///
/// 1. Redis `unix:` (and `redis+unix:`) — a local UDS socket, not a
///    TCP host:port. Config-validate at `HarnessConfig::validate`
///    (state_endpoint scheme allowlist) accepts `unix:...` for Redis.
///    We probe the socket file's existence and move on.
///
/// 2. Kafka bootstrap list — a comma-separated `host:port,host:port,...`
///    string. The bare list has no scheme, so `probe_target` would
///    misparse the first comma as trailing garbage in the port.
///    Probing every bootstrap is overkill; the runtime only needs
///    ONE reachable broker. We treat the whole list as "reachable"
///    if any single member is reachable.
async fn probe_endpoint_any(endpoint: &str) -> Result<()> {
    if endpoint.starts_with("unix:") || endpoint.starts_with("redis+unix:") {
        let path = endpoint
            .strip_prefix("redis+unix:")
            .or_else(|| endpoint.strip_prefix("unix:"))
            .unwrap_or(endpoint)
            .trim_start_matches("//");
        if path.is_empty() {
            anyhow::bail!("unix endpoint has empty path");
        }
        match std::fs::metadata(path) {
            // Existence alone is not reachability: a regular file at
            // the socket path passed doctor while the runtime's Redis
            // client requires an actual Unix domain socket — a false
            // "reachable" verdict on exactly the misconfiguration
            // doctor exists to catch.
            Ok(metadata) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::FileTypeExt as _;
                    if !metadata.file_type().is_socket() {
                        anyhow::bail!(
                            "unix socket {path}: exists but is not a socket (type: {:?})",
                            metadata.file_type()
                        );
                    }
                }
                #[cfg(not(unix))]
                let _ = metadata;
                return Ok(());
            }
            Err(error) => anyhow::bail!("unix socket {path}: {error}"),
        }
    }
    if endpoint.contains(',') {
        let mut last_err: Option<anyhow::Error> = None;
        for member in endpoint.split(',').map(str::trim).filter(|m| !m.is_empty()) {
            match probe_endpoint(member).await {
                Ok(()) => return Ok(()),
                Err(error) => last_err = Some(error),
            }
        }
        return Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no bootstrap members configured")));
    }
    probe_endpoint(endpoint).await
}

/// Round-42 F1: mirror `av_harness::pipeline::require_owner_only_secret`
/// posture so `avctl doctor` cannot falsely PASS a key file the
/// harness would refuse: symlinks, non-regular files,
/// group/other-readable modes on Unix, and empty content.
fn check_owner_only_secret(path: &Path) -> std::result::Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let metadata =
            std::fs::symlink_metadata(path).map_err(|error| format!("stat {}: {error}", path.display()))?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            return Err(format!(
                "{} is a symbolic link; refusing to follow",
                path.display()
            ));
        }
        if !file_type.is_file() {
            return Err(format!("{} is not a regular file", path.display()));
        }
        let mode = metadata.mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "{} has mode 0o{mode:03o}; must be owner-only (chmod 600 {})",
                path.display(),
                path.display()
            ));
        }
    }
    #[cfg(not(unix))]
    {
        let metadata =
            std::fs::metadata(path).map_err(|error| format!("stat {}: {error}", path.display()))?;
        if !metadata.is_file() {
            return Err(format!("{} is not a regular file", path.display()));
        }
    }
    let contents = std::fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    if contents.iter().all(u8::is_ascii_whitespace) {
        return Err(format!("{} is empty", path.display()));
    }
    Ok(())
}

/// Round-42 F2: return the same signing-seed path `avctl start`
/// will actually hand to the harness. Precedence:
///
/// 1. `AV_SIGNING_SEED_FILE` — explicit operator override, always wins.
/// 2. `<user_config_dir>/signing.seed` — when the running config was
///    resolved from `user_config_path()`, `avctl start` sets
///    `AV_SIGNING_SEED_FILE` to this path (see main.rs "Starting
///    AgentVisor AI"). Without this override, doctor would probe a
///    stale `config/signing.seed` and miss real seed problems.
/// 3. `config/signing.seed` — the harness default.
fn seed_path_for(source: Option<&av_harness::config::ConfigSource>) -> PathBuf {
    if let Some(explicit) = std::env::var_os("AV_SIGNING_SEED_FILE") {
        return PathBuf::from(explicit);
    }
    if let Some(av_harness::config::ConfigSource::File(config_path)) = source {
        if Some(config_path) == av_harness::config::user_config_path().as_ref() {
            if let Some(root) = config_path.parent() {
                return root.join("signing.seed");
            }
        }
    }
    PathBuf::from("config/signing.seed")
}

/// Round-42 F2 partner: validate signing-seed contents the way
/// `av_harness::main::read_signer` will at startup — hex-decoded,
/// exactly 32 bytes, and not a known-weak seed (all-zero or all-0xFF).
/// A doctor that only checks file mode / symlink status lets a
/// truncated or textbook-wrong seed pass, and the operator only
/// discovers the problem when `avctl start` fails.
fn check_signing_seed_content(path: &Path) -> std::result::Result<(), String> {
    let contents =
        std::fs::read_to_string(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    let decoded = hex::decode(contents.trim()).map_err(|error| format!("decode as hex: {error}"))?;
    if decoded.len() != 32 {
        return Err(format!("must be exactly 32 bytes, got {}", decoded.len()));
    }
    if decoded.iter().all(|byte| *byte == 0x00) {
        return Err("all-zero seed (known-weak, globally predictable public key)".to_owned());
    }
    if decoded.iter().all(|byte| *byte == 0xFF) {
        return Err("all-0xFF seed (known-weak, globally predictable public key)".to_owned());
    }
    Ok(())
}

/// Round-28 F1 + F5: extract the `host:port` from a URL or bare
/// `host:port` string. Split out as a pure helper so tests can lock
/// in three formerly-buggy behaviours: (F1) scheme-driven default
/// ports for HTTPS/redis/nats/rediss, (F5) userinfo stripping so
/// credentials never leak into the connect target or into error text,
/// and IPv6 bracketed literals staying intact.
fn probe_target(endpoint: &str) -> Result<String> {
    let (scheme, rest) = match endpoint.split_once("://") {
        Some((scheme, rest)) => (Some(scheme), rest),
        None => (None, endpoint),
    };
    // Trim path/query/fragment BEFORE stripping userinfo: RFC 3986
    // userinfo cannot contain '/', so an '@' after the first '/' is
    // path data, not credentials ("http://h/p@th" must probe h, not
    // "th"). Mirrors redact_userinfo's authority-first parse.
    let hostpart = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    // Strip userinfo (`user:pass@`).
    let host_and_port = hostpart
        .rsplit_once('@')
        .map_or(hostpart, |(_userinfo, host)| host);
    let (host, port_opt) = if let Some(stripped) = host_and_port.strip_prefix('[') {
        match stripped.split_once(']') {
            Some((h, tail)) => {
                let port = tail.strip_prefix(':').and_then(|p| p.parse::<u16>().ok());
                (format!("[{h}]"), port)
            }
            None => (host_and_port.to_owned(), None),
        }
    } else {
        match host_and_port.rsplit_once(':') {
            Some((h, p)) if p.parse::<u16>().is_ok() => (h.to_owned(), p.parse::<u16>().ok()),
            _ => (host_and_port.to_owned(), None),
        }
    };
    let default_port: u16 = match scheme {
        Some("https") | Some("wss") | Some("qdrant+https") => 443,
        Some("nats") | Some("tls+nats") | Some("nats+tls") | Some("tls") => 4222,
        // `rediss://` is TLS Redis, not HTTPS: redis-rs applies
        // `port().unwrap_or(6379)` for BOTH redis:// and rediss://, so
        // the daemon connects to :6379 on a portless endpoint. Probing
        // :443 (the old mapping) reported FAIL "unreachable" for a
        // working production config — or a false PASS if an unrelated
        // HTTPS service listened there.
        Some("redis") | Some("rediss") => 6379,
        _ => 80,
    };
    let port = port_opt.unwrap_or(default_port);
    if host.is_empty() {
        anyhow::bail!("no host in endpoint");
    }
    Ok(format!("{host}:{port}"))
}

/// Round-40 F2: parse the operator-configured listen address into a
/// loopback probe URL. Handles four forms explicitly:
///
/// * IPv4/IPv6 unspecified addresses map to loopback (matches the
///   family: `0.0.0.0` -> `127.0.0.1`, `[::]` / expanded
///   `[0:0:0:0:0:0:0:0]` -> `[::1]`).
/// * Any other IPv4/IPv6 literal is preserved (an operator binding
///   to a specific interface probes that same interface).
/// * IPv6 addresses with a zone identifier (`[fe80::1%eth0]`) drop
///   the zone id — loopback connects don't need it and the raw `%`
///   in an unencoded URL breaks RFC 3986 parsers.
/// * Anything unparsable (hostname, `*:port`, mangled config) falls
///   back to the pre-round-40 string-replace behaviour so the
///   change is strictly additive vs. round-21 F6.
fn build_probe_base(listen: &str) -> String {
    if let Ok(sa) = listen.parse::<std::net::SocketAddr>() {
        let host = if sa.ip().is_unspecified() {
            if sa.is_ipv6() {
                "[::1]".to_owned()
            } else {
                "127.0.0.1".to_owned()
            }
        } else {
            match sa.ip() {
                std::net::IpAddr::V4(v4) => v4.to_string(),
                // Rust's `Ipv6Addr::Display` already emits the
                // shortened form and does not include a zone id
                // (`sa.ip()` discards any scope id that parsed), so this branch
                // gives us a stable bracketed form.
                std::net::IpAddr::V6(v6) => format!("[{v6}]"),
            }
        };
        format!("http://{host}:{}", sa.port())
    } else {
        // Fallback: preserve the round-21 F6 behaviour when parse
        // fails (bare hostname, `*:port`, IPv6 with an interface-NAME
        // zone id like `%eth0` — numeric ids such as `%1` parse fine
        // on stable and take the branch above, where `sa.ip()` drops
        // the scope); drop the zone id via a
        // second replace so at least the loopback rewrite still
        // runs.
        let rewritten = listen.replace("0.0.0.0", "127.0.0.1").replace("[::]", "[::1]");
        // Strip an IPv6 zone identifier if present: `[fe80::1%eth0]`
        // -> `[fe80::1]`. Loopback connects don't need it, and the
        // raw `%` breaks URL parsing downstream.
        let rewritten = if let (Some(start), Some(pct), Some(end)) =
            (rewritten.find('['), rewritten.find('%'), rewritten.find(']'))
        {
            if start < pct && pct < end {
                let mut owned = String::with_capacity(rewritten.len());
                owned.push_str(&rewritten[..pct]);
                owned.push_str(&rewritten[end..]);
                owned
            } else {
                rewritten
            }
        } else {
            rewritten
        };
        format!("http://{rewritten}")
    }
}

/// `avctl health` — probe a running harness; exit 0 only on an HTTP 2xx.
pub async fn health(base_url: &str) -> Result<()> {
    // Accept both the base URL (documented) and a pasted full /health URL:
    // silently appending a second /health would probe a nonexistent path and
    // report a healthy harness as unhealthy.
    let base = base_url.trim_end_matches('/');
    let base = base.strip_suffix("/health").unwrap_or(base);
    let url = format!("{base}/health");
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(3))
        .build()
        .context("build health client")?;
    let response = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    if !response.status().is_success() {
        anyhow::bail!("harness unhealthy: HTTP {}", response.status().as_u16());
    }
    println!("healthy {url}");
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    /// QC round 28: the doctor promise is "never prints secret values or
    /// URL userinfo" — the redactor must strip credentials from every
    /// display shape doctor prints (single URLs, cluster lists, bare
    /// host:port) without corrupting credential-free endpoints.
    #[test]
    fn redact_userinfo_strips_credentials_from_every_display_shape() {
        assert_eq!(
            redact_userinfo("redis://user:s3cret@host:6379/0"),
            "redis://***@host:6379/0"
        );
        assert_eq!(
            redact_userinfo("redis://a:p@h1:7000,redis://a:p@h2:7001"),
            "redis://***@h1:7000,redis://***@h2:7001"
        );
        assert_eq!(redact_userinfo("http://plain:8484/v1"), "http://plain:8484/v1");
        assert_eq!(redact_userinfo("host:9092"), "host:9092");
        // '@' after the authority (in a path) is not userinfo.
        assert_eq!(redact_userinfo("http://h/p@th"), "http://h/p@th");
    }

    /// Round-39 F1: the piped-stdin (Plain) secret-reading path uses
    /// a `Zeroizing<String>` buffer from the first allocation.
    /// A compile-time type check on the return type is the tightest
    /// property test — if a future refactor accidentally unwraps
    /// the Zeroizing wrapper somewhere in ask_secret_line's chain,
    /// this fails to type-check. Also assert a runtime behaviour
    /// property: the returned buffer's Deref exposes the exact bytes
    /// read (secret + trailing newline) so the caller sees the raw
    /// content and can trim() to a &str borrow into the Zeroizing
    /// buffer without creating a fresh un-zeroed allocation.
    #[test]
    fn ask_secret_line_returns_zeroizing_string() {
        let mut cursor = std::io::Cursor::new(b"sk-test-key\n".to_vec());
        let line = ask_secret_line("prompt: ", &mut cursor).unwrap();
        // Type is Zeroizing<String>.
        let _explicit: zeroize::Zeroizing<String> = line;
        // Content is exactly what stdin fed us — the trailing '\n'
        // is preserved so the caller (round-38 F2 flow) trims via
        // `.trim()` (a &str borrow into the Zeroizing buffer)
        // instead of `.trim().to_owned()` which would spawn a fresh
        // un-zeroed allocation.
        let mut cursor = std::io::Cursor::new(b"sk-abc-123\n".to_vec());
        let line = ask_secret_line("prompt: ", &mut cursor).unwrap();
        assert_eq!(&*line, "sk-abc-123\n");
    }

    #[test]
    fn split_embedded_chat_path_covers_pasted_endpoint_urls() {
        // Default chat path collapses to the base URL alone.
        assert_eq!(
            split_embedded_chat_path("http://10.0.0.5:8000/v1/chat/completions".into()),
            ("http://10.0.0.5:8000".into(), None)
        );
        // Non-default embedded paths are preserved verbatim as overrides.
        assert_eq!(
            split_embedded_chat_path("http://gw.corp/llm/v1/chat/completions".into()),
            ("http://gw.corp".into(), Some("/llm/v1/chat/completions".into()))
        );
        assert_eq!(
            split_embedded_chat_path(
                "https://r.openai.azure.com/openai/deployments/d/chat/completions?api-version=1".into()
            ),
            (
                "https://r.openai.azure.com".into(),
                Some("/openai/deployments/d/chat/completions?api-version=1".into())
            )
        );
        // Base URLs pass through untouched.
        assert_eq!(
            split_embedded_chat_path("http://10.0.0.5:8000".into()),
            ("http://10.0.0.5:8000".into(), None)
        );
        assert_eq!(
            split_embedded_chat_path("http://10.0.0.5:8000/v1".into()),
            ("http://10.0.0.5:8000/v1".into(), None)
        );
        // A path that merely mentions the words is not a chat endpoint.
        assert_eq!(
            split_embedded_chat_path("http://h/x/chat/completionsfoo".into()),
            ("http://h/x/chat/completionsfoo".into(), None)
        );
    }

    fn plan_for(preset: Preset, upstream_url: &str, key_env: Option<&str>) -> ConfigPlan {
        ConfigPlan {
            preset,
            upstream_url: upstream_url.to_owned(),
            chat_path: None,
            key: match key_env {
                Some(env) => KeySpec::Env(env.to_owned()),
                None => KeySpec::NoKey,
            },
            data_root: None,
        }
    }

    #[test]
    fn every_preset_generates_a_valid_config() {
        for preset in [
            Preset::Openai,
            Preset::Azure,
            Preset::Anthropic,
            Preset::Gemini,
            Preset::Groq,
            Preset::Mistral,
            Preset::Openrouter,
            Preset::Together,
            Preset::Deepseek,
            Preset::Xai,
            Preset::Ollama,
            Preset::Lmstudio,
            Preset::Vllm,
            Preset::Llamacpp,
            Preset::Litellm,
        ] {
            let s = spec(preset);
            let rendered = render_config(&plan_for(preset, s.upstream_url, s.key_env));
            let config = av_harness::HarnessConfig::from_toml(&rendered)
                .unwrap_or_else(|error| panic!("{preset:?}: {error}"));
            assert!(!config.upstream_url.is_empty(), "{preset:?} upstream_url");
        }
        // Custom with an explicit URL also validates.
        let rendered = render_config(&plan_for(Preset::Custom, "http://10.0.0.5:9000", Some("MY_KEY")));
        av_harness::HarnessConfig::from_toml(&rendered).unwrap();
    }

    #[test]
    fn azure_preset_uses_raw_key_header() {
        let s = spec(Preset::Azure);
        let rendered = render_config(&plan_for(Preset::Azure, s.upstream_url, s.key_env));
        let config = av_harness::HarnessConfig::from_toml(&rendered).unwrap();
        assert_eq!(config.upstream_auth_header, "api-key");
        assert_eq!(config.upstream_auth_scheme, "");
        assert!(config.upstream_chat_path.starts_with("/openai/deployments/"));
        assert_eq!(
            config.upstream_api_key_env.as_deref(),
            Some("AZURE_OPENAI_API_KEY")
        );
    }

    #[test]
    fn local_presets_need_no_key() {
        for preset in [Preset::Ollama, Preset::Lmstudio, Preset::Vllm, Preset::Llamacpp] {
            let s = spec(preset);
            assert!(s.key_env.is_none(), "{preset:?} must not demand a key");
            let rendered = render_config(&plan_for(preset, s.upstream_url, s.key_env));
            let config = av_harness::HarnessConfig::from_toml(&rendered).unwrap();
            assert!(config.upstream_api_key_env.is_none());
            assert!(config.upstream_api_key_file.is_none());
        }
    }

    #[test]
    fn init_writes_and_refuses_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agentvisor.toml");
        init(Preset::Ollama, &path, false, None, None).unwrap();
        assert!(path.is_file());
        let error = init(Preset::Ollama, &path, false, None, None).unwrap_err();
        assert!(error.to_string().contains("--force"), "{error}");
        init(Preset::Openai, &path, true, None, None).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("api.openai.com"));
    }

    #[test]
    fn custom_preset_requires_url() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agentvisor.toml");
        let error = init(Preset::Custom, &path, false, None, None).unwrap_err();
        assert!(error.to_string().contains("--upstream-url"), "{error}");
    }

    /// User-supplied values are interpolated into TOML: anything that could
    /// escape the string literal must be rejected, not written.
    #[test]
    fn init_rejects_toml_injection_attempts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agentvisor.toml");
        for url in [
            "http://x\"\nrequire_identity = false #", // quote escape
            "http://x\\y",                            // backslash escape
            "ftp://host",                             // wrong scheme
            "api.openai.com",                         // missing scheme
            "http://x y",                             // embedded space
        ] {
            let error = init(Preset::Custom, &path, true, Some(url), None).unwrap_err();
            assert!(!path.exists(), "{url:?} must not produce a file: {error}");
        }
        for env in ["MY KEY", "1KEY", "KEY\"X", "", "KEY-NAME"] {
            let error = init(
                Preset::Custom,
                &path,
                true,
                Some("http://127.0.0.1:9000"),
                Some(env),
            )
            .unwrap_err();
            assert!(error.to_string().contains("--key-env"), "{env:?}: {error}");
            assert!(!path.exists(), "{env:?} must not produce a file");
        }
        // Sane values still pass.
        init(
            Preset::Custom,
            &path,
            true,
            Some("http://127.0.0.1:9000"),
            Some("MY_KEY_9"),
        )
        .unwrap();
        assert!(path.exists());
    }

    // --- wizard -----------------------------------------------------------

    fn drive_wizard(home: &Path, script: &str) -> Result<WizardOutcome> {
        let mut input = std::io::Cursor::new(script.as_bytes().to_vec());
        wizard(home, &mut input, &SecretInput::Plain)
    }

    #[test]
    fn wizard_openai_stores_key_privately() {
        let home = tempfile::tempdir().unwrap();
        // Choice 1 (OpenAI), paste key, don't start.
        let outcome = drive_wizard(home.path(), "1\nsk-wizard-test\nn\n").unwrap();
        assert!(!outcome.start_now);

        let config_text = std::fs::read_to_string(&outcome.config_path).unwrap();
        let config = av_harness::HarnessConfig::from_toml(&config_text).unwrap();
        assert_eq!(config.upstream_url, "https://api.openai.com");
        assert!(config.upstream_api_key_env.is_none(), "no export step allowed");

        let key_path = PathBuf::from(config.upstream_api_key_file.unwrap());
        assert_eq!(std::fs::read_to_string(&key_path).unwrap(), "sk-wizard-test");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&key_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "key file must be owner-only");
        }
        // Data dirs are absolute so the server works from any folder.
        assert!(PathBuf::from(&config.atif_spool_dir).is_absolute());
        assert!(PathBuf::from(&config.bridge_data_dir).is_absolute());
        // The config landed exactly where the server searches.
        assert_eq!(
            outcome.config_path,
            av_harness::config::user_config_path_from(home.path())
        );
    }

    #[test]
    fn wizard_local_provider_needs_no_key() {
        let home = tempfile::tempdir().unwrap();
        // Choice 11 (Ollama), start now (default Y via empty line).
        let outcome = drive_wizard(home.path(), "11\n\n").unwrap();
        assert!(outcome.start_now);
        let config_text = std::fs::read_to_string(&outcome.config_path).unwrap();
        let config = av_harness::HarnessConfig::from_toml(&config_text).unwrap();
        assert_eq!(config.upstream_url, "http://127.0.0.1:11434");
        assert!(config.upstream_api_key_file.is_none());
        assert!(!home.path().join(".agentvisor/keys").exists());
    }

    #[test]
    fn wizard_reasks_on_invalid_choice_and_empty_key() {
        let home = tempfile::tempdir().unwrap();
        // 99 and "abc" are re-asked; 2 = Anthropic; empty key re-asked.
        let outcome = drive_wizard(home.path(), "99\nabc\n2\n\nsk-ant\nn\n").unwrap();
        let config_text = std::fs::read_to_string(&outcome.config_path).unwrap();
        let config = av_harness::HarnessConfig::from_toml(&config_text).unwrap();
        assert_eq!(config.upstream_url, "https://api.anthropic.com");
        let key_path = config.upstream_api_key_file.unwrap();
        assert_eq!(std::fs::read_to_string(key_path).unwrap(), "sk-ant");
    }

    #[test]
    fn wizard_reasks_on_non_ascii_and_oversized_key() {
        let home = tempfile::tempdir().unwrap();
        // Emoji key re-asked (would break the HTTP auth header later),
        // then a >8 KiB paste re-asked, then a real key accepted.
        let huge = "k".repeat(9000);
        let outcome = drive_wizard(home.path(), &format!("1\nsk-🔑-emoji\n{huge}\nsk-real\nn\n")).unwrap();
        let config_text = std::fs::read_to_string(&outcome.config_path).unwrap();
        let config = av_harness::HarnessConfig::from_toml(&config_text).unwrap();
        let key_path = config.upstream_api_key_file.unwrap();
        assert_eq!(std::fs::read_to_string(key_path).unwrap(), "sk-real");
    }

    #[test]
    fn wizard_azure_builds_deployment_path() {
        let home = tempfile::tempdir().unwrap();
        let outcome = drive_wizard(home.path(), "4\nmyres\ngpt4o\nazure-key-1\nn\n").unwrap();
        let config_text = std::fs::read_to_string(&outcome.config_path).unwrap();
        let config = av_harness::HarnessConfig::from_toml(&config_text).unwrap();
        assert_eq!(config.upstream_url, "https://myres.openai.azure.com");
        assert_eq!(
            config.upstream_chat_path,
            "/openai/deployments/gpt4o/chat/completions?api-version=2024-10-21"
        );
        assert_eq!(config.upstream_auth_header, "api-key");
        assert_eq!(config.upstream_auth_scheme, "");
    }

    #[test]
    fn wizard_custom_url_optional_key() {
        let home = tempfile::tempdir().unwrap();
        // Bad URL re-asked, then good URL, no key, don't start.
        let outcome = drive_wizard(home.path(), "13\nnot-a-url\nhttp://10.0.0.5:8000\nn\nn\n").unwrap();
        let config_text = std::fs::read_to_string(&outcome.config_path).unwrap();
        let config = av_harness::HarnessConfig::from_toml(&config_text).unwrap();
        assert_eq!(config.upstream_url, "http://10.0.0.5:8000");
        assert!(config.upstream_api_key_file.is_none());
    }

    #[test]
    fn wizard_backs_up_previous_settings() {
        let home = tempfile::tempdir().unwrap();
        drive_wizard(home.path(), "11\nn\n").unwrap();
        let outcome = drive_wizard(home.path(), "12\nn\n").unwrap();
        let backup = outcome.config_path.with_extension("toml.bak");
        assert!(backup.exists(), "previous settings must be preserved");
        assert!(std::fs::read_to_string(&backup).unwrap().contains("11434"));
        let config_text = std::fs::read_to_string(&outcome.config_path).unwrap();
        assert!(config_text.contains("1234"), "new settings active");
    }

    #[test]
    fn wizard_fails_cleanly_on_closed_input() {
        let home = tempfile::tempdir().unwrap();
        let error = drive_wizard(home.path(), "").unwrap_err();
        assert!(error.to_string().contains("ended unexpectedly"), "{error}");
        assert!(
            !av_harness::config::user_config_path_from(home.path()).exists(),
            "no partial config on abort"
        );
    }

    #[test]
    fn wizard_eof_after_config_written_means_do_not_start() {
        let home = tempfile::tempdir().unwrap();
        // Input ends right after setup finishes — the config is saved, so
        // this must succeed with start_now == false, not error out.
        let outcome = drive_wizard(home.path(), "11\n").unwrap();
        assert!(!outcome.start_now);
        assert!(outcome.config_path.exists());
    }

    #[test]
    fn relative_home_is_anchored_to_an_absolute_path() {
        // A relative $HOME must not leak relative paths into the config —
        // they would break the moment the server runs from another cwd.
        let anchored = absolute_home(Path::new("odd-home")).unwrap();
        assert!(anchored.is_absolute());
        assert!(anchored.ends_with("odd-home"));
        let already = absolute_home(Path::new("/etc/xdg-home")).unwrap();
        assert_eq!(already, Path::new("/etc/xdg-home"));
    }

    #[cfg(unix)]
    #[test]
    fn wizard_replaces_config_symlink_instead_of_following_it() {
        let home = tempfile::tempdir().unwrap();
        let victim = home.path().join("victim.toml");
        std::fs::write(&victim, "untouched").unwrap();
        let config_path = av_harness::config::user_config_path_from(home.path());
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&victim, &config_path).unwrap();

        drive_wizard(home.path(), "11\nn\n").unwrap();

        assert!(
            !std::fs::symlink_metadata(&config_path)
                .unwrap()
                .file_type()
                .is_symlink(),
            "config must become a real file"
        );
        // The backup step reads through the symlink, so the pre-existing
        // "config" is preserved; the victim itself must not gain our TOML.
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "untouched");
        assert!(std::fs::read_to_string(&config_path).unwrap().contains("11434"));
    }

    /// Round-28 F1 + F5: probe_target parses URLs correctly across
    /// scheme-driven default ports, userinfo stripping, and IPv6
    /// literals.
    #[test]
    fn round_28_probe_target_parses_urls_correctly() {
        // F1: scheme-driven defaults, not the old hardcoded :80.
        assert_eq!(
            probe_target("https://api.example.com").unwrap(),
            "api.example.com:443"
        );
        assert_eq!(
            probe_target("redis://cache.example.com").unwrap(),
            "cache.example.com:6379"
        );
        assert_eq!(
            probe_target("rediss://cache.example.com").unwrap(),
            // TLS Redis defaults to 6379 like plain redis:// — redis-rs
            // (which the daemon uses) applies port().unwrap_or(6379)
            // for both schemes, and doctor must probe what the daemon
            // dials.
            "cache.example.com:6379"
        );
        assert_eq!(
            probe_target("nats://bus.example.com").unwrap(),
            "bus.example.com:4222"
        );
        // Explicit port always wins over scheme default.
        assert_eq!(
            probe_target("https://api.example.com:6333").unwrap(),
            "api.example.com:6333"
        );
        assert_eq!(
            probe_target("http://api.example.com:8080/path?q=1").unwrap(),
            "api.example.com:8080"
        );
        // Bare host without scheme defaults to :80.
        assert_eq!(probe_target("localhost").unwrap(), "localhost:80");
        assert_eq!(probe_target("localhost:6379").unwrap(), "localhost:6379");
        // F5: userinfo is stripped before the connect target so
        // credentials never reach TcpStream::connect or the failure
        // path's error text.
        let target = probe_target("redis://user:pass@cache.example.com/0").unwrap();
        assert_eq!(target, "cache.example.com:6379");
        assert!(!target.contains("user"), "userinfo leaked into target: {target}");
        assert!(!target.contains("pass"), "userinfo leaked into target: {target}");
        // IPv6 literals stay bracketed and preserve default port.
        assert_eq!(probe_target("http://[::1]").unwrap(), "[::1]:80");
        assert_eq!(
            probe_target("https://[2001:db8::1]:8443").unwrap(),
            "[2001:db8::1]:8443"
        );
        // '@' after the authority (in path/query) is not userinfo — the
        // authority must be isolated before stripping credentials.
        assert_eq!(probe_target("http://h/p@th").unwrap(), "h:80");
        assert_eq!(probe_target("http://h:8080/p@th").unwrap(), "h:8080");
        assert_eq!(probe_target("http://h?q=a@b").unwrap(), "h:80");
        // Userinfo combined with a path containing '@' still strips
        // only the real credentials.
        assert_eq!(probe_target("http://u:p@h:8080/p@th").unwrap(), "h:8080");
    }

    /// Round-40 F2: `build_probe_base` handles the four listen-form
    /// variants round-21 F6 missed. The prior string-replace pair
    /// left every `[fe80::1%eth0]:8484` config broken; the parse-
    /// based rewrite recovers correctly.
    #[test]
    fn build_probe_base_covers_ipv6_zones_and_family_dispatch() {
        // IPv4 unspecified -> IPv4 loopback.
        assert_eq!(build_probe_base("0.0.0.0:8484"), "http://127.0.0.1:8484");
        // IPv6 unspecified -> IPv6 loopback (bracketed).
        assert_eq!(build_probe_base("[::]:8484"), "http://[::1]:8484");
        // IPv6 unspecified expanded form — SocketAddr parse
        // normalises to `::` so we still get [::1].
        assert_eq!(build_probe_base("[0:0:0:0:0:0:0:0]:8484"), "http://[::1]:8484");
        // Concrete IPv4/IPv6 interface bindings are preserved.
        assert_eq!(build_probe_base("127.0.0.1:8484"), "http://127.0.0.1:8484");
        assert_eq!(
            build_probe_base("[2001:db8::1]:8484"),
            "http://[2001:db8::1]:8484"
        );
        // IPv6 with a zone id: SocketAddr parse fails on stable
        // Rust (zone ids are Rust-nightly only), so we fall through
        // to the string-fallback which now strips the zone id
        // before the URL is built. The raw `%` MUST NOT survive.
        let probed = build_probe_base("[fe80::1%eth0]:8484");
        assert!(
            !probed.contains('%'),
            "raw `%` from zone id must not survive into probe URL: {probed}"
        );
        assert!(
            probed.contains("[fe80::1]"),
            "loopback probe should still target the address (with zone id stripped): {probed}"
        );
    }
}
