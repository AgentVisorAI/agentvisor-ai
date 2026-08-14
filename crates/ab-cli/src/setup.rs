//! `abctl init` / `abctl doctor` / `abctl health` — first-run setup and
//! environment diagnosis.
//!
//! `init` writes a provider-specific `agentbridge.toml` that the harness
//! picks up automatically (it is first in the config search path), then
//! prints copy-paste next steps. `doctor` re-resolves configuration the
//! exact same way the server does and checks every runtime prerequisite
//! without printing a single secret value. `health` probes a running
//! harness and is intended for container HEALTHCHECK directives.

use anyhow::{Context, Result};
use clap::ValueEnum;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Supported provider presets for `abctl init`.
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

/// Render the annotated TOML for a plan.
fn render_config(plan: &ConfigPlan) -> String {
    let spec = spec(plan.preset);
    let chat_path = plan.chat_path.as_deref().or(spec.chat_path);
    let upstream_url = &plan.upstream_url;
    let mut out = String::new();
    out.push_str("# AgentBridge harness configuration (generated by `abctl init`).\n");
    out.push_str("# Every omitted field keeps a safe default; see config/harness.example.toml\n");
    out.push_str("# in the AgentBridge repository for the full annotated reference.\n\n");
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
    out.push_str("\n# Signed receipts, OCSF events, and ATIF trajectories are written here.\n");
    match &plan.data_root {
        Some(root) => {
            out.push_str(&format!("atif_spool_dir = \"{root}/spool\"\n"));
            out.push_str(&format!("bridge_data_dir = \"{root}/bridge\"\n"));
        }
        None => {
            out.push_str("atif_spool_dir = \"data/spool\"\n");
            out.push_str("bridge_data_dir = \"data/bridge\"\n");
        }
    }
    out
}

/// `abctl init` — write a provider-specific config and print next steps.
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
    let rendered = render_config(&plan);
    // Refuse to write anything the harness itself would reject.
    ab_harness::HarnessConfig::from_toml(&rendered)
        .map_err(|error| anyhow::anyhow!("generated config failed validation (bug): {error}"))?;
    if output.exists() && !force {
        anyhow::bail!("{} already exists; pass --force to overwrite", output.display());
    }
    if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).with_context(|| format!("create directory {}", parent.display()))?;
    }
    std::fs::write(output, &rendered).with_context(|| format!("write {}", output.display()))?;
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
    println!("  {step}. agent-bridge        # starts on 127.0.0.1:8484");
    step += 1;
    println!("  {step}. point your OpenAI-compatible client at http://127.0.0.1:8484/v1");
    println!();
    println!("Check the environment any time with: abctl doctor");
    Ok(())
}

// ---------------------------------------------------------------------------
// Guided setup (bare `abctl`) and `abctl start` — the no-experience path.
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
/// (vllm, llamacpp, litellm) stay available through `abctl init`.
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

fn ask_secret(prompt: &str, input: &mut dyn std::io::BufRead, mode: &SecretInput) -> Result<String> {
    match mode {
        SecretInput::Hidden => {
            rpassword::prompt_password(format!("{prompt} (typing is hidden): ")).context("read key")
        }
        SecretInput::Plain => ask_line(&format!("{prompt}: "), input),
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
fn write_private_key_file(path: &Path, key: &str) -> Result<()> {
    use std::io::Write as _;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create key directory {}", parent.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    let _ = std::fs::remove_file(path);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("create key file {}", path.display()))?;
    file.write_all(key.as_bytes())
        .with_context(|| format!("write key file {}", path.display()))?;
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

/// The guided setup: two questions (provider, key), everything stored
/// under `home/.agentbridge/` so no environment variables, exports, or
/// file editing are ever needed. Drive `input` with scripted answers and
/// `SecretInput::Plain` in tests.
pub fn wizard(home: &Path, input: &mut dyn std::io::BufRead, secrets: &SecretInput) -> Result<WizardOutcome> {
    println!("Welcome to AgentBridge! Two quick questions and you're done.");
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
            (url, None, needs_key)
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
    let root = home.join(".agentbridge");
    std::fs::create_dir_all(&root)
        .with_context(|| format!("create settings directory {}", root.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700));
    }
    let key_file = if needs_key {
        let name = friendly_name(preset);
        let mut key = None;
        for _ in 0..5 {
            let pasted = ask_secret(&format!("\nPaste your {name} API key"), input, secrets)?;
            let pasted = pasted.trim();
            if pasted.is_empty() {
                println!("The key looked empty — please paste it again.");
                continue;
            }
            if pasted.chars().any(char::is_control) {
                println!("That key contains characters that don't belong — please try again.");
                continue;
            }
            key = Some(pasted.to_owned());
            break;
        }
        let Some(key) = key else {
            anyhow::bail!("no API key provided");
        };
        let path = root.join("keys").join(format!("{}.key", slug(preset)));
        write_private_key_file(&path, &key)?;
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
    ab_harness::HarnessConfig::from_toml(&rendered)
        .map_err(|error| anyhow::anyhow!("generated config failed validation (bug): {error}"))?;
    let config_path = ab_harness::config::user_config_path_from(home);
    if config_path.exists() {
        let backup = config_path.with_extension("toml.bak");
        std::fs::copy(&config_path, &backup).with_context(|| format!("back up {}", config_path.display()))?;
        println!("\n(Your previous settings were saved to {})", backup.display());
    }
    std::fs::write(&config_path, &rendered).with_context(|| format!("write {}", config_path.display()))?;

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
    let start_now = ask_yes_no("\nStart AgentBridge now? [Y/n]: ", input, true)?;
    Ok(WizardOutcome {
        config_path,
        start_now,
    })
}

/// Is a harness answering at `base` right now?
async fn health_ok(base: &str) -> bool {
    let Ok(client) = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(1))
        .build()
    else {
        return false;
    };
    matches!(
        client.get(format!("{base}/health")).send().await,
        Ok(response) if response.status().is_success()
    )
}

/// Prefer the server binary installed next to abctl; fall back to PATH.
fn find_server_binary() -> PathBuf {
    let name = if cfg!(windows) {
        "agent-bridge.exe"
    } else {
        "agent-bridge"
    };
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sibling = dir.join(name);
            if sibling.is_file() {
                return sibling;
            }
        }
    }
    PathBuf::from(name)
}

/// Print the last `count` log lines, unwrapping the JSON envelope when
/// possible so failures read like sentences instead of telemetry.
fn print_log_tail(path: &Path, count: usize) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
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
        eprintln!("    {friendly}");
    }
}

fn print_usage_banner(base: &str) {
    println!();
    println!("  Use it from any OpenAI-compatible app:");
    println!("    Base URL: {base}/v1");
    println!("    API key:  anything (your real key stays on this machine)");
    println!();
}

/// `abctl start` — run the server in the foreground with friendly output.
/// Logs go to a file so the terminal stays readable; Ctrl-C stops both
/// processes gracefully (the server flushes trajectories on shutdown).
pub async fn start() -> Result<()> {
    // Friendly pre-checks with the exact resolution the server uses.
    let not_set_up = matches!(
        ab_harness::config::resolve_config_source(),
        Ok(ab_harness::config::ConfigSource::BuiltIn)
    ) && std::env::var_os("AB_UPSTREAM_URL").is_none_or(|value| value.is_empty());
    if not_set_up {
        anyhow::bail!(
            "AgentBridge is not set up yet.\nRun `abctl` (no arguments) and answer two questions, then try again."
        );
    }
    let (config, source) = ab_harness::config::load_config().map_err(|error| {
        anyhow::anyhow!("configuration problem: {error}\nRun `abctl doctor` for a full diagnosis.")
    })?;
    let probe_host = config.listen.replace("0.0.0.0", "127.0.0.1");
    let base = format!("http://{probe_host}");

    if health_ok(&base).await {
        println!("AgentBridge is already running at {base}");
        print_usage_banner(&base);
        return Ok(());
    }

    let binary = find_server_binary();
    let log_path = ab_harness::config::user_config_path()
        .and_then(|path| Some(path.parent()?.join("agent-bridge.log")))
        .unwrap_or_else(|| PathBuf::from("agent-bridge.log"));
    if let Some(parent) = log_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("open log file {}", log_path.display()))?;
    let log_err = log.try_clone().context("clone log handle")?;

    println!("Starting AgentBridge (settings: {source})...");
    let mut command = tokio::process::Command::new(&binary);
    command
        .stdout(std::process::Stdio::from(log))
        .stderr(std::process::Stdio::from(log_err));
    // When running from the per-user config, keep every file the server
    // creates (signing seed included) inside ~/.agentbridge/ instead of
    // scattering a config/ directory into whatever folder we run from.
    if std::env::var_os("AB_SIGNING_SEED_FILE").is_none() {
        if let ab_harness::config::ConfigSource::File(config_path) = &source {
            if Some(config_path) == ab_harness::config::user_config_path().as_ref() {
                if let Some(root) = config_path.parent() {
                    command.env("AB_SIGNING_SEED_FILE", root.join("signing.seed"));
                }
            }
        }
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("could not run {}", binary.display()))?;

    // Wait until healthy — or explain why it died.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = child.try_wait().context("check server status")? {
            eprintln!("AgentBridge stopped right away ({status}). Last log lines:");
            print_log_tail(&log_path, 12);
            anyhow::bail!("startup failed — run `abctl doctor` for a diagnosis");
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
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    println!("✓ AgentBridge is running at {base}");
    print_usage_banner(&base);
    println!("  Log file: {}", log_path.display());
    println!("  Press Ctrl-C to stop.");

    tokio::select! {
        status = child.wait() => {
            let status = status.context("wait for server")?;
            if status.success() {
                println!("AgentBridge stopped.");
            } else {
                eprintln!("AgentBridge exited unexpectedly ({status}). Last log lines:");
                print_log_tail(&log_path, 12);
                anyhow::bail!("server exited unexpectedly");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            println!("\nStopping AgentBridge...");
            // The server received the same Ctrl-C (same terminal group)
            // and shuts down gracefully; force only if it hangs.
            match tokio::time::timeout(Duration::from_secs(10), child.wait()).await {
                Ok(_) => println!("Stopped. Your data is saved."),
                Err(_) => {
                    let _ = child.start_kill();
                    let _ = child.wait().await;
                    println!("Stopped (forced).");
                }
            }
        }
    }
    Ok(())
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

/// `abctl doctor` — resolve config exactly like the server and verify every
/// runtime prerequisite. Never prints secret values, only source names.
pub async fn doctor(offline: bool) -> Result<()> {
    let mut checks = Vec::new();

    // 1. Config resolution (same search order as the server).
    let resolved = ab_harness::config::load_config();
    let config = match resolved {
        Ok((config, source)) => {
            checks.push(Check::Pass(format!("config: {source}")));
            Some(config)
        }
        Err(error) => {
            checks.push(Check::Fail(format!("config: {error}")));
            None
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
        let auth = ab_harness::pipeline::describe_upstream_auth(config);
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
            match std::fs::metadata(file) {
                Ok(_) => checks.push(Check::Pass(format!("upstream auth: {auth}"))),
                Err(error) => {
                    checks.push(Check::Fail(format!("upstream auth: {auth} — {error}")));
                }
            }
        } else {
            checks.push(Check::Pass(format!("upstream auth: {auth}")));
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
                    "upstream: {url} reachable (HTTP {})",
                    response.status().as_u16()
                ))),
                Err(error) => {
                    // Sanitize: reqwest Display includes the URL, never a key.
                    checks.push(Check::Fail(format!("upstream: {url} unreachable ({error})")));
                }
            }
        }

        // 5. Bridge manifest.
        match std::fs::read_to_string(&config.bridge_manifest_path) {
            Ok(text) => match ab_bridge::BridgeManifest::from_yaml(&text) {
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
            } else if ab_harness::HarnessConfig::is_default_policy_path(path) {
                checks.push(Check::Pass(format!("policy: {path} (embedded built-in)")));
            } else {
                checks.push(Check::Fail(format!("policy: {path} not found")));
            }
        }

        // 7. Tool schemas.
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
                            "tool schemas: none in {dir}; tool calls will be rejected"
                        )));
                    }
                }
                Err(_) if config.uses_default_tool_schema_dir() => checks.push(Check::Warn(
                    "tool schemas: default directory missing; tool calls will be rejected".to_owned(),
                )),
                Err(error) => checks.push(Check::Fail(format!("tool schemas: {dir}: {error}"))),
            },
            None => checks.push(Check::Warn(
                "tool schemas: no directory configured; tool calls will be rejected".to_owned(),
            )),
        }

        // 8. Signing seed (created on first run if absent).
        let seed_path = std::env::var_os("AB_SIGNING_SEED_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("config/signing.seed"));
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
                    Ok(_) => checks.push(Check::Pass(format!("signing seed: {}", seed_path.display()))),
                    Err(error) => {
                        checks.push(Check::Fail(format!(
                            "signing seed: {}: {error}",
                            seed_path.display()
                        )));
                    }
                }
            }
            #[cfg(not(unix))]
            checks.push(Check::Pass(format!("signing seed: {}", seed_path.display())));
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
            // ownership, ACLs, and read-only mounts.
            let probe = probe_parent.join(format!(".abctl-doctor-{}", std::process::id()));
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&probe)
            {
                Ok(_) => {
                    let _ = std::fs::remove_file(&probe);
                    checks.push(Check::Pass(format!("{label}: {dir}")));
                }
                Err(error) => checks.push(Check::Fail(format!(
                    "{label}: cannot write in {} ({error})",
                    probe_parent.display()
                ))),
            }
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
                match probe_endpoint(endpoint).await {
                    Ok(()) => checks.push(Check::Pass(format!("{label}: {endpoint} reachable"))),
                    Err(error) => {
                        checks.push(Check::Fail(format!("{label}: {endpoint} unreachable ({error})")));
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

    println!("abctl doctor");
    let (warnings, failures) = report(&checks);
    println!();
    if failures > 0 {
        anyhow::bail!("{failures} check(s) failed, {warnings} warning(s)");
    }
    println!("all checks passed ({warnings} warning(s))");
    Ok(())
}

/// TCP-connect to `host:port` extracted from a URL or bare `host:port`.
async fn probe_endpoint(endpoint: &str) -> Result<()> {
    let target = match endpoint.split_once("://") {
        Some((_, rest)) => rest.split(['/', '?']).next().unwrap_or(rest),
        None => endpoint,
    };
    let target = if target.contains(':') {
        target.to_owned()
    } else {
        // Scheme-driven default port for schemeless probing.
        format!("{target}:80")
    };
    tokio::time::timeout(Duration::from_secs(3), tokio::net::TcpStream::connect(&target))
        .await
        .map_err(|_| anyhow::anyhow!("timeout"))?
        .map(|_| ())
        .map_err(anyhow::Error::from)
}

/// `abctl health` — probe a running harness; exit 0 only on HTTP 200.
pub async fn health(base_url: &str) -> Result<()> {
    let url = format!("{}/health", base_url.trim_end_matches('/'));
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
            let config = ab_harness::HarnessConfig::from_toml(&rendered)
                .unwrap_or_else(|error| panic!("{preset:?}: {error}"));
            assert!(!config.upstream_url.is_empty(), "{preset:?} upstream_url");
        }
        // Custom with an explicit URL also validates.
        let rendered = render_config(&plan_for(Preset::Custom, "http://10.0.0.5:9000", Some("MY_KEY")));
        ab_harness::HarnessConfig::from_toml(&rendered).unwrap();
    }

    #[test]
    fn azure_preset_uses_raw_key_header() {
        let s = spec(Preset::Azure);
        let rendered = render_config(&plan_for(Preset::Azure, s.upstream_url, s.key_env));
        let config = ab_harness::HarnessConfig::from_toml(&rendered).unwrap();
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
            let config = ab_harness::HarnessConfig::from_toml(&rendered).unwrap();
            assert!(config.upstream_api_key_env.is_none());
            assert!(config.upstream_api_key_file.is_none());
        }
    }

    #[test]
    fn init_writes_and_refuses_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agentbridge.toml");
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
        let path = dir.path().join("agentbridge.toml");
        let error = init(Preset::Custom, &path, false, None, None).unwrap_err();
        assert!(error.to_string().contains("--upstream-url"), "{error}");
    }

    /// User-supplied values are interpolated into TOML: anything that could
    /// escape the string literal must be rejected, not written.
    #[test]
    fn init_rejects_toml_injection_attempts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agentbridge.toml");
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
        let config = ab_harness::HarnessConfig::from_toml(&config_text).unwrap();
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
            ab_harness::config::user_config_path_from(home.path())
        );
    }

    #[test]
    fn wizard_local_provider_needs_no_key() {
        let home = tempfile::tempdir().unwrap();
        // Choice 11 (Ollama), start now (default Y via empty line).
        let outcome = drive_wizard(home.path(), "11\n\n").unwrap();
        assert!(outcome.start_now);
        let config_text = std::fs::read_to_string(&outcome.config_path).unwrap();
        let config = ab_harness::HarnessConfig::from_toml(&config_text).unwrap();
        assert_eq!(config.upstream_url, "http://127.0.0.1:11434");
        assert!(config.upstream_api_key_file.is_none());
        assert!(!home.path().join(".agentbridge/keys").exists());
    }

    #[test]
    fn wizard_reasks_on_invalid_choice_and_empty_key() {
        let home = tempfile::tempdir().unwrap();
        // 99 and "abc" are re-asked; 2 = Anthropic; empty key re-asked.
        let outcome = drive_wizard(home.path(), "99\nabc\n2\n\nsk-ant\nn\n").unwrap();
        let config_text = std::fs::read_to_string(&outcome.config_path).unwrap();
        let config = ab_harness::HarnessConfig::from_toml(&config_text).unwrap();
        assert_eq!(config.upstream_url, "https://api.anthropic.com");
        let key_path = config.upstream_api_key_file.unwrap();
        assert_eq!(std::fs::read_to_string(key_path).unwrap(), "sk-ant");
    }

    #[test]
    fn wizard_azure_builds_deployment_path() {
        let home = tempfile::tempdir().unwrap();
        let outcome = drive_wizard(home.path(), "4\nmyres\ngpt4o\nazure-key-1\nn\n").unwrap();
        let config_text = std::fs::read_to_string(&outcome.config_path).unwrap();
        let config = ab_harness::HarnessConfig::from_toml(&config_text).unwrap();
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
        let config = ab_harness::HarnessConfig::from_toml(&config_text).unwrap();
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
            !ab_harness::config::user_config_path_from(home.path()).exists(),
            "no partial config on abort"
        );
    }
}
