//! Operator-authenticated revocation commands. Credentials never enter argv
//! or server-response diagnostics.

use anyhow::{bail, Context, Result};
use clap::{Args, ValueEnum};
use serde::Deserialize;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

#[derive(Debug, Args)]
pub(crate) struct Options {
    /// Harness base URL; repeat to reach every replica using memory state.
    #[arg(long = "url", default_value = "http://127.0.0.1:8484")]
    pub urls: Vec<String>,
    /// Owner-only credential file. Also accepts AV_OPERATOR_TOKEN_FILE;
    /// otherwise reads the separate operator credential from AV_OPERATOR_TOKEN.
    #[arg(long)]
    pub operator_token_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum TokenKind {
    Nhi,
    Exchanged,
}

pub(crate) enum Target<'a> {
    Token { jti: &'a str, kind: TokenKind },
    Instance(&'a str),
}

impl Target<'_> {
    fn body(&self) -> Result<serde_json::Value> {
        match self {
            Self::Token { jti, kind } => {
                validate_identifier(jti, 256, "jti")?;
                Ok(
                    serde_json::json!({ "jti": jti, "token_kind": match kind { TokenKind::Nhi => "nhi", TokenKind::Exchanged => "exchanged" } }),
                )
            }
            Self::Instance(uid) => {
                validate_identifier(uid, 128, "instance_uid")?;
                Ok(serde_json::json!({ "instance_uid": uid }))
            }
        }
    }
}

fn validate_identifier(value: &str, max: usize, field: &str) -> Result<()> {
    if value.trim().is_empty()
        || value.chars().count() > max
        || value.chars().any(char::is_control)
        || av_core::text::contains_bidi_or_zero_width(value)
    {
        bail!("{field} must contain 1–{max} characters without control or invisible formatting characters");
    }
    Ok(())
}

fn endpoint(base: &str) -> Result<reqwest::Url> {
    let mut url = reqwest::Url::parse(base).context("invalid harness URL")?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("harness URL must not contain credentials, a query, or a fragment");
    }
    let loopback = url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        bail!("operator credentials require HTTPS, except for HTTP on loopback");
    }
    url.path_segments_mut()
        .map_err(|()| anyhow::anyhow!("harness URL cannot carry an API path"))?
        .pop_if_empty()
        .extend(["admin", "v1", "revocations"]);
    Ok(url)
}

fn read_credential_file(path: &Path) -> Result<Zeroizing<String>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(av_core::fsutil::unix_o_nofollow() | av_core::fsutil::unix_o_nonblock());
    }
    let file = options.open(path).context("open operator credential file")?;
    let metadata = file.metadata().context("inspect operator credential file")?;
    if !metadata.is_file() {
        bail!("operator credential must be a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("operator credential file must be owner-only; set its permissions to 0600");
        }
    }
    let mut raw = Zeroizing::new(String::new());
    file.take(16 * 1024 + 1)
        .read_to_string(&mut raw)
        .context("read operator credential file")?;
    if raw.len() > 16 * 1024 {
        bail!("operator credential exceeds 16 KiB");
    }
    Ok(raw)
}

fn credential(options: &Options) -> Result<Zeroizing<String>> {
    let path = options
        .operator_token_file
        .clone()
        .or_else(|| std::env::var_os("AV_OPERATOR_TOKEN_FILE").map(PathBuf::from));
    let raw = match path {
        Some(path) => read_credential_file(&path)?,
        None => Zeroizing::new(std::env::var("AV_OPERATOR_TOKEN").map_err(|_| {
            anyhow::anyhow!("provide --operator-token-file, AV_OPERATOR_TOKEN_FILE, or AV_OPERATOR_TOKEN")
        })?),
    };
    let token = Zeroizing::new(raw.trim().to_owned());
    if token.len() < 32 || token.len() > 4096 || !token.bytes().all(|b| b.is_ascii_graphic()) {
        bail!("operator credential must contain 32–4096 printable ASCII characters without whitespace");
    }
    Ok(token)
}

#[derive(Deserialize)]
struct Acknowledgement {
    revoked: bool,
    audited: bool,
    #[serde(default)]
    issued_at_or_before: Option<u64>,
}

pub(crate) async fn run(options: &Options, target: Target<'_>) -> Result<()> {
    let body = target.body()?;
    // Validate all destinations before sending the first revocation.
    let endpoints = options
        .urls
        .iter()
        .map(|url| endpoint(url))
        .collect::<Result<Vec<_>>>()?;
    let token = credential(options)?;
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("build operator revocation client")?;
    let mut failed = 0;
    for endpoint in endpoints {
        let label = crate::sanitize_for_terminal(endpoint.as_str());
        match revoke(&client, endpoint, &token, &body).await {
            Ok(ack) => {
                println!("{label}: Revocation was recorded. The server does not confirm that the target token exists.");
                if let Some(cutoff) = ack.issued_at_or_before {
                    println!("Tokens issued at or before epoch second {cutoff} are revoked; later tokens remain usable.");
                }
                if !ack.audited {
                    eprintln!("WARNING: {label}: Revocation succeeded, but its signed audit receipt could not be confirmed. Check the harness audit logs.");
                }
            }
            Err(error) => {
                failed += 1;
                eprintln!("{label}: {error}");
            }
        }
    }
    if failed > 0 {
        bail!("revocation failed or was not acknowledged by {failed} destination(s)");
    }
    Ok(())
}

async fn revoke(
    client: &reqwest::Client,
    endpoint: reqwest::Url,
    token: &str,
    body: &serde_json::Value,
) -> Result<Acknowledgement> {
    let response = client
        .post(endpoint)
        .bearer_auth(token)
        .json(body)
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("operator revocation request failed; check connectivity and TLS"))?;
    let status = response.status();
    if !status.is_success() {
        // Do not print a server-controlled body: a malicious or misconfigured
        // endpoint might echo the Authorization header into its error message.
        bail!(
            "operator revocation returned HTTP {}; redirects are not followed",
            status.as_u16()
        );
    }
    let body = crate::read_capped_response(response, av_core::fsutil::MAX_CONTROL_BYTES)
        .await
        .map_err(|_| {
            anyhow::anyhow!("could not read the revocation acknowledgement; it may already be recorded")
        })?;
    let ack: Acknowledgement = serde_json::from_str(&body)
        .map_err(|_| anyhow::anyhow!("invalid revocation acknowledgement; it may already be recorded"))?;
    if !ack.revoked {
        bail!("the server did not acknowledge a successful revocation");
    }
    Ok(ack)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use clap::Parser as _;

    #[test]
    fn parses_targets_and_rejects_token_arguments() {
        let parsed = crate::Cli::try_parse_from([
            "avctl",
            "token-revoke",
            "--jti",
            "one",
            "--token-kind",
            "exchanged",
        ])
        .unwrap();
        assert!(matches!(
            parsed.command,
            Some(crate::Command::TokenRevoke {
                token_kind: TokenKind::Exchanged,
                ..
            })
        ));
        assert!(
            crate::Cli::try_parse_from(["avctl", "instance-revoke", "--instance-uid", "agent-a"]).is_ok()
        );
        for args in [
            vec!["avctl", "token-revoke"],
            vec![
                "avctl",
                "token-revoke",
                "--jti",
                "one",
                "--operator-token",
                "secret",
            ],
            vec![
                "avctl",
                "token-revoke",
                "--jti",
                "one",
                "--instance-uid",
                "agent-a",
            ],
        ] {
            assert!(crate::Cli::try_parse_from(args).is_err());
        }
    }

    #[test]
    fn endpoint_requires_tls_except_loopback_and_has_no_credentials() {
        for valid in [
            "http://127.0.0.1:8484",
            "http://[::1]:8484",
            "http://localhost:8484",
            "https://harness.example/gateway",
        ] {
            assert!(endpoint(valid).is_ok(), "{valid}");
        }
        for invalid in [
            "http://harness.example",
            "http://127.0.0.1.example",
            "https://user:secret@harness.example",
            "https://harness.example?token=secret",
            "https://harness.example#token",
            "ftp://127.0.0.1",
        ] {
            assert!(endpoint(invalid).is_err(), "{invalid}");
        }
        assert_eq!(
            endpoint("https://harness.example/gateway/").unwrap().as_str(),
            "https://harness.example/gateway/admin/v1/revocations"
        );
    }

    #[cfg(unix)]
    #[test]
    fn credential_files_must_be_private_regular_files_without_symlinks() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("operator-token");
        std::fs::write(&file, "secret").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_credential_file(&file).is_err());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_credential_file(&file).unwrap().as_str(), "secret");
        let link = dir.path().join("linked-token");
        symlink(&file, &link).unwrap();
        assert!(read_credential_file(&link).is_err());
        assert!(read_credential_file(dir.path()).is_err());
    }
}
