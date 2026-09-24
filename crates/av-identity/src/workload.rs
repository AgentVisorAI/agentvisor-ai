//! Platform workload identity: RFC 7523 JWT-bearer assertions signed with a
//! Cloud Foundry instance identity certificate.
//!
//! Cloud Foundry gives every app instance an X.509 certificate and RSA key
//! (paths in `CF_INSTANCE_CERT` and `CF_INSTANCE_KEY`), rotated before they
//! expire. The certificate's subject names the instance (`CN`) and, in `OU`
//! values, its `app:<guid>`, `space:<guid>`, and `organization:<guid>`.
//!
//! An app (or the AgentVisor sidecar beside it) proves that identity by
//! sending `/v1/token` an RFC 7523 assertion
//! (`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`): a short-lived
//! JWT signed `RS256` with the instance key, whose `x5c` header carries the
//! instance certificate and its intermediates. [`WorkloadTrust::verify`]
//! checks, in order:
//!
//! 1. size, JOSE header (`alg = RS256`, 1 to 4 `x5c` certificates);
//! 2. the certificate chain up to a configured instance-identity root, valid
//!    now, with the clientAuth extended key usage;
//! 3. the assertion signature with the certificate's key;
//! 4. the claims: `aud` names the gateway, `sub` is the instance GUID, the
//!    lifetime is at most [`MAX_ASSERTION_LIFETIME_S`], and `jti` is present;
//! 5. `jti` was not seen before (a bounded replay cache).
//!
//! The caller then maps the verified identity to a configured workload,
//! which names the human principal the agent acts for, and issues a
//! gateway-signed agent token.

use base64::Engine as _;
use rustls_pki_types::{CertificateDer, TrustAnchor, UnixTime};
use serde::Deserialize;
use std::collections::HashMap;

/// RFC 7523 §2.1 grant type.
pub const JWT_BEARER_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// Longest accepted assertion lifetime (`exp - iat`), in seconds.
pub const MAX_ASSERTION_LIFETIME_S: u64 = 300;

/// Tolerated clock difference, in seconds.
const CLOCK_SKEW_S: u64 = 60;

/// Largest accepted assertion, before any decoding.
const MAX_ASSERTION_BYTES: usize = 48 * 1024;

/// Most certificates accepted in `x5c` (leaf plus intermediates).
const MAX_CHAIN_CERTS: usize = 4;

/// Largest single certificate accepted.
const MAX_CERT_BYTES: usize = 16 * 1024;

/// Most unexpired assertion ids remembered for replay detection.
const MAX_REPLAY_ENTRIES: usize = 100_000;

/// Signature algorithms accepted on the certificate chain.
static CHAIN_ALGORITHMS: &[&dyn rustls_pki_types::SignatureVerificationAlgorithm] = &[
    webpki::ring::RSA_PKCS1_2048_8192_SHA256,
    webpki::ring::RSA_PKCS1_2048_8192_SHA384,
    webpki::ring::RSA_PKCS1_2048_8192_SHA512,
    webpki::ring::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    webpki::ring::ECDSA_P256_SHA256,
    webpki::ring::ECDSA_P384_SHA384,
];

/// Why an assertion was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum WorkloadError {
    /// Not a well-formed RS256 JWT with an `x5c` chain.
    #[error("malformed assertion: {0}")]
    Malformed(String),
    /// The certificate chain does not lead to a trusted root.
    #[error("certificate chain rejected: {0}")]
    Chain(String),
    /// The assertion signature does not verify with the certificate key.
    #[error("assertion signature does not verify")]
    Signature,
    /// The claims are invalid (audience, lifetime, subject, id).
    #[error("invalid assertion claims: {0}")]
    Claims(String),
    /// The certificate subject lacks the instance-identity fields.
    #[error("certificate subject is not a Cloud Foundry instance identity: {0}")]
    Subject(String),
    /// This assertion id was already used.
    #[error("assertion was already used")]
    Replay,
    /// The trust configuration is invalid.
    #[error("invalid workload trust configuration: {0}")]
    Config(String),
}

/// The platform identity proven by a verified assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfInstanceIdentity {
    /// Instance GUID (certificate `CN`).
    pub instance_guid: String,
    /// App GUID (`OU=app:<guid>`).
    pub app_guid: String,
    /// Space GUID (`OU=space:<guid>`).
    pub space_guid: String,
    /// Organization GUID (`OU=organization:<guid>`).
    pub org_guid: String,
}

/// A verified assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAssertion {
    /// The proven platform identity.
    pub identity: CfInstanceIdentity,
    /// Assertion id.
    pub jti: String,
    /// Assertion expiry, epoch seconds.
    pub exp: u64,
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    #[serde(default)]
    x5c: Vec<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AudienceClaim {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: AudienceClaim,
    iat: u64,
    exp: u64,
    #[serde(default)]
    nbf: Option<u64>,
    jti: String,
}

/// Trusted instance-identity roots plus the replay cache.
pub struct WorkloadTrust {
    anchors: Vec<TrustAnchor<'static>>,
    seen: parking_lot::Mutex<HashMap<(String, String), u64>>,
}

impl WorkloadTrust {
    /// Trust the `CERTIFICATE` blocks of a PEM bundle as roots.
    pub fn from_pem(pem: &[u8]) -> Result<Self, WorkloadError> {
        let text =
            std::str::from_utf8(pem).map_err(|_| WorkloadError::Config("CA bundle is not UTF-8".into()))?;
        let mut anchors = Vec::new();
        let mut rest = text;
        while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
            let body_start = start.saturating_add("-----BEGIN CERTIFICATE-----".len());
            let body_and_rest = rest.get(body_start..).unwrap_or_default();
            let end = body_and_rest
                .find("-----END CERTIFICATE-----")
                .ok_or_else(|| WorkloadError::Config("unterminated CERTIFICATE block".into()))?;
            let body: String = body_and_rest
                .get(..end)
                .unwrap_or_default()
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            let der = base64::engine::general_purpose::STANDARD
                .decode(body)
                .map_err(|_| WorkloadError::Config("CERTIFICATE block is not base64".into()))?;
            let cert = CertificateDer::from(der);
            let anchor = webpki::anchor_from_trusted_cert(&cert)
                .map_err(|error| WorkloadError::Config(format!("unusable CA certificate: {error:?}")))?
                .to_owned();
            anchors.push(anchor);
            rest = body_and_rest
                .get(end.saturating_add("-----END CERTIFICATE-----".len())..)
                .unwrap_or_default();
        }
        if anchors.is_empty() {
            return Err(WorkloadError::Config("CA bundle contains no certificate".into()));
        }
        Ok(Self {
            anchors,
            seen: parking_lot::Mutex::new(HashMap::new()),
        })
    }

    /// Number of trusted roots.
    pub fn anchor_count(&self) -> usize {
        self.anchors.len()
    }

    /// Verify an assertion addressed to `audience` at `now_s`.
    pub fn verify(
        &self,
        assertion: &str,
        audience: &str,
        now_s: u64,
    ) -> Result<VerifiedAssertion, WorkloadError> {
        if assertion.len() > MAX_ASSERTION_BYTES {
            return Err(WorkloadError::Malformed("assertion is too large".into()));
        }
        let mut parts = assertion.split('.');
        let (Some(header_b64), Some(claims_b64), Some(signature_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(WorkloadError::Malformed("not a compact JWS".into()));
        };
        let url = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header: Header = serde_json::from_slice(
            &url.decode(header_b64)
                .map_err(|_| WorkloadError::Malformed("header is not base64url".into()))?,
        )
        .map_err(|_| WorkloadError::Malformed("header is not a JOSE header".into()))?;
        if header.alg != "RS256" {
            return Err(WorkloadError::Malformed(format!(
                "alg {:?} is not RS256",
                header.alg
            )));
        }
        if header.x5c.is_empty() || header.x5c.len() > MAX_CHAIN_CERTS {
            return Err(WorkloadError::Malformed(format!(
                "x5c must carry 1 to {MAX_CHAIN_CERTS} certificates"
            )));
        }
        let mut chain = Vec::with_capacity(header.x5c.len());
        for encoded in &header.x5c {
            let der = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| WorkloadError::Malformed("x5c entry is not base64".into()))?;
            if der.len() > MAX_CERT_BYTES {
                return Err(WorkloadError::Malformed("x5c certificate is too large".into()));
            }
            chain.push(CertificateDer::from(der));
        }
        let (leaf, intermediates) = chain
            .split_first()
            .ok_or_else(|| WorkloadError::Malformed("x5c is empty".into()))?;
        let end_entity = webpki::EndEntityCert::try_from(leaf)
            .map_err(|error| WorkloadError::Chain(format!("leaf certificate: {error:?}")))?;
        let time = UnixTime::since_unix_epoch(std::time::Duration::from_secs(now_s));
        end_entity
            .verify_for_usage(
                CHAIN_ALGORITHMS,
                &self.anchors,
                intermediates,
                time,
                webpki::KeyUsage::client_auth(),
                None,
                None,
            )
            .map_err(|error| WorkloadError::Chain(format!("{error:?}")))?;
        let signature = url
            .decode(signature_b64)
            .map_err(|_| WorkloadError::Malformed("signature is not base64url".into()))?;
        let signing_input = assertion
            .get(
                ..header_b64
                    .len()
                    .saturating_add(1)
                    .saturating_add(claims_b64.len()),
            )
            .ok_or_else(|| WorkloadError::Malformed("signing input".into()))?;
        end_entity
            .verify_signature(
                webpki::ring::RSA_PKCS1_2048_8192_SHA256,
                signing_input.as_bytes(),
                &signature,
            )
            .map_err(|_| WorkloadError::Signature)?;

        let identity = cf_identity(end_entity.subject())?;
        let claims: Claims = serde_json::from_slice(
            &url.decode(claims_b64)
                .map_err(|_| WorkloadError::Malformed("claims are not base64url".into()))?,
        )
        .map_err(|_| WorkloadError::Claims("claims must include iss, sub, aud, iat, exp, jti".into()))?;
        let audience_ok = match &claims.aud {
            AudienceClaim::One(aud) => aud == audience,
            AudienceClaim::Many(auds) => auds.iter().any(|aud| aud == audience),
        };
        if !audience_ok {
            return Err(WorkloadError::Claims("aud does not name this gateway".into()));
        }
        if claims.iss.trim().is_empty() {
            return Err(WorkloadError::Claims("iss is empty".into()));
        }
        if claims.sub != identity.instance_guid {
            return Err(WorkloadError::Claims(
                "sub must be the instance GUID of the certificate".into(),
            ));
        }
        if claims.jti.trim().is_empty() || claims.jti.len() > 256 || claims.jti.chars().any(char::is_control)
        {
            return Err(WorkloadError::Claims(
                "jti must be 1-256 printable characters".into(),
            ));
        }
        if claims.exp <= now_s {
            return Err(WorkloadError::Claims("assertion has expired".into()));
        }
        if claims.iat > now_s.saturating_add(CLOCK_SKEW_S)
            || claims
                .nbf
                .is_some_and(|nbf| nbf > now_s.saturating_add(CLOCK_SKEW_S))
        {
            return Err(WorkloadError::Claims("assertion is not yet valid".into()));
        }
        if claims.exp < claims.iat || claims.exp.saturating_sub(claims.iat) > MAX_ASSERTION_LIFETIME_S {
            return Err(WorkloadError::Claims(format!(
                "assertion lifetime must be at most {MAX_ASSERTION_LIFETIME_S} seconds"
            )));
        }
        self.remember(&identity.instance_guid, &claims.jti, claims.exp, now_s)?;
        Ok(VerifiedAssertion {
            identity,
            jti: claims.jti,
            exp: claims.exp,
        })
    }

    /// Record an assertion id, refusing one already seen. Entries expire
    /// with their assertion; a full cache of live entries fails closed.
    fn remember(&self, instance: &str, jti: &str, exp: u64, now_s: u64) -> Result<(), WorkloadError> {
        let mut seen = self.seen.lock();
        let key = (instance.to_owned(), jti.to_owned());
        if seen.get(&key).is_some_and(|expires| *expires > now_s) {
            return Err(WorkloadError::Replay);
        }
        if seen.len() >= MAX_REPLAY_ENTRIES {
            seen.retain(|_, expires| *expires > now_s);
            if seen.len() >= MAX_REPLAY_ENTRIES {
                return Err(WorkloadError::Claims(
                    "too many live assertions; retry shortly".into(),
                ));
            }
        }
        seen.insert(key, exp.saturating_add(CLOCK_SKEW_S));
        Ok(())
    }
}

/// Split one DER TLV off the front of `input`: `(tag, value, rest)`.
fn tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (length, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return None;
        }
        let (bytes, rest) = rest.split_at_checked(count)?;
        let mut length = 0_usize;
        for byte in bytes {
            length = length.checked_mul(256)?.checked_add(usize::from(*byte))?;
        }
        (length, rest)
    };
    let (value, rest) = rest.split_at_checked(length)?;
    Some((tag, value, rest))
}

const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
const OID_ORGANIZATIONAL_UNIT: &[u8] = &[0x55, 0x04, 0x0b];

/// `(attribute OID, text)` pairs of an X.509 Name, given the contents of its
/// outer SEQUENCE. String types other than UTF8String, PrintableString, and
/// IA5String are skipped.
fn name_attributes(mut name: &[u8]) -> Option<Vec<(Vec<u8>, String)>> {
    let mut attributes = Vec::new();
    while !name.is_empty() {
        let (set_tag, mut set, rest) = tlv(name)?;
        if set_tag != 0x31 {
            return None;
        }
        while !set.is_empty() {
            let (sequence_tag, attribute, after) = tlv(set)?;
            if sequence_tag != 0x30 {
                return None;
            }
            let (oid_tag, oid, value_part) = tlv(attribute)?;
            if oid_tag != 0x06 {
                return None;
            }
            let (value_tag, value, _) = tlv(value_part)?;
            if matches!(value_tag, 0x0c | 0x13 | 0x16) {
                attributes.push((oid.to_vec(), String::from_utf8(value.to_vec()).ok()?));
            }
            set = after;
        }
        name = rest;
    }
    Some(attributes)
}

fn cf_identity(subject: &[u8]) -> Result<CfInstanceIdentity, WorkloadError> {
    let attributes =
        name_attributes(subject).ok_or_else(|| WorkloadError::Subject("subject is not valid DER".into()))?;
    let mut common_names = attributes
        .iter()
        .filter(|(oid, _)| oid == OID_COMMON_NAME)
        .map(|(_, value)| value.as_str());
    let instance_guid = match (common_names.next(), common_names.next()) {
        (Some(cn), None) => cn.to_owned(),
        _ => return Err(WorkloadError::Subject("expected exactly one CN".into())),
    };
    let unit = |prefix: &str| -> Result<String, WorkloadError> {
        let mut values = attributes
            .iter()
            .filter(|(oid, _)| oid == OID_ORGANIZATIONAL_UNIT)
            .filter_map(|(_, value)| value.strip_prefix(prefix));
        match (values.next(), values.next()) {
            (Some(value), None) if !value.is_empty() => Ok(value.to_owned()),
            _ => Err(WorkloadError::Subject(format!(
                "expected exactly one OU {prefix}<guid>"
            ))),
        }
    };
    let identity = CfInstanceIdentity {
        instance_guid,
        app_guid: unit("app:")?,
        space_guid: unit("space:")?,
        org_guid: unit("organization:")?,
    };
    let guid_like = |value: &str| {
        !value.is_empty()
            && value.len() <= 64
            && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    if ![
        &identity.instance_guid,
        &identity.app_guid,
        &identity.space_guid,
        &identity.org_guid,
    ]
    .iter()
    .all(|value| guid_like(value))
    {
        return Err(WorkloadError::Subject("identity fields must be GUIDs".into()));
    }
    Ok(identity)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;

    #[test]
    fn tlv_rejects_truncated_and_oversized_lengths() {
        assert_eq!(
            tlv(&[0x30, 0x02, 0x01, 0x02]),
            Some((0x30, &[0x01, 0x02][..], &[][..]))
        );
        assert!(tlv(&[0x30, 0x05, 0x01]).is_none(), "truncated value");
        assert!(
            tlv(&[0x30, 0x85, 1, 2, 3, 4, 5]).is_none(),
            "length of length > 4"
        );
        assert!(tlv(&[0x30]).is_none());
    }

    #[test]
    fn name_parsing_extracts_cn_and_ou() {
        // SET { SEQ { OID 2.5.4.11, UTF8 "app:abc" } } SET { SEQ { OID 2.5.4.3, PRINTABLE "inst" } }
        let name = [
            0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x07, b'a', b'p', b'p', b':', b'a',
            b'b', b'c', 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x04, b'i', b'n', b's',
            b't',
        ];
        let attributes = name_attributes(&name).unwrap();
        assert_eq!(attributes.len(), 2);
        assert_eq!(
            attributes[0],
            (OID_ORGANIZATIONAL_UNIT.to_vec(), "app:abc".to_owned())
        );
        assert_eq!(attributes[1], (OID_COMMON_NAME.to_vec(), "inst".to_owned()));
        assert!(cf_identity(&name).is_err(), "space and organization are missing");
    }
}
