//! TLS contract. scripts/redis-tls-test.py provisions isolated trusted/untrusted
//! certificates and Redis, then runs these tests in separate trust environments.
#![cfg(feature = "redis")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use av_state::{redis_store::RedisStore, StateStore};

fn endpoint() -> Option<String> {
    std::env::var("AV_REDIS_TLS_URL").map_or_else(
        |_| {
            eprintln!("SKIPPED (AV_REDIS_TLS_URL unset): use scripts/redis-tls-test.py");
            None
        },
        Some,
    )
}

#[test]
fn redis_tls_checks_certificate_name_credentials_and_insecure_flag() {
    let Some(url) = endpoint() else { return };
    let store = RedisStore::connect(&url).expect("trusted TLS must connect");
    let key = format!("av-test-tls:{}", av_core::new_event_uid());
    assert_eq!(store.add(&key, 7).unwrap(), 7);
    assert_eq!(store.get(&key).unwrap(), 7);
    store.remove(&key);
    for invalid in [
        std::env::var("AV_REDIS_TLS_WRONG_NAME_URL").unwrap(),
        std::env::var("AV_REDIS_TLS_WRONG_PASSWORD_URL").unwrap(),
        format!("{url}/#insecure"),
    ] {
        assert!(
            RedisStore::connect(&invalid).is_err(),
            "invalid TLS/auth accepted"
        );
    }
}

#[test]
fn redis_tls_rejects_untrusted_ca() {
    if std::env::var_os("AV_REDIS_TLS_UNTRUSTED_TEST").is_none() {
        eprintln!("SKIPPED (AV_REDIS_TLS_UNTRUSTED_TEST unset): requires an untrusted CA environment");
        return;
    }
    let url = endpoint().expect("TLS fixture endpoint");
    assert!(
        RedisStore::connect(&url).is_err(),
        "untrusted TLS certificate accepted"
    );
}
