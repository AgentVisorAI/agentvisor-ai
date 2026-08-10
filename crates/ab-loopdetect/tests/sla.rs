//! Success-criterion suite for Module A (R5/R22):
//! "Catch and terminate 100 % of synthetic infinite agent loops within 3
//! execution cycles" — plus the dual requirement the brief implies: zero
//! false trips on genuinely progressing sessions.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ab_loopdetect::{BreakerConfig, BreakerVerdict, HashEmbedder, SessionLoopState};

fn cfg() -> BreakerConfig {
    BreakerConfig { min_tokens: 500, ..BreakerConfig::default() }
}

/// 20 synthetic loop families: verbatim repeats and light paraphrase cycles
/// (the brief: "slight variations, bypassing standard rate-limiters").
fn loop_corpora() -> Vec<Vec<String>> {
    let mut corpora = Vec::new();
    // Verbatim loops across varied domains.
    for base in [
        "I should check the order database again for pending records",
        "Let me retry the API call to fetch the user profile",
        "Attempting to parse the JSON response from the payment service",
        "I will search the knowledge base for the answer to this question",
        "Trying to acquire the file lock before writing the report",
        "Re-reading the configuration file to find the missing key",
        "Calling the currency conversion tool with the same arguments",
        "Checking whether the deployment finished successfully",
        "Escalating: the previous step did not return any new information",
        "Looking up the customer id in the CRM system once more",
    ] {
        corpora.push(vec![base.to_owned(); 8]);
    }
    // Paraphrase loops: prefix/suffix jitter around an unchanged core.
    for core in [
        "check the inventory service for stock level of SKU 12345",
        "retry fetching the shipment tracking status from the carrier api",
        "query the analytics warehouse for yesterday's conversion rate",
        "ask the calendar tool for the next available meeting slot",
        "look for the error message in the application logs again",
        "call the geocoding endpoint with the customer address",
        "validate the invoice totals against the ledger entries",
        "poll the job queue to see if the export job completed",
        "scan the document store for the signed contract pdf",
        "request the exchange rate for EUR to USD one more time",
    ] {
        let variants: Vec<String> = [
            format!("I should {core}"),
            format!("Let me {core}"),
            format!("Okay, I will {core}"),
            format!("Next step: {core}"),
            format!("I need to {core} now"),
            format!("Proceeding to {core}"),
            format!("Alright, {core}"),
            format!("Now I will {core}"),
        ]
        .to_vec();
        corpora.push(variants);
    }
    corpora
}

/// 10 progressing sessions: every step introduces genuinely new content.
fn progressing_corpora() -> Vec<Vec<String>> {
    vec![
        vec![
            "Read the ticket: user reports login failures since the 14:00 deploy".into(),
            "Pulled auth-service logs; 401 spike correlates with JWT clock skew errors".into(),
            "Found the cause: the new pod image has no NTP sync; drift is 42 seconds".into(),
            "Patched the base image with chrony and redeployed to staging".into(),
            "Staging verifies clean; promoting to production and watching error rates".into(),
            "Error rate back to baseline; writing the incident summary".into(),
        ],
        vec![
            "Plan the ETL: source is a 2GB CSV of transactions".into(),
            "Schema inferred: 14 columns, 3 need type coercion from strings".into(),
            "Wrote the dbt staging model with the coercions and null guards".into(),
            "Backfill running: 1.2M rows/minute, ETA 90 seconds".into(),
            "Backfill done; row counts reconcile with the source exactly".into(),
        ],
        vec![
            "Refactor request: extract the retry logic into a shared helper".into(),
            "Identified 7 call sites with subtly different backoff parameters".into(),
            "Designed the RetryPolicy struct covering all 7 configurations".into(),
            "Migrated 4 call sites; tests green so far".into(),
            "Migrated the remaining 3; deleted 240 lines of duplication".into(),
            "Opened the PR with benchmarks showing no regression".into(),
        ],
        vec![
            "Research task: compare vector databases for the recommender".into(),
            "Qdrant: rust-native, good filtering; benchmarked 3ms p99 on our corpus".into(),
            "pgvector: simpler ops story since we already run Postgres; 9ms p99".into(),
            "Milvus: fastest bulk ingest but heaviest operational footprint".into(),
            "Recommendation drafted: pgvector now, Qdrant if p99 becomes binding".into(),
        ],
        vec![
            "Customer asks for a refund on order 8812".into(),
            "Order 8812 found: delivered 3 days ago, within the return window".into(),
            "Policy check passed; initiating refund of $84.50 to the original card".into(),
            "Refund issued, confirmation email queued; updating the CRM record".into(),
        ],
        vec![
            "Debug the flaky test: test_concurrent_checkout fails 1 in 20 runs".into(),
            "Captured a failing seed; the race is between cart cleanup and payment capture".into(),
            "Root cause: the cleanup task lacks a happens-before edge on the capture future".into(),
            "Fix: await the capture handle before spawning cleanup; 500 runs green".into(),
        ],
        vec![
            "Summarize the Q3 metrics deck for the exec update".into(),
            "Revenue +12% QoQ driven by the enterprise tier; churn flat at 2.1%".into(),
            "NRR at 118%; support tickets down 9% after the docs overhaul".into(),
            "Draft summary written with three callouts and one risk flag".into(),
        ],
        vec![
            "Set up the new service: scaffold a Rust axum app with CI".into(),
            "Scaffold done; adding the health endpoint and prometheus metrics".into(),
            "Wiring the postgres pool with sqlx and running the first migration".into(),
            "CI pipeline green: fmt, clippy, tests, and a docker image build".into(),
        ],
        vec![
            "Translate the onboarding guide to French for the Paris launch".into(),
            "Sections 1-3 translated; glossary decisions logged for consistency".into(),
            "Sections 4-6 translated; screenshots swapped for the FR locale".into(),
            "Review pass complete; delivering the final document".into(),
        ],
        vec![
            "Analyze why the cache hit rate dropped from 92% to 71% yesterday".into(),
            "The drop starts at 09:40 UTC, exactly when the new release shipped".into(),
            "The release changed the cache key to include a per-request UUID — bug".into(),
            "Reverted the key change; hit rate recovering, now at 88% and climbing".into(),
        ],
    ]
}

/// R22: every synthetic loop must trip within 3 cycles after the baseline step,
/// under sustained token consumption.
#[test]
fn sla_catches_100_percent_of_loops_within_3_cycles() {
    let embedder = HashEmbedder::default();
    let corpora = loop_corpora();
    assert_eq!(corpora.len(), 20);
    for (ci, corpus) in corpora.iter().enumerate() {
        let session = SessionLoopState::new(cfg());
        let mut tripped_at = None;
        for (si, step) in corpus.iter().enumerate() {
            match session.observe(&embedder, step, 400) {
                BreakerVerdict::Tripped { .. } => {
                    tripped_at = Some(si);
                    break;
                }
                _ => continue,
            }
        }
        let at = tripped_at.unwrap_or_else(|| panic!("corpus {ci} never tripped: {:?}", corpus.first()));
        // Step 0 is the baseline; trip must come within 3 further cycles.
        assert!(at <= 3, "corpus {ci} tripped at step {at} (> 3 cycles): {:?}", corpus.first());
    }
}

/// Dual SLA: zero false positives across progressing sessions.
#[test]
fn sla_zero_false_positives_on_progressing_sessions() {
    let embedder = HashEmbedder::default();
    for (ci, corpus) in progressing_corpora().iter().enumerate() {
        let session = SessionLoopState::new(cfg());
        for (si, step) in corpus.iter().enumerate() {
            let v = session.observe(&embedder, step, 5_000);
            assert!(
                !matches!(v, BreakerVerdict::Tripped { .. }),
                "false positive in progressing corpus {ci} at step {si}: {v:?}"
            );
        }
    }
}
