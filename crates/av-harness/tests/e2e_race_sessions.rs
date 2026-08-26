//! Race-condition resilience for session lifecycle state machines: the
//! close/promote CAS gates, seq allocation, registry coherence, and totals
//! accumulation. A TOCTOU bug in any of these becomes a double-receipt,
//! a duplicate sequence number, or a split-brain session.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]

use av_events::{AgentIdentity, CharterFile};
use av_harness::session::{Session, SessionRegistry, Workflow};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

fn identity() -> AgentIdentity {
    AgentIdentity {
        version: "1".to_owned(),
        charter: CharterFile::from("c"),
        instance_uid: "i".to_owned(),
        ttl_remaining_s: None,
    }
}

fn session(id: &str) -> Arc<Session> {
    Arc::new(Session::new(
        id.to_owned(),
        Workflow::Unsigned,
        identity(),
        av_loopdetect::BreakerConfig::default(),
    ))
}

// ---------------------------------------------------------------------------
// 1. `try_close` fires exactly once under N-way contention. Multiple
//    winners = multiple finalizations = duplicate receipts.
// ---------------------------------------------------------------------------

#[test]
fn try_close_wins_exactly_once_under_contention() {
    let s = session("close-race");
    const N: usize = 64;
    let barrier = Arc::new(Barrier::new(N));
    let winners = Arc::new(AtomicU64::new(0));
    let handles: Vec<_> = (0..N)
        .map(|_| {
            let s = Arc::clone(&s);
            let barrier = Arc::clone(&barrier);
            let winners = Arc::clone(&winners);
            thread::spawn(move || {
                barrier.wait();
                if s.try_close() {
                    winners.fetch_add(1, Ordering::Relaxed);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(winners.load(Ordering::Relaxed), 1, "multiple close winners");
    assert!(s.is_closed());
}

// ---------------------------------------------------------------------------
// 2. `try_promote` fires exactly once under contention (same CAS shape as
//    close; a double promotion would double-publish the unsigned artifact).
// ---------------------------------------------------------------------------

#[test]
fn try_promote_wins_exactly_once_under_contention() {
    let s = session("promote-race");
    const N: usize = 64;
    let barrier = Arc::new(Barrier::new(N));
    let winners = Arc::new(AtomicU64::new(0));
    let handles: Vec<_> = (0..N)
        .map(|_| {
            let s = Arc::clone(&s);
            let barrier = Arc::clone(&barrier);
            let winners = Arc::clone(&winners);
            thread::spawn(move || {
                barrier.wait();
                if s.try_promote() {
                    winners.fetch_add(1, Ordering::Relaxed);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(winners.load(Ordering::Relaxed), 1, "multiple promotion winners");
}

// ---------------------------------------------------------------------------
// 3. `next_seq` yields a gap-free, duplicate-free sequence under N threads.
//    A duplicate seq forges event ordering; a gap breaks replay.
// ---------------------------------------------------------------------------

#[test]
fn next_seq_is_unique_and_gap_free_under_contention() {
    let s = session("seq-race");
    const N: usize = 16;
    const K: usize = 500;
    let barrier = Arc::new(Barrier::new(N));
    let handles: Vec<_> = (0..N)
        .map(|_| {
            let s = Arc::clone(&s);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                let mut got = Vec::with_capacity(K);
                for _ in 0..K {
                    got.push(s.next_seq());
                }
                got
            })
        })
        .collect();
    let mut all: Vec<u64> = Vec::with_capacity(N * K);
    for h in handles {
        all.extend(h.join().unwrap());
    }
    let unique: HashSet<u64> = all.iter().copied().collect();
    assert_eq!(unique.len(), N * K, "duplicate sequence numbers issued");
    let max = *all.iter().max().unwrap();
    assert_eq!(max as usize, N * K - 1, "sequence range has gaps");
}

// ---------------------------------------------------------------------------
// 4. Registry `get_or_open` coherence: N threads racing the same id get
//    the SAME session instance. Two instances = split-brain (two chains,
//    two receipts for one session id).
// ---------------------------------------------------------------------------

#[test]
fn get_or_open_returns_one_instance_per_id_under_contention() {
    let registry = Arc::new(SessionRegistry::new());
    const N: usize = 64;
    let barrier = Arc::new(Barrier::new(N));
    let handles: Vec<_> = (0..N)
        .map(|_| {
            let registry = Arc::clone(&registry);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                registry.get_or_open(
                    "sess-shared",
                    Workflow::Unsigned,
                    &identity(),
                    &av_loopdetect::BreakerConfig::default(),
                )
            })
        })
        .collect();
    let sessions: Vec<Arc<Session>> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let first = &sessions[0];
    for s in &sessions[1..] {
        assert!(
            Arc::ptr_eq(first, s),
            "get_or_open returned distinct instances for one id"
        );
    }
    assert_eq!(registry.len(), 1);
}

// ---------------------------------------------------------------------------
// 5. `get_or_open` racing `remove`: every returned Arc must be usable
//    (no panic, seq allocation works), and the registry never corrupts.
// ---------------------------------------------------------------------------

#[test]
fn get_or_open_racing_remove_never_corrupts_the_registry() {
    let registry = Arc::new(SessionRegistry::new());
    const OPENERS: usize = 8;
    let barrier = Arc::new(Barrier::new(OPENERS + 1));
    let mut handles = Vec::new();
    for _ in 0..OPENERS {
        let registry = Arc::clone(&registry);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..500 {
                let s = registry.get_or_open(
                    "ephemeral",
                    Workflow::Unsigned,
                    &identity(),
                    &av_loopdetect::BreakerConfig::default(),
                );
                // The Arc we got must always be internally consistent.
                let _ = s.next_seq();
                assert_eq!(s.id, "ephemeral");
            }
        }));
    }
    let registry_rm = Arc::clone(&registry);
    let barrier_rm = Arc::clone(&barrier);
    handles.push(thread::spawn(move || {
        barrier_rm.wait();
        for _ in 0..500 {
            registry_rm.remove("ephemeral");
        }
    }));
    for h in handles {
        h.join().unwrap();
    }
    assert!(registry.len() <= 1);
}

// ---------------------------------------------------------------------------
// 6. Totals accumulate exactly under concurrent workers, and identity
//    refresh is never torn: readers see one of the written versions in
//    full, never a mix.
// ---------------------------------------------------------------------------

#[test]
fn totals_and_identity_are_consistent_under_concurrent_updates() {
    let s = session("totals-race");
    const N: usize = 8;
    const K: u64 = 1_000;
    let barrier = Arc::new(Barrier::new(N + N + 2));
    let mut handles = Vec::new();
    for _ in 0..N {
        let s = Arc::clone(&s);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..K {
                s.totals.tool_calls.fetch_add(1, Ordering::AcqRel);
                s.totals.cost_usd_micros.fetch_add(3, Ordering::AcqRel);
            }
        }));
    }
    // Identity writers alternate between two fully-formed identities.
    for w in 0..N {
        let s = Arc::clone(&s);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for i in 0..200 {
                let version = if (w + i) % 2 == 0 { "vA" } else { "vB" };
                let ident = AgentIdentity {
                    version: version.to_owned(),
                    charter: CharterFile::from(version),
                    instance_uid: version.to_owned(),
                    ttl_remaining_s: None,
                };
                s.refresh_identity(&ident);
            }
        }));
    }
    // Readers assert identity coherence (version == charter == uid family).
    for _ in 0..2 {
        let s = Arc::clone(&s);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..2_000 {
                let ident = s.current_identity();
                let v = ident.version.as_str();
                assert!(v == "1" || v == "vA" || v == "vB", "torn version {v:?}");
                if v != "1" {
                    assert_eq!(ident.instance_uid, v, "identity fields torn across writers");
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(s.totals.tool_calls.load(Ordering::Acquire), (N as u64) * K);
    assert_eq!(
        s.totals.cost_usd_micros.load(Ordering::Acquire),
        (N as u64) * K * 3
    );
}

// ---------------------------------------------------------------------------
// 7. Close vs open_sessions snapshot: a session that wins try_close must
//    never appear in a subsequent open_sessions snapshot; concurrent
//    closers + snapshotters must agree on the final state.
// ---------------------------------------------------------------------------

#[test]
fn closed_sessions_never_reappear_in_open_snapshots() {
    let registry = Arc::new(SessionRegistry::new());
    const SESSIONS: usize = 32;
    for i in 0..SESSIONS {
        registry.get_or_open(
            &format!("s{i}"),
            Workflow::Unsigned,
            &identity(),
            &av_loopdetect::BreakerConfig::default(),
        );
    }
    // R54 mutation-run hardening: the test's stated invariant
    // ("a session that closed BEFORE the snapshot must be gone")
    // was never actually asserted — reader threads only did
    // `let _ = s.id.as_str()`. Track closed ids in a shared set;
    // every reader now asserts that no snapshot entry names an id
    // the closers have already committed. A snapshot-consistency
    // bug that briefly re-exposes a previously-closed session
    // would surface here.
    let closed = Arc::new(parking_lot::Mutex::new(std::collections::HashSet::<String>::new()));
    let barrier = Arc::new(Barrier::new(SESSIONS + 4));
    let mut handles = Vec::new();
    for i in 0..SESSIONS {
        let registry = Arc::clone(&registry);
        let barrier = Arc::clone(&barrier);
        let closed = Arc::clone(&closed);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let id = format!("s{i}");
            let s = registry.get(&id).unwrap();
            assert!(s.try_close());
            // Register the id as closed AFTER `try_close` committed.
            // Every subsequent reader-snapshot MUST NOT observe this
            // id as open.
            closed.lock().insert(id);
        }));
    }
    for _ in 0..4 {
        let registry = Arc::clone(&registry);
        let barrier = Arc::clone(&barrier);
        let closed = Arc::clone(&closed);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..100 {
                // Snapshot the closed-set FIRST, then open_sessions.
                // A session id that was already in `closed` at the
                // moment we sampled MUST NOT then appear in an
                // `open_sessions()` snapshot taken later — that
                // would be a snapshot-consistency regression (the
                // registry re-exposes a session after its close was
                // committed by a peer). Sampling closed AFTER
                // open_sessions would be a false-positive-prone
                // ordering: a legitimate close committed between
                // the two reads would make the reader see the
                // still-open snapshot plus the just-committed
                // closed id.
                let closed_snapshot = closed.lock().clone();
                let snapshot: Vec<String> = registry
                    .open_sessions()
                    .into_iter()
                    .map(|s| s.id.clone())
                    .collect();
                for id in &snapshot {
                    assert!(
                        !closed_snapshot.contains(id),
                        "session {id} is in an open_sessions() snapshot \
                         after it was already recorded as closed — \
                         snapshot-consistency regression"
                    );
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert!(
        registry.open_sessions().is_empty(),
        "closed sessions still visible in open snapshot"
    );
    assert_eq!(
        closed.lock().len(),
        SESSIONS,
        "every session should have been recorded as closed by the joiners"
    );
}
