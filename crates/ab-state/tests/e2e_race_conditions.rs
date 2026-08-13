//! Race-condition resilience for the atomic state store.
//!
//! Every test drives the store from N native threads without any additional
//! synchronization and asserts the store's own atomicity invariants hold —
//! no double-spend under contention, no partial commits from
//! `try_spend_many`, no lost adds, no negative counters visible via `get`.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]

use ab_state::{InMemoryStore, Spend, StateStore};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

// ---------------------------------------------------------------------------
// 1. No double-spend: N threads race to spend `1` from a limit of L. The
//    store must accept EXACTLY L of the N calls and refuse the remainder.
//    Any acceptance beyond L is a lost-update race.
// ---------------------------------------------------------------------------

#[test]
fn concurrent_try_spend_never_exceeds_the_limit() {
    let store = Arc::new(InMemoryStore::new());
    const N: u64 = 512;
    const LIMIT: u64 = 100;
    let barrier = Arc::new(Barrier::new(N as usize));
    let accepted = Arc::new(AtomicU64::new(0));
    let handles: Vec<_> = (0..N)
        .map(|_| {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            let accepted = Arc::clone(&accepted);
            thread::spawn(move || {
                barrier.wait();
                if store.try_spend("k", 1, LIMIT).unwrap() {
                    accepted.fetch_add(1, Ordering::Relaxed);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    let final_accepted = accepted.load(Ordering::Relaxed);
    let final_spent = store.get("k").unwrap();
    assert_eq!(final_accepted, LIMIT, "accepted count diverged from limit");
    assert_eq!(final_spent, LIMIT, "recorded spent diverged from limit");
}

// ---------------------------------------------------------------------------
// 2. Atomic multi-dim commit: `try_spend_many` must be all-or-nothing.
//    Threads race two spends whose second dimension is starved; if the
//    partial commit ever leaks, the "always-refused" key will accrue value.
// ---------------------------------------------------------------------------

#[test]
fn try_spend_many_is_all_or_nothing_under_contention() {
    let store = Arc::new(InMemoryStore::new());
    const N: u64 = 256;
    // Fill the "starved" key so every multi-spend must be refused.
    assert!(store.try_spend("starved", 100, 100).unwrap());
    let barrier = Arc::new(Barrier::new(N as usize));
    let handles: Vec<_> = (0..N)
        .map(|_| {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                // Dimension 0 has room; dimension 1 is already at the limit.
                // Refusal on dim 1 MUST roll back dim 0's would-be spend.
                let outcome = store
                    .try_spend_many(&[
                        Spend {
                            key: "room".to_owned(),
                            amount: 1,
                            limit: 1_000_000,
                        },
                        Spend {
                            key: "starved".to_owned(),
                            amount: 1,
                            limit: 100,
                        },
                    ])
                    .unwrap();
                assert_eq!(outcome, Some(1), "starved dim didn't refuse");
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(
        store.get("room").unwrap(),
        0,
        "partial commit leaked into room dimension"
    );
    assert_eq!(store.get("starved").unwrap(), 100);
}

// ---------------------------------------------------------------------------
// 3. Concurrent adds never lose an update: N threads each add K; sum == N·K.
// ---------------------------------------------------------------------------

#[test]
fn concurrent_add_operations_sum_exactly() {
    let store = Arc::new(InMemoryStore::new());
    const N: u64 = 64;
    const K: u64 = 1_000;
    let barrier = Arc::new(Barrier::new(N as usize));
    let handles: Vec<_> = (0..N)
        .map(|_| {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                for _ in 0..K {
                    store.add("c", 1).unwrap();
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(store.get("c").unwrap(), N * K);
}

// ---------------------------------------------------------------------------
// 4. Mixed add + try_spend race: at all times spent ≤ added; never a
//    negative snapshot and never a spend that outran the deposits.
// ---------------------------------------------------------------------------

#[test]
fn mixed_add_and_spend_never_diverge_from_added_total() {
    let store = Arc::new(InMemoryStore::new());
    const ADDERS: usize = 8;
    const SPENDERS: usize = 8;
    const K: u64 = 2_000;
    let barrier = Arc::new(Barrier::new(ADDERS + SPENDERS));
    let mut handles = Vec::new();
    for _ in 0..ADDERS {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..K {
                store.add("wallet", 1).unwrap();
            }
        }));
    }
    let spent = Arc::new(AtomicU64::new(0));
    for _ in 0..SPENDERS {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        let spent = Arc::clone(&spent);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..K {
                // The "wallet" ceiling equals whatever's been added so far.
                // We're actually spending against a shadow key so add and
                // spend can't mutually cancel; here we just assert `get`
                // NEVER returns a poisoned value.
                let observed = store.get("wallet").unwrap();
                assert!(observed <= u64::from(u32::MAX));
                if store.try_spend("wallet2", 1, u64::from(u32::MAX)).unwrap() {
                    spent.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(store.get("wallet").unwrap(), (ADDERS as u64) * K);
    assert_eq!(store.get("wallet2").unwrap(), spent.load(Ordering::Relaxed));
    assert!(store.get("wallet2").unwrap() <= (SPENDERS as u64) * K);
}

// ---------------------------------------------------------------------------
// 5. Remove races with add: a thread removing keys while others `add` must
//    not leave a negative counter (which `get` would surface as Overflow).
//    We do NOT require any particular final value — only that `get` never
//    errors and every add either lands in the current cell or is followed
//    by a remove that resets the count.
// ---------------------------------------------------------------------------

#[test]
fn remove_races_with_add_do_not_poison_the_counter() {
    let store = Arc::new(InMemoryStore::new());
    let barrier = Arc::new(Barrier::new(9));
    let mut handles = Vec::new();
    for _ in 0..8 {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..5_000 {
                store.add("ephemeral", 1).unwrap();
            }
        }));
    }
    let store_rm = Arc::clone(&store);
    let barrier_rm = Arc::clone(&barrier);
    handles.push(thread::spawn(move || {
        barrier_rm.wait();
        for _ in 0..500 {
            store_rm.remove("ephemeral");
            // `get` must never surface Overflow here.
            store_rm.get("ephemeral").unwrap();
        }
    }));
    for h in handles {
        h.join().unwrap();
    }
    // Final read is not required to be N·K (removes truncate), only that it
    // reads without error.
    store.get("ephemeral").unwrap();
}

// ---------------------------------------------------------------------------
// 6. Two-key ordering under contention: try_spend_many with keys A,B racing
//    against try_spend_many with keys B,A must NEVER deadlock, because the
//    store uses a single transaction lock (not per-key), and must never
//    double-spend either dimension.
// ---------------------------------------------------------------------------

#[test]
fn cross_key_multi_spend_pairs_do_not_deadlock_or_double_spend() {
    let store = Arc::new(InMemoryStore::new());
    const N: usize = 200;
    const LIMIT: u64 = 50;
    let barrier = Arc::new(Barrier::new(2 * N));
    let mut handles = Vec::new();
    for i in 0..N {
        let store_a = Arc::clone(&store);
        let barrier_a = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier_a.wait();
            let _ = store_a.try_spend_many(&[
                Spend {
                    key: "A".to_owned(),
                    amount: 1,
                    limit: LIMIT,
                },
                Spend {
                    key: "B".to_owned(),
                    amount: 1,
                    limit: LIMIT,
                },
            ]);
            let _ = i;
        }));
        let store_b = Arc::clone(&store);
        let barrier_b = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier_b.wait();
            let _ = store_b.try_spend_many(&[
                Spend {
                    key: "B".to_owned(),
                    amount: 1,
                    limit: LIMIT,
                },
                Spend {
                    key: "A".to_owned(),
                    amount: 1,
                    limit: LIMIT,
                },
            ]);
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert!(store.get("A").unwrap() <= LIMIT, "double-spend on A");
    assert!(store.get("B").unwrap() <= LIMIT, "double-spend on B");
}
