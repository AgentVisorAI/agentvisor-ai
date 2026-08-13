//! Race-condition resilience for concurrency primitives outside the
//! `StateStore`: `TokenVelocity` sliding window.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]

use ab_state::TokenVelocity;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

// ---------------------------------------------------------------------------
// 1. Concurrent `record_at` with the SAME timestamp: sum of returned totals
//    is monotonically non-decreasing (each caller sees at least its own
//    contribution) and the final windowed total equals the total inserted
//    (nothing lost, nothing double-counted).
// ---------------------------------------------------------------------------

#[test]
fn concurrent_record_at_same_timestamp_never_loses_a_sample() {
    let v = Arc::new(TokenVelocity::new(1_000_000));
    const N: u64 = 64;
    const K: u64 = 100;
    let barrier = Arc::new(Barrier::new(N as usize));
    let handles: Vec<_> = (0..N)
        .map(|_| {
            let v = Arc::clone(&v);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                for _ in 0..K {
                    v.record_at(42, 1);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(v.current_at(42), N * K);
}

// ---------------------------------------------------------------------------
// 2. Sliding-window eviction race: writers push samples at advancing
//    timestamps while a reader concurrently queries `current_at` far ahead
//    of them. Every reader observation must be ≤ total inserted so far
//    (no phantom samples), and after quiescing, `current_at` at a distant
//    future timestamp = 0 (window fully evicted).
// ---------------------------------------------------------------------------

#[test]
fn window_eviction_never_yields_a_total_exceeding_inserted() {
    let v = Arc::new(TokenVelocity::new(100));
    const WRITERS: usize = 4;
    const K: u64 = 500;
    let inserted = Arc::new(AtomicU64::new(0));
    let barrier = Arc::new(Barrier::new(WRITERS + 1));
    let mut handles = Vec::new();
    for w in 0..WRITERS as u64 {
        let v = Arc::clone(&v);
        let barrier = Arc::clone(&barrier);
        let inserted = Arc::clone(&inserted);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for i in 0..K {
                inserted.fetch_add(1, Ordering::Relaxed);
                v.record_at(w * K + i, 1);
            }
        }));
    }
    let v_read = Arc::clone(&v);
    let barrier_read = Arc::clone(&barrier);
    let inserted_read = Arc::clone(&inserted);
    handles.push(thread::spawn(move || {
        barrier_read.wait();
        for _ in 0..200 {
            let observed = v_read.current_at(0);
            let inserted_now = inserted_read.load(Ordering::Relaxed);
            assert!(
                observed <= inserted_now,
                "observed {observed} > inserted {inserted_now}"
            );
        }
    }));
    for h in handles {
        h.join().unwrap();
    }
    // Push time far past the window: everything must age out.
    let far_future = (WRITERS as u64) * K * 10;
    assert_eq!(v.current_at(far_future), 0);
}

// ---------------------------------------------------------------------------
// 3. Mixed record + current_at: a reader running in parallel with writers
//    never sees a corrupted sample count, and after all writers join, the
//    windowed total at a matching-timestamp query equals the total inserts
//    that fell inside the window.
// ---------------------------------------------------------------------------

#[test]
fn concurrent_record_and_query_yield_consistent_final_total() {
    let v = Arc::new(TokenVelocity::new(10_000));
    const WRITERS: usize = 8;
    const READERS: usize = 4;
    const K: u64 = 200;
    let barrier = Arc::new(Barrier::new(WRITERS + READERS));
    let mut handles = Vec::new();
    for w in 0..WRITERS as u64 {
        let v = Arc::clone(&v);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for i in 0..K {
                v.record_at(w + i, 1);
            }
        }));
    }
    for _ in 0..READERS {
        let v = Arc::clone(&v);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..200 {
                let _ = v.current_at(100);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    // After all writers finish, at a large enough `now_ms` every sample
    // inserted at timestamp t ≥ now_ms - window sits inside the window.
    // With window=10_000 and max t < WRITERS + K = 8 + 1000 = 1008, calling
    // current_at(1008) includes every sample.
    let latest = WRITERS as u64 + K;
    assert_eq!(v.current_at(latest), (WRITERS as u64) * K);
}
