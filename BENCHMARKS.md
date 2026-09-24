# Benchmarks

Measured on 2026-09-24 on an Apple M4 Pro with 24 GiB of memory, macOS,
Rust 1.97.1, and release builds. Live Redis and Kafka ran through Colima on
Linux arm64. Compilation and container scanning finished before these runs.
These results describe this machine and these fixtures; they are not
cross-machine promises or a production capacity certification.

This record replaces the earlier August measurements. The broader correctness,
security, browser, packaging, and fuzz results are in the
[validation record](docs/PRODUCTION-VALIDATION.md).

## Results and measurement boundaries

| Measurement | Acceptance limit | Result | Scope |
| --- | --- | --- | --- |
| Signed admission without authentication | p95 <= 5 ms; p99 <= 8 ms | p95 116 us; p99 341 us | 2,000 direct async-wrapper samples; identity disabled, token quotas unlimited, compression and bounded audit reservation enabled. |
| Explicit durable admission | Diagnostic only | p95 235.201 ms; p99 277.855 ms | 200 direct `prepare_chat_durable` samples. The HTTP route does not call this helper; it separately persists a response marker before upstream dispatch. |
| Event enqueue | p99 <= 0.5 ms | p99 4 us | Bounded reservation/submission; broker I/O happens outside this timer. |
| MCP denial | p99 < 5 ms | p99 152 us | HTTP route with the shipped schema and WASM policy. |
| Ed25519 receipt signing | p99 < 2 ms | p99 histogram bucket 250 us | Signing within close/promotion work. |
| Retroactive receipt | <= 60 s | 236 ms | Strict ATIF validation, persistence, and signing. |
| Embedded Bridge provision | < 15 minutes | 1,147 ms | Local provision from the six-topic manifest. |
| Authenticated admission with Redis | Diagnostic only | p95 7.413 ms; p99 46.248 ms; maximum 49.191 ms | 200 sequential samples after 20 warmups, with HMAC identity, scope checks, shared revocation, and a per-session token quota. |
| Concurrent SSE completions | 10,000; admission p95 <= 5 ms and p99 <= 8 ms; zero audit errors | Passed; admission p95 0.727 ms and p99 1.286 ms | Every exact SSE response completed; audit work drained to zero pending jobs with zero worker errors. All five services were healthy before and after, with unchanged runtime records. |

The core suite measures direct admission calls and an HTTP MCP denial. The
concurrent test exercises the HTTP router. They are not interchangeable
measurements of total proxy overhead.

## Concurrent request fixture

The concurrent test opens 10,000 client connections and corresponding upstream
HTTP/2 streams. The mock holds every response until all 10,000 requests arrive.
It then returns valid assistant content, a terminal `finish_reason`, and
`[DONE]`. Every client must receive the exact complete SSE body and complete
HTTP chunk framing. HTTP 200 alone is insufficient. A regression test verifies
that truncated responses, missing terminal markers, and injected error frames
are refused by this check.

The earlier successful run, before the final durability changes, reported `ramp_ms=166724` and `completed_ms=168098`: every
request reached the mock in 166.724 seconds, and every complete response was
received by 168.098 seconds from the start. Accepted audit work then drained
in another 371.344 seconds, reaching zero pending jobs and zero worker errors.
Spool cleanup took 7.305 seconds. The test passed and exited in 547.22 seconds,
including setup and cleanup. These times are distinct from admission latency.

An earlier run coincided with a Docker VM reboot and failed with 1,568 reported
worker-job errors after its responses completed. That run is not counted as
successful. That earlier successful repeat kept the same latency limits and zero-error
assertion; recorded container start times matched before and after it.

An intermediate run included the durability changes but preceded the final
revocation fix. It returned all 10,000 exact
responses in 116.695 seconds (114.475 seconds to reach the mock). Admission p95
was 1.133 ms and p99 was 2.558 ms. However, a separate application's watchdog
issued `colima restart` at 10:52:54 UTC, stopping Kafka and the other services.
The run logged 641 worker failures and was stopped after 152.34 seconds; it
cannot count as a full successful performance gate. Its interrupted result and
logs are retained in `followup-performance.json` and `followup-sla-10k.log`.

The preceding revocation-fix source passed after the first watchdog correction. All
10,000 requests reached the mock in 162.250 seconds, and all exact responses
completed in 165.418 seconds. Admission p95 was 0.803 ms and p99 was 1.639 ms.
Audit work then drained in another 374.400 seconds, ending with zero pending
jobs and zero worker errors. Spool cleanup took 19.113 seconds. The native test
passed in 559.70 seconds; the wrapper, including Cargo and final service
inspection, took 562.043 seconds. All five backing services were healthy before
and after, with identical container identities, start times, and restart counts.

After the Redis pool fix, all 10,000 requests reached the mock in
137.659 seconds, and every exact response completed in 139.604 seconds.
Admission p95/p99 were 0.727/1.286 ms. Audit work drained in another
263.744 seconds, with zero pending jobs and zero worker errors.
Spool cleanup took 9.800 seconds. The native test passed in 413.59 seconds;
the wrapper took 414.685 seconds. All five original services stayed
healthy, with identical container identities, start times, and restart counts.

Resource observations were sampled every 30 seconds. The maximum sampled test
process RSS was 89.05 MiB; this is not a peak-memory measurement. System-wide
swap ranged from 25,364.62 to 29,486.12 MiB. Those swap samples include other
applications and do not establish isolated daemon memory use or production
memory requirements.

The reported percentiles come from `x-av-middleware-us`. Its timer starts after
authentication, duplicate-key scanning, JSON parsing, and depth checks. It ends
before forwarding. It includes preparation and any queue wait within that
preparation, but excludes persistence of the response marker, upstream waiting,
response capture, and response transfer. It therefore does not establish that
complete request overhead is below 5 ms.

The fixture uses 32,768 request slots and 32,768 reserved response slots,
with 16 session-ordered shards,
`--features full`, and live Kafka/Redis endpoints. Identity is disabled and
token quotas are unlimited, so this is not a concurrent authentication or
Redis quota-round-trip benchmark. The fixture uses the default 512-dimensional
hash embedder and no external vector sink; ONNX and Qdrant are compiled but
are not active in this measurement. The mock sends the complete SSE sequence in
one padded upstream body frame; sustained token-by-token generation and a
long-running production workload remain outside this measurement.

The arrival allowance is 900 seconds. The mock read timeout is 930 seconds
because it intentionally withholds responses during the entire arrival period.
This test-only setting does not change the production timeout or prove that
all arrivals fit inside the ordinary 60-second provider timeout. Arrival and
completion times are reported separately from the admission percentiles.

After all client responses complete, the fixture waits up to 600 seconds for
accepted audit-worker jobs to leave the queue and requires zero reported
worker-job errors. This covers normal journal and broker acknowledgement work.
The drain and subsequent spool cleanup are outside both response and admission
timings. This fixture does not close all 10,000 sessions, issue or verify their
receipts, independently reread every journal, or test restart recovery. Separate
security and crash-recovery tests cover those behaviors at smaller scale.

An earlier run exposed a blocking-pool regression: admission p95 reached
37.16 seconds while filesystem work occupied the same pool. Small validated
requests without quotas now prepare inline. Configured authentication, quota
checks, and larger bodies remain offloaded. Worker-saturation tests preserve
that distinction and the existing identity and cancellation checks.

## Authenticated Redis diagnostic

The separate diagnostic includes identity validation and Redis calls inside
the direct async admission-wrapper timer. It uses a null event bus and does
not include HTTP parsing, durable forwarding markers, provider I/O, or a
principal-wide quota. Sampling stops before request cleanup; asynchronous
refund and audit work can contend with later samples. There is no latency
acceptance threshold for this diagnostic.

Untimed assertions require a bearer token and the correct scope, verify the
exact debit in live Redis, check the resulting identity, and reject that same
token after shared revocation. Storage outage and recovery are verified by
the separate real-daemon security drills. These results do not establish
capacity for other algorithms, JWKS fetching, or concurrent authenticated
traffic.

## Reproduction

Start working Redis and Kafka endpoints before running these commands.
`--features full` alone does not select live services; without the environment
variables, the core/concurrent fixture uses memory and an embedded broker.

```sh
export AV_REDIS_URL=redis://127.0.0.1:6379
export AV_KAFKA_BROKER=127.0.0.1:19092

cargo test --locked -p av-harness --release --features full --test sla \
  sla_core_metrics -- --ignored --nocapture

cargo test --locked -p av-harness --release --features full --test sla_security \
  authenticated_admission_with_live_revocation_and_quota -- --ignored --nocapture

ulimit -n 65536
RUN_HEAVY_PERF=1 AV_SLA_CONNECTIONS=10000 AV_SLA_ARRIVAL_TIMEOUT_S=900 \
  AV_SLA_STREAMING_P95_US=5000 AV_SLA_STREAMING_P99_US=8000 \
  cargo test --locked -p av-harness --release --features full --test sla \
  sla_10k_streaming_connections -- --ignored --nocapture
```

The recorded local run uses the strict 5 ms / 8 ms limits. CI's existing shared
runner limits are 7.5 ms / 12 ms. The `full` feature is the daemon runtime
bundle; it is not literally every Cargo feature. Correctness and lint checks
also ran separately with `--all-features`.

The exact commands, exit codes, and logs are retained on the validation host
under `/tmp/agentvisor-production-validation`. The earlier complete pass is
in `final-performance.json` and the three `sla-*-current.log` files. The
intermediate measurements and interrupted concurrent run remain in
`followup-performance.json` and `followup-sla-*.log`. The preceding revocation-fix
core measurements remain under `revocation-final`, with that concurrent result
in the root `final-10k-repeat.json`. The final Redis-pool measurements are under
`pool-final`: `followup-performance.json`, `final-10k-repeat.json`, and
`performance-metrics.json`, with their logs, service snapshots, and sampled
resources. These temporary files are evidence for these runs, not durable
release artifacts.
