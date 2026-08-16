# Contributing to AgentVisor AI

Thank you for wanting to contribute. This file describes what a good change
looks like and how to verify it locally before you open a pull request.

## Ground rules

- Assume every change ships to production. Include the test that would have
  caught the bug you are fixing (or the behaviour you are adding).
- Keep changes surgical. Rewrites of unrelated code slow down review and hide
  the actual delta.
- The audit-trail invariants are load-bearing. If your change touches receipts,
  the event chain, JCS canonicalization, journal recovery, or any code marked
  "fail closed" in comments, expect deeper review.
- Security-sensitive reports go to `SECURITY.md`, not the public tracker.

## Local checks

The project pins `rustc 1.97.1` via `rust-toolchain.toml` and uses stable
tools throughout. The following runs the same gates as CI:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace                            # in-process suites
cargo test --workspace --all-features             # feature matrix
RUSTDOCFLAGS="-D rustdoc::broken_intra_doc_links -D warnings" \
  cargo doc --workspace --all-features --no-deps
```

Some suites depend on live backends (Redis, Kafka/Redpanda, NATS, Qdrant).
Bring them up with the compose file used by CI:

```bash
docker compose -f docker/docker-compose.yml up -d --wait redpanda redis qdrant nats
```

The 10,000-connection SLA gate is opt-in behind `RUN_HEAVY_PERF=1`; see the
[`Release SLA` job in `ci.yml`](.github/workflows/ci.yml) for the exact
invocation.

## Commits and pull requests

- One logical change per commit. Commit subjects use the imperative mood.
- Explain *why* in the body when the code alone does not.
- Rebase on `main` before requesting review; do not merge `main` into your
  branch.
- The PR template captures the review checklist. Fill in every section that
  applies to your change; delete the sections that do not.

## Where things live

- Crate-level READMEs are in each `crates/<name>/` directory (when present).
- Architecture and threat model: [`ARCHITECTURE.md`](ARCHITECTURE.md),
  [`SECURITY.md`](SECURITY.md), [`SECURITY-AUDIT.md`](SECURITY-AUDIT.md).
- Benchmarks and SLAs: [`BENCHMARKS.md`](BENCHMARKS.md).
- Public verification protocol: [`VERIFICATION.md`](VERIFICATION.md).
- Design evolution and decisions: [`EVOLUTION.md`](EVOLUTION.md).

## Licensing

By contributing you agree that your contribution is licensed under
[Apache-2.0](LICENSE), the same license as the project.
