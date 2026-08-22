# AgentVisor AI Fuzz Suite

Coverage-guided libFuzzer targets for the parsers on the audit path.
Requires [cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz.html)
and a nightly toolchain.

Targets:

* `canonicalize_receipt_subject` — JCS canonicalization over
  arbitrary JSON values (any panic here breaks the signing chain).
* `parse_provider_chunk` — provider SSE frame parser (bytes-in,
  ParsedProviderChunk-out; must be total over arbitrary input).
* `sse_frame_end` — SSE frame terminator scanner (bytes-in, index-out;
  must never overflow or misreport).
* `parse_tool_call` — MCP JSON-RPC tool-call parser (bytes-in,
  ToolCallRequest-out; must reject duplicate keys and non-JSON-RPC
  shapes without panic).

## Running a single target

```
cd fuzz
cargo +nightly fuzz run canonicalize_receipt_subject
cargo +nightly fuzz run parse_provider_chunk -- -max_total_time=300
```

## Corpus

Each target keeps its own corpus under `fuzz/corpus/<target>/`. Seed
files are stored under `fuzz/seeds/<target>/` and merged in on first
run. Reproduce a crash:

```
cargo +nightly fuzz run parse_provider_chunk fuzz/artifacts/parse_provider_chunk/crash-<hash>
```

## CI

The fuzz suite is NOT part of the default `make ci` target — it needs
a nightly toolchain and time. Run the smoke variant (10 minutes per
target) with:

```
make fuzz-smoke
```

Full-duration runs are for release-cycle gates only.
