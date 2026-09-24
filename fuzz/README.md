# AgentVisor AI Fuzz Suite

Coverage-guided libFuzzer targets for the parsers on the audit path.
Requires [cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz.html)
and a nightly toolchain.

Targets:

* `canonicalize_receipt_subject` — JCS canonicalization over
  arbitrary JSON values (any panic here breaks the signing chain).
* `compress_invariants` — prompt-compression passes over arbitrary
  chat payloads (must preserve tail/system invariants without panic).
* `parse_provider_chunk` — provider SSE frame parser (bytes-in,
  ParsedProviderChunk-out; must be total over arbitrary input).
* `redact_userinfo` — URL userinfo redactor guarding secrets in
  logs (must never leak credentials or panic on malformed URLs).
* `sse_frame_end` — SSE frame terminator scanner (bytes-in, index-out;
  must never overflow or misreport).
* `parse_tool_call` — MCP JSON-RPC tool-call parser (bytes-in,
  ToolCallRequest-out; must reject duplicate keys and non-JSON-RPC
  shapes without panic).

## Running a single target

Run from the repository root. The runner copies the committed seeds into a new,
writable corpus and gives libFuzzer 60 seconds of execution per target:

```sh
python3 scripts/fuzz-smoke.py --target parse_provider_chunk
python3 scripts/fuzz-smoke.py --target canonicalize_receipt_subject --seconds 60
```

The nightly toolchain and `cargo-fuzz` must already be installed. Compilation
happens before fuzzing and adds to the elapsed time. The runner executes targets
sequentially and stops on the first failure. It also sets a 10-second timeout per
input, a 2 GiB memory limit, and a 64 KiB mutation size limit.

## Corpus and reproducibility

The repository contains 40 valid and adversarial seeds under
`fuzz/seeds/<target>/`. They cover receipt and numeric boundaries, chat and tool
history, provider SSE formats, credential-bearing URLs with synthetic secrets,
frame delimiters, duplicate JSON keys, malformed shapes, and invalid UTF-8.

Every runner invocation starts with those seeds in a fresh directory under
`fuzz/corpus/smoke-<run>/<target>/`. LibFuzzer writes new discoveries there, so it
cannot mutate the committed seed files. A fixed random seed (`20260924`) is the
default; override it with `--seed`. A fixed seed and initial corpus improve
reproducibility, but coverage, timing, compiler versions, and platform differences
can still change a fuzz run.

The generated `run.json` records each seed's SHA-256 digest, the exact commands,
and exit codes. Crash artifacts remain under
`fuzz/artifacts/smoke-<run>/<target>/`. Both directories are ignored by Git.
Inspect inputs and commands without compiling or running Cargo:

```sh
python3 scripts/fuzz-smoke.py --prepare-only
```

Cargo-fuzz does **not** automatically load `fuzz/seeds/`. Direct invocations must
provide an initialized corpus, or use this runner. To reproduce one crash, run
from `fuzz/` and pass the artifact path reported by libFuzzer:

```sh
cd fuzz
cargo +nightly fuzz run parse_provider_chunk /absolute/path/to/crash-<hash>
```

## CI and release checks

The fuzz suite is not part of the default `make ci` target because it requires
nightly and additional execution time. The smoke command runs all six existing
targets for 60 seconds each, plus compilation time:

```sh
make fuzz-smoke
```

Use `--seconds` for a different bounded duration (1–3600 seconds per target).
Retain the printed manifest and any crash artifacts with release test evidence.
