# Platform support

What runs where, and how it was verified. Every claim below was
exercised against real binaries — install, boot, policy verdicts,
budget blocks, receipt seal/verify, tamper rejection — not inferred
from "it compiles". (Verification rounds 93–99, September 2026.)

## Tier 1 — prebuilt binaries (installer default)

`curl -fsS https://agentvisorai.me/install.sh | sh` downloads these,
verifies the SHA-256, installs, and smoke-runs them on your machine.

| Target | Notes |
|---|---|
| `x86_64-unknown-linux-musl` | **Static** — runs on every x86_64 Linux regardless of glibc age or libc flavor. Verified on Ubuntu 24.04/22.04, Debian 12/11, Rocky 8 (glibc 2.28), Amazon Linux 2023, Fedora 42, Arch, openSUSE Leap 15.6, Alpine 3.20. |
| `aarch64-unknown-linux-musl` | Static; verified on Ubuntu 22.04, Debian 12, Alpine 3.20, Fedora 42 (arm64). |
| `aarch64-apple-darwin` | Verified on macOS 14+ (Apple silicon). |
| `x86_64-apple-darwin` | Verified on macOS 15 (Intel). |
| `x86_64-unknown-linux-gnu` | Also published; needs glibc ≥ 2.38. The installer prefers musl. |

## Tier 2 — build from source (verified working)

The installer falls back to `cargo install` from the public repo on
any other Unix (or force it with `AV_INSTALL_SOURCE=1`). These
targets were built and run through the full gate battery under
emulation:

| Target | Notes |
|---|---|
| `aarch64-unknown-linux-gnu` | Also exercised nightly in CI. |
| `armv7-unknown-linux-gnueabihf` | 32-bit ARM (Raspberry Pi OS 32-bit). The policy sandbox uses wasmtime's portable interpreter where no native JIT exists. Expect a long compile on a Pi. |
| `riscv64gc-unknown-linux-gnu` | Native cranelift JIT backend. |
| `powerpc64le-unknown-linux-gnu` | Works from v0.1.0-rc.4; earlier builds hit a per-arch `O_NOFOLLOW` constant bug that fail-closed every session (fixed, regression-tested on ppc64le). |
| `s390x-unknown-linux-gnu` | Big-endian. Receipts sealed on s390x verify on little-endian hosts and vice versa — the receipt framing and signatures are endian-clean. |

## Receipts are portable

A receipt sealed on any platform above verifies with `avctl
receipt-verify` on any other — across architecture, bitness (32→64),
and endianness (BE⇄LE) — because verification hashes a canonical
byte frame (`agentvisor-receipt-v2\0` + big-endian length + body).

## Windows

Use WSL: the static Linux binaries are the supported path. A native
Windows port is not planned for the beta (the daemon uses Unix
process and file-permission semantics in its evidence spool).

## Hosted console (self-host)

`server/Dockerfile` builds and passes the full 93-check e2e suite on
both `linux/amd64` and `linux/arm64` (node:22-slim, Prisma
auto-migrate, non-root, fail-closed production env guard).

## Continuously verified

- `public-consumer.yml` (nightly): installer on 4 real runners
  (linux x64/arm64, macOS arm64/x64), 3 containers (Ubuntu 22.04,
  Debian 12, Alpine — old glibc + musl), the `AV_INSTALL_SOURCE=1`
  source build, and the full outsider quickstart.
- `release.yml`: every tag builds all Tier-1 targets; the installer
  pin bump and Pages deploy chain automatically.
