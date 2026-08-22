# AgentVisor AI Reference Documentation

Operator- and developer-facing reference material. Written for people
who need to **use** the harness rather than modify its internals; for
the latter, start with `ARCHITECTURE.md` at the repo root.

* [`VERIFYING-A-RECEIPT.md`](VERIFYING-A-RECEIPT.md) — offline audit
  chain verification with `avctl receipt-verify` and the
  `av_receipts::keys::Keyring` API.
* [`CONFIGURATION.md`](CONFIGURATION.md) — every `harness.toml` key,
  its default, its purpose, and the `validate()` guards that refuse
  bad combinations.
* [`OPENAI-COMPATIBILITY.md`](OPENAI-COMPATIBILITY.md) — supported
  request/response surface, intentional differences, and session
  semantics.
* [`OPERATIONS.md`](OPERATIONS.md) — boot, health probes, key
  rotation, spool recovery, and the metrics you should alert on.
* [`LIMITS.md`](LIMITS.md) — hard ceilings enforced by the harness and
  the refusal points on request size, budgets, loops, and
  compression.

Other repo-root docs:

* `README.md` — quickstart and marketing surface.
* `ARCHITECTURE.md` — high-level structure of the workspace.
* `SECURITY.md` — vulnerability disclosure.
* `SECURITY-AUDIT.md` — deferred security posture notes.
* `VERIFICATION.md` — the compliance / MVP verdict record.
* `BENCHMARKS.md` — SLA measurements against 10k connections.
* `CHANGELOG.md` — release history.
* `PLAN.md` — roadmap.
* `EVOLUTION.md` — design decisions and their rationale.
