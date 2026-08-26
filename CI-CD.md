# CI, CD and continuous updates

One page. What runs when, where the artifacts live, how to roll back,
how updates land, how backups escape any single provider.

## The one-picture summary

```
        ┌─────────────────────────────────────────────────────────────┐
        │  Push to a branch / open a PR                               │
        └──────────────────────────┬──────────────────────────────────┘
                                   │
      ┌────────────────────────────┼───────────────────────────┐
      ▼                            ▼                           ▼
 ┌────────────┐            ┌────────────────┐        ┌────────────────┐
 │ ci.yml     │            │ console-api.yml│        │ deploy.yml     │
 │ Rust check │            │ SPA + backend  │        │ Build → scan → │
 │ + tests    │            │ smoke + e2e    │        │ SBOM → sign →  │
 │            │            │ docker image   │        │ push GHCR      │
 └────────────┘            └────────────────┘        └───────┬────────┘
                                                             │
              ┌──────────────────────────────────────────────┤
              ▼                                              ▼
     ┌────────────────────┐                       ┌────────────────────┐
     │ On PR: sticky      │                       │ On main: Fly.io    │
     │ comment with       │                       │ rolling deploy     │
     │ pull/run + Render  │                       │ (opt-in via        │
     │ / Fly instructions │                       │ FLY_API_TOKEN)     │
     └────────────────────┘                       └────────────────────┘

Nightly (04:17 UTC)         Weekly (Mon 06:00 UTC)
 backup.yml                  Dependabot
 pg_dump → artifact          npm / cargo / actions / docker
 30-day retention            → patch auto-merge, minor+ needs review
```

## The workflows in detail

| Workflow | Runs on | Purpose | Free-tier cost |
|---|---|---|---|
| `.github/workflows/ci.yml` | push to main, all PRs | Rust workspace fmt / clippy / tests, live contract services, cargo-deny already gates supply chain | 20-30 runner-minutes |
| `.github/workflows/console-api.yml` | push/PR touching `docs/app/**` or `server/**` | Console syntax check, TypeScript typecheck, Prisma migration deploy against a fresh PG, Python smoke + Node e2e, Docker image build | 5 runner-minutes |
| `.github/workflows/deploy.yml` | push to main (`server/**`) + PRs + manual | Build multi-arch image (amd64+arm64) → Trivy scan → SPDX SBOM → SLSA v1 provenance → push GHCR → (if `FLY_API_TOKEN`) Fly rolling deploy → PR preview comment | 5 runner-minutes |
| `.github/workflows/pages.yml` | push to main | Rustdoc + docs SPA + `.well-known/security.txt` → GitHub Pages | 3 runner-minutes |
| `.github/workflows/deny.yml` | push to main, all PRs | cargo-deny CVE / license / duplicate check | 2 runner-minutes |
| `.github/workflows/publish-crates.yml` | tag `av-*-vX.Y.Z` | Publish crates to crates.io | On-demand |
| `.github/workflows/release.yml` | tag `vX.Y.Z` | Build cross-platform release binaries + GH release | On-demand |
| `.github/workflows/dependabot-automerge.yml` | Dependabot PRs | Approve + auto-merge patch bumps (and SHA-pinned minor bumps) once CI is green | Seconds |
| `.github/workflows/backup.yml` | daily 04:17 UTC + manual | pg_dump against `$BACKUP_DATABASE_URL` → 30-day artifact | ~1 runner-minute/day |

Everything is pinned by commit SHA — a tag rewrite (see the March 2025
tj-actions/changed-files incident) cannot silently substitute code into
our pipeline.

## Container image lifecycle

Every push to `main` produces an OCI image at `ghcr.io/agentvisorai/agentvisor-api`
with three tags:

| Tag | When it moves | Use it for |
|---|---|---|
| `:latest` | Every push to main | Prod deploys (rolling) |
| `:main` | Every push to main | Sticky reference from Render/Railway/Koyeb blueprints |
| `:sha-<7>` | Once, never moves | Reproducible + rollback target |

Every PR produces an ephemeral tag:

| Tag | Retention | Use it for |
|---|---|---|
| `:pr-<num>-sha-<7>` | 7 days on GHCR | Preview deploys, reviewer sanity check |

Attached to every image (as OCI referrers, verifiable with `gh attestation verify`):

1. **SLSA v1 build provenance** — proves the image came from this repo,
   this commit, this workflow run.
2. **SPDX SBOM** — every package in the image, machine-readable.

Verify from a shell:

```bash
gh attestation verify \
  oci://ghcr.io/agentvisorai/agentvisor-api:sha-<7> \
  --owner AgentVisorAI
```

## Deploying

The recommended production target is Fly.io (rolling deploys, free tier
absorbs the pitch demo). Any container host works.

### Automated (Fly.io on push to main)

Once `FLY_API_TOKEN` is added as a repository secret:

1. Push to main → deploy.yml builds + scans the image, pushes GHCR.
2. `deploy-fly` job fires `fly deploy --image ghcr.io/…@<digest> --strategy rolling`.
3. Fly rolls one machine at a time, waits for the healthcheck, moves on.
4. Zero downtime, sub-second cutover per machine.

Without `FLY_API_TOKEN`, the deploy-fly job is a documented no-op. The
image still lands in GHCR so any operator can `fly deploy --image …`
manually — or point Render / Railway / Koyeb at the same tag.

### Manual (any other host)

```bash
# Fly
fly deploy --image ghcr.io/agentvisorai/agentvisor-api:sha-<7>

# Render — paste the image URL in the dashboard, or:
render deploys create --service-id srv-… --image-url ghcr.io/agentvisorai/agentvisor-api:sha-<7>

# Cloud Run
gcloud run deploy agentvisor-api --image ghcr.io/agentvisorai/agentvisor-api:sha-<7>

# Kubernetes
kubectl set image deployment/agentvisor-api api=ghcr.io/agentvisorai/agentvisor-api:sha-<7>

# Plain Docker
docker run -p 8080:8080 -e DATABASE_URL=… -e JWT_SECRET=… \
  ghcr.io/agentvisorai/agentvisor-api:sha-<7>
```

Every path is one command. No platform-native artifact required.

## Rollback

```bash
# Fly — the same command, older SHA.
fly deploy --image ghcr.io/agentvisorai/agentvisor-api:sha-<older>

# Or if you already know the machine ID:
fly machines update <machine-id> --image ghcr.io/agentvisorai/agentvisor-api:sha-<older>
```

Because every commit produces an immutable `:sha-<7>` tag, rollback is
just re-pointing to a previous digest. No re-build, no cross-branch git
gymnastics. The rollback is byte-identical to what CI produced when that
commit landed.

## Preview deploys (PRs)

Every PR that touches `server/**` triggers `deploy.yml` on the PR
branch. Once the build finishes, a sticky bot comment lands on the PR
with:

- The image digest (immutable OCI reference).
- A `docker run` snippet with the right env vars.
- A `fly deploy --image …` snippet.
- A `gh attestation verify` command so reviewers can verify provenance.

Non-technical reviewers can hand the digest to anyone with a Docker
host to see the change live. Technical reviewers can `docker run` it in
under a minute.

## Continuous updates

Dependabot runs Mondays at 06:00 UTC. Ecosystems:

| Ecosystem | Directory | Grouping | Auto-merge |
|---|---|---|---|
| cargo | `/` | Minor+patch grouped, security individual | Patch only |
| npm | `/server` | Minor+patch grouped, security individual | Patch only |
| github-actions | `/` | Ungrouped | Patch + minor (SHA-pinned) |
| docker | `/docker` | Ungrouped | Patch + minor (SHA-pinned) |
| docker | `/server` | Ungrouped | Patch + minor (SHA-pinned) |

Auto-merge policy lives in `dependabot-automerge.yml`. The bot approves
+ enables auto-merge; GitHub actually merges only after every required
status check goes green. A regression in the update still blocks the
merge.

Security advisories (CVEs) bypass the weekly grouping and land as
individual PRs, so a critical fix isn't stuck behind an unrelated minor
bump.

## Backups (off-provider escape hatch)

`backup.yml` runs every night at 04:17 UTC:

1. Installs `postgres-client-16` on the runner.
2. `pg_dump --format=custom --compress=9` against `$BACKUP_DATABASE_URL`.
3. Uploads the dump as a GitHub-hosted artifact with 30-day retention.

This is an off-provider copy — even if Neon disappears overnight, the
last 30 days of data are restorable via `pg_restore` to any Postgres
target (self-hosted, Cloud SQL, Supabase, RDS, anywhere). Zero paid
service in the loop.

Longer-horizon backups should push the artifact to S3 / R2 / any object
store from the same workflow (three lines to add).

## Supply-chain hardening summary

- All third-party actions pinned by full commit SHA.
- Every workflow has a top-level `permissions:` block; jobs opt in.
- `deploy.yml` uses OIDC (`id-token: write`) to sign attestations —
  no long-lived registry credentials in secrets.
- Trivy blocks HIGH/CRITICAL CVEs at image push time.
- cargo-deny gates every PR against a curated advisory + license list.
- `.well-known/security.txt` served from both the SPA and the API.

## Cost snapshot (public repo)

| Item | Cost |
|---|---|
| GitHub Actions runner-minutes | 0 (public repos have unlimited minutes) |
| GHCR public image storage | 0 |
| GHCR public image bandwidth | 0 |
| Cloudflare Pages (frontend) | 0 |
| Neon Postgres (0.5 GB) | 0 |
| Fly.io hobby (256 MB, auto-stop) | 0 |
| Uptime monitoring (BetterStack free / UptimeRobot) | 0 |
| **Total** | **$0** |

The whole CI/CD/CU pipeline costs zero dollars up to the pitch-demo
footprint. Every step of the pipeline uses standard, portable formats
(OCI, SPDX, SLSA, pg_dump custom) — no vendor lock-in, no rewrite when
we outgrow a tier.
