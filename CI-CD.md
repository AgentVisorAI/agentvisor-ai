# CI, CD and continuous updates

One page. What runs when, where the artifacts live, how to roll back,
how updates land, how backups escape any single provider.

## The one-picture summary

```
        ┌─────────────────────────────────────────────────────────────┐
        │  Push to main / open a PR                                   │
        └──────────────────────────┬──────────────────────────────────┘
                                   │
      ┌────────────────────────────┼───────────────────────────┐
      ▼                            ▼                           ▼
 ┌────────────┐            ┌────────────────┐        ┌────────────────┐
 │ ci.yml     │            │ console-api.yml│        │ deploy.yml     │
 │ Rust check │            │ SPA + backend  │        │ Build → test → │
 │ + tests    │            │ smoke + e2e    │        │ scan → attest │
 │            │            │ docker image   │        │ → promote      │
 └────────────┘            └────────────────┘        └───────┬────────┘
                                                             │
              ┌──────────────────────────────────────────────┤
              ▼                                              ▼
     ┌────────────────────┐                       ┌────────────────────┐
     │ On PR: read-only   │                       │ On main: Fly.io    │
     │ API/runtime checks │                       │ rolling deploy     │
     │ and downloadable   │                       │ (opt-in via        │
     │ image + evidence   │                       │ FLY_API_TOKEN)     │
     └────────────────────┘                       └────────────────────┘

Nightly (04:17 UTC)         Weekly (Mon 06:00 UTC)
 backup.yml                  Dependabot
 pg_dump → verified encryption → artifact          npm / cargo / actions / docker
 30-day retention            → patch auto-merge, minor+ needs review
```

## The workflows in detail

| Workflow | Runs on | Purpose |
|---|---|---|
| `.github/workflows/ci.yml` | push to main, all PRs | Rust workspace checks, tests, and live contract services |
| `.github/workflows/console-api.yml` | push to main, all PRs | Console syntax and TypeScript checks, API and browser tests, two-instance recovery, daemon crash synchronization, container runtime checks, and encrypted backup/restore tests |
| `.github/workflows/deploy.yml` | main pushes and PRs matching console/release-tool paths; manual runs | Build local OCI archives, test and scan each platform, promote verified bytes on main, then optionally deploy the exact digest to Fly |
| `.github/workflows/pages.yml` | main pushes matching its source/docs path filters; manual runs | Rustdoc and the docs SPA to GitHub Pages |
| `.github/workflows/deny.yml` | push to main, all PRs | cargo-deny advisory, license, and duplicate checks |
| `.github/workflows/publish-crates.yml` | tag `av-*-vX.Y.Z` | Publish crates to crates.io |
| `.github/workflows/release.yml` | tag `vX.Y.Z` | Build release binaries and a GitHub release |
| `.github/workflows/dependabot-automerge.yml` | Dependabot PRs | Approve and enable auto-merge for eligible dependency updates after required checks pass |
| `.github/workflows/backup.yml` | daily 04:17 UTC; manual runs | Verify and encrypt a PostgreSQL dump, then upload the ciphertext with 30-day retention |

Third-party GitHub Actions are pinned by commit SHA. This does not imply
that every downloaded tool, image tag, or hosted runner is immutable.

The Rust workflow also requires the delayed-Redis introspection regression on
every pull request and main push. A separate job builds the daemon with Redis
support, starts its own authenticated Redis process, and verifies that a token
which expires during a revocation read returns only `active: false`. The
11-check drill removes its processes and private credentials and retains only
its result and diagnostic logs in the `introspection-expiry` artifact for 14 days.

## Container image lifecycle

`deploy.yml` runs for changes to the console, its datasource/runtime checks,
the release-policy helper/tests, or the workflow itself. It can also be
started manually. Pull requests build and validate amd64 with read-only
permissions. Main and manual runs validate amd64 and arm64 on separate native
runners. No validation job logs in to GHCR or receives registry, OIDC, or
attestation write permissions.

The same run also calls the complete console regression workflow. Its
authentication, database recovery, browser, backup, and daemon synchronization
checks must succeed before the promotion job can start.

Notification recovery tests run against both the TypeScript source and the
compiled module inside the production image. A controlled PostgreSQL protocol
peer stalls setup, publication, and listener traffic to exercise deadlines,
queue limits, reconnection, and tenant isolation using the installed database
driver. These fault-injection tests complement the separate real PostgreSQL
outage and recovery drill; they do not simulate database durability.

Each platform produces an OCI archive containing its BuildKit provenance and
SPDX attestations. The runner checks the archive graph and architecture,
loads its runnable image, and compares its configuration and filesystem
hashes before executing the API and startup checks. Trivy 0.74.0 is pinned by its
multi-platform image digest, matching the locally validated scanner. It writes a complete
report with all severities and unfixed findings; the policy then rejects
fixable HIGH/CRITICAL findings, missing reports, and reports for another image.
A separate SPDX inventory, test logs, archive checksum, source revision, and
workflow run identity travel with the validated archive.

Only a successful push or manual run on the current `main` revision in a
non-fork repository may promote images. The promotion job first rechecks
both platforms and their artifact hashes, then logs in to GHCR. It copies
the archives without rebuilding, preserves their digests, and verifies that
the merged index contains exactly their runtime and attestation descriptors.
Public repositories attach GitHub-signed provenance to that index and signed
SPDX inventories to each platform index before deployable tags move. Private
repositories retain the embedded BuildKit metadata and downloadable SPDX
inventories, but skip those GitHub-signed attestations.

| Reference | Behavior | Use |
|---|---|---|
| `:validated-<run>-<attempt>[-<arch>]` | Receives already tested bytes while the promotion job verifies and attests them | Internal staging reference; its existence does not prove promotion completed |
| `:latest`, `:main` | Updated only after both platforms and required attestations pass | Convenience references; record the resulting digest |
| `:sha-<full revision>` | Identifies source but can change after an approved rebuild | Find a release, then record its digest |
| `@sha256:<digest>` | Identifies immutable image content | Pin the promoted deployment or rollback target |

A failed build, runtime check, scan, or artifact verification cannot update
these deployable tags. Registry tag updates are separate requests, so a
publication interruption may update only some tags; every updated tag still
points to validated bytes. Fly runs only after all tag copies and digest
checks succeed, and uses the exact digest output rather than a mutable tag.
No image rebuild occurs between testing and deployment.

The `console-evidence-<arch>` artifacts retain available reports even when a
validation step fails. Successful archives are kept as
`console-release-<arch>` artifacts for seven days. The `console-promotion`
artifact records the selected index and copy digests. No PR preview tag or
write-permission comment is published. Unfixed vulnerabilities remain visible
and require release review; passing the policy is not a zero-findings claim.

When the public-repository attestation steps ran, verify the promoted index:

```bash
# Set IMAGE_DIGEST to the promoted sha256:... digest from the workflow.
gh attestation verify \
  "oci://ghcr.io/agentvisorai/agentvisor-api@${IMAGE_DIGEST:?}" \
  --owner AgentVisorAI
```

The copy boundary uses Skopeo's [digest-preserving OCI copy](https://github.com/containers/skopeo/blob/main/docs/skopeo-copy.1.md)
and Docker's [multiarch index operations](https://docs.docker.com/reference/cli/docker/buildx/imagetools/create/).
These controls preserve and identify the tested bytes; they do not establish
reproducible builds or an independently certified SLSA level.

## Deploying

The workflow supports an optional Fly.io deployment. Other container hosts
can use the same OCI image. Configure the database, HTTPS origins, mailer,
application secrets, and host networking before the first deployment; see
[the deployment guide](server/DEPLOY.md). Local tests do not establish
availability or capacity on a selected production host.

### Automated (Fly.io on a matching push to main)

With `FLY_API_TOKEN` configured as a repository secret:

1. A matching main push validates both local platform archives, then the promotion job copies and verifies their bytes before updating deployable tags.
2. After promotion succeeds, `deploy-fly` runs `fly deploy` with the exact verified image digest and `--strategy rolling`.
3. The platform replaces machines using its configured health checks.

Availability during replacement depends on healthy replicas, spare capacity,
readiness checks, and the deployment configuration. No downtime or cutover
latency guarantee has been measured here. Without `FLY_API_TOKEN`, the Fly
step skips deployment; the image remains available in GHCR.

### Manual (an already configured host)

Use the digest of a build whose checks have passed. These commands assume
that the target application and its required configuration already exist.

```bash
# Set IMAGE_DIGEST to the reviewed sha256:... digest.
image_ref="ghcr.io/agentvisorai/agentvisor-api@${IMAGE_DIGEST:?}"

# Fly; run from server/ so fly.toml is available.
(cd server && fly deploy --image "$image_ref")

# Cloud Run
gcloud run deploy agentvisor-api --image "$image_ref"

# Kubernetes
kubectl set image deployment/agentvisor-api "api=$image_ref"

# Plain Docker behind an HTTPS reverse proxy. The private environment file
# must supply DATABASE_URL, JWT_SECRET, HTTPS APP_BASE_URL, ALLOWED_ORIGINS,
# and SMTP_URL or RESEND_API_KEY. Configure API_PUBLIC_URL if it differs.
# Keep this file outside the repository with owner-only read permissions.
docker run --env-file "${CONSOLE_ENV_FILE:?}" \
  -p 127.0.0.1:8080:8080 "$image_ref"
```

Provider setup, migrations, secret delivery, and restore compatibility need
separate validation. An image update command alone does not establish them.

## Rollback

Record the previous successful image digest before deploying. From `server/`:

```bash
fly deploy --image "ghcr.io/agentvisorai/agentvisor-api@${PREVIOUS_IMAGE_DIGEST:?}"
```

A digest selects the same image bytes without rebuilding. Source-revision
tags can be overwritten, so they are not immutable rollback references.
Check database migration compatibility before rolling back the application.

## Pull request validation

Pull requests run the amd64 image's API/startup checks and scan, including
fork PRs. They request only `contents: read`, do not log in to a registry,
and cannot reach the promotion or Fly jobs. Downloadable image/evidence
artifacts replace the old published preview tags and sticky comments.
An artifact is test evidence, not an approved production release. A manual
run on a non-main branch also cannot publish or deploy.

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

1. Installs PostgreSQL 18 clients and invokes their versioned binaries.
2. Runs `scripts/postgres-backup.py` with the database URI and passphrase supplied through environment variables. The helper keeps credentials out of tool arguments and sends the GnuPG passphrase through standard input.
3. Creates a custom-format dump in a private temporary directory, validates its archive, encrypts it with AES-256, and decrypts it again to verify the original bytes.
4. Publishes only the verified ciphertext and uploads that single file with 30-day retention. Failures, deadlines, and handled termination remove temporary plaintext and prevent an upload from that step.

This copy is independent of the database provider. Recovery requires a compatible PostgreSQL target, a matching PostgreSQL 18 restore client, and the passphrase stored in a separate accessible vault. A missing database URL skips the job; a configured URL without a passphrase fails. The helper has a 15-minute deadline, and the whole job has a 25-minute limit.

The console CI runs failure and cancellation tests plus an isolated PostgreSQL 18 encrypted backup/restore drill. The drill checks row content, Unicode, JSON, binary data, restored constraints and sequences, and rejection of incorrect passphrases and modified ciphertext. It does not fetch production artifacts or prove that the production vault is accessible.

See [the recovery runbook](docs/RUNBOOK.md) for restoring a scheduled artifact into a separate empty database. Longer retention requires configuring an additional storage destination and testing its retrieval path.

## Supply-chain hardening summary

- All third-party actions pinned by full commit SHA.
- Every workflow has a top-level `permissions:` block; jobs opt in.
- Public-repository builds use OIDC (`id-token: write`) for signed attestations. Registry publication uses the job's GitHub token.
- Trivy retains a complete vulnerability report, including unfixed findings. Both platforms must pass the fixable HIGH/CRITICAL policy before the promotion job can publish anything; scanner errors and artifact mismatches fail closed. Unfixed findings require release review.
- cargo-deny gates every PR against a curated advisory + license list.
- `.well-known/security.txt` served from both the SPA and the API.

## Costs and limits

Runner usage, registry storage, hosting, database, and backup retention costs
depend on the current provider plans and workload. This repository does not
guarantee a free deployment or a fixed CI duration. Review those limits for
the selected environment before relying on a deployment budget.
