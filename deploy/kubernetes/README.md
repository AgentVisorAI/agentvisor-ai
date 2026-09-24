# Kubernetes template

This manifest requires an operator-selected cluster, an image built from this repository, a persistent volume, upstream credentials, a trusted identity issuer, a complete CA trust bundle, and persistent Redis. It requires both valid identities and the scopes needed by each operation. Its single replica uses the embedded bridge and a `ReadWriteOnce` volume. Running multiple replicas also requires a shared event bridge and durable evidence storage suitable for that deployment.

The template requires `state_backend = "redis"`. Its reserved `.invalid` endpoint must be replaced by `AV_STATE_ENDPOINT`, sourced from the required `agentvisor-ai-state` Secret. Configure Redis authentication, TLS, persistence, backups, and recovery before deployment, including deployments with only one replica. The spool PVC preserves audit evidence; Redis preserves revocations and instance cutoffs. See [revocation configuration](../../docs/reference/CONFIGURATION.md#token-revocation-post-v1revoke).

Before applying it:

1. Build and publish `docker/Dockerfile` to your registry, then replace `agentvisor-ai:local` with your image digest.
2. Replace `https://identity.example.invalid` in the ConfigMap with your trusted token issuer. Tokens must use audience `agentvisor-ai` and the application's required identity claims. See [identity configuration](../../docs/reference/CONFIGURATION.md).
3. Create namespace `agentvisor-ai` and the five Secrets named in the manifest: `agentvisor-ai-upstream` (`api-key`), `agentvisor-ai-signing-seed` (`signing.seed`), `agentvisor-ai-identity` (`identity.hmac`), `agentvisor-ai-state` (`redis-url`), and `agentvisor-ai-trust` (`ca-bundle.crt`). The HMAC secret must match the trusted issuer. The Redis connection URI belongs in the Secret, never in the ConfigMap. Use `avctl keygen --output` to generate the signing seed, and retain a protected backup because it anchors receipt verification.
4. For a JWKS-based issuer, replace `identity_hmac_secret_file` with `identity_jwks_url`, remove `identity.hmac` from the init container's copy loop, and remove the identity Secret volumes and mounts. Retain explicit issuer and audience constraints.
5. Review the namespace's access controls, TLS termination, storage class, retention, resource limits, and network policy for your cluster. The template provides a ClusterIP Service and does not choose an ingress controller. `network-policies.yaml` provides the network allowlist described below.
6. Validate against your selected cluster with `kubectl --context YOUR_CONTEXT -n agentvisor-ai apply --dry-run=server -f deploy/kubernetes/agentvisor-ai.yaml`, then apply the same manifest and verify readiness and authenticated requests.

The init container copies the signing and identity secrets into memory-backed storage, sets their owner to UID 65532 and mode to `0600`, and prepares the persistent spool directory. The application receives only read-only secret mounts. Missing or empty credentials prevent startup. Secret updates require a pod restart because the application reads the copied files at startup.

The CA bundle is mounted read-only and selected with `SSL_CERT_FILE`. Include the private CA that signs Redis's server certificate and any public roots required by other configured TLS destinations. This environment variable affects clients using native trust roots, so a bundle containing only a private root can remove trust required elsewhere. Use `rediss://` for TLS, match the URI hostname to the server certificate, and never disable certificate verification. Restart pods after changing the mounted bundle.

The daemon runs as UID 65532 with a read-only root filesystem. Its data and spool paths use the persistent volume, and `/tmp` uses a separate memory-backed volume capped at 64 MiB. The production image smoke test verifies startup, streaming, signing, and restart with these writable paths.

Repository tests validate the embedded configuration and shutdown budget. Run `python3 scripts/kubernetes-secrets-test.py` to exercise the exact init command in isolated Docker containers, including private file ownership, read-only mounts, retries, and empty-secret refusal. This test requires Docker and Ruby's standard YAML library. The local image smoke tests exercise the runtime image, requests, receipts, and persistent restart behavior.

For an actual local Kubernetes drill, build the gateway image and release `avctl`, then run:

```sh
python3 scripts/kubernetes-runtime-test.py --self-test
python3 scripts/kubernetes-runtime-test.py --image agentvisor-ai:local
```

The offline verifier defaults to `target/release/avctl`; set `AVCTL` to select another current build. The result records its path, version, and binary digest.

The drill requires Docker, kind, kubectl, Ruby, and OpenSSL. Docker must support [`image save --platform`](https://docs.docker.com/reference/cli/docker/image/save/) (API 1.48 or later). The drill exports only the gateway image's architecture so kind does not import references to undownloaded platform layers.

It uses a digest-pinned Kubernetes node image from [kind's official release](https://github.com/kubernetes-sigs/kind/releases/tag/v0.31.0), a uniquely named cluster and Docker network, and a private temporary kubeconfig. It never selects or changes the user's default Kubernetes context.

The drill applies this template with generated fixture credentials, a private CA, authenticated TLS Redis, persistent volumes, and a mock model/tool service. It checks Secret projection and permissions, probes, scope enforcement, real SSE and tool requests, receipt verification, pod replacement, shared revocation during an outage, and restoring Redis revocations from a snapshot into a fresh volume. The restore loads the snapshot with AOF disabled, creates the AOF, then restarts Redis with the normal persistence configuration before testing a fresh gateway. `--plaintext-redis` explicitly reduces the transport coverage and records that limitation.

The script records image identities and runtime versions, retains redacted logs, and removes only its own cluster, network, image aliases, credentials, and backup. The gateway image and cached upstream images remain available. Its three unit tests check cleanup ownership, token construction, and the template's identity and scope requirements.

Local kind validation covers the scheduler and Secret projection, but its single node and local-path volumes do not establish production CSI behavior, multi-host recovery, ingress, network policy enforcement, or an external identity provider. Validate those properties in the selected deployment environment. No remote cluster is modified by these repository tests.

## Network isolation for MCP backends

`network-policies.yaml` makes the gateway the only way to reach your MCP
servers. Its first policy lets only pods labeled `agentvisor.ai/client:
"true"` reach the gateway port. Its second policy, which you apply in each
namespace that runs MCP backends, lets pods labeled
`agentvisor.ai/mcp-backend: "true"` accept traffic only from the gateway
pods. Agents therefore cannot bypass the gateway's identity checks,
authorization, credential handling, and audit by calling a backend
directly.

Set `require_private_backends = true` in the gateway configuration as
well. The gateway then resolves every backend host when it connects and
refuses any address that is not private (loopback, RFC 1918, unique-local
IPv6, or link-local), so a misconfigured or rebinding backend name cannot
send tool traffic to the internet.

These policies take effect only when the cluster's network plugin enforces
NetworkPolicy. The local kind validation above does not enforce them;
verify enforcement in the target cluster, for example by calling a backend
from a pod without the client label and confirming the connection fails.
