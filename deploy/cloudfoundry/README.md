# Deploying on Cloud Foundry

The manifest maps only `agentvisor-ai.apps.internal`. The gateway requires a
valid identity token with the required operation scopes and disables its unauthenticated dashboard. Update the
internal domain if your foundation uses another one. Container networking must
be enabled on the foundation.

## Foundation shutdown preflight

Before starting this template in production, ask the foundation operator to
verify the deployed Diego `rep` job's
`containers.graceful_shutdown_interval_in_seconds` setting on every cell that
can host the application. Require at least **120 seconds** for this template.
Cloud Foundry normally allows only ten seconds between `SIGTERM` and `SIGKILL`;
the interval is a foundation setting, not an application manifest setting.
See the [Cloud Foundry shutdown lifecycle](https://docs.cloudfoundry.org/devguide/deploy-apps/app-lifecycle.html#shutdown)
and the [Diego rep property reference](https://bosh.io/jobs/rep?source=github.com%2Fcloudfoundry%2Fdiego-release&version=2.143.0#p=containers.graceful_shutdown_interval_in_seconds).

The supplied `harness.toml` allows 30 seconds to drain HTTP requests. Audit
worker draining and session finalization each have a further 30-second limit,
and the full image allows five seconds for telemetry flushing. Their combined
budget is 95 seconds; the 120-second minimum leaves some additional time for
shutdown overhead. These are the explicitly timed phases, not an overall
wall-clock shutdown bound. The daemon also awaits cooperative completion of
background reconciliation, bridge maintenance, and spool retention before these
phases. Filesystem or broker work already in progress can extend shutdown.
The operator must allow longer grace when staging measurements require it.
Recalculate the phase budget if its limits change. Reducing only
`shutdown_drain_timeout_s` cannot fit the remaining 65 seconds into Cloud
Foundry's default ten-second interval. The manifest's `timeout` attribute controls
application startup and does not extend shutdown grace.

Record the operator-confirmed interval before deployment, then test a restart
under an in-flight request on a staging foundation with the same setting and
image. Verify request completion and durable audit output before the process
exits. If the foundation cannot provide sufficient grace, this template cannot
promise orderly completion of in-flight requests and audit finalization:
`SIGKILL` can interrupt them. Persistent storage is still required for recovery;
it does not extend the shutdown deadline. This repository does not change a
foundation's BOSH configuration.

## Application setup

The manifest separates liveness (`/livez`) from HTTP readiness (`/readyz`).
Ask the foundation operator to confirm readiness-check support before applying
it: Cloud Foundry documents minimum versions of garden-runc-release 1.37.0,
diego-release 2.81.0, and capi-release 1.158.0. The readiness check runs every five
seconds with a three-second invocation timeout. It observes draining and spool
failures without turning them into liveness failures and restart loops. See
[Cloud Foundry health checks](https://docs.cloudfoundry.org/devguide/deploy-apps/healthchecks.html)
and the [manifest attributes](https://docs.cloudfoundry.org/devguide/deploy-apps/manifest-attributes.html#readiness-health-check-type).
Validate the manifest against your selected foundation; local configuration tests
do not prove that its deployed releases support these fields.

1. Edit `harness.toml` in this directory with your identity provider's JWKS URL,
   allowed issuer, and the audience assigned to AgentVisor. The supplied
   `example.invalid` values intentionally cannot authenticate real clients.
2. Provision a protected Redis service with authentication, TLS, persistence,
   backups, and a tested recovery procedure. Redis is required even for one
   instance so revocations and instance cutoffs survive restarts. Put its
   connection URI in a private YAML variables file (mode `0600`), under the
   key `redis_url`. The manifest supplies that value as `AV_STATE_ENDPOINT`.
   The reserved `.invalid` configuration endpoint cannot silently select an
   unrelated live Redis service. Existing AgentVisor client service bindings
   describe gateway discovery; they do not discover Redis credentials for the
   gateway. If your CF service broker supplies Redis credentials in a binding,
   transfer its connection URI into this explicit deployment setting using
   your platform's protected deployment workflow.
   For a private Redis CA, mount a complete PEM trust bundle using the
   foundation's supported volume or certificate-delivery mechanism and set
   `SSL_CERT_FILE` to its readable in-container path before starting the app.
   Include the private root and any public roots needed by JWKS, upstream,
   or other TLS clients that honor this environment variable. Do not disable
   verification: use a `rediss://` URI whose hostname matches the Redis server
   certificate. Restart the application after updating the bundle. The example
   does not select a foundation-specific certificate or volume service.
3. Build the standard image and then the Cloud Foundry image from the repository
   root. Replace the registry and image tags in these commands and the manifest.

   ```sh
   docker build -f docker/Dockerfile -t agentvisor-base:local .
   docker build -f deploy/cloudfoundry/Dockerfile \
     --build-arg AGENTVISOR_IMAGE=agentvisor-base:local \
     -t registry.example.com/agentvisor-ai:cf .
   docker push registry.example.com/agentvisor-ai:cf
   cf push -f deploy/cloudfoundry/manifest.yml \
     --vars-file /secure/path/agentvisor-vars.yml --no-start
   cf set-env agentvisor-ai AV_UPSTREAM_URL https://api.openai.com
   cf set-env agentvisor-ai AV_UPSTREAM_API_KEY YOUR_PROVIDER_KEY
   cf start agentvisor-ai
   ```

4. Permit only the intended client applications to reach the gateway:

   ```sh
   cf add-network-policy my-ai-app agentvisor-ai --port 8484 --protocol tcp
   ```

The internal gateway URL is `http://agentvisor-ai.apps.internal:8484`. Internal
DNS does not provide TLS termination; use the foundation's protected container
network, or configure an internal TLS endpoint when required. Inspect `cf routes`
when updating an existing installation. A new manifest does not necessarily
remove previously mapped public routes; remove those mappings with
`cf unmap-route` before starting the application.

Direct `apps.internal` connections bypass the Gorouter. The readiness fields
therefore do not establish readiness-aware client load balancing on their own.
Clients must handle unavailable instances and `503` responses; verify service
discovery, connection reuse, and any client-side readiness selection on your
foundation before relying on rolling-deployment behavior. Cloud Foundry also
documents this [internal-route limitation](https://docs.cloudfoundry.org/buildpacks/nginx/index.html#name-resolution).

The sample uses one instance and ephemeral local spool storage. Before production use,
provide persistent spool storage and signing material (`AV_SIGNING_SEED_FILE`),
and configure a durable event bridge. The required Redis service must retain
revocations across restarts and use appropriate backups. Shared state and
revocation storage are also required before increasing the instance count. Cloud Foundry does not preserve
container files across restaging. Set resource limits using measurements of your
configured workload; the manifest's values are starting points.

## Client discovery and identity (no code change)

An `agentvisor` service binding describes how a **client** reaches the
gateway. Create a user-provided service and bind it to the client, not to
`agentvisor-ai`:

```sh
cf cups agentvisor -t agentvisor \
  -p '{"gateway_url":"http://agentvisor-ai.apps.internal:8484","audience":"agentvisor-ai","backends":["my-mcp-backend"]}'
cf bind-service my-ai-app agentvisor
```

Push the application with the packaged buildpack
(`agentvisor-buildpack-<version>.zip` from a release, or built with
`scripts/package-buildpack.py`) listed before the language buildpack. At
staging it points `OPENAI_BASE_URL` and the MCP configuration
(`$AGENTVISOR_MCP_CONFIG`) at a loopback sidecar, and declares that sidecar
in `launch.yml`. At run time the sidecar proves the instance identity
certificate Cloud Foundry gives the container and attaches the resulting
agent token to every request. See [the buildpack
instructions](../../buildpack/README.md).

On the gateway, register the application as a workload and trust the
foundation's instance-identity CA. In `harness.toml`:

```toml
token_exchange_seed_file = "/app/secrets/exchange.seed"
identity_human_subject_pattern = "^user:"

[workload_identity]
ca_file = "/app/secrets/instance-identity-ca.pem"

[[workload_identities]]
name = "my-ai-app"
cf_app_guid = "<output of: cf app my-ai-app --guid>"
sub = "user:owner@example.com"     # the human this agent acts for
charter = "support"
scopes = ["chat", "tool:*"]
```

Ask the platform operator for the Diego instance identity CA certificate.
Allow the client to reach the gateway with
`cf add-network-policy my-ai-app agentvisor-ai --port 8484 --protocol tcp`
(step 4 above). The sidecar needs no route and no network policy of its own.

## MCP backend networking

Give each MCP backend an internal route only, as in
[`mcp-backend.manifest.yml`](mcp-backend.manifest.yml), for example
`my-mcp-backend.apps.internal`, and configure its gateway backend URL as
`http://my-mcp-backend.apps.internal:8080/mcp`. The backend then has no
public route through the Gorouter. An app pushed with `no-route: true` has
no route at all, internal ones included, so the gateway would have no DNS
name to reach it by; the internal-only route gives the same protection from
outside the foundation. Allow the gateway, and only the gateway, to reach
the backend:

```sh
cf add-network-policy agentvisor-ai my-mcp-backend --port 8080 --protocol tcp
```

Do not grant client applications direct access to a backend: its calls must
pass through AgentVisor's authorization and audit controls. Set
`require_private_backends = true` in `harness.toml` so the gateway refuses
to connect to a backend address that is not private.

All backends sit behind the one gateway host. Clients use
`http://agentvisor-ai.apps.internal:8484/mcp` for every backend's tools, or
`/mcp/<backend-name>` for one backend's tools only; each backend keeps its
own authentication policy (`auth` in its `[[backends]]` entry).

These examples follow Cloud Foundry's [container networking
instructions](https://docs.cloudfoundry.org/devguide/deploy-apps/cf-networking.html).
