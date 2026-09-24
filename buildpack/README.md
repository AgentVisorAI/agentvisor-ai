# AgentVisor service binding buildpack

This buildpack connects an application to AgentVisor without code changes.
It reads exactly one `agentvisor` service binding at staging time and does
three things:

1. **Configures standard SDKs.** It sets `OPENAI_BASE_URL` and
   `OPENAI_API_BASE` (read by the OpenAI SDKs and by frameworks built on
   them), `AGENTVISOR_MCP_URL`, and `AGENTVISOR_MCP_CONFIG`. When the sidecar
   runs, these point at `http://127.0.0.1:<port>`; otherwise they point at
   the gateway. It also keeps `AV_GATEWAY_URL`, `AV_AUDIENCE`,
   `AV_IDENTITY_JWKS_URL`, and adds `AV_CLIENT_BASE_URL`.
2. **Writes an MCP client configuration** (`mcp.json`, path in
   `AGENTVISOR_MCP_CONFIG`) in the common `mcpServers` format: an
   `agentvisor` server for every backend's tools, plus an
   `agentvisor-<name>` server for each backend named in the binding. Adding
   a backend name to the binding and restaging updates the configuration;
   the gateway's `tools/list` supplies the tools themselves.
3. **Starts the identity sidecar** (`avctl sidecar`) beside the
   application, on a loopback port. The sidecar attaches a short-lived
   AgentVisor agent token to every request and forwards it to the gateway,
   so the application stores no secret and presents no token itself. On
   Cloud Foundry it proves the instance identity certificate the platform
   gives every container; the gateway maps the app to a registered workload
   that names the human the agent acts for (see "Platform workload identity"
   in [the configuration reference](../docs/reference/CONFIGURATION.md)).
   SDKs refuse to start without an API key, so the buildpack sets
   `OPENAI_API_KEY=agentvisor-sidecar` when no key is set; the sidecar
   replaces it.

The build environment must provide a POSIX shell and `jq` 1.6 or newer. No
runtime parser is required: all configuration is written at staging time.
Restage after changing a binding. The binding carries connection metadata,
never secrets.

## What "zero code change" covers

- OpenAI SDKs (Python, Node, and others that read `OPENAI_BASE_URL`), and
  frameworks built on them, reach the gateway unchanged.
- MCP clients reach the gateway unchanged when they read their server list
  from a configuration file; point them at `$AGENTVISOR_MCP_CONFIG`. A
  client that takes its server URL only in code needs that one URL
  (`$AGENTVISOR_MCP_URL`).
- Tool discovery happens live: the gateway answers `tools/list` with every
  tool the caller may call. Discovery is not done at staging, because the
  staging container has no identity to ask the gateway with (and the
  binding holds no secret to give it one).

## Binding fields

| Field | Required | Meaning |
| --- | --- | --- |
| `gateway_url` | yes | Gateway base URL, for example `http://agentvisor-ai.apps.internal:8484`. |
| `audience` | yes | The gateway's `audience`. |
| `identity_jwks_url` | no | Exported as `AV_IDENTITY_JWKS_URL` for applications that validate tokens themselves. |
| `backends` | no | Backend names for per-backend MCP servers: a JSON array, or names separated by commas, spaces, or newlines (the form a binding file carries). Names are lowercase letters, digits, `.`, `_`, `-`. |
| `sidecar` | no | `false` disables the sidecar. When absent, Cloud Foundry starts it (from `launch.yml`); Cloud Native Buildpacks only add the `agentvisor-sidecar` process type and point SDKs at the gateway, because nothing starts a second container automatically. Set `true` for a pod that runs the sidecar container, so SDKs use it. |
| `sidecar_port` | no | Loopback port, 1024 to 65535. Default `8485`. |
| `sidecar_credential` | no | `cf-instance` (Cloud Foundry default) or `token-file:<path>` (Cloud Native Buildpacks default: `token-file:/var/run/secrets/agentvisor/token`). |

`VCAP_SERVICES` takes precedence when it contains a match. Matches use the
exact service label, name, or tag `agentvisor`. Otherwise discovery scans
non-hidden binding directories whose `type` file contains `agentvisor`
(symlinks are supported for projected Kubernetes bindings); each field is a
file of the same name. Multiple matches fail staging. Malformed JSON,
invalid types, missing or blank required fields, invalid names or ports, and
embedded ASCII control characters fail staging. Values are trimmed.

## The sidecar binary

A packaged buildpack carries static Linux `avctl` binaries in
`vendor/avctl-linux-x86_64` and `vendor/avctl-linux-aarch64`. Build the
package from the release's musl binaries:

```sh
python3 scripts/package-buildpack.py \
  --avctl-x86_64 target/x86_64-unknown-linux-musl/release/avctl \
  --avctl-aarch64 target/aarch64-unknown-linux-musl/release/avctl \
  --output dist
```

The release workflow publishes `agentvisor-buildpack-<version>.zip` (Cloud
Foundry) and `.tgz` (Cloud Native Buildpacks) with checksums. A buildpack
used straight from this directory has no `vendor/` binaries: staging then
prints that no sidecar is available and points the SDK variables at the
gateway, and the application must present its own identity token.

The sidecar listens on a loopback address only, reads its settings from a
file the buildpack writes (so binding values never appear on a command
line), forwards method, path, body, and end-to-end headers (including
`MCP-Session-Id`), replaces the application's `Authorization` header, and
streams responses back unchanged. On Cloud Foundry it re-reads
`CF_INSTANCE_CERT` and `CF_INSTANCE_KEY` on every token refresh, because the
platform rotates them.

## Cloud Foundry classic

Package this directory with its sidecar binaries (above) as a classic
buildpack and list it explicitly before your language buildpack. It is a
supply component and cannot serve as a final buildpack. Its classic `detect`
always declines automatic selection. `supply` writes only within
`DEPS_DIR/DEPS_IDX`, as required by the [Cloud Foundry buildpack
contract](https://docs.cloudfoundry.org/buildpacks/understand-buildpacks.html):
`profile.d/agentvisor.sh`, `agentvisor/mcp.json`, `agentvisor/sidecar.json`,
`bin/avctl`, and a `launch.yml` that declares the `agentvisor-sidecar`
process for the `web` process type, as [sidecar
buildpacks](https://docs.cloudfoundry.org/buildpacks/sidecar-buildpacks.html)
do. The sidecar gets a 64 MB memory limit. Register the app as a workload on
the gateway (`[[workload_identities]]` with its app GUID) before starting it.

## Cloud Native Buildpacks

`buildpack.toml` declares API 0.9. `bin/detect` returns 100 when there is no
binding, and `bin/build` creates a launch-only layer with `env.launch`
values, `mcp.json`, and, when the sidecar is enabled, `bin/avctl`,
`sidecar.json`, and an `agentvisor-sidecar` process type (not the default
process). The application still needs a language buildpack. Supply a
service binding at build time under `$CNB_PLATFORM_DIR/bindings`, or set
`SERVICE_BINDING_ROOT`. The selected builder must include `jq`; minimal
builders without it are not supported. See the [Buildpack
API](https://buildpacks.io/docs/reference/spec/buildpack-api/).

In Kubernetes, run the sidecar as a second container of the same pod from
the same image (`command: ["/cnb/process/agentvisor-sidecar"]`); containers
of a pod share `127.0.0.1`. Set `sidecar: true` in the binding so the SDK
variables point at it; without it they point at the gateway. Its default credential reads a token that an
identity agent keeps current at `/var/run/secrets/agentvisor/token`.

## Tests

Run `python3 buildpack/tests/test_buildpack.py` for executable contract tests
that exercise both entry points without a Cloud Foundry foundation or CNB
builder, including a packaged copy with a stub sidecar binary. Run
`python3 scripts/test-package-buildpack.py` for the packaging script.

Run `python3 buildpack/tests/lifecycle.py --download-pack` with Docker
available to verify actual CNB detection, build, export, non-root launch, and
rebuilds. The runner downloads a pinned, checksum-verified official `pack`
binary to a temporary directory. Alternatively, install `pack` yourself or
set `PACK` to its executable and omit `--download-pack`. It also checks
malformed and absent bindings through the lifecycle and executes the classic
supply/profile contract in Linux. Its uniquely named containers, images, and
volumes are removed afterward; logs remain in the printed temporary
directory. This does not replace a staging test against your Cloud Foundry
foundation and its language buildpack, which is also the only way to confirm
that the foundation starts the buildpack-provided sidecar.
