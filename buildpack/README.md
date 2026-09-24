# AgentVisor service binding buildpack

This component exposes client connection metadata from exactly one `agentvisor`
service binding. It does not install or start the gateway, issue identity tokens,
or change an SDK's configuration automatically. Your application must consume
`AV_GATEWAY_URL`, `AV_AUDIENCE`, and optional `AV_IDENTITY_JWKS_URL`. It must obtain
and present a valid identity token itself. An omitted JWKS URL is exported as an
empty string.

The build environment must provide a POSIX shell and `jq` 1.6 or newer. No runtime
parser is required: validated metadata is written at staging time. Restage or
rebuild after changing a binding. The values are connection metadata, not secrets.

## Cloud Foundry classic

Package this directory as a classic buildpack and list it explicitly before your
language buildpack. It is a supply component and cannot serve as a final
buildpack. Its classic `detect` always declines automatic selection. `supply`
writes only within `DEPS_DIR/DEPS_IDX/profile.d`, as required by the [Cloud Foundry
buildpack contract](https://docs.cloudfoundry.org/buildpacks/understand-buildpacks.html).

## Cloud Native Buildpacks

`buildpack.toml` declares API 0.9. `bin/detect` returns 100 when there is no binding,
and `bin/build` creates a launch-only layer with `env.launch/*.override` values.
The application still needs a language buildpack. Supply a service binding at
build time under `$CNB_PLATFORM_DIR/bindings`, or set `SERVICE_BINDING_ROOT`.
The selected builder must include `jq`; minimal builders without it are not
supported. See the [Buildpack API](https://buildpacks.io/docs/reference/spec/buildpack-api/).

## Binding validation

`VCAP_SERVICES` takes precedence when it contains a match. Matches use the exact
service label, name, or tag `agentvisor`. Otherwise discovery scans non-hidden
binding directories whose `type` file contains `agentvisor` (symlinks are
supported for projected Kubernetes bindings). Multiple matches fail staging.
Malformed JSON, invalid types, missing or blank required fields, and embedded
ASCII control characters fail staging. Values are trimmed. `gateway_url` and
`audience` are required strings; `identity_jwks_url` may be omitted, null, or blank.

Run `python3 buildpack/tests/test_buildpack.py` for executable contract tests that
exercise both entry points without a Cloud Foundry foundation or CNB builder.

Run `python3 buildpack/tests/lifecycle.py --download-pack` with Docker available
to verify actual CNB detection, build, export, non-root launch, and rebuilds. The
runner downloads a pinned, checksum-verified official `pack` binary to a temporary
directory. Alternatively, install `pack` yourself or set `PACK` to its executable
and omit `--download-pack`. It also checks malformed and absent bindings through
the lifecycle and executes the classic supply/profile contract in Linux. Its
uniquely named containers, images, and volumes are removed afterward; logs remain
in the printed temporary directory. This does not replace a staging test against
your Cloud Foundry foundation and its language buildpack.
