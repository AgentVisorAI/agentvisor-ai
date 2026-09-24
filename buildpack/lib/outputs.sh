# shellcheck shell=sh
# Sourced by the classic and CNB entry points. Derives the client
# configuration an unmodified application needs from the validated binding
# JSON (see fields.jq). Never evaluates binding content as code.

# Path of the vendored sidecar binary for this architecture, or nothing.
sidecar_binary() {
    buildpack_dir=${buildpack_dir:?entry point must set buildpack_dir}
    case "$(uname -m)" in
        x86_64|amd64) arch=x86_64 ;;
        aarch64|arm64) arch=aarch64 ;;
        *) return 0 ;;
    esac
    candidate=$buildpack_dir/vendor/avctl-linux-$arch
    if [ -f "$candidate" ] && [ -x "$candidate" ]; then
        printf '%s' "$candidate"
    fi
}

# Base URL the application talks to: the loopback sidecar when it runs,
# otherwise the gateway itself. $1 = binding JSON, $2 = true|false.
client_base() {
    if [ "$2" = true ]; then
        printf '%s' "$1" | jq -j '"http://127.0.0.1:\(.sidecar_port)"'
    else
        printf '%s' "$1" | jq -j '.gateway_url | sub("/+$"; "")'
    fi
}

# MCP client configuration in the common `mcpServers` format: one server
# for every backend's tools, plus one per backend named in the binding.
# $1 = binding JSON, $2 = client base URL.
mcp_config() {
    printf '%s' "$1" | jq --arg base "$2" '{
        mcpServers: (
            {agentvisor: {type: "http", url: ($base + "/mcp")}}
            + (.backends | map({key: ("agentvisor-" + .), value: {type: "http", url: ($base + "/mcp/" + .)}})
               | from_entries)
        )
    }'
}

# Environment for the application, one NAME=VALUE per line (values never
# contain newlines: fields.jq rejects control characters).
# $1 = binding JSON, $2 = client base URL, $3 = MCP config path.
client_environment() {
    printf '%s' "$1" | jq -r --arg base "$2" --arg mcp "$3" '
        "AV_GATEWAY_URL=\(.gateway_url)",
        "AV_AUDIENCE=\(.audience)",
        "AV_IDENTITY_JWKS_URL=\(.identity_jwks_url // "")",
        "AV_CLIENT_BASE_URL=\($base)",
        "OPENAI_BASE_URL=\($base)/v1",
        "OPENAI_API_BASE=\($base)/v1",
        "AGENTVISOR_MCP_URL=\($base)/mcp",
        "AGENTVISOR_MCP_CONFIG=\($mcp)"'
}

# Sidecar settings file read by `avctl sidecar --config`, so no binding
# value ever appears on a command line. $1 = binding JSON,
# $2 = default credential.
sidecar_config() {
    printf '%s' "$1" | jq --arg credential "$2" '{
        gateway: .gateway_url,
        audience: .audience,
        listen: "127.0.0.1:\(.sidecar_port)",
        credential: (.sidecar_credential // $credential)
    }'
}
