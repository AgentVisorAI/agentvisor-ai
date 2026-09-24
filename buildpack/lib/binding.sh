# shellcheck shell=sh
# Sourced by the classic and CNB entry points; requires POSIX sh and jq.
# Prints validated JSON or null. Never evaluates binding content as code.
read_binding() {
    buildpack_dir=${buildpack_dir:?entry point must set buildpack_dir}
    command -v jq >/dev/null 2>&1 || {
        printf 'error: AgentVisor binding discovery requires jq in the build environment\n' >&2
        return 1
    }
    binding=null
    if [ -n "$(printf '%s' "${VCAP_SERVICES:-}" | jq -Rrs 'gsub("^\\s+|\\s+$"; "")')" ]; then
        binding=$(printf '%s' "$VCAP_SERVICES" | jq -sc -f "$buildpack_dir/lib/vcap.jq") || return 1
    fi
    if [ "$binding" = null ]; then
        binding_root=${SERVICE_BINDING_ROOT:-${CNB_PLATFORM_DIR:-/platform}/bindings}
        match_dir=''
        if [ -e "$binding_root" ] && [ ! -d "$binding_root" ]; then
            printf 'error: service binding root is not a directory\n' >&2
            return 1
        fi
        for dir in "$binding_root"/*/; do
            [ -f "${dir}type" ] || continue
            # Keep the type inside jq: command substitution could discard NULs.
            jq -Rse 'gsub("^\\s+|\\s+$"; "") == "agentvisor"' "${dir}type" >/dev/null || continue
            if [ -n "$match_dir" ]; then
                printf 'error: ambiguous agentvisor binding\n' >&2
                return 1
            fi
            match_dir=$dir
        done
        if [ -n "$match_dir" ]; then
            for field in gateway_url audience; do
                if [ ! -f "$match_dir$field" ]; then
                    printf 'error: binding is missing %s\n' "$field" >&2
                    return 1
                fi
            done
            optional() {
                if [ -e "$match_dir$1" ]; then printf '%s' "$match_dir$1"; else printf '/dev/null'; fi
            }
            # Optional files that are absent (read as "") are dropped, so
            # fields.jq applies its defaults.
            binding=$(jq -cn --rawfile gateway_url "${match_dir}gateway_url" \
                --rawfile audience "${match_dir}audience" \
                --rawfile identity_jwks_url "$(optional identity_jwks_url)" \
                --rawfile backends "$(optional backends)" \
                --rawfile sidecar "$(optional sidecar)" \
                --rawfile sidecar_port "$(optional sidecar_port)" \
                --rawfile sidecar_credential "$(optional sidecar_credential)" \
                '{gateway_url:$gateway_url,audience:$audience,identity_jwks_url:$identity_jwks_url,
                  backends:$backends,sidecar:$sidecar,sidecar_port:$sidecar_port,
                  sidecar_credential:$sidecar_credential}
                 | with_entries(select(.key == "gateway_url" or .key == "audience"
                     or (.value | gsub("^\\s+|\\s+$"; "")) != ""))') || return 1
        fi
    fi
    if [ "$binding" = null ]; then
        printf 'null\n'
    else
        printf '%s' "$binding" | jq -c -f "$buildpack_dir/lib/fields.jq" || return 1
    fi
}
