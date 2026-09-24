def field($name; $required):
  .[$name]
  | if . == null and ($required | not) then null
    elif type != "string" then error($name + " must be a string")
    else gsub("^\\s+|\\s+$"; "")
      | if . == "" then
          if $required then error($name + " must not be empty") else null end
        elif test("[\\x{0000}-\\x{001f}\\x{007f}]") then error($name + " contains a control character")
        else . end
    end;
# Backend names: a JSON array of strings, or a string of names separated by
# commas, spaces, or newlines (the form a binding file carries).
def backends:
  .backends
  | if . == null then []
    elif type == "string" then [splits("[,\\s]+") | select(. != "")]
    elif type == "array" then map(if type == "string" then gsub("^\\s+|\\s+$"; "") else error("backends entries must be strings") end)
    else error("backends must be an array of names") end
  | map(if test("^[a-z0-9][a-z0-9_.-]{0,62}$") then . else error("backend name " + . + " is invalid") end)
  | unique;
# `sidecar` stays null when absent: Cloud Foundry then starts the sidecar
# (launch.yml guarantees it runs), while CNB points SDKs at the gateway
# unless the binding says `sidecar: true` (a second container must run it).
def sidecar:
  .sidecar
  | if . == null then null
    elif type == "boolean" then .
    elif type == "string" and (gsub("^\\s+|\\s+$"; "") | ascii_downcase) == "false" then false
    elif type == "string" and (gsub("^\\s+|\\s+$"; "") | ascii_downcase) == "true" then true
    else error("sidecar must be true or false") end;
def sidecar_port:
  .sidecar_port
  | if . == null then 8485
    elif type == "number" then .
    elif type == "string" then (gsub("^\\s+|\\s+$"; "") | tonumber? // error("sidecar_port must be a number"))
    else error("sidecar_port must be a number") end
  | if . == floor and . >= 1024 and . <= 65535 then . else error("sidecar_port must be an integer from 1024 to 65535") end;
{gateway_url: field("gateway_url"; true),
 audience: field("audience"; true),
 identity_jwks_url: field("identity_jwks_url"; false),
 backends: backends,
 sidecar: sidecar,
 sidecar_port: sidecar_port,
 sidecar_credential: field("sidecar_credential"; false)}
