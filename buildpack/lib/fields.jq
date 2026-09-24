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
{gateway_url: field("gateway_url"; true), audience: field("audience"; true),
 identity_jwks_url: field("identity_jwks_url"; false)}
