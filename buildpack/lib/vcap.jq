# Keep matching and validation consistent with service_binding.rs.
if length != 1 then error("VCAP_SERVICES must contain one JSON object") else .[0] end |
if type != "object" then error("VCAP_SERVICES must be an object") else . end
| [to_entries[]
   | .key as $label
   | if (.value | type) != "array" then error("VCAP_SERVICES values must be arrays") else .value[] end
   | if type != "object" then error("VCAP_SERVICES entries must be objects") else . end
   | select($label == "agentvisor" or .label == "agentvisor" or .name == "agentvisor"
       or ((.tags | if type == "array" then . else [] end) | any(. == "agentvisor")))]
| if length > 1 then error("ambiguous agentvisor binding")
  elif length == 0 then null
  else .[0].credentials
    | if type != "object" then error("agentvisor credentials must be an object") else . end
  end
