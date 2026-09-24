#!/usr/bin/env python3
"""Check the Kubernetes template's actual init command in isolated containers.

Requires Docker and Ruby's standard YAML library. This verifies file ownership
and retry behavior; it does not substitute for validation on a Kubernetes cluster.
"""
import json
from pathlib import Path
import subprocess
import tempfile
import uuid


def main():
    root = Path(__file__).resolve().parents[1]
    prefix = "av-kubernetes-secrets-" + uuid.uuid4().hex[:12]
    work = Path(tempfile.mkdtemp(prefix=prefix + "-"))
    calls = 0
    volumes = []

    def run(args, expected=0):
        nonlocal calls
        calls += 1
        result = subprocess.run(args, text=True, capture_output=True, timeout=90)
        (work / "{:02d}.log".format(calls)).write_text(result.stdout + result.stderr)
        if (result.returncode == 0) != (expected == 0):
            raise RuntimeError("Unexpected result for {}: {}{}".format(args[:5], result.stdout, result.stderr))
        return result.stdout + result.stderr

    print("Kubernetes secret test logs: " + str(work), flush=True)
    resources = json.loads(run(["ruby", "-ryaml", "-rjson", "-e",
                               "puts JSON.generate(YAML.load_stream(File.read(ARGV[0])))",
                               str(root / "deploy/kubernetes/agentvisor-ai.yaml")]))
    pod = next(item for item in resources if item and item.get("kind") == "Deployment")["spec"]["template"]["spec"]
    installer = pod["initContainers"][0]
    if pod["securityContext"]["runAsUser"] != 65532 or pod["automountServiceAccountToken"]:
        raise RuntimeError("Unexpected pod privilege configuration")
    security = installer["securityContext"]
    if not security["readOnlyRootFilesystem"] or security["allowPrivilegeEscalation"]:
        raise RuntimeError("The init container must have a read-only root and no privilege escalation")
    runtime = pod["containers"][0]
    if not runtime["securityContext"]["readOnlyRootFilesystem"]:
        raise RuntimeError("The daemon must have a read-only root")
    temporary = next(mount for mount in runtime["volumeMounts"] if mount["mountPath"] == "/tmp")
    volume = next(volume for volume in pod["volumes"] if volume["name"] == temporary["name"])
    if volume.get("emptyDir") != {"medium": "Memory", "sizeLimit": "64Mi"}:
        raise RuntimeError("Temporary files must use the bounded memory-backed mount")
    secret_mounts = [mount for mount in pod["containers"][0]["volumeMounts"]
                     if mount["mountPath"] in ("/etc/agentvisor-ai/signing.seed", "/etc/agentvisor-ai/identity.hmac")]
    if len(secret_mounts) != 2 or not all(mount["readOnly"] for mount in secret_mounts):
        raise RuntimeError("Both runtime secret files must be mounted read-only")
    source, destination, data = [prefix + "-" + name for name in ("source", "destination", "data")]
    image = installer["image"]
    base = ["docker", "run", "--rm", "--network", "none", "--read-only",
            "--security-opt", "no-new-privileges", "--cap-drop", "ALL"]
    try:
        for volume in (source, destination, data):
            volumes.append(volume)
            run(["docker", "volume", "create", volume])
        # Prepare root-owned source files like Secret projections. These are
        # synthetic test strings, never operator secrets from the host.
        run(base + ["-v", source + ":/source", image, "sh", "-ec",
                    "printf '%s' signing-fixture > /source/signing.seed; "
                    "printf '%s' identity-fixture > /source/identity.hmac; "
                    "chmod 0400 /source/*"])
        init = base + ["--user", str(security["runAsUser"])]
        for capability in security["capabilities"]["add"]:
            init += ["--cap-add", capability]
        init += ["-v", source + ":/var/run/agentvisor-ai/secret-source:ro",
                 "-v", destination + ":/etc/agentvisor-ai",
                 "-v", data + ":/var/run/agentvisor-ai/data", image] + installer["command"]
        verify = base + ["--user", "65532:65532", "-v", destination + ":/etc/agentvisor-ai:ro",
                         "-v", data + ":/data", image, "sh", "-ec", """
for name in signing.seed identity.hmac; do
  path="/etc/agentvisor-ai/$name"
  [ "$(stat -c '%u:%g:%a' "$path")" = '65532:65532:600' ]
  [ -r "$path" ]
  # BusyBox test -w checks mode bits; verify the read-only mount with a write.
  if (printf forbidden >> "$path") 2>/dev/null; then exit 1; fi
done
[ "$(cat /etc/agentvisor-ai/signing.seed)" = signing-fixture ]
[ "$(cat /etc/agentvisor-ai/identity.hmac)" = identity-fixture ]
[ "$(stat -c '%u:%g:%a' /etc/agentvisor-ai)" = '65532:65532:700' ]
touch /data/spool/non-root-write
"""]
        run(init)
        run(verify)
        print("PASS: actual Kubernetes init command delivers private read-only credentials and a writable spool to UID 65532", flush=True)
        run(init)
        run(verify)
        print("PASS: init command safely repeats after files become owned by the daemon", flush=True)
        denied = run(base + ["--user", "65531:65531", "-v", destination + ":/etc/agentvisor-ai:ro",
                             image, "cat", "/etc/agentvisor-ai/identity.hmac"], expected=1)
        if "Permission denied" not in denied:
            raise RuntimeError("Another UID could not read the credential for an unrelated reason")
        print("PASS: another UID cannot read the identity credential", flush=True)
        run(base + ["-v", source + ":/source", image, "sh", "-ec",
                    "chmod 0600 /source/identity.hmac; : > /source/identity.hmac; chmod 0400 /source/identity.hmac"])
        if "Required secret identity.hmac is empty" not in run(init, expected=1):
            raise RuntimeError("Empty identity source failed for an unrelated reason")
        print("PASS: an empty identity credential prevents init completion", flush=True)
    finally:
        for volume in volumes:
            run(["docker", "volume", "rm", "-f", volume])


if __name__ == "__main__":
    main()
