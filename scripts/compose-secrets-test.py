#!/usr/bin/env python3
"""Exercise the shipped Compose secret installer without starting user services."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]


def main():
    project = "av-secrets-test-" + uuid.uuid4().hex[:12]
    # Home directories are shared into common desktop Docker VMs; host /tmp
    # frequently is not. Never mount actual operator secrets into this fixture.
    work = Path(tempfile.mkdtemp(prefix=project + "-", dir=Path.home()))
    calls = 0

    def run(args, expected=0, log_output=True):
        nonlocal calls
        calls += 1
        result = subprocess.run(args, capture_output=True, text=True, timeout=90)
        (work / "{:02d}.log".format(calls)).write_text(
            (result.stdout if log_output else "Resolved Compose configuration omitted.\n") + result.stderr)
        if (result.returncode == 0) != (expected == 0):
            raise RuntimeError("Unexpected result for {}: {}{}".format(args[:5], result.stdout, result.stderr))
        return result

    print("Compose secret test logs: " + str(work), flush=True)
    model = json.loads(run(["docker", "compose", "-f", str(ROOT / "docker/docker-compose.yml"),
                            "config", "--format", "json"], log_output=False).stdout)
    installer = model["services"]["install-secrets"]
    source_secrets = {}
    expected_hashes = {}
    for name in ("identity_hmac", "signing_seed"):
        file = work / name
        file.write_text(uuid.uuid4().hex + uuid.uuid4().hex)
        file.chmod(0o600)
        source_secrets[name] = {"file": str(file)}
        expected_hashes["EXPECTED_" + name.upper()] = hashlib.sha256(file.read_bytes()).hexdigest()
    fixture = {
        "services": {
            "install-secrets": installer,
            "verify": {
                "image": installer["image"], "user": "65532:65532",
                "network_mode": "none", "read_only": True, "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "environment": expected_hashes,
                "volumes": ["runtime-secrets:/run/secrets:ro"],
                "entrypoint": ["/bin/sh", "-ec"],
                "command": ["""for name in identity_hmac signing_seed; do
  file="/run/secrets/$$name"
  [ "$$(stat -c '%u:%g:%a' "$$file")" = '65532:65532:400' ]
  [ "$$(wc -c < "$$file")" -eq 64 ]
  [ -r "$$file" ]
  [ ! -w "$$file" ]
done
[ "$$(sha256sum /run/secrets/identity_hmac | cut -d ' ' -f 1)" = "$$EXPECTED_IDENTITY_HMAC" ]
[ "$$(sha256sum /run/secrets/signing_seed | cut -d ' ' -f 1)" = "$$EXPECTED_SIGNING_SEED" ]
[ "$$(stat -c '%u:%g:%a' /run/secrets)" = '65532:65532:700' ]
printf 'verified private runtime secrets\\n'
"""],
                "depends_on": {"install-secrets": {"condition": "service_completed_successfully"}},
            },
        },
        "secrets": source_secrets,
        "volumes": {"runtime-secrets": {}},
    }
    compose = work / "compose.json"
    compose.write_text(json.dumps(fixture))
    command = ["docker", "compose", "-p", project, "-f", str(compose)]
    try:
        run(command + ["up", "--abort-on-container-exit", "--exit-code-from", "verify"])
        raw_states = run(command + ["ps", "--all", "--format", "json"]).stdout.strip()
        states = json.loads(raw_states) if raw_states.startswith("[") else [json.loads(line) for line in raw_states.splitlines()]
        if not any(state["Service"] == "verify" and state["ExitCode"] == 0 for state in states):
            raise RuntimeError("The non-root verifier did not exit successfully")
        print("PASS: host-owned secrets become private, read-only files readable by UID 65532", flush=True)
        # Running the installer again must also work after the destination
        # directory has become private and owned by the application user.
        run(command + ["run", "--rm", "install-secrets"])
        print("PASS: installer safely repeats against the existing private volume", flush=True)
        (work / "identity_hmac").chmod(0o644)
        result = run(command + ["run", "--rm", "install-secrets"], expected=1)
        if "must be owner-only" not in result.stdout + result.stderr:
            raise RuntimeError("Public source secret was rejected for an unrelated reason")
        print("PASS: world-readable source secret is refused", flush=True)
        (work / "identity_hmac").chmod(0o600)
        (work / "identity_hmac").write_text("")
        result = run(command + ["run", "--rm", "install-secrets"], expected=1)
        if "is empty" not in result.stdout + result.stderr:
            raise RuntimeError("Empty source secret was rejected for an unrelated reason")
        print("PASS: empty source secret is refused", flush=True)
    finally:
        try:
            run(command + ["down", "--volumes", "--remove-orphans"])
        finally:
            for secret in source_secrets:
                (work / secret).unlink(missing_ok=True)


if __name__ == "__main__":
    main()
