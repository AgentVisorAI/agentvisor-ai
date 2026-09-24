#!/usr/bin/env python3
"""Verify a locally built AgentVisor image against an isolated mock provider.

Usage: python3 scripts/container-smoke.py --image agentvisor-ai:local
       python3 scripts/container-smoke.py --console-image agentvisor-api:local
Docker is required. Only this run's uniquely named resources are removed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

ALPINE = "alpine@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6"
POSTGRES = "postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea"
MOCK = '''from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ready")
    def do_POST(self):
        data = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        if (self.path != "/v1/chat/completions" or
            self.headers.get("Authorization") != "Bearer smoke-provider-key" or
            data.get("model") != "container-smoke"):
            self.send_response(400)
            self.end_headers()
            return
        chunk = {"choices": [{"delta": {"content": "hello from container provider"}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 12, "completion_tokens": 6}}
        body = ("data: " + json.dumps(chunk) + "\\n\\ndata: [DONE]\\n\\n").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass
ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
'''


class Smoke:
    def __init__(self, image, port=0):
        self.image = image
        self.port = port
        self.container_port = 8484
        self.prefix = "av-container-smoke-" + uuid.uuid4().hex[:12]
        self.work = Path(tempfile.mkdtemp(prefix=self.prefix + "-"))
        self.containers, self.volumes, self.images, self.networks = [], [], [], []
        self.step = 0
        self.secret_files = []
        self.daemon_binaries = None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def run(self, args, timeout=45, expected=0, input=None, env=None, combine_output=False):
        self.step += 1
        log = self.work / "{:02d}.log".format(self.step)
        try:
            result = subprocess.run(args, input=input, capture_output=True, text=True, timeout=timeout, env=env)
        except subprocess.TimeoutExpired as error:
            chunks = [chunk.decode(errors="replace") if isinstance(chunk, bytes) else (chunk or "")
                      for chunk in (error.stdout, error.stderr)]
            log.write_text("Timed out: " + repr(args) + "\n" + "".join(chunks))
            raise
        log.write_text(
            "Command: " + repr(args) + "\n" + result.stdout + result.stderr)
        good = result.returncode == 0 if expected == 0 else result.returncode != 0
        if not good:
            raise RuntimeError("Unexpected result for {}: {}{}".format(args[:5], result.stdout, result.stderr))
        return result.stdout + result.stderr if combine_output else result.stdout

    def request(self, path, body=None, headers=None):
        request = urllib.request.Request(self.base + path,
                                         data=None if body is None else json.dumps(body).encode(),
                                         headers=headers or {}, method="GET" if body is None else "POST")
        try:
            with self.opener.open(request, timeout=10) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.read()

    def readiness_body(self, body):
        return json.loads(body).get("status") == "ready"

    def ready(self):
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            state = self.run(["docker", "inspect", "--format", "{{.State.Running}}", self.gateway]).strip()
            if state != "true":
                raise RuntimeError("Gateway exited before readiness")
            try:
                status, body = self.request("/readyz")
                if status == 200 and self.readiness_body(body):
                    return
            except (OSError, ValueError):
                pass
            time.sleep(0.2)
        raise RuntimeError("Gateway did not become ready within 45 seconds")

    def verify(self):
        configuration = json.loads(self.run(["docker", "image", "inspect", self.image]))[0]["Config"]
        if configuration.get("User", "").split(":")[0] != "65532":
            raise RuntimeError("Production image does not declare non-root UID 65532")
        if configuration.get("Entrypoint") != ["agentvisord"]:
            raise RuntimeError("Production image has an unexpected entry point")
        self.mock_image = self.prefix + "-provider"
        self.images.append(self.mock_image)
        (self.work / "mock.py").write_text(MOCK)
        (self.work / "Dockerfile").write_text(
            "FROM " + ALPINE + "\nRUN apk add --no-cache python3\n"
            "COPY mock.py /mock.py\nUSER 65532:65532\nCMD [\"python3\", \"/mock.py\"]\n")
        self.run(["docker", "build", "-t", self.mock_image, str(self.work)], timeout=300)
        network = self.prefix + "-network"
        self.networks.append(network)
        self.run(["docker", "network", "create", network])
        provider = self.prefix + "-provider"
        self.containers.append(provider)
        self.run(["docker", "run", "-d", "--name", provider, "--network", network,
                  "--network-alias", "provider", "--read-only", "--cap-drop", "ALL",
                  "--security-opt", "no-new-privileges", self.mock_image])
        deadline = time.monotonic() + 20
        while True:
            try:
                self.run(["docker", "exec", provider, "python3", "-c",
                          "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080',timeout=1).read()"])
                break
            except RuntimeError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.2)
        mounts = []
        for part in ("data", "spool"):
            volume = self.prefix + "-" + part
            if part == "spool":
                self.spool_volume = volume
            self.volumes.append(volume)
            self.run(["docker", "volume", "create", volume])
            mounts += ["--mount", "type=volume,src={},dst=/app/{}".format(volume, part)]
        self.gateway = self.prefix + "-gateway"
        self.containers.append(self.gateway)
        self.run(["docker", "run", "-d", "--name", self.gateway, "--network", network,
                  "--read-only", "--tmpfs", "/tmp:uid=65532,gid=65532,mode=0700",
                  "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "512",
                  "-p", "127.0.0.1:{}:8484".format(self.port or ""), "-e", "AV_UPSTREAM_URL=http://provider:8080",
                  "-e", "AV_UPSTREAM_API_KEY=smoke-provider-key",
                  "-e", "RUST_LOG=info",
                  "-e", "AV_SIGNING_SEED_FILE=/app/data/signing.seed"] + mounts + [self.image])
        self.refresh_port()
        self.ready()
        self.run(["docker", "exec", self.gateway, "avctl", "health", "--url", "http://127.0.0.1:8484/readyz"])
        print("PASS: production image boots as UID 65532 with read-only root and writable data/spool; readiness and CLI health", flush=True)
        session = "container-" + uuid.uuid4().hex
        status, body = self.request("/v1/chat/completions", {
            "model": "container-smoke", "stream": True,
            "messages": [{"role": "user", "content": "hello"}]
        }, {"Content-Type": "application/json", "x-av-session": session, "x-av-workflow": "signed"})
        if status != 200 or b"hello from container provider" not in body or b"[DONE]" not in body:
            raise RuntimeError("Proxy request failed: {} {}".format(status, body.decode(errors="replace")))
        print("PASS: real streaming request reaches isolated provider with configured credentials", flush=True)
        status, body = self.request("/v1/sessions/" + session + "/close", {})
        if status != 200 or json.loads(body).get("kind") != "receipt":
            raise RuntimeError("Session close failed: " + body.decode(errors="replace"))
        status, body = self.request("/v1/sessions/" + session + "/promote", {})
        receipt = json.loads(body)
        if status != 200 or "receipt_id" not in receipt:
            raise RuntimeError("Receipt promotion failed: " + repr(receipt))
        (self.work / "receipt.json").write_bytes(body)
        original = json.loads(body)
        before = self.receipt_events(original)
        pubkey = self.public_key()
        self.verify_receipt(body.decode(), pubkey)
        receipt["cost"]["prompt_tokens"] = 999999
        self.verify_receipt(json.dumps(receipt), pubkey, expected=1)
        print("PASS: packaged avctl verifies the signed receipt and refuses a modified receipt", flush=True)
        self.run(["docker", "restart", "--time", "30", self.gateway], timeout=45)
        self.refresh_port()
        self.ready()
        if self.public_key() != pubkey:
            raise RuntimeError("Signing key changed across restart despite persistent data volume")
        # Signed close removes session controls after its durable receipt and
        # broker acknowledgement. The receipt remains in spool and Bridge;
        # promote is not an API for querying closed sessions after restart.
        status, _ = self.request("/v1/sessions/" + session + "/promote", {})
        if status != 404:
            raise RuntimeError("Closed signed session unexpectedly retained controls after restart")
        name = hashlib.sha256(session.encode()).hexdigest()[:32] + ".json"
        restored = self.run([
            "docker", "run", "--rm", "--network", "none", "--read-only",
            "--user", "65532:65532", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "-v", self.spool_volume + ":/evidence:ro",
            self.mock_image, "python3", "-c",
            "import pathlib; print(pathlib.Path('/evidence/atif/receipts/" + name + "').read_text())"])
        (self.work / "restored-receipt.json").write_text(restored)
        if json.loads(restored) != original:
            raise RuntimeError("Persisted receipt changed across restart")
        self.verify_receipt(restored, pubkey)
        # Allow the default five-second reconciliation tick to run before
        # checking that restart did not emit the receipt again.
        time.sleep(6)
        if self.receipt_events(original) != before:
            raise RuntimeError("Persisted Bridge receipt event changed across restart")
        print("PASS: restart preserves signing key and original stored receipt; packaged CLI verifies it and Bridge contains exactly one receipt event", flush=True)

    def receipt_events(self, receipt):
        events = []
        for partition in range(8):
            output = self.run([
                "docker", "exec", self.gateway, "avctl", "event-tail",
                "--data-dir", "/app/data/bridge", "--topic", "agent.receipt",
                "--partition", str(partition), "--offset", "0", "--max", "100"])
            for line in output.splitlines():
                event = json.loads(line)
                payload = event.get("value", {}).get("payload", {})
                if payload.get("receipt_id") == receipt["receipt_id"]:
                    if payload.get("receipt") != receipt:
                        raise RuntimeError("Bridge receipt differs from the signed receipt")
                    events.append(event)
        if len(events) != 1:
            raise RuntimeError("Expected one durable receipt event, found " + str(len(events)))
        return events

    def refresh_port(self):
        ports = json.loads(self.run(["docker", "inspect", "--format", "{{json .NetworkSettings.Ports}}", self.gateway]))
        bindings = ports.get(str(self.container_port) + "/tcp")
        if not bindings:
            raise RuntimeError("Docker did not publish the requested loopback port")
        port = bindings[0]
        if port["HostIp"] != "127.0.0.1":
            raise RuntimeError("Gateway was not bound exclusively to loopback")
        self.base = "http://127.0.0.1:" + port["HostPort"]

    def public_key(self):
        return json.loads(self.run(["docker", "exec", self.gateway, "avctl", "pubkey",
                                   "--seed", "/app/data/signing.seed"]))["public_key_hex"]

    def verify_receipt(self, receipt, key, expected=0):
        # avctl refuses pipes and special files. Docker also refuses cp into
        # a container with a read-only root, even when the destination is a
        # tmpfs. Put a normal file in a separate volume, then run the packaged
        # CLI with that volume mounted read-only and no network access.
        if not hasattr(self, "receipt_volume"):
            self.receipt_volume = self.prefix + "-receipt"
            self.volumes.append(self.receipt_volume)
            self.run(["docker", "volume", "create", self.receipt_volume])
        self.run(["docker", "run", "--rm", "-i", "--network", "none", "--user", "0:0",
                  "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                  "-v", self.receipt_volume + ":/evidence", self.mock_image, "python3", "-c",
                  "import pathlib,sys; p=pathlib.Path('/evidence/receipt.json'); "
                  "p.unlink(missing_ok=True); p.write_text(sys.stdin.read()); p.chmod(0o444)"], input=receipt)
        output = self.run(["docker", "run", "--rm", "--network", "none", "--read-only",
                           "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                           "-v", self.receipt_volume + ":/evidence:ro", "--entrypoint", "avctl", self.image,
                           "receipt-verify", "/evidence/receipt.json", "--public-key-hex", key], expected=expected)
        if expected == 0 and not output.startswith("verified "):
            raise RuntimeError("Receipt verifier did not report verified")

    def cleanup(self):
        for name in self.containers:
            try:
                self.run(["docker", "logs", name])
            except (RuntimeError, subprocess.TimeoutExpired):
                pass
        for kind, names in (("container", self.containers), ("volume", self.volumes),
                            ("image", self.images), ("network", self.networks)):
            for name in names:
                try:
                    flags = [] if kind == "network" else (["-f", "-v"] if kind == "container" else ["-f"])
                    self.run(["docker", kind, "rm"] + flags + [name])
                except (RuntimeError, subprocess.TimeoutExpired) as error:
                    print("Cleanup could not remove {} {}: {}".format(kind, name, error), flush=True)
        for path in self.secret_files:
            path.unlink(missing_ok=True)


class ConsoleSmoke(Smoke):
    """Exercise migrations and the production Node entry point against a private DB."""

    def readiness_body(self, body):
        value = json.loads(body)
        return value.get("ok") is True and value.get("checks", {}).get("db") == "ok"

    def environment_file(self, name, values):
        path = self.work / name
        path.touch(mode=0o600)
        path.write_text("".join(key + "=" + value + "\n" for key, value in values.items()))
        self.secret_files.append(path)
        return str(path)

    def database_ready(self):
        deadline = time.monotonic() + 40
        while True:
            try:
                self.run(["docker", "exec", self.database, "pg_isready", "-U", "agentvisor", "-d", "agentvisor"])
                return
            except RuntimeError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.25)

    def verify(self):
        self.container_port = 8080
        configuration = json.loads(self.run(["docker", "image", "inspect", self.image]))[0]["Config"]
        user = configuration.get("User")
        uids = {"node": 1000, "1000": 1000, "1000:1000": 1000,
                "nonroot": 65532, "65532": 65532, "65532:65532": 65532}
        if user not in uids:
            raise RuntimeError("Console image does not declare its non-root user")
        uid = uids[user]
        if "readyz" not in repr(configuration.get("Healthcheck", {}).get("Test", [])):
            raise RuntimeError("Console image has no readiness healthcheck")
        network = self.prefix + "-network"
        self.networks.append(network)
        self.run(["docker", "network", "create", network])
        password = secrets.token_hex(24)
        db_environment = self.environment_file("database.env", {
            "POSTGRES_USER": "agentvisor", "POSTGRES_PASSWORD": password, "POSTGRES_DB": "agentvisor"})
        api_environment = self.environment_file("api.env", {
            "DATABASE_URL": "postgresql://agentvisor:" + password + "@database:5432/agentvisor?connect_timeout=2",
            "JWT_SECRET": secrets.token_hex(32), "NODE_ENV": "production", "PORT": "8080",
            "APP_BASE_URL": "https://console.example.test", "ALLOWED_ORIGINS": "https://console.example.test",
            "SMTP_URL": "smtp://fixture:fixture@127.0.0.1:2525"})
        self.database = self.prefix + "-database"
        self.containers.append(self.database)
        self.run(["docker", "run", "-d", "--name", self.database, "--network", network,
                  "--network-alias", "database", "--memory", "512m", "--pids-limit", "128",
                  "--env-file", db_environment, POSTGRES], timeout=300)
        self.database_ready()
        refused = self.prefix + "-refused-migration"
        self.containers.append(refused)
        self.run(["docker", "run", "-d", "--name", refused, "--network", network,
                  "--read-only", "--tmpfs", "/tmp:uid={},gid={},mode=0700".format(uid, uid),
                  "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                  "--memory", "512m", "--pids-limit", "256", "--env-file", api_environment,
                  "-e", "DATABASE_URL=postgresql://agentvisor:intentionally-invalid@database:5432/agentvisor?connect_timeout=2",
                  self.image])
        deadline = time.monotonic() + 25
        while True:
            state = json.loads(self.run(["docker", "inspect", "--format", "{{json .State}}", refused]))
            if not state["Running"]:
                if state["ExitCode"] == 0:
                    raise RuntimeError("Failed migrations incorrectly produced a successful container exit")
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("The container did not stop after migration authentication failed")
            time.sleep(0.25)
        logs = self.run(["docker", "logs", refused], combine_output=True)
        if "P1000" not in logs or "Server listening" in logs:
            raise RuntimeError("Migration refusal was not an authentication error before API startup")
        print("PASS: actual image preserves migration failure and does not start the API", flush=True)
        self.gateway = self.prefix + "-api"
        self.containers.append(self.gateway)
        self.run(["docker", "run", "-d", "--name", self.gateway, "--network", network,
                  "--read-only", "--tmpfs", "/tmp:uid={},gid={},mode=0700".format(uid, uid),
                  "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "256",
                  "--memory", "512m", "--health-interval", "1s", "--health-start-period", "5s",
                  "-p", "127.0.0.1:{}:8080".format(self.port or ""),
                  "--env-file", api_environment, self.image])
        self.refresh_port()
        self.ready()
        actual_uid = self.run(["docker", "exec", self.gateway, "node", "-p", "process.getuid()"]).strip()
        if actual_uid != str(uid):
            raise RuntimeError("Console process does not run as its declared non-root UID")
        native = self.run(["docker", "exec", self.gateway, "node", "-e", """
const fs = require('node:fs');
const directory = '/app/node_modules/.prisma/client';
const engine = fs.readdirSync(directory).find(name => name.startsWith('libquery_engine-') && name.endsWith('.so.node'));
if (!engine) throw new Error('Packaged native Prisma engine is missing');
require(directory + '/' + engine);
const libraries = process.report.getReport().sharedObjects;
for (const library of ['libssl.so.3', 'libcrypto.so.3', 'libz.so.1']) {
  if (!libraries.some(path => path.endsWith('/' + library))) throw new Error('Missing loaded library: ' + library);
}
console.log(JSON.stringify({node:process.version, uid:process.getuid(), prisma:require('@prisma/client').Prisma.prismaVersion.client,
  engine, openssl:process.versions.openssl, libraries}));
"""])
        (self.work / "native-runtime.json").write_text(native)
        print("PASS: packaged Prisma native engine loads OpenSSL 3, libcrypto, and zlib", flush=True)
        deadline = time.monotonic() + 15
        while self.run(["docker", "inspect", "--format", "{{.State.Health.Status}}", self.gateway]).strip() != "healthy":
            if time.monotonic() >= deadline:
                raise RuntimeError("Console Docker healthcheck did not become healthy")
            time.sleep(0.25)
        print("PASS: console image runs migrations and boots as UID {} with a read-only root; Docker healthcheck passes".format(uid), flush=True)
        environment = dict(os.environ, API_BASE=self.base, SPA_ORIGIN="https://console.example.test",
                           PYTHONUNBUFFERED="1", NO_PROXY="127.0.0.1,localhost")
        output = self.run([sys.executable, str(Path(__file__).resolve().parents[1] / "server/ci/smoke.py")],
                          timeout=180, env=environment)
        print(output, end="", flush=True)
        output = self.run(["node", str(Path(__file__).resolve().parents[1] / "server/ci/e2e.mjs")],
                          timeout=180, env=environment)
        print(output, end="", flush=True)
        if self.daemon_binaries:
            environment.update(AGENTVISORD=self.daemon_binaries[0], AVCTL=self.daemon_binaries[1])
            output = self.run(["node", str(Path(__file__).resolve().parents[1] /
                                         "server/scripts/daemon-console-drill.mjs")], timeout=180, env=environment)
            print(output, end="", flush=True)
        self.run(["docker", "stop", "--time", "10", self.database])
        status, body = self.request("/readyz")
        if status != 503 or json.loads(body).get("checks", {}).get("db") != "fail":
            raise RuntimeError("Console readiness did not report the stopped database")
        if self.request("/healthz")[0] != 200:
            raise RuntimeError("Console liveness should remain healthy during a database outage")
        self.run(["docker", "start", self.database])
        self.database_ready()
        self.ready()
        print("PASS: database outage returns readiness 503, liveness remains 200, and readiness recovers", flush=True)
        self.run(["docker", "stop", "--time", "10", self.gateway])
        if self.run(["docker", "inspect", "--format", "{{.State.ExitCode}}", self.gateway]).strip() != "0":
            raise RuntimeError("Console did not stop cleanly on SIGTERM")
        print("PASS: production entry point forwards SIGTERM and exits cleanly", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    images = parser.add_mutually_exclusive_group(required=True)
    images.add_argument("--image", help="AgentVisor daemon image")
    images.add_argument("--console-image", help="AgentVisor Node console API image")
    parser.add_argument("--port", type=int, default=0, help="Loopback host port; default chooses a free port")
    parser.add_argument("--agentvisord", help="Also run the real daemon crash drill against the console image")
    parser.add_argument("--avctl", help="CLI binary for the real daemon crash drill")
    args = parser.parse_args()
    if not 0 <= args.port <= 65535:
        parser.error("--port must be between 0 and 65535")
    if bool(args.agentvisord) != bool(args.avctl) or (args.agentvisord and not args.console_image):
        parser.error("--agentvisord and --avctl must be used together with --console-image")
    smoke = ConsoleSmoke(args.console_image, args.port) if args.console_image else Smoke(args.image, args.port)
    if args.agentvisord:
        smoke.daemon_binaries = [str(Path(binary).resolve()) for binary in (args.agentvisord, args.avctl)]
        if not all(os.access(binary, os.X_OK) and Path(binary).is_file() for binary in smoke.daemon_binaries):
            parser.error("Both daemon crash-drill binaries must exist and be executable")
    print("Container verification logs: " + str(smoke.work), flush=True)
    try:
        smoke.verify()
    finally:
        smoke.cleanup()


if __name__ == "__main__":
    main()
