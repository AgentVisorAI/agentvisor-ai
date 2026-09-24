#!/usr/bin/env python3
"""Exercise uncertain MCP effects through a real daemon and restart.

Build separately, then set AGENTVISORD or pass --agentvisord. This standard-
library drill uses only owned processes, private files and loopback HTTP. It
never invokes Cargo, Docker, an external provider, or a shared service.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
import uuid


ROOT = Path(__file__).resolve().parents[1]
MAX_RESPONSE = 1024 * 1024


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def request(base, path, token=None, data=None, session=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if session:
        headers["X-AV-Session"] = session
    body = json.dumps(data).encode() if data is not None else None
    req = Request(base + path, headers=headers, data=body)
    try:
        response = build_opener(ProxyHandler({}), NoRedirect()).open(req, timeout=10)
    except HTTPError as error:
        response = error
    with response:
        payload = response.read(MAX_RESPONSE + 1)
        if len(payload) > MAX_RESPONSE:
            raise RuntimeError("Fixture response exceeded its size bound")
        return response.status, payload


def mint(secret, identity):
    def encode(value):
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode()
    now = int(time.time())
    claims = {"iss": "mcp-uncertainty-test", "aud": "agentvisor-ai", "sub": identity,
              "jti": uuid.uuid4().hex, "iat": now, "exp": now + 600,
              "instance_uid": identity, "version": "1", "charter": "test",
              "scopes": ["tool:read", "session:close", "session:promote"]}
    signing = encode(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "dev-hmac"}).encode())
    signing += "." + encode(json.dumps(claims).encode())
    return signing + "." + encode(hmac.new(secret, signing.encode(), hashlib.sha256).digest())


def free_port():
    with socket.socket() as connection:
        connection.bind(("127.0.0.1", 0))
        return connection.getsockname()[1]


def stop(process, *, crash=False):
    if process.poll() is None:
        # This is a process group created by this drill, never a discovered PID.
        try:
            os.killpg(process.pid, signal.SIGKILL if crash else signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def events(directory, topic):
    found = []
    for path in directory.glob(f"topics/{topic}/p*.jsonl"):
        if path.name.endswith(".event-uids.jsonl"):
            continue
        for line in path.read_text().splitlines():
            try:
                value = json.loads(line)["value"]
            except (ValueError, KeyError):
                continue  # The current writer may not have finished its line.
            if isinstance(value, dict):
                found.append(value)
    return found


def run(args):
    binary = Path(args.agentvisord).resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError("Set AGENTVISORD to a previously built executable")
    output = Path(args.output_dir).absolute()
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    if (output.is_symlink() or output.stat().st_uid != os.getuid()
            or output.stat().st_mode & 0o077 or any(output.iterdir())):
        raise ValueError("Output must be an empty owner-only directory")
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    report = {"status": "running", "binary": str(binary), "binary_sha256": digest,
              "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "checks": [], "cleanup_complete": False}
    work = Path(tempfile.mkdtemp(prefix=".mcp-uncertainty-", dir=output))
    processes = []
    release = threading.Event()
    lock = threading.Lock()
    effect_counts = {}
    active = 0
    server = thread = None

    def check(name, condition):
        report["checks"].append({"name": name, "passed": bool(condition)})
        print(("PASS " if condition else "FAIL ") + name, flush=True)
        if not condition:
            raise AssertionError(name)

    class Backend(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            nonlocal active
            length = int(self.headers.get("Content-Length", "0"))
            if self.path != "/mcp" or not 0 < length <= 64 * 1024:
                self.send_error(400)
                return
            self.connection.settimeout(5)
            body = json.loads(self.rfile.read(length))
            execution_id = body["id"]
            with lock:
                active += 1
                effect_counts[execution_id] = effect_counts.get(execution_id, 0) + 1
            try:
                # The effect already occurred. No status/headers go out until
                # the gateway's one-second deadline has expired. A finite
                # fallback also bounds failures against an older binary.
                release.wait(timeout=6)
                payload = b'{"jsonrpc":"2.0","result":{"effect":true}}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError, TimeoutError):
                pass
            finally:
                with lock:
                    active -= 1

    def start(config, base, label, await_ready=True):
        environment = {k: v for k, v in os.environ.items() if not k.startswith("AV_")}
        environment.update(AV_SIGNING_SEED_FILE=str(work / "signing.seed"), RUST_LOG="info")
        with (output / f"{label}.log").open("ab") as log:
            process = subprocess.Popen([str(binary), "--config", str(config)], cwd=work,
                                       env=environment, stdout=log, stderr=subprocess.STDOUT,
                                       start_new_session=True)
        processes.append(process)
        if not await_ready:
            return process
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and process.poll() is None:
            try:
                if request(base, "/readyz")[0] == 200:
                    return process
            except (OSError, URLError):
                pass
            time.sleep(0.1)
        raise RuntimeError(f"Owned daemon {label} did not become ready")

    try:
        secret = os.urandom(32).hex().encode()
        (work / "hmac.secret").write_bytes(secret)
        (work / "signing.seed").write_text(os.urandom(32).hex())
        server = ThreadingHTTPServer(("127.0.0.1", 0), Backend)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        for workflow in ("signed", "unsigned"):
            release.clear()
            directory = work / workflow
            directory.mkdir()
            session = "uncertain-" + workflow + "-" + uuid.uuid4().hex
            execution_id = "effect-" + workflow
            base = "http://127.0.0.1:" + str(free_port())
            upstream = "http://127.0.0.1:" + str(server.server_port)
            config = directory / "harness.toml"
            values = {"config_version": 1, "listen": base.removeprefix("http://"),
                      "upstream_url": upstream, "tool_upstream_url": upstream + "/mcp",
                      "require_identity": True, "enforce_identity_scopes": True,
                      "identity_hmac_secret_file": str(work / "hmac.secret"),
                      "require_tool_schema": False, "require_intent_mapping": True,
                      "default_workflow": workflow, "dashboard_enabled": False,
                      "atif_spool_dir": str(directory / "spool"),
                      "bridge_data_dir": str(directory / "bridge"),
                      "mcp_concurrency": 1, "mcp_request_timeout_s": 1,
                      "upstream_read_timeout_s": 10, "shutdown_drain_timeout_s": 5}
            config.write_text("\n".join(f"{key} = {json.dumps(value)}" for key, value in values.items())
                              + '\n\n[intent_map]\nread = "test.read"\n')
            token = mint(secret, "identity-" + workflow)
            body = {"jsonrpc": "2.0", "id": execution_id, "method": "tools/call",
                    "params": {"name": "read", "arguments": {}}}
            daemon = start(config, base, workflow + "-first")
            status, _ = request(base, "/v1/mcp", token, body, session)
            check(workflow + ": pre-header timeout returns 502", status == 502)
            with lock:
                count = effect_counts.get(execution_id, 0)
            check(workflow + ": the remote effect actually occurred once", count == 1)
            intents = list((directory / "spool/tool-executions").glob("*.intent.json"))
            check(workflow + ": one primary intent persists", len(intents) == 1)
            intent = intents[0]
            intent_before = intent.read_bytes()
            release.set()
            for phase in ("before restart", "after restart"):
                status, payload = request(base, "/v1/mcp", token, body, session)
                check(workflow + ": retry refuses duplicate " + phase,
                      status == 409 and b"outcome is uncertain" in payload)
                status, payload = request(base, f"/v1/sessions/{session}/close", token, {})
                safe_close = status == 409 or (status == 200 and json.loads(payload) == {"kind": "already_closed"})
                check(workflow + ": close cannot claim complete evidence " + phase, safe_close)
                status, _ = request(base, f"/v1/sessions/{session}/promote", token, {})
                check(workflow + ": promotion refuses incomplete evidence " + phase, status == 409)
                check(workflow + ": authenticated intent is unchanged " + phase,
                      intent.is_file() and intent.read_bytes() == intent_before)
                check(workflow + ": no outcome or audited marker appears " + phase,
                      not list(intent.parent.glob("*.outcome.json")) and not list(intent.parent.glob("*.audited")))
                check(workflow + ": no receipt is emitted " + phase,
                      not events(directory / "bridge", "agent.receipt")
                      and not list((directory / "spool/receipts").glob("*.json")))
                notices = [event for event in events(directory / "bridge", "agent.session")
                           if event.get("payload", {}).get("action") == "quarantined"]
                check(workflow + ": quarantine reaches the audit bridge " + phase,
                      len(notices) == 1 and notices[0]["payload"].get("evidence_complete") is False)
                with lock:
                    count = effect_counts.get(execution_id, 0)
                check(workflow + ": total remote effects remains exactly one " + phase, count == 1)
                if phase == "before restart":
                    stop(daemon, crash=True)
                    daemon = start(config, base, workflow + "-restart")
            stop(daemon)
            # Deliberate filesystem fault in an owned COPY, not a claim that
            # the healthy restart lost metadata. Keep the authenticated intent
            # and signing seed intact while removing only its session metadata.
            fault = work / (workflow + "-metadata-loss")
            shutil.copytree(directory, fault)
            metadata = list((directory / "spool").glob("*.session.json"))
            copied_metadata = list((fault / "spool").glob("*.session.json"))
            label = workflow + ": deliberate metadata-loss copy "
            check(label + "has exactly one metadata file to remove",
                  len(metadata) == 1 and len(copied_metadata) == 1)
            metadata_before = metadata[0].read_bytes()
            copied_metadata[0].unlink()
            copied_intent = fault / "spool/tool-executions" / intent.name
            fault_base = "http://127.0.0.1:" + str(free_port())
            fault_values = dict(values, listen=fault_base.removeprefix("http://"),
                                atif_spool_dir=str(fault / "spool"),
                                bridge_data_dir=str(fault / "bridge"))
            fault_config = fault / "harness.toml"
            fault_config.write_text("\n".join(f"{key} = {json.dumps(value)}"
                                               for key, value in fault_values.items())
                                    + '\n\n[intent_map]\nread = "test.read"\n')
            failed_daemon = start(fault_config, fault_base, workflow + "-metadata-loss", await_ready=False)
            failed_code = failed_daemon.wait(timeout=15)
            check(label + "refuses daemon startup", failed_code != 0)
            diagnostic = (output / (workflow + "-metadata-loss.log")).read_text()
            check(label + "identifies the unresolved execution",
                  "unresolved tool execution" in diagnostic and "session metadata" in diagnostic)
            try:
                ready_status = request(fault_base, "/readyz")[0]
            except (OSError, URLError):
                ready_status = 0
            check(label + "does not accept traffic", ready_status == 0)
            check(label + "preserves the authenticated intent",
                  copied_intent.read_bytes() == intent_before and intent.read_bytes() == intent_before)
            check(label + "does not mint a receipt",
                  not events(fault / "bridge", "agent.receipt")
                  and not list((fault / "spool/receipts").glob("*.json")))
            check(label + "leaves original metadata unchanged", metadata[0].read_bytes() == metadata_before)
            with lock:
                count = effect_counts.get(execution_id, 0)
            check(label + "does not repeat the remote effect", count == 1)
        check("the validated executable did not change", hashlib.sha256(binary.read_bytes()).hexdigest() == digest)
        if len(report["checks"]) != 55:
            raise AssertionError("The drill did not execute all 55 required checks")
        report["status"] = "passed"
    except BaseException as error:
        report["status"] = "failed"
        # Error strings can carry private request data; report only the type.
        report["error_type"] = type(error).__name__
        raise
    finally:
        release.set()
        cleanup_errors = []
        for process in processes:
            try:
                stop(process)
            except (OSError, subprocess.TimeoutExpired) as error:
                cleanup_errors.append(type(error).__name__)
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=5)
            if thread.is_alive():
                cleanup_errors.append("BackendThreadStillAlive")
        deadline = time.monotonic() + 5
        while active and time.monotonic() < deadline:
            time.sleep(0.05)
        if active:
            cleanup_errors.append("BackendHandlerStillAlive")
        try:
            shutil.rmtree(work)
        except OSError as error:
            cleanup_errors.append(type(error).__name__)
        report["expected_checks"] = 55
        report["binary_sha256_after"] = hashlib.sha256(binary.read_bytes()).hexdigest()
        report["cleanup_complete"] = not cleanup_errors
        report["cleanup_errors"] = cleanup_errors
        report["passed"] = sum(check["passed"] for check in report["checks"])
        report["failed"] = sum(not check["passed"] for check in report["checks"])
        if cleanup_errors:
            report["status"] = "failed"
        (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["status"] == "passed" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agentvisord", default=os.environ.get("AGENTVISORD", str(ROOT / "target/release/agentvisord")))
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    os.umask(0o077)

    def interrupted(*_args):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        return run(args)
    except BaseException as error:
        print(f"MCP uncertainty drill failed ({type(error).__name__}); inspect the private result directory", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
