#!/usr/bin/env python3
"""Check introspection expiry across an actual delayed Redis response.

Requires previously built agentvisord and local redis-server executables.
Creates private files and owned loopback processes only. It never invokes Cargo,
Docker, a shared Redis, or an external provider. Tokens are never logged.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
import uuid


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def stop(process):
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def resp(stream, depth=0):
    """Parse one bounded RESP2 frame while preserving its exact wire bytes."""
    if depth > 8:
        raise ValueError("RESP nesting limit")
    line = stream.readline(65537)
    if not line:
        raise EOFError
    if len(line) > 65536 or not line.endswith(b"\r\n"):
        raise ValueError("RESP line limit")
    kind, value = line[:1], line[1:-2]
    if kind in (b"+", b"-", b":"):
        return value, line
    if kind == b"$":
        length = int(value)
        if length == -1:
            return None, line
        if not 0 <= length <= 1024 * 1024:
            raise ValueError("RESP bulk limit")
        data = stream.read(length + 2)
        if len(data) != length + 2 or not data.endswith(b"\r\n"):
            raise ValueError("Incomplete RESP bulk")
        return data[:-2], line + data
    if kind == b"*":
        length = int(value)
        if length == -1:
            return None, line
        if not 0 <= length <= 64:
            raise ValueError("RESP array limit")
        values, raw = [], bytearray(line)
        for _ in range(length):
            item, encoded = resp(stream, depth + 1)
            values.append(item)
            raw.extend(encoded)
            if len(raw) > 1024 * 1024:
                raise ValueError("RESP message limit")
        return values, bytes(raw)
    raise ValueError("Unsupported RESP type")


def redis_auth(port, password):
    with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
        value = password.encode()
        connection.sendall(b"*2\r\n$4\r\nAUTH\r\n$%d\r\n" % len(value) + value + b"\r\n")
        with connection.makefile("rb") as stream:
            return resp(stream)[0] == b"OK"


def http(base, path, token=None, form=None):
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = urlencode(form).encode() if form is not None else None
    request = Request(base + path, data=data, headers=headers)
    try:
        response = build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=5)
    except HTTPError as error:
        response = error
    with response:
        raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError("HTTP response limit")
        return response.status, dict(response.headers), json.loads(raw)


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def run(args):
    binary = Path(args.agentvisord).resolve()
    redis_binary = shutil.which(args.redis_server)
    if not binary.is_file() or not os.access(binary, os.X_OK) or not redis_binary:
        raise ValueError("Built agentvisord and redis-server executables are required")
    output = Path(args.output_dir).absolute()
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    if (output.is_symlink() or output.stat().st_uid != os.getuid()
            or output.stat().st_mode & 0o077 or any(output.iterdir())):
        raise ValueError("Output must be an empty owner-only directory")
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    result = {"status": "running", "binary_sha256": digest, "binary": str(binary),
              "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "checks": [], "cleanup_complete": False}
    work = Path(tempfile.mkdtemp(prefix=".introspection-expiry-", dir=output))
    processes, sockets = [], set()
    lock = threading.Lock()
    closing = threading.Event()
    gate = {}
    relay = relay_thread = None

    def check(name, passed):
        result["checks"].append({"name": name, "passed": bool(passed)})
        print(("PASS " if passed else "FAIL ") + name, flush=True)
        if not passed:
            raise AssertionError(name)

    def start(executable, config, label, environment):
        with (output / (label + ".log")).open("ab") as log:
            process = subprocess.Popen([str(executable), str(config)] if label == "redis" else
                                       [str(executable), "--config", str(config)], cwd=work,
                                       env=environment, stdout=log, stderr=subprocess.STDOUT,
                                       start_new_session=True)
        processes.append(process)
        return process

    try:
        environment = {k: v for k, v in os.environ.items() if not k.startswith("AV_")}
        redis_port = free_port()
        password = os.urandom(32).hex()
        redis_config = work / "redis.conf"
        redis_config.write_text(f'bind 127.0.0.1\nport {redis_port}\nprotected-mode yes\n'
                                f'requirepass {password}\nsave ""\nappendonly no\n')
        redis_process = start(redis_binary, redis_config, "redis", environment)
        deadline = time.monotonic() + 10
        while True:
            try:
                if redis_auth(redis_port, password):
                    break
            except OSError:
                pass
            if redis_process.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("Owned Redis did not become ready")
            time.sleep(0.05)
        check("isolated Redis accepts its private credential", True)

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                upstream = None
                with lock:
                    sockets.add(self.request)
                try:
                    self.request.settimeout(10)
                    upstream = socket.create_connection(("127.0.0.1", redis_port), timeout=3)
                    with lock:
                        sockets.add(upstream)
                    with self.request.makefile("rb") as incoming, upstream.makefile("rb") as returned:
                        while not closing.is_set():
                            command, encoded = resp(incoming)
                            started = time.time()
                            upstream.sendall(encoded)
                            response, encoded_response = resp(returned)
                            delayed = None
                            with lock:
                                if (isinstance(command, list) and len(command) == 2
                                        and command[0].upper() == b"GET"
                                        and command[1] == gate.get("key") and gate.get("armed")):
                                    gate["armed"] = False
                                    gate["read_started_s"] = started
                                    gate["actual_redis_missing"] = response is None
                                    delayed = gate["expires_s"]
                            if delayed is not None:
                                # This exact successful Redis GET crosses expiry,
                                # while remaining below the normal two-second timeout.
                                while time.time() <= delayed + 0.1 and not closing.is_set():
                                    closing.wait(0.01)
                                with lock:
                                    gate["reply_released_s"] = time.time()
                            self.request.sendall(encoded_response)
                except (OSError, EOFError, ValueError):
                    pass
                finally:
                    with lock:
                        sockets.discard(self.request)
                        if upstream is not None:
                            sockets.discard(upstream)
                    if upstream is not None:
                        upstream.close()

        class Relay(socketserver.ThreadingTCPServer):
            daemon_threads = True
            request_queue_size = 64

        relay = Relay(("127.0.0.1", 0), Handler)
        relay_thread = threading.Thread(target=relay.serve_forever, daemon=True)
        relay_thread.start()
        base = "http://127.0.0.1:" + str(free_port())
        secret = os.urandom(32).hex().encode()
        backend_secret = os.urandom(32).hex()
        (work / "identity.secret").write_bytes(secret)
        (work / "exchange.seed").write_text(os.urandom(32).hex())
        (work / "signing.seed").write_text(os.urandom(32).hex())
        values = {"config_version": 1, "listen": base.removeprefix("http://"),
                  "upstream_url": "http://127.0.0.1:9", "require_identity": True,
                  "enforce_identity_scopes": True, "dashboard_enabled": False,
                  "require_tool_schema": False,
                  "identity_hmac_secret_file": str(work / "identity.secret"),
                  "token_exchange_seed_file": str(work / "exchange.seed"),
                  "token_exchange_enabled": True, "token_exchange_ttl_s": 5,
                  "state_backend": "redis",
                  "state_endpoint": f"redis://:{password}@127.0.0.1:{relay.server_address[1]}",
                  "atif_spool_dir": str(work / "spool"), "bridge_data_dir": str(work / "bridge")}
        config = work / "harness.toml"
        config.write_text("\n".join(f"{key} = {json.dumps(value)}" for key, value in values.items())
                          + '\n[[backends]]\nname="svc"\nurl="http://127.0.0.1:9"\nauth="exchange"\ntools=["read"]\n'
                          + '\n[[introspection_tokens]]\nbackend="svc"\nsha256='
                          + json.dumps(hashlib.sha256(backend_secret.encode()).hexdigest()) + '\n')
        daemon = start(binary, config, "daemon", environment | {
            "AV_SIGNING_SEED_FILE": str(work / "signing.seed"), "RUST_LOG": "info"})
        deadline = time.monotonic() + 30
        while True:
            try:
                if http(base, "/readyz")[0] == 200:
                    break
            except (OSError, URLError):
                pass
            if daemon.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("Owned daemon did not become ready")
            time.sleep(0.05)
        now = int(time.time())
        claims = {"iss": "expiry-fixture", "aud": "agentvisor-ai", "sub": "fixture-user",
                  "jti": uuid.uuid4().hex, "iat": now, "exp": now + 600,
                  "instance_uid": "fixture-instance", "version": "1", "charter": "test",
                  "scopes": ["tool:read"]}
        signing = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "dev-hmac"}).encode())
        signing += "." + b64(json.dumps(claims).encode())
        subject = signing + "." + b64(hmac.new(secret, signing.encode(), hashlib.sha256).digest())

        def exchange():
            status, _, body = http(base, "/v1/token", form={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
                "subject_token": subject, "audience": "svc", "scope": "tool:read"})
            if status != 200:
                raise RuntimeError("Fixture exchange failed")
            return body["access_token"]

        token = exchange()
        status, _, live = http(base, "/v1/introspect", backend_secret, {"token": token})
        check("the exchanged token is initially active", status == 200 and live.get("active") is True)
        expires = live["exp"]
        key = ("av:revoked-exchanged:issuer:" + hashlib.sha256(live["iss"].encode()).hexdigest()
               + ":" + hashlib.sha256(live["jti"].encode()).hexdigest()).encode()
        with lock:
            gate.update(key=key, armed=True, expires_s=expires)
        deadline = time.monotonic() + 7
        while time.time() < expires - 1:
            if time.monotonic() > deadline:
                raise RuntimeError("Expiry scheduling exceeded its bound")
            time.sleep(0.01)
        status, headers, delayed = http(base, "/v1/introspect", backend_secret, {"token": token})
        result["introspection"] = {"status": status, "active": delayed.get("active"),
                                   "response_keys": sorted(delayed)}
        with lock:
            timing = {key: value for key, value in gate.items() if key not in ("key", "armed")}
        result["delayed_read"] = timing
        check("the actual revocation GET began before token expiry", timing.get("read_started_s", expires) < expires)
        check("the real Redis result was not revoked", timing.get("actual_redis_missing") is True)
        check("the Redis reply was released after token expiry", timing.get("reply_released_s", 0) > expires)
        check("the injected delay stayed below the normal Redis timeout",
              0 < timing["reply_released_s"] - timing["read_started_s"] < 2)
        check("delayed introspection succeeds without a storage error", status == 200)
        check("expired introspection returns only active false", delayed == {"active": False})
        check("introspection disables response caching", headers.get("cache-control", headers.get("Cache-Control")) == "no-store")
        status, _, fresh = http(base, "/v1/introspect", backend_secret, {"token": exchange()})
        check("a fresh token remains usable after the delayed read", status == 200 and fresh.get("active") is True)
        check("the validated executable did not change", hashlib.sha256(binary.read_bytes()).hexdigest() == digest)
        if len(result["checks"]) != 11:
            raise AssertionError("The drill did not execute all required checks")
        result["status"] = "passed"
    except BaseException as error:
        result["status"] = "failed"
        result["error_type"] = type(error).__name__
        raise
    finally:
        # A repeated cancellation must not interrupt owned process/secret cleanup.
        saved_signals = {sig: signal.signal(sig, signal.SIG_IGN)
                         for sig in (signal.SIGTERM, signal.SIGINT)}
        closing.set()
        cleanup_errors = []
        for process in reversed(processes):
            try:
                stop(process)
            except (OSError, subprocess.TimeoutExpired) as error:
                cleanup_errors.append(type(error).__name__)
        with lock:
            remaining = list(sockets)
        for connection in remaining:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        if relay is not None:
            relay.shutdown()
            relay.server_close()
        if relay_thread is not None:
            relay_thread.join(timeout=3)
            if relay_thread.is_alive():
                cleanup_errors.append("RelayThreadStillAlive")
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            with lock:
                if not sockets:
                    break
            time.sleep(0.02)
        with lock:
            if sockets:
                cleanup_errors.append("RelayConnectionsStillAlive")
        try:
            shutil.rmtree(work)
        except OSError as error:
            cleanup_errors.append(type(error).__name__)
        result["binary_sha256_after"] = hashlib.sha256(binary.read_bytes()).hexdigest()
        result["cleanup_complete"] = not cleanup_errors
        result["cleanup_errors"] = cleanup_errors
        result["passed"] = sum(check["passed"] for check in result["checks"])
        result["failed"] = sum(not check["passed"] for check in result["checks"])
        result["expected_checks"] = 11
        if cleanup_errors:
            result["status"] = "failed"
        (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        for sig, handler in saved_signals.items():
            signal.signal(sig, handler)
    return 0 if result["status"] == "passed" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agentvisord", default=os.environ.get("AGENTVISORD", "target/release/agentvisord"))
    parser.add_argument("--redis-server", default="redis-server")
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    os.umask(0o077)

    def interrupted(*_args):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        return run(args)
    except BaseException as error:
        print(f"Introspection expiry drill failed ({type(error).__name__}); inspect private diagnostics", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
