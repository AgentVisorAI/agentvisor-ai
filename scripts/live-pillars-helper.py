#!/usr/bin/env python3
"""Live checks using real processes and HTTP; Python 3.9, standard library only.

JWT decoding here inspects claims, not signatures. The Rust suite verifies the
exchanged/intent signatures; avctl verifies the actual signed receipt here.
"""
import argparse
import base64
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import urlencode, urlsplit, urlunsplit
import uuid

ROOT = Path(__file__).resolve().parents[1]
HERE = Path(__file__).resolve()


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def mint(secret, run_id, scopes, jti=None, now=None):
    now = int(time.time()) if now is None else now
    claims = {"sub": "user:live-" + run_id, "iss": "live-check", "aud": "agentvisor-ai",
              "iat": now, "exp": now + 600, "jti": jti or str(uuid.uuid4()),
              "instance_uid": "inst-" + run_id, "charter": "support", "version": "1.0",
              "scopes": scopes}
    header = {"alg": "HS256", "typ": "JWT", "kid": "dev-hmac"}
    signing = b64(json.dumps(header).encode()) + "." + b64(json.dumps(claims).encode())
    return signing + "." + b64(hmac.new(secret, signing.encode(), hashlib.sha256).digest())


def decode_part(token, part=1):
    value = token.split(".")[part]
    return json.loads(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))


def bridge_events(directory, topic):
    events = []
    for path in Path(directory).glob("topics/" + topic + "/p*.jsonl"):
        if path.name.endswith(".event-uids.jsonl"):
            continue
        for line in path.read_text().splitlines():
            try:
                event = json.loads(line)["value"]
            except (ValueError, KeyError, TypeError):
                continue  # A writer may not have completed the current line yet.
            if isinstance(event, dict):
                events.append(event)
    return events


def bridge_matches(directory, denial_code="UNMAPPED_TOOL", policy="pdp.intent_map"):
    return any(event.get("payload", {}).get("denial_code") == denial_code
               and event.get("payload", {}).get("policy") == policy
               and event.get("payload", {}).get("allowed") is False
               for event in bridge_events(directory, "agent.tool_call"))


def receipt_counts(receipt):
    calls = receipt["tool_calls"]
    return calls["total"], calls["allowed"], calls["blocked"]


def headers_from(text):
    result = {}
    for line in text.splitlines():
        if line.startswith("HTTP/"):
            result = {}  # Last response block, following a possible 100 Continue.
        elif ":" in line:
            name, value = line.split(":", 1)
            result[name.lower()] = value.strip()
    return result


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def loopback_redis(value):
    parsed = urlsplit(value)
    if parsed.scheme != "redis" or not parsed.hostname:
        raise ValueError("--redis requires a redis:// loopback URL")
    # Literal addresses only: no DNS lookup can accidentally reach a remote Redis.
    host = "127.0.0.1" if parsed.hostname == "localhost" else parsed.hostname
    if not ipaddress.ip_address(host).is_loopback:
        raise ValueError("--redis is restricted to a loopback Redis")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("live Redis checks require a local test Redis without credentials or URL options")
    if parsed.path not in ("", "/") and not re.fullmatch(r"/[0-9]+", parsed.path):
        raise ValueError("Redis database must be a nonnegative integer")
    port = parsed.port or 6379
    return parsed, host, port


def redis_ping(host, port):
    with socket.create_connection((host, port), timeout=2) as connection:
        connection.sendall(b"*1\r\n$4\r\nPING\r\n")
        return connection.makefile("rb").readline(256) == b"+PONG\r\n"


def serve_mock(port, path):
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()

        def do_POST(self):
            data = self.rfile.read(int(self.headers.get("content-length", "0")))
            with lock, open(path, "a") as output:
                output.write(json.dumps({"path": self.path,
                                         "headers": {k.lower(): v for k, v in self.headers.items()},
                                         "body": data.decode()}) + "\n")
            message = json.loads(data)
            request_id = message.get("id")
            method = message.get("method", "")
            # Speak just enough MCP Streamable HTTP for `transport = "mcp"`
            # backends: a handshake with a session id, and 202 for
            # notifications. Plain JSON-RPC calls get the echo as before.
            if request_id is None and method.startswith("notifications/"):
                self.send_response(202)
                self.send_header("content-length", "0")
                self.end_headers()
                return
            if method == "initialize":
                result = {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}},
                          "serverInfo": {"name": "live-pillars-mock", "version": "1"}}
            else:
                result = {"content": [{"type": "text", "text": "ok"}]}
            body = json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result}).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            if method == "initialize":
                self.send_header("mcp-session-id", "live-pillars-session")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()


def serve_forwarder(port, host, destination_port):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                with socket.create_connection((host, destination_port), timeout=2) as upstream:
                    sockets = [self.request, upstream]
                    while True:
                        readable, _, _ = select.select(sockets, [], [], 10)
                        for source in readable:
                            data = source.recv(65536)
                            if not data:
                                return
                            target = upstream if source is self.request else self.request
                            target.sendall(data)
            except OSError:
                return

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True
        request_queue_size = 128

    with Server(("127.0.0.1", port), Handler) as server:
        server.serve_forever()


class Response:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers
        self.body = body

    def json(self):
        return json.loads(self.body)


class LiveChecks:
    def __init__(self, args):
        self.args = args
        self.binary = Path(os.environ.get("AGENTVISORD", str(ROOT / "target/release/agentvisord"))).resolve()
        self.avctl = Path(os.environ.get("AVCTL", str(ROOT / "target/release/avctl"))).resolve()
        for path in (self.binary, self.avctl):
            if not path.is_file() or not os.access(path, os.X_OK):
                raise ValueError("missing executable {} (build binaries first, or set AGENTVISORD/AVCTL)".format(path))
        if not shutil.which("curl"):
            raise ValueError("curl is required")
        self.redis = loopback_redis(args.redis) if args.redis else None
        if self.redis and not redis_ping(self.redis[1], self.redis[2]):
            raise ValueError("the requested local Redis did not answer PING")
        parent = os.environ.get("AV_LIVE_TMPDIR")
        if parent:
            Path(parent).mkdir(parents=True, exist_ok=True)
        self.work = Path(tempfile.mkdtemp(prefix="av-live-pillars-", dir=parent)).resolve()
        # Cargo can replace target/debug binaries while another suite runs.
        # Every daemon restart and avctl invocation must use this exact pair.
        executable_dir = self.work / "bin"
        executable_dir.mkdir()
        try:
            for attribute in ("binary", "avctl"):
                source = getattr(self, attribute)
                target = executable_dir / attribute
                shutil.copy2(source, target)
                setattr(self, attribute, target)
        except OSError:
            shutil.rmtree(self.work)
            raise
        self.run_id = uuid.uuid4().hex
        self.secret = os.urandom(32).hex().encode()
        self.operator_secret = os.urandom(32).hex()
        self.backend_secret = os.urandom(32).hex()
        self.static_backend_secret = os.urandom(32).hex()
        self.processes = []
        self.passed = 0
        self.failed = 0
        self.request_id = 0
        self.tokens = []
        self.mock_port = free_port()
        self.base = "http://127.0.0.1:{}".format(free_port())
        self.log_path = self.work / "requests.jsonl"
        self.log_path.touch()
        (self.work / "hmac.secret").write_bytes(self.secret)
        (self.work / "exchange.seed").write_text(os.urandom(32).hex())
        (self.work / "static.token").write_text("static-backend-secret\n")
        self.environment = {k: v for k, v in os.environ.items() if not k.startswith("AV_")}
        self.environment["RUST_LOG"] = "info"
        print("Live checks use {}".format(self.work), flush=True)

    def check(self, description, condition):
        try:
            success = condition() if callable(condition) else condition
        except Exception as error:
            success = False
            print("      {}: {}".format(type(error).__name__, error), flush=True)
        if success:
            self.passed += 1
            print("PASS  " + description, flush=True)
        else:
            self.failed += 1
            print("FAIL  " + description, flush=True)
        return success

    def token(self, scopes=None, identity=None):
        token = mint(self.secret, identity or self.run_id, ["tool:*"] if scopes is None else scopes)
        self.tokens.append(token)
        return token

    def start(self, name, command, env=None):
        with open(self.work / (name + ".log"), "ab") as output:
            process = subprocess.Popen(command, cwd=self.work, env=env or self.environment,
                                       stdout=output, stderr=subprocess.STDOUT)
        self.processes.append(process)
        return process

    @staticmethod
    def stop(process):
        if process.poll() is None:
            process.kill()  # These are disposable processes; skip the production drain.
        process.wait(timeout=10)

    def request(self, path, token=None, form=None, data=None, base=None, method=None, timeout=20, headers=None):
        self.request_id += 1
        prefix = self.work / ("http-{:04d}".format(self.request_id))
        header_file = prefix.with_suffix(".headers")
        body_file = prefix.with_suffix(".body")
        command = ["curl", "--silent", "--show-error", "--noproxy", "*", "--connect-timeout", "2",
                   "--max-time", str(timeout), "--dump-header", str(header_file),
                   "--output", str(body_file), "--write-out", "%{http_code}"]
        if token:
            command += ["-H", "authorization: Bearer " + token]
        for name, value in (headers or {}).items():
            command += ["-H", name + ": " + value]
        if form is not None:
            command += ["-H", "content-type: application/x-www-form-urlencoded", "--data-raw", urlencode(form)]
        elif data is not None:
            command += ["-H", "content-type: application/json", "--data-raw", json.dumps(data)]
        if method:
            command += ["-X", method]
        command.append((base or self.base) + path)
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout + 3)
        body = body_file.read_text() if body_file.exists() else ""
        response_headers = headers_from(header_file.read_text()) if header_file.exists() else {}
        if result.returncode:
            return Response(0, response_headers, result.stderr)
        return Response(int(result.stdout), response_headers, body)

    def wait_ready(self, process, base, label):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(label + " exited before becoming ready")
            if self.request("/readyz", base=base, timeout=1).status == 200:
                self.check(label + " became ready", True)
                return
            time.sleep(0.1)
        raise RuntimeError(label + " did not become ready within 20 seconds")

    def config(self, name, base, redis_url=None):
        directory = self.work / name
        directory.mkdir(exist_ok=True)
        values = {
            "config_version": 1, "listen": urlsplit(base).netloc,
            "upstream_url": "http://127.0.0.1:{}".format(self.mock_port),
            "require_identity": True, "identity_hmac_secret_file": str(self.work / "hmac.secret"),
            "dashboard_enabled": False, "require_tool_schema": False,
            "atif_spool_dir": str(directory / "spool"), "bridge_data_dir": str(directory / "bridge"),
            "token_exchange_enabled": True, "token_exchange_seed_file": str(self.work / "exchange.seed"),
            "token_exchange_ttl_s": 120, "default_workflow": "signed", "require_intent_mapping": True,
        }
        if redis_url:
            values.update(state_backend="redis", state_endpoint=redis_url)
        content = "\n".join("{} = {}".format(key, json.dumps(value)) for key, value in values.items())
        content += '\n\n[intent_map]\nlookup = "customer.read"\nread_static = "docs.read"\nread_open = "docs.read"\n'
        # Two backends use the default MCP transport; the open backend keeps
        # the plain JSON-RPC transport so both stay exercised end to end.
        for name_, tool, route, auth, transport in (
            ("secure-backend", "lookup", "secure", '"exchange"', "mcp"),
            ("static-backend", "read_static", "static", '{ static_file = ' + json.dumps(str(self.work / "static.token")) + ' }', "mcp"),
            ("open-backend", "read_open", "open", '"none"', "json_rpc"),
        ):
            content += '\n[[backends]]\nname = {}\nurl = {}\nauth = {}\ntools = {}\ntransport = {}\n'.format(
                json.dumps(name_), json.dumps("http://127.0.0.1:{}/{}".format(self.mock_port, route)),
                auth, json.dumps([tool]), json.dumps(transport))
        content += '\n[[operator_tokens]]\nname = "live-operator"\nsha256 = ' + json.dumps(hashlib.sha256(self.operator_secret.encode()).hexdigest()) + '\n'
        for backend, secret in (("secure-backend", self.backend_secret), ("static-backend", self.static_backend_secret)):
            content += '\n[[introspection_tokens]]\nbackend = {}\nsha256 = {}\n'.format(
                json.dumps(backend), json.dumps(hashlib.sha256(secret.encode()).hexdigest()))
        path = directory / "harness.toml"
        path.write_text(content)
        return path

    def start_daemon(self, name, config):
        env = dict(self.environment, AV_CONFIG=str(config),
                   AV_SIGNING_SEED_FILE=str(config.parent / "signing.seed"))
        return self.start(name, [str(self.binary), "--config", str(config)], env)

    def call(self, token, tool="read_open", session=None, base=None):
        return self.request("/v1/mcp", token=token, base=base,
                            headers={"x-av-session": session or "live-" + self.run_id + "-" + uuid.uuid4().hex},
                            data={"jsonrpc": "2.0", "id": self.request_id + 1, "method": "tools/call",
                                  "params": {"name": tool, "arguments": {}}})

    def exchange(self, token, audience="static-backend", base=None, scope="tool:read_static"):
        return self.request("/v1/token", base=base, form={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": token, "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "audience": audience, "scope": scope})

    def revoke(self, token, base=None):
        return self.request("/v1/revoke", base=base, form={"token": token})

    def requests(self):
        return [json.loads(line) for line in self.log_path.read_text().splitlines()]

    def command(self, args, log_name):
        result = subprocess.run([str(self.avctl)] + args, env=self.environment, cwd=self.work,
                                capture_output=True, text=True, timeout=30)
        (self.work / log_name).write_text(result.stdout + result.stderr)
        return result

    def run(self):
        mock = self.start("mock", [sys.executable, str(HERE), "mock", str(self.mock_port), str(self.log_path)])
        self.wait_ready(mock, "http://127.0.0.1:{}".format(self.mock_port), "mock backend")
        config = self.config("a", self.base, self.args.redis)
        result = self.command(["config-validate", str(config)], "validate.log")
        if not self.check("documented backend auth syntax validates", result.returncode == 0):
            raise RuntimeError("config validation failed; see validate.log")
        bad = self.work / "bad.toml"
        bad.write_text('config_version = 1\nupstream_url = "http://127.0.0.1:1"\ntoken_exchange_enabled = true\n' +
                       'token_exchange_seed_file = ' + json.dumps(str(self.work / "exchange.seed")) + '\n')
        result = self.command(["config-validate", str(bad)], "bad-validate.log")
        self.check("exchange without backends or identity is refused",
                   result.returncode != 0 and "no [[backends]]" in result.stdout + result.stderr)
        daemon = self.start_daemon("daemon-a", config)
        self.wait_ready(daemon, self.base, "identity-enabled gateway")
        self.core_checks()
        self.authority_checks()
        if self.redis:
            self.redis_checks()
        self.check("no caller token appeared in any backend request",
                   lambda: all(token not in self.log_path.read_text() for token in self.tokens))

    def core_checks(self):
        token = self.token()
        validations = self.validation_count()
        response = self.call(token, "lookup")
        self.check("a forwarded exchange call validates inbound identity exactly once",
                   self.validation_count() - validations == 1)
        self.check("exchange backend call succeeds", response.status == 200)
        requests = self.requests()
        if not requests:
            raise RuntimeError("no request reached the mock backend")
        request = requests[-1]
        self.check("the exchange backend path is used", request["path"] == "/secure")
        exchanged = request["headers"].get("authorization", "").removeprefix("Bearer ")
        self.check("forwarded exchange tokens use the av-tool+jwt profile",
                   lambda: decode_part(exchanged, 0)["typ"] == "av-tool+jwt")
        self.check("the backend can introspect the forwarded av-tool+jwt token",
                   lambda: self.introspect(exchanged).json()["active"] is True)
        claims = decode_part(exchanged)
        self.check("the exchanged token is for the backend", claims.get("aud") == "secure-backend")
        self.check("the exchanged token has exactly the called tool scope", claims.get("scopes") == ["tool:lookup"])
        self.check("the exchanged token preserves the human and agent identities",
                   lambda: claims["sub"] == "user:live-" + self.run_id and claims["act"]["sub"] == "inst-" + self.run_id)
        self.check("the exchanged token has the configured lifetime", lambda: claims["exp"] - claims["iat"] == 120)
        intent = request["headers"].get("x-av-intent-token", "")
        self.check("the intent token has type av-intent+jwt", lambda: decode_part(intent, 0)["typ"] == "av-intent+jwt")
        self.check("the intent token is bound to the backend, the human, and the agent",
                   lambda: decode_part(intent)["aud"] == "secure-backend"
                   and decode_part(intent)["sub"] == "user:live-" + self.run_id
                   and decode_part(intent)["act"]["sub"] == "inst-" + self.run_id)
        self.check("the MCP backend received the handshake and the session id",
                   lambda: any(json.loads(r["body"]).get("method") == "initialize" for r in requests)
                   and request["headers"].get("mcp-session-id") == "live-pillars-session")
        jwks = self.request("/.well-known/jwks.json")
        self.check("JWKS publishes the exchanged token's signing key",
                   lambda: jwks.status == 200 and decode_part(exchanged, 0)["kid"] in [key["kid"] for key in jwks.json()["keys"]])
        self.check("the static backend call succeeds", self.call(token, "read_static").status == 200)
        self.check("the static backend receives its own trimmed credential",
                   lambda: self.requests()[-1]["path"] == "/static"
                   and self.requests()[-1]["headers"].get("authorization") == "Bearer static-backend-secret")
        self.check("the open backend call succeeds", self.call(token).status == 200)
        self.check("the open backend receives no authorization header",
                   lambda: self.requests()[-1]["path"] == "/open" and "authorization" not in self.requests()[-1]["headers"])
        before = len(self.requests())
        narrow = self.token(["chat:write"])
        narrow_session = "scope-" + self.run_id
        self.check("a caller without a tool scope is refused with 403", self.call(narrow, "lookup", narrow_session).status == 403)
        self.check("the refused call never reaches the backend", len(self.requests()) == before)
        event = self.wait_event("agent.tool_call", lambda event: event.get("session_uid") == narrow_session
                                and event.get("payload", {}).get("policy") == "backend.exchange"
                                and event.get("payload", {}).get("denial_code") == "POLICY_DENIED"
                                and event.get("payload", {}).get("allowed") is False)
        self.check("scope refusal is published as a blocked tool event", event is not None)
        self.request("/v1/sessions/" + narrow_session + "/close", token=narrow, method="POST")
        scope_receipt = self.request("/v1/sessions/" + narrow_session + "/promote", token=narrow, method="POST")
        self.check("the scope refusal receipt counts one blocked call and no allowed call",
                   lambda: scope_receipt.status == 200 and receipt_counts(scope_receipt.json()) == (1, 0, 1))
        if event:
            self.verify_event_receipt(event, "scope-refusal")
        response = self.exchange(token)
        self.check("publicly exchanged tokens use the JWT profile",
                   lambda: decode_part(response.json()["access_token"], 0)["typ"] == "JWT")
        self.check("the token endpoint issues a token for a configured backend", response.status == 200)
        self.check("token responses cannot be cached", response.headers.get("cache-control") == "no-store" and response.headers.get("pragma") == "no-cache")
        self.check("the token response has the standard type, lifetime, and scope",
                   lambda: response.json()["token_type"] == "Bearer"
                   and response.json()["issued_token_type"] == "urn:ietf:params:oauth:token-type:jwt"
                   and response.json()["expires_in"] == 120 and response.json()["scope"] == "tool:read_static")
        self.check("the endpoint-issued token is bound to its audience",
                   lambda: decode_part(response.json()["access_token"])["aud"] == "static-backend")
        unknown = self.exchange(token, "https://unknown.example")
        self.check("an unknown audience is refused with invalid_target",
                   lambda: unknown.status == 400 and unknown.json()["error"] == "invalid_target")
        self.check("the token works before revocation", self.call(token).status == 200)
        revoked = self.revoke(token)
        self.check("revocation returns 200", revoked.status == 200)
        self.check("revocation responses cannot be cached", revoked.headers.get("cache-control") == "no-store")
        self.check("the revoked token is refused by tools", self.call(token).status == 401)
        response = self.exchange(token)
        self.check("the revoked token is refused by token exchange without disclosing details",
                   lambda: response.status == 400 and response.json()["error"] == "invalid_request"
                   and response.json()["error_description"] == "identity validation failed")
        self.check("repeated revocation still returns 200", self.revoke(token).status == 200)
        self.check("an invalid token revocation still returns 200", self.revoke("garbage").status == 200)
        self.check("another token for the same agent still works", self.call(self.token()).status == 200)
        metrics = self.request("/metrics")
        self.check("only one token revocation was counted",
                   re.search(r"^av_tokens_revoked_total 1$", metrics.body, re.MULTILINE) is not None)
        self.check("the gateway logged the revocation", "token authority revoked" in (self.work / "daemon-a.log").read_text())
        event = self.wait_event("agent.identity", lambda event: event.get("payload", {}).get("action") == "token_revoked"
                                and event.get("payload", {}).get("jti") == decode_part(token)["jti"])
        self.check("revocation produces a published identity event", event is not None)
        self.check("revocation retries produce exactly one published identity event",
                   lambda: len([item for item in bridge_events(self.work / "a/bridge", "agent.identity")
                                if item.get("payload", {}).get("jti") == decode_part(token)["jti"]]) == 1)
        if event:
            self.verify_event_receipt(event, "nhi-revocation")
        signed = self.token()
        session = "signed-" + self.run_id
        self.check("the signed session forwards an exchange call", self.call(signed, "lookup", session).status == 200)
        before = len(self.requests())
        denied = self.call(signed, "unmapped_tool", session)
        self.check("an unmapped tool is denied before backend contact",
                   denied.status == 403 and "UNMAPPED_TOOL" in denied.body and len(self.requests()) == before)
        closed = self.request("/v1/sessions/" + session + "/close", token=signed, method="POST")
        self.check("closing the session seals a receipt", lambda: closed.status == 200 and closed.json()["kind"] == "receipt")
        receipt = self.request("/v1/sessions/" + session + "/promote", token=signed, method="POST")
        self.check("promoting the session returns the signed receipt", lambda: receipt.status == 200 and "receipt_id" in receipt.json())
        receipt_path = self.work / "receipt.json"
        receipt_path.write_text(receipt.body)
        public = self.command(["pubkey", "--seed", str(self.work / "a/signing.seed")], "pubkey.log")
        public_key = json.loads(public.stdout)["public_key_hex"]
        verified = self.command(["receipt-verify", str(receipt_path), "--public-key-hex", public_key], "receipt-verify.log")
        self.check("the signed receipt verifies offline", verified.returncode == 0 and verified.stdout.startswith("verified "))
        self.check("the receipt records one allowed and one blocked call", lambda: receipt_counts(receipt.json()) == (2, 1, 1))
        deadline = time.monotonic() + 10
        found = False
        while time.monotonic() < deadline:
            if bridge_matches(self.work / "a/bridge"):
                found = True
                break
            time.sleep(0.1)
        self.check("the published denial includes its code, policy, and allowed=false", found)

    def validation_count(self):
        response = self.request("/metrics")
        match = re.search(r"^av_identity_validations_total ([0-9]+)$", response.body, re.MULTILINE)
        return int(match.group(1)) if match else 0

    def wait_event(self, topic, predicate, replica="a"):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            for event in bridge_events(self.work / replica / "bridge", topic):
                if predicate(event):
                    return event
            time.sleep(0.1)
        return None

    def verify_event_receipt(self, event, label, replica="a"):
        session = event["session_uid"]
        path = self.work / replica / "spool/receipts" / (hashlib.sha256(session.encode()).hexdigest()[:32] + ".json")
        deadline = time.monotonic() + 10
        while not path.exists() and time.monotonic() < deadline:
            time.sleep(0.1)
        self.check(label + " has a persisted signed receipt", path.exists())
        if not path.exists():
            return
        receipt = json.loads(path.read_text())
        self.check(label + " receipt is bound to the event session and contains events",
                   receipt.get("session_id") == session and receipt.get("subject", {}).get("event_count", 0) >= 1)
        public = self.command(["pubkey", "--seed", str(self.work / replica / "signing.seed")], label + "-pubkey.log")
        key = json.loads(public.stdout)["public_key_hex"]
        verified = self.command(["receipt-verify", str(path), "--public-key-hex", key], label + "-verify.log")
        self.check(label + " receipt verifies offline", verified.returncode == 0 and verified.stdout.startswith("verified "))

    def introspect(self, token, credential=None, base=None):
        return self.request("/v1/introspect", token=credential or self.backend_secret, base=base, form={"token": token})

    def admin_revoke(self, target, credential=None, base=None):
        # Each operator command is audited; only repeated holder revocations
        # are deduplicated, as checked in core_checks.
        return self.request("/admin/v1/revocations", token=credential or self.operator_secret, base=base, data=target)

    def authority_checks(self):
        source = self.token()
        first = self.exchange(source, "secure-backend", scope="tool:lookup")
        self.check("a backend token is issued for introspection", first.status == 200)
        leaf = first.json()["access_token"]
        second = self.exchange(source, "secure-backend", scope="tool:lookup").json()["access_token"]
        response = self.introspect(leaf)
        self.check("the audience backend sees its token as active",
                   lambda: response.status == 200 and response.json()["active"] is True
                   and response.json()["aud"] == "secure-backend" and response.headers.get("cache-control") == "no-store")
        response = self.introspect(leaf, self.static_backend_secret)
        self.check("another backend cannot introspect the token as active",
                   lambda: response.status == 200 and response.json() == {"active": False})
        self.check("introspection refuses an unrecognized backend credential", self.introspect(leaf, "x" * 64).status == 401)
        self.check("introspection requires authentication", self.request("/v1/introspect", form={"token": leaf}).status == 401)
        self.check("an exchanged backend token is not accepted as an inbound NHI token", self.call(leaf).status == 401)
        self.check("an exchanged leaf can be revoked with RFC 7009", self.revoke(leaf).status == 200)
        self.check("introspection refuses a revoked exchanged leaf", lambda: self.introspect(leaf).json() == {"active": False})
        self.check("revoking one exchanged leaf leaves another active", lambda: self.introspect(second).json()["active"] is True)
        self.check("leaf revocation leaves the source NHI token usable", self.call(source).status == 200)
        self.check("the source NHI token can be revoked", self.revoke(source).status == 200)
        self.check("source revocation cascades to previously issued exchanged tokens",
                   lambda: self.introspect(second).json() == {"active": False})
        unrelated = self.token()
        target = {"jti": decode_part(unrelated)["jti"], "token_kind": "nhi"}
        self.check("ordinary agent tokens cannot administer revocations", self.admin_revoke(target, unrelated).status == 401)
        self.check("backend introspection credentials cannot administer revocations", self.admin_revoke(target, self.backend_secret).status == 401)
        response = self.admin_revoke(target)
        self.check("an operator can revoke by NHI JTI with a signed audit",
                   lambda: response.status == 200 and response.json()["revoked"] is True and response.json()["audited"] is True)
        self.check("operator JTI revocation is enforced on the data plane", self.call(unrelated).status == 401)
        event = self.wait_event("agent.identity", lambda event: event.get("payload", {}).get("method") == "operator"
                                and event.get("payload", {}).get("jti") == target["jti"])
        self.check("operator revocation publishes the operator identity",
                   lambda: event is not None and event["payload"]["operator"] == "live-operator")
        if event:
            self.verify_event_receipt(event, "operator-revocation")
        source = self.token()
        leaf = self.exchange(source, "secure-backend", scope="tool:lookup").json()["access_token"]
        response = self.admin_revoke({"jti": decode_part(leaf)["jti"], "token_kind": "exchanged"})
        self.check("operators can revoke exchanged JTIs in their own namespace", response.status == 200)
        self.check("operator exchanged-token revocation is enforced by introspection",
                   lambda: self.introspect(leaf).json() == {"active": False})
        self.check("operator exchanged-token revocation leaves the NHI source usable", self.call(source).status == 200)
        instance = "bulk-" + uuid.uuid4().hex
        first = self.token(identity=instance)
        second = self.token(identity=instance)
        leaf = self.exchange(first, "secure-backend", scope="tool:lookup").json()["access_token"]
        response = self.admin_revoke({"instance_uid": "inst-" + instance})
        self.check("an operator can revoke an entire agent instance",
                   lambda: response.status == 200 and response.json()["audited"] is True
                   and response.json()["issued_at_or_before"] >= decode_part(first)["iat"])
        self.check("instance revocation refuses both existing NHI tokens",
                   self.call(first).status == 401 and self.call(second).status == 401)
        self.check("instance revocation cascades to exchanged tokens",
                   lambda: self.introspect(leaf).json() == {"active": False})
        self.check("another instance remains usable after instance revocation", self.call(self.token()).status == 200)

    def redis_checks(self):
        parsed, host, destination = self.redis
        port = free_port()
        base_b = "http://127.0.0.1:{}".format(free_port())
        forward_args = [sys.executable, str(HERE), "forward", str(port), host, str(destination)]
        forwarder = self.start("redis-forwarder", forward_args)
        deadline = time.monotonic() + 10
        while True:
            try:
                if redis_ping("127.0.0.1", port):
                    break
            except OSError:
                pass
            if forwarder.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("Redis forwarder failed to become ready")
            time.sleep(0.1)
        config_b = self.config("b", base_b, urlunsplit(("redis", "127.0.0.1:" + str(port), parsed.path, "", "")))
        daemon_b = self.start_daemon("daemon-b", config_b)
        self.wait_ready(daemon_b, base_b, "second gateway")
        shared = self.token()
        unrevoked = self.token()
        locally_revoked = self.token()
        self.check("a fresh token works on replica B", self.call(shared, base=base_b).status == 200)
        shared_leaf = self.exchange(shared, "secure-backend", scope="tool:lookup").json()["access_token"]
        self.check("replica B introspects a token issued by replica A",
                   lambda: self.introspect(shared_leaf, base=base_b).json()["active"] is True)
        self.check("replica A revokes the shared token", self.revoke(shared).status == 200)
        before = len(self.requests())
        self.check("replica B immediately refuses the revoked token", self.call(shared, base=base_b).status == 401)
        self.check("cross-replica refusal makes no backend request", len(self.requests()) == before)
        response = self.exchange(shared, base=base_b)
        self.check("replica B also refuses exchange of the revoked token",
                   lambda: response.status == 400 and response.json()["error"] == "invalid_request")
        self.check("source revocation cascades through introspection on replica B",
                   lambda: self.introspect(shared_leaf, base=base_b).json() == {"active": False})
        self.check("another token still works on replica B", self.call(unrevoked, base=base_b).status == 200)
        unrevoked_leaf = self.exchange(unrevoked, "secure-backend", scope="tool:lookup").json()["access_token"]
        self.stop(daemon_b)
        daemon_b = self.start_daemon("daemon-b", config_b)
        self.wait_ready(daemon_b, base_b, "restarted second gateway")
        self.check("revocation survives a process restart", self.call(shared, base=base_b).status == 401)
        self.check("cascading revocation survives a process restart",
                   lambda: self.introspect(shared_leaf, base=base_b).json() == {"active": False})
        # Killing the whole forwarder closes every pooled connection, not just
        # its listening socket. Redis itself remains running and untouched.
        self.stop(forwarder)
        before = len(self.requests())
        # A failed shared write still denies that token locally. Keep a
        # different token for unreadable-store and recovery checks; successful
        # "not revoked" reads must never become cached permission to proceed.
        for label, response in (("revocation", self.revoke(locally_revoked, base=base_b)),
                                ("exchange", self.exchange(unrevoked, base=base_b)),
                                ("introspection", self.introspect(unrevoked_leaf, base=base_b)),
                                ("operator revocation", self.admin_revoke({"jti": str(uuid.uuid4())}, base=base_b))):
            self.check(label + " fails closed with a retryable 503 during a Redis outage",
                       lambda r=response: r.status == 503 and r.json()["error"] == "temporarily_unavailable"
                       and bool(r.headers.get("retry-after")))
        response = self.call(unrevoked, base=base_b)
        self.check("tools fail closed with 503 and Retry-After during the Redis outage",
                   response.status == 503 and bool(response.headers.get("retry-after")))
        # The post-restart check above repopulates B's known-denial cache for
        # shared. Without that read, a restarted process could only return 503.
        self.check("a known revoked token remains refused with 401 during the outage",
                   self.call(shared, base=base_b).status == 401)
        self.check("a token whose revocation write failed is still refused locally with 401",
                   self.call(locally_revoked, base=base_b).status == 401)
        readiness = self.request("/readyz", base=base_b)
        self.check("readiness reports unavailable revocation storage without changing its 200 status",
                   lambda: readiness.status == 200 and readiness.json()["status"] == "ready"
                   and readiness.json()["checks"]["revocation_available"] is False)
        self.check("no outage request reaches the backend", len(self.requests()) == before)
        self.start("redis-forwarder", forward_args)
        deadline = time.monotonic() + 30
        recovered = False
        while time.monotonic() < deadline:
            if self.call(unrevoked, base=base_b).status == 200:
                recovered = True
                break
            time.sleep(0.2)
        self.check("replica B recovers after Redis connectivity returns", recovered)
        introspection = self.introspect(unrevoked_leaf, base=base_b)
        self.check("introspection of an unrevoked token recovers after Redis returns",
                   lambda: introspection.status == 200 and introspection.json()["active"] is True)
        readiness = self.request("/readyz", base=base_b)
        self.check("readiness reports revocation storage recovery after successful dependency calls",
                   lambda: readiness.status == 200 and readiness.json()["checks"]["revocation_available"] is True)
        self.check("the token denied by a failed write stays denied locally after recovery",
                   self.call(locally_revoked, base=base_b).status == 401)
        self.check("the failed revocation write can be retried after recovery",
                   self.revoke(locally_revoked, base=base_b).status == 200)
        self.check("the successful retry shares the formerly local revocation with replica A",
                   self.call(locally_revoked).status == 401)
        self.check("replica B can revoke after recovery", self.revoke(unrevoked, base=base_b).status == 200)
        self.check("replica A enforces the revocation made after recovery", self.call(unrevoked).status == 401)
        self.check("replica A introspection enforces the revocation made after recovery",
                   lambda: self.introspect(unrevoked_leaf).json() == {"active": False})
        instance = "redis-bulk-" + uuid.uuid4().hex
        first, second = self.token(identity=instance), self.token(identity=instance)
        response = self.admin_revoke({"instance_uid": "inst-" + instance}, base=base_b)
        self.check("operator instance revocation is shared between replicas",
                   response.status == 200 and self.call(first).status == 401 and self.call(second).status == 401)

    def cleanup(self, successful):
        for process in reversed(self.processes):
            self.stop(process)
        print("\n{} checks passed; {} failed.".format(self.passed, self.failed), flush=True)
        if not successful:
            for path in sorted(self.work.glob("*.log")):
                print("\n--- {} (last 60 lines) ---".format(path.name), file=sys.stderr)
                print("\n".join(path.read_text(errors="replace").splitlines()[-60:]), file=sys.stderr)
        if successful and os.environ.get("AV_KEEP_TMP") != "1":
            shutil.rmtree(self.work)
        else:
            print("Artifacts retained at {}".format(self.work), flush=True)


class HelperTests(unittest.TestCase):
    def test_minted_token_claims_signature_and_random_ids(self):
        token = mint(b"secret", "run", ["tool:lookup"], now=123)
        signing, signature = token.rsplit(".", 1)
        self.assertEqual(signature, b64(hmac.new(b"secret", signing.encode(), hashlib.sha256).digest()))
        self.assertEqual(decode_part(token, 0)["alg"], "HS256")
        self.assertEqual(decode_part(token)["exp"], 723)
        self.assertEqual(decode_part(token)["scopes"], ["tool:lookup"])
        self.assertNotEqual(decode_part(token)["jti"], decode_part(mint(b"secret", "run", []))["jti"])

    def test_header_names_and_final_response(self):
        headers = headers_from("HTTP/1.1 100 Continue\r\nFake: yes\r\n\r\nHTTP/1.1 200 OK\r\nCache-Control: no-store\r\nPRAGMA: no-cache\r\n")
        self.assertEqual(headers, {"cache-control": "no-store", "pragma": "no-cache"})

    def test_bridge_layout_and_uid_index_exclusion(self):
        with tempfile.TemporaryDirectory() as directory:
            topic = Path(directory) / "topics/agent.tool_call"
            topic.mkdir(parents=True)
            record = json.dumps({"value": {"payload": {"denial_code": "UNMAPPED_TOOL", "policy": "pdp.intent_map", "allowed": False}}})
            (topic / "p0.event-uids.jsonl").write_text(record + "\n")
            self.assertFalse(bridge_matches(directory))
            (topic / "p0.jsonl").write_text('{"unfinished"\n' + record + "\n")
            self.assertTrue(bridge_matches(directory))

    def test_receipt_counts(self):
        self.assertEqual(receipt_counts({"tool_calls": {"total": 2, "allowed": 1, "blocked": 1}}), (2, 1, 1))

    def test_redis_rejects_nonlocal_and_ambiguous_urls(self):
        self.assertEqual(loopback_redis("redis://127.0.0.1:6380/2")[2], 6380)
        self.assertEqual(loopback_redis("redis://localhost")[1], "127.0.0.1")
        for url in ("redis://10.0.0.1", "redis://example.com", "http://127.0.0.1", "redis://user:pass@127.0.0.1", "redis://127.0.0.1?x=1"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                loopback_redis(url)


    def test_forwarder_shutdown_closes_existing_connections(self):
        # A real socket fixture proves that killing the forwarder interrupts
        # existing pooled connections, which is essential to the outage check.
        class Echo(socketserver.BaseRequestHandler):
            def handle(self):
                while True:
                    data = self.request.recv(1024)
                    if not data:
                        return
                    self.request.sendall(data)

        class EchoServer(socketserver.ThreadingTCPServer):
            daemon_threads = True

        with EchoServer(("127.0.0.1", 0), Echo) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            port = free_port()
            process = subprocess.Popen([sys.executable, str(HERE), "forward", str(port),
                                        "127.0.0.1", str(server.server_address[1])])
            connection = None
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    try:
                        connection = socket.create_connection(("127.0.0.1", port), timeout=1)
                        break
                    except OSError:
                        time.sleep(0.05)
                self.assertIsNotNone(connection, "forwarder never opened its listener")
                connection.sendall(b"before-outage")
                self.assertEqual(connection.recv(64), b"before-outage")
                process.kill()
                process.wait(timeout=5)
                try:
                    self.assertEqual(connection.recv(64), b"")
                except ConnectionResetError:
                    pass  # A reset also proves the existing connection died.
            finally:
                if connection is not None:
                    connection.close()
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
                server.shutdown()
                thread.join(timeout=5)

    def test_runner_reports_boot_failure_and_retains_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            daemon = root / "daemon"
            avctl = root / "avctl"
            # These executables isolate the driver's startup failure behavior.
            daemon.write_text("#!/bin/sh\necho deliberate-daemon-failure >&2\nexit 7\n")
            avctl.write_text('#!/bin/sh\ncase "$2" in *bad.toml) echo "no [[backends]]"; exit 1;; esac\nexit 0\n')
            daemon.chmod(0o700)
            avctl.chmod(0o700)
            environment = dict(os.environ, AGENTVISORD=str(daemon), AVCTL=str(avctl),
                               AV_LIVE_TMPDIR=str(root / "artifacts"))
            result = subprocess.run([sys.executable, str(HERE), "run"], env=environment,
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("exited before becoming ready", result.stdout)
            self.assertIn("checks passed; 1 failed", result.stdout)
            self.assertIn("deliberate-daemon-failure", result.stderr)
            self.assertIn("Artifacts retained", result.stdout)

    def test_missing_binary_and_closed_redis_are_prerequisite_errors(self):
        environment = dict(os.environ, AGENTVISORD="/nonexistent/agentvisord", AVCTL=sys.executable)
        result = subprocess.run([sys.executable, str(HERE), "run"], env=environment,
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        environment["AGENTVISORD"] = sys.executable
        # Reserve a port without listening so no other process can take it.
        with socket.socket() as unavailable:
            unavailable.bind(("127.0.0.1", 0))
            result = subprocess.run([sys.executable, str(HERE), "run", "--redis",
                                     "redis://127.0.0.1:" + str(unavailable.getsockname()[1])],
                                    env=environment, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2)

    def test_binary_snapshot_survives_source_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "build-output"
            executable.write_text("#!/bin/sh\nprintf old-binary\n")
            executable.chmod(0o700)
            with patch.dict(os.environ, {"AGENTVISORD": str(executable), "AVCTL": str(executable),
                                         "AV_LIVE_TMPDIR": directory, "AV_KEEP_TMP": "0"}):
                checks = LiveChecks(argparse.Namespace(redis=None))
                try:
                    executable.write_text("#!/bin/sh\nprintf replacement-binary\n")
                    result = subprocess.run([str(checks.binary)], text=True, capture_output=True, timeout=5)
                    self.assertEqual(result.stdout, "old-binary")
                    result = subprocess.run([str(checks.avctl)], text=True, capture_output=True, timeout=5)
                    self.assertEqual(result.stdout, "old-binary")
                finally:
                    checks.cleanup(True)

    def test_cleanup_reaps_child_processes(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {
                "AGENTVISORD": sys.executable, "AVCTL": sys.executable, "AV_LIVE_TMPDIR": directory,
                "AV_KEEP_TMP": "0"}):
            checks = LiveChecks(argparse.Namespace(redis=None))
            process = checks.start("sleeper", [sys.executable, "-c", "import time; time.sleep(60)"])
            checks.cleanup(True)
            self.assertIsNotNone(process.poll())
            self.assertFalse(checks.work.exists())


def interrupted(signum, frame):
    raise KeyboardInterrupt("signal {}".format(signum))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    runner = subparsers.add_parser("run")
    runner.add_argument("--redis", help="run replica, restart, outage and recovery checks with a local test Redis")
    subparsers.add_parser("self-test")
    mock = subparsers.add_parser("mock")
    mock.add_argument("port", type=int)
    mock.add_argument("log")
    forward = subparsers.add_parser("forward")
    forward.add_argument("port", type=int)
    forward.add_argument("host")
    forward.add_argument("destination_port", type=int)
    args = parser.parse_args()
    if args.command == "self-test":
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(HelperTests))
        return 0 if result.wasSuccessful() else 1
    if args.command == "mock":
        serve_mock(args.port, args.log)
        return 0
    if args.command == "forward":
        serve_forwarder(args.port, args.host, args.destination_port)
        return 0
    os.umask(0o077)
    try:
        checks = LiveChecks(args)
    except (ValueError, OSError) as error:
        print("Prerequisite error: {}".format(error), file=sys.stderr)
        return 2
    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    success = False
    try:
        checks.run()
        success = checks.failed == 0
    except (Exception, KeyboardInterrupt) as error:
        checks.check("live verification completed: {}".format(error), False)
    finally:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        checks.cleanup(success)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
