#!/usr/bin/env python3
"""Run the shipped Kubernetes template in a disposable, isolated kind cluster.

Requires kind, kubectl, Docker, Ruby (standard YAML library), and the local
release avctl. Never reads or changes the user's kubeconfig. Fixture credentials
and the Redis backup are private and are deleted after task-owned resources.
The local cluster tests Kubernetes behavior, not a remote storage driver or HA.
"""
import argparse
import base64
import copy
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
import uuid

ROOT = Path(__file__).resolve().parents[1]
NODE = "kindest/node:v1.35.0@sha256:452d707d4862f52530247495d180205e029056831160e22870e37e3f6c1ac31f"
REDIS = "redis:8.2.1-alpine@sha256:987c376c727652f99625c7d205a1cba3cb2c53b92b0b62aade2bd48ee1593232"
ISSUER = "https://kubernetes-staging.invalid"
OWNER = "agentvisor.test.owner"

MOCK = r'''
import json, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
    def do_POST(self):
        data = json.loads(self.rfile.read(int(self.headers.get("content-length", "0"))))
        expected = "Bearer " + os.environ["PROVIDER_KEY"]
        if self.headers.get("Authorization") != expected:
            self.send_response(401); self.end_headers(); return
        if self.path == "/v1/chat/completions":
            body = ('data: ' + json.dumps({"id":"staging", "object":"chat.completion.chunk",
                "model":"staging", "choices":[{"index":0,"delta":{"role":"assistant",
                "content":"hello from Kubernetes staging"},"finish_reason":"stop"}]})
                + '\n\ndata: [DONE]\n\n').encode()
            kind = "text/event-stream"
        else:
            body = json.dumps({"jsonrpc":"2.0", "id":data.get("id"),
                "result":{"content":[{"type":"text","text":"tool staging success"}]}}).encode()
            kind = "application/json"
        self.send_response(200); self.send_header("content-type", kind)
        self.send_header("content-length", str(len(body))); self.end_headers(); self.wfile.write(body)
ThreadingHTTPServer(("0.0.0.0",8080), Handler).serve_forever()
'''


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def mint(secret, subject, scopes):
    now = int(time.time())
    claims = {"iss": ISSUER, "sub": subject, "aud": "agentvisor-ai", "iat": now,
              "exp": now + 900, "jti": str(uuid.uuid4()), "instance_uid": subject,
              "charter": "staging", "version": "1.0", "scopes": scopes}
    content = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "dev-hmac"}).encode())
    content += "." + b64(json.dumps(claims).encode())
    return content + "." + b64(hmac.new(secret.encode(), content.encode(), hashlib.sha256).digest())


def owned_node(value, name):
    return (value.get("Name", "").lstrip("/") == name + "-control-plane"
            and value.get("Config", {}).get("Labels", {}).get("io.x-k8s.kind.cluster") == name)


class Drill:
    def __init__(self, image, work, plaintext_redis=False):
        self.name = "av-k8s-" + uuid.uuid4().hex[:10]
        self.namespace = self.name
        self.work = work
        self.work.mkdir(parents=True, exist_ok=True)
        self.private = self.work / "private"
        self.private.mkdir(mode=0o700)
        self.kubeconfig = self.private / "kubeconfig"
        self.env = dict(os.environ, KUBECONFIG=str(self.kubeconfig),
                        KIND_EXPERIMENTAL_DOCKER_NETWORK=self.name,
                        KIND_EXPERIMENTAL_PROVIDER="docker")
        self.image = image
        self.plaintext_redis = plaintext_redis
        self.calls = 0
        self.passed = []
        self.forward = None
        self.network_created = False
        self.cluster_requested = False
        self.tagged = {}
        self.credentials = [secrets.token_hex(32) for _ in range(4)]
        self.identity, self.seed, self.provider_key, self.redis_password = self.credentials
        self.tokens = []
        self.provenance = {"cluster": self.name, "namespace": self.namespace,
                           "node_image": NODE, "redis_image": REDIS,
                           "drill_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                           "source_commit": self.raw(["git", "rev-parse", "HEAD"]).strip(),
                           "source_diff_sha256": hashlib.sha256(self.raw(["git", "diff", "--binary"]).encode()).hexdigest(),
                           "checks": self.passed}

    @staticmethod
    def raw(args):
        return subprocess.check_output(args, cwd=ROOT, text=True, timeout=30)

    def scrub(self, text):
        for value in self.credentials + self.tokens:
            text = text.replace(value, "<fixture-secret>")
        return text

    def run(self, args, *, data=None, timeout=90, check=True, binary=False):
        self.calls += 1
        result = subprocess.run(args, input=data, capture_output=True, text=not binary,
                                env=self.env, cwd=ROOT, timeout=timeout)
        output = "<binary output omitted>" if binary else result.stdout
        errors = result.stderr.decode(errors="replace") if binary else result.stderr
        (self.work / ("%03d.log" % self.calls)).write_text(
            self.scrub("$ " + " ".join(args) + "\n" + output + errors))
        if check and result.returncode:
            raise RuntimeError("Command failed; see %03d.log: %s" % (self.calls, args[:5]))
        return result

    def kube(self, *args, **kwargs):
        return self.run(["kubectl", "--kubeconfig", str(self.kubeconfig),
                         "--context", "kind-" + self.name, "-n", self.namespace, *args], **kwargs)

    def apply(self, resources):
        self.kube("apply", "-f", "-", data=json.dumps({"apiVersion": "v1", "kind": "List", "items": resources}))

    def check(self, label, condition=True):
        if not condition:
            raise AssertionError(label)
        self.passed.append(label)
        print("PASS: " + label, flush=True)
        self.save()

    def save(self):
        (self.work / "result.json").write_text(json.dumps(self.provenance, indent=2) + "\n")

    def metadata(self, name):
        return {"name": name, "namespace": self.namespace, "labels": {OWNER: self.name}}

    def secret(self, name, values):
        return {"apiVersion": "v1", "kind": "Secret", "metadata": self.metadata(name), "stringData": values}

    def deployment(self, name, image, container, volumes=None, security=None):
        pod = {"automountServiceAccountToken": False,
               "securityContext": security or {"runAsUser": 65532, "runAsNonRoot": True, "fsGroup": 65532},
               "containers": [dict({"name": name, "image": image, "imagePullPolicy": "Never",
                                    "resources": {"requests": {"cpu": "50m", "memory": "32Mi"},
                                                  "limits": {"memory": "256Mi"}},
                                    "securityContext": {"allowPrivilegeEscalation": False,
                                                        "capabilities": {"drop": ["ALL"]},
                                                        "seccompProfile": {"type": "RuntimeDefault"}}}, **container)],
               "volumes": volumes or []}
        return {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": self.metadata(name),
                "spec": {"replicas": 1, "strategy": {"type": "Recreate"},
                         "selector": {"matchLabels": {"app": name}},
                         "template": {"metadata": {"labels": {"app": name, OWNER: self.name}}, "spec": pod}}}

    def service(self, name, port):
        return {"apiVersion": "v1", "kind": "Service", "metadata": self.metadata(name),
                "spec": {"selector": {"app": name}, "ports": [{"port": port, "targetPort": port}]}}

    def pvc(self, name):
        return {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": self.metadata(name),
                "spec": {"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "1Gi"}}}}

    def redis_deployment(self, name, claim, load_rdb=False):
        return self.deployment(name, self.redis_tag, {
            "args": ["redis-server", "/etc/redis/redis.conf"] + (["--appendonly", "no"] if load_rdb else []),
            "env": [{"name": "REDISCLI_AUTH", "valueFrom": {"secretKeyRef": {"name": "redis-config", "key": "password"}}}],
            "volumeMounts": [{"name": "data", "mountPath": "/data"},
                             {"name": "config", "mountPath": "/etc/redis", "readOnly": True}],
            "readinessProbe": {"exec": {"command": self.redis_cli() + ["ping"]}, "periodSeconds": 2},
        }, [{"name": "data", "persistentVolumeClaim": {"claimName": claim}},
            {"name": "config", "secret": {"secretName": "redis-config", "defaultMode": 0o440}}],
            {"runAsUser": 999, "runAsNonRoot": True, "fsGroup": 999})

    def redis_cli(self):
        return ["redis-cli"] + ([] if self.plaintext_redis else ["--tls", "--cacert", "/etc/redis/ca.crt"])

    def redis_url(self, hostname):
        return ("redis" if self.plaintext_redis else "rediss") + "://:" + self.redis_password + "@" + hostname + ":6379"

    def certificates(self):
        ca_key, ca, key, csr, cert, extensions = [self.private / name for name in
            ("ca.key", "ca.crt", "redis.key", "redis.csr", "redis.crt", "redis.ext")]
        self.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                  "-subj", "/CN=" + self.name + " CA", "-keyout", str(ca_key), "-out", str(ca)])
        self.run(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=redis",
                  "-keyout", str(key), "-out", str(csr)])
        extensions.write_text("subjectAltName=DNS:redis,DNS:redis-restored,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n")
        self.run(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key),
                  "-CAcreateserial", "-days", "1", "-extfile", str(extensions), "-out", str(cert)])
        for path in self.private.iterdir():
            if path.is_file():
                path.chmod(0o600)
        self.credentials.append(key.read_text())
        return {"ca.crt": ca.read_text(), "redis.crt": cert.read_text(), "redis.key": key.read_text()}

    def wait_deployment(self, name):
        self.kube("rollout", "status", "deployment/" + name, "--timeout=240s", timeout=250)

    def pod(self, app):
        pods = json.loads(self.kube("get", "pods", "-l", "app=" + app, "-o", "json").stdout)["items"]
        return next(p for p in pods if not p["metadata"].get("deletionTimestamp"))

    def gateway_exec(self, *args):
        return self.kube("exec", self.pod("agentvisor-ai")["metadata"]["name"], "--", *args).stdout

    def forward_gateway(self):
        if self.forward:
            self.forward.terminate()
            self.forward.wait(timeout=10)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            self.port = listener.getsockname()[1]
        output = open(self.work / ("port-forward-%s.log" % self.port), "w")
        self.forward = subprocess.Popen(["kubectl", "--kubeconfig", str(self.kubeconfig),
            "--context", "kind-" + self.name, "-n", self.namespace,
            "port-forward", "--address=127.0.0.1", "service/agentvisor-ai", str(self.port) + ":8484"],
            env=self.env, stdout=output, stderr=subprocess.STDOUT)
        output.close()
        self.until(lambda: self.http("/readyz")[0] == 200, "gateway port forwarding", 60)

    def http(self, path, data=None, token=None, headers=None, form=None):
        headers = dict(headers or {})
        if token:
            headers["Authorization"] = "Bearer " + token
        if form is not None:
            body = urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif data is not None:
            body = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
        else:
            body = None
        request = Request("http://127.0.0.1:%s%s" % (self.port, path), data=body, headers=headers)
        try:
            with urlopen(request, timeout=90) as response:
                return response.status, response.read()
        except HTTPError as error:
            return error.code, error.read()

    @staticmethod
    def until(predicate, label, seconds=120):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                if predicate():
                    return
            except (OSError, URLError, StopIteration):
                pass
            time.sleep(2)
        raise RuntimeError("Timed out waiting for " + label)

    def token(self, subject=None, scopes=None):
        token = mint(self.identity, subject or self.name,
                     scopes if scopes is not None else ["chat:write", "session:close", "session:promote", "tool:db_write"])
        self.tokens.append(token)
        return token

    def chat(self, token, session=None):
        return self.http("/v1/chat/completions", {"model": "staging", "stream": True,
            "messages": [{"role": "user", "content": "hello"}]}, token,
            {"x-av-session": session or self.name + "-" + uuid.uuid4().hex})

    def recreate_gateway(self):
        previous = self.pod("agentvisor-ai")["metadata"]["uid"]
        self.kube("delete", "pod", self.pod("agentvisor-ai")["metadata"]["name"], "--timeout=180s", timeout=190)
        self.wait_deployment("agentvisor-ai")
        self.check("Kubernetes replaces the gateway pod", self.pod("agentvisor-ai")["metadata"]["uid"] != previous)
        self.forward_gateway()

    def setup(self):
        self.provenance["kind_version"] = self.run(["kind", "version"]).stdout.strip()
        self.provenance["kubectl"] = json.loads(self.run(["kubectl", "version", "--client", "-o", "json"]).stdout)
        info = json.loads(self.run(["docker", "image", "inspect", self.image]).stdout)[0]
        self.provenance["gateway_image"] = {"tag": self.image, "id": info["Id"], "architecture": info["Architecture"],
                                             "created": info["Created"], "labels": info["Config"].get("Labels")}
        self.check("gateway image declares non-root UID 65532", info["Config"]["User"].split(":")[0] == "65532")
        resources = json.loads(self.run(["ruby", "-ryaml", "-rjson", "-e",
            "puts JSON.generate(YAML.load_stream(File.read(ARGV[0])))", str(ROOT / "deploy/kubernetes/agentvisor-ai.yaml")]).stdout)
        resources = [item for item in resources if item]
        deployment = next(item for item in resources if item["kind"] == "Deployment")
        pod = deployment["spec"]["template"]["spec"]
        init_image = pod["initContainers"][0]["image"]
        self.run(["docker", "pull", NODE], timeout=600)
        self.run(["docker", "pull", REDIS], timeout=300)
        self.run(["docker", "pull", init_image], timeout=300)
        self.redis_tag, self.init_tag = self.name + "-redis:fixture", self.name + "-init:fixture"
        for source, tag in [(REDIS, self.redis_tag), (init_image, self.init_tag)]:
            self.run(["docker", "tag", source, tag])
            self.tagged[tag] = self.run(["docker", "image", "inspect", tag, "--format", "{{.Id}}"]).stdout.strip()
        mock_dir = self.private / "mock"
        mock_dir.mkdir()
        (mock_dir / "mock.py").write_text(MOCK)
        (mock_dir / "Dockerfile").write_text("FROM " + init_image + "\nRUN apk add --no-cache python3\n"
            "COPY mock.py /mock.py\nUSER 65532:65532\nCMD [\"python3\",\"/mock.py\"]\nLABEL " + OWNER + "=" + self.name + "\n")
        self.mock_tag = self.name + "-mock:fixture"
        self.run(["docker", "build", "-t", self.mock_tag, str(mock_dir)], timeout=300)
        self.tagged[self.mock_tag] = self.run(["docker", "image", "inspect", self.mock_tag, "--format", "{{.Id}}"]).stdout.strip()
        self.run(["docker", "network", "create", "--label", OWNER + "=" + self.name, self.name])
        self.network_created = True
        kind_config = self.private / "kind.json"
        kind_config.write_text(json.dumps({"kind": "Cluster", "apiVersion": "kind.x-k8s.io/v1alpha4",
            "networking": {"apiServerAddress": "127.0.0.1"}, "nodes": [{"role": "control-plane", "image": NODE}]}))
        self.cluster_requested = True
        self.run(["kind", "create", "cluster", "--name", self.name, "--kubeconfig", str(self.kubeconfig),
                  "--config", str(kind_config), "--wait", "180s"], timeout=420)
        self.kubeconfig.chmod(0o600)
        # Docker's containerd image store may retain an index for platforms
        # whose blobs are not downloaded. Export this node's architecture
        # explicitly so kind's all-platform import does not request them.
        archive = self.private / "images.tar"
        self.run(["docker", "image", "save", "--platform", "linux/" + info["Architecture"],
                  "--output", str(archive), self.image, self.redis_tag, self.init_tag, self.mock_tag], timeout=600)
        self.run(["kind", "load", "image-archive", "--name", self.name, str(archive)], timeout=600)
        archive.unlink()
        self.provenance["server_version"] = json.loads(self.kube("version", "-o", "json").stdout)["serverVersion"]
        self.apply([{"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": self.namespace, "labels": {OWNER: self.name}}}])
        certificates = self.certificates()
        redis_config = "dir /data\nappendonly yes\nappendfsync always\nsave 60 1\nrequirepass " + self.redis_password + "\n"
        if not self.plaintext_redis:
            redis_config += ("port 0\ntls-port 6379\ntls-auth-clients no\ntls-cert-file /etc/redis/redis.crt\n"
                             "tls-key-file /etc/redis/redis.key\ntls-ca-cert-file /etc/redis/ca.crt\n")
        self.apply([self.secret("redis-config", dict(certificates, **{"redis.conf": redis_config, "password": self.redis_password})),
            self.pvc("redis-data"), self.redis_deployment("redis", "redis-data"), self.service("redis", 6379),
            self.secret("agentvisor-ai-upstream", {"api-key": self.provider_key}),
            self.deployment("model", self.mock_tag, {"env": [{"name": "PROVIDER_KEY", "valueFrom": {
                "secretKeyRef": {"name": "agentvisor-ai-upstream", "key": "api-key"}}}]}), self.service("model", 8080)])
        self.wait_deployment("redis")
        self.wait_deployment("model")
        self.check("dedicated persistent authenticated Redis and mock backend become ready")
        self.apply([self.secret("agentvisor-ai-signing-seed", {"signing.seed": self.seed}),
            self.secret("agentvisor-ai-identity", {"identity.hmac": self.identity}),
            self.secret("agentvisor-ai-trust", {"ca-bundle.crt": certificates["ca.crt"]}),
            self.secret("agentvisor-ai-state", {"redis-url": self.redis_url("redis")})])
        for resource in resources:
            resource["metadata"].update(self.metadata(resource["metadata"]["name"]))
        configuration = next(item for item in resources if item["kind"] == "ConfigMap")["data"]
        configuration["agentvisor.toml"] = configuration["agentvisor.toml"].replace(
            "https://api.openai.com", "http://model:8080").replace("https://identity.example.invalid", ISSUER).replace(
            'upstream_api_key_env = "AV_UPSTREAM_API_KEY"',
            'upstream_api_key_env = "AV_UPSTREAM_API_KEY"\ntool_upstream_url = "http://model:8080/tool"\n'
            'tool_upstream_bearer_env = "AV_UPSTREAM_API_KEY"')
        pod["containers"][0]["image"] = self.image
        pod["containers"][0]["imagePullPolicy"] = "Never"
        pod["initContainers"][0]["image"] = self.init_tag
        pod["initContainers"][0]["imagePullPolicy"] = "Never"
        self.kube("apply", "--dry-run=server", "-f", "-", data=json.dumps({"apiVersion": "v1", "kind": "List", "items": resources}))
        self.apply(resources)
        self.wait_deployment("agentvisor-ai")
        self.check("production template passes server-side validation, scheduling, init and startup probes")
        self.forward_gateway()

    def validate(self):
        pod = self.pod("agentvisor-ai")
        self.provenance["gateway_running_image_id"] = pod["status"]["containerStatuses"][0]["imageID"]
        self.provenance["gateway_runtime_version"] = self.gateway_exec("agentvisord", "--version").strip()
        self.check("startup and readiness probes report a ready gateway", all(item["ready"] for item in pod["status"]["containerStatuses"]))
        self.check("liveness endpoint succeeds", self.http("/livez")[0] == 200)
        container = pod["status"]["containerStatuses"][0]["containerID"].split("://", 1)[1]
        node = self.name + "-control-plane"
        process = json.loads(self.run(["docker", "exec", node, "crictl", "inspect", container]).stdout)["info"]["pid"]
        if not isinstance(process, int) or process < 1:
            raise RuntimeError("Invalid container process ID")
        prefix = "/proc/%s" % process
        status = self.run(["docker", "exec", node, "cat", prefix + "/status"]).stdout
        self.check("gateway runs without root, capabilities, or privilege escalation", "Uid:\t65532\t65532\t65532\t65532" in status
                   and "CapEff:\t0000000000000000" in status and "NoNewPrivs:\t1" in status and "Seccomp:\t2" in status)
        for secret in ("signing.seed", "identity.hmac"):
            mode = self.run(["docker", "exec", node, "stat", "-Lc", "%u:%g:%a", prefix + "/root/etc/agentvisor-ai/" + secret]).stdout.strip()
            self.check("projected %s is copied with owner-only mode" % secret, mode == "65532:65532:600")
        self.check("gateway has no Kubernetes service-account token", self.run(["docker", "exec", node, "test", "!", "-e",
            prefix + "/root/var/run/secrets/kubernetes.io/serviceaccount/token"], check=False).returncode == 0)
        mounts = self.run(["docker", "exec", node, "cat", prefix + "/mountinfo"]).stdout
        self.check("gateway root and credential mounts are read-only", all(any(
            line.split()[4] == path and "ro" in line.split()[5].split(",") for line in mounts.splitlines())
            for path in ("/", "/etc/agentvisor-ai/signing.seed", "/etc/agentvisor-ai/identity.hmac")))
        anonymous = self.chat(None)
        self.check("anonymous chat is refused", anonymous[0] == 401)
        self.check("valid identity without chat scope is refused", self.chat(self.token(scopes=["unrelated"]))[0] == 403)
        token = self.token()
        session = self.name + "-signed"
        code, body = self.chat(token, session)
        self.check("authenticated SSE reaches the mock with only configured provider credentials", code == 200
                   and b"hello from Kubernetes staging" in body and b'"finish_reason": "stop"' in body
                   and body.rstrip().endswith(b"data: [DONE]") and b'"error"' not in body and b"event: error" not in body)
        code, body = self.http("/v1/mcp", {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "db_write", "arguments": {"table": "fixture", "row": {}}}}, token,
            {"x-av-session": self.name + "-tool"})
        self.check("authenticated tool routing uses the configured backend credential", code == 200 and b"tool staging success" in body)
        self.check("signed session closes successfully", self.http("/v1/sessions/" + session + "/close", {}, token)[0] == 200)
        code, receipt = self.http("/v1/sessions/" + session + "/promote", {}, token)
        self.check("session produces a signed receipt", code == 200 and "receipt_id" in json.loads(receipt))
        pubkey = json.loads(self.gateway_exec("avctl", "pubkey", "--seed", "/etc/agentvisor-ai/signing.seed"))["public_key_hex"]
        receipt_file = self.work / "receipt.json"
        receipt_file.write_bytes(receipt)
        verifier = os.environ.get("AVCTL", str(ROOT / "target/release/avctl"))
        self.provenance["local_avctl"] = {"path": str(Path(verifier).resolve()),
                                           "sha256": hashlib.sha256(Path(verifier).read_bytes()).hexdigest(),
                                           "version": self.run([verifier, "--version"]).stdout.strip()}
        self.run([verifier, "receipt-verify", str(receipt_file), "--public-key-hex", pubkey])
        modified = json.loads(receipt)
        modified["cost"]["prompt_tokens"] = 999999
        tampered = self.work / "tampered-receipt.json"
        tampered.write_text(json.dumps(modified))
        self.check("receipt verifies against the retained key and tampering is refused", self.run(
            [verifier, "receipt-verify", str(tampered), "--public-key-hex", pubkey], check=False).returncode != 0)
        revoked = self.token(subject=self.name + "-revoked")
        self.check("holder token revocation succeeds", self.http("/v1/revoke", form={"token": revoked})[0] == 200)
        self.check("revoked token is refused", self.chat(revoked)[0] == 401)
        self.recreate_gateway()
        self.check("pod recreation retains signing identity", json.loads(self.gateway_exec("avctl", "pubkey", "--seed",
                   "/etc/agentvisor-ai/signing.seed"))["public_key_hex"] == pubkey)
        self.check("pod recreation retains shared revocation", self.chat(revoked)[0] == 401)
        events = []
        for partition in range(8):
            output = self.gateway_exec("avctl", "event-tail", "--data-dir", "/app/data/bridge", "--topic", "agent.receipt",
                "--partition", str(partition), "--offset", "0", "--max", "100")
            events.extend(json.loads(line) for line in output.splitlines() if line.strip())
        matches = [event for event in events if event.get("value", {}).get("payload", {}).get("receipt_id") == json.loads(receipt)["receipt_id"]]
        self.check("persistent bridge retains exactly one unchanged receipt after pod recreation", len(matches) == 1
                   and matches[0]["value"]["payload"]["receipt"] == json.loads(receipt))
        unknown = self.token(subject=self.name + "-unknown")
        self.kube("scale", "deployment/redis", "--replicas=0")
        self.until(lambda: not json.loads(self.kube("get", "pods", "-l", "app=redis", "-o", "json").stdout)["items"], "Redis outage")
        # The availability indicator opens after three dependency failures;
        # each individual lookup must already fail closed before that point.
        self.check("unknown token fails closed throughout the Redis circuit transition",
                   all(self.chat(unknown)[0] == 503 for _ in range(3)))
        self.check("known revoked token stays refused during outage", self.chat(revoked)[0] == 401)
        ready_status, ready = self.http("/readyz")
        self.check("dependency outage is reported without a liveness restart", ready_status == 200
                   and json.loads(ready)["checks"]["revocation_available"] is False and self.http("/livez")[0] == 200)
        self.kube("scale", "deployment/redis", "--replicas=1")
        self.wait_deployment("redis")
        self.until(lambda: self.chat(unknown)[0] == 200, "Redis recovery")
        self.check("authenticated traffic recovers after Redis pod recreation")
        self.check("Redis persistent volume preserves revocation", self.chat(revoked)[0] == 401)
        self.backup_restore(revoked, pubkey)

    def backup_restore(self, revoked, pubkey):
        redis_pod = self.pod("redis")["metadata"]["name"]
        self.kube("exec", redis_pod, "--", *self.redis_cli(), "SAVE")
        backup = self.kube("exec", redis_pod, "--", "cat", "/data/dump.rdb", binary=True).stdout
        self.check("Redis produces a nonempty RDB snapshot", backup.startswith(b"REDIS") and len(backup) > 20)
        backup_file = self.private / "redis-backup.rdb"
        backup_file.write_bytes(backup)
        backup_file.chmod(0o600)
        self.provenance["redis_backup_sha256"] = hashlib.sha256(backup).hexdigest()
        self.apply([self.pvc("redis-restored-data"), {"apiVersion": "v1", "kind": "Pod", "metadata": self.metadata("restore-copy"),
            "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                "securityContext": {"runAsUser": 999, "runAsNonRoot": True, "fsGroup": 999},
                "containers": [{"name": "copy", "image": self.redis_tag, "imagePullPolicy": "Never",
                    "command": ["sh", "-ec", "sleep 600"], "volumeMounts": [{"name": "data", "mountPath": "/data"}]}],
                "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": "redis-restored-data"}}]}}])
        self.kube("wait", "--for=condition=Ready", "pod/restore-copy", "--timeout=120s", timeout=130)
        self.kube("exec", "-i", "restore-copy", "--", "sh", "-ec", "cat > /data/dump.rdb", data=backup, binary=True)
        self.kube("delete", "pod", "restore-copy", "--grace-period=1", "--timeout=30s")
        # Redis prefers AOF when enabled. Bootstrap the RDB with AOF disabled,
        # then generate its AOF before returning to the normal durable config.
        self.apply([self.redis_deployment("redis-restored", "redis-restored-data", load_rdb=True),
                    self.service("redis-restored", 6379)])
        self.wait_deployment("redis-restored")
        restored_pod = self.pod("redis-restored")["metadata"]["name"]
        self.check("restored Redis loads nonempty snapshot state", int(self.kube("exec", restored_pod, "--",
                   *self.redis_cli(), "DBSIZE").stdout.strip()) > 0)
        enabled = self.kube("exec", restored_pod, "--", *self.redis_cli(), "CONFIG", "SET", "appendonly", "yes")
        self.check("restored Redis enables AOF persistence", enabled.stdout.strip() == "OK")
        def aof_ready():
            info = self.kube("exec", restored_pod, "--", *self.redis_cli(), "INFO", "persistence").stdout
            fields = dict(line.split(":", 1) for line in info.splitlines() if ":" in line)
            return (fields.get("aof_enabled") == "1" and fields.get("aof_rewrite_in_progress") == "0"
                    and fields.get("aof_rewrite_scheduled") == "0" and fields.get("aof_last_bgrewrite_status") == "ok"
                    and fields.get("aof_last_write_status") == "ok" and int(fields.get("aof_current_size", "0")) > 0)
        self.until(aof_ready, "restored Redis AOF generation")
        self.apply([self.redis_deployment("redis-restored", "redis-restored-data")])
        self.wait_deployment("redis-restored")
        self.check("restored Redis restarts with normal AOF configuration",
                   self.pod("redis-restored")["metadata"]["name"] != restored_pod)
        self.apply([self.secret("agentvisor-ai-state", {"redis-url": self.redis_url("redis-restored")})])
        self.recreate_gateway()
        claims_part = revoked.split(".")[1]
        revoked_claims = json.loads(base64.urlsafe_b64decode(claims_part + "=" * (-len(claims_part) % 4)))
        if revoked_claims["exp"] <= int(time.time()) + 30:
            raise AssertionError("Fixture token expired before restored revocation could be tested")
        self.check("restored Redis backup enforces revocation in a fresh gateway process", self.chat(revoked)[0] == 401)
        self.check("fresh token works against restored Redis", self.chat(self.token(subject=self.name + "-restored"))[0] == 200)
        self.check("Redis restore preserves the signing identity", json.loads(self.gateway_exec("avctl", "pubkey", "--seed",
                   "/etc/agentvisor-ai/signing.seed"))["public_key_hex"] == pubkey)
        self.provenance["limitations"] = ["One local kind node and local-path volumes; no multi-host failover or production CSI validation.",
            "No public ingress, external identity provider, real model provider, or remote Kubernetes deployment."]
        self.provenance["redis_transport"] = "plaintext" if self.plaintext_redis else "TLS with private CA and password authentication"
        if self.plaintext_redis:
            self.provenance["limitations"].append("Redis TLS was explicitly disabled for this run.")

    def cleanup(self):
        if self.forward:
            self.forward.terminate()
            try:
                self.forward.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.forward.kill()
                self.forward.wait(timeout=10)
        try:
            if self.kubeconfig.exists():
                # An unavailable API must not prevent cleanup of our own node.
                for args in [("get", "pods,pvc,events", "-o", "wide"),
                             ("logs", "deployment/agentvisor-ai", "--all-containers=true", "--tail=200")]:
                    try:
                        self.kube(*args, check=False, timeout=20)
                    except subprocess.TimeoutExpired:
                        self.provenance.setdefault("diagnostic_timeouts", []).append(args[0])
            if self.cluster_requested:
                node = self.run(["docker", "inspect", self.name + "-control-plane"], check=False)
                if node.returncode == 0:
                    if not owned_node(json.loads(node.stdout)[0], self.name):
                        raise RuntimeError("Refusing to clean an unowned kind node")
                    self.run(["kind", "delete", "cluster", "--name", self.name, "--kubeconfig", str(self.kubeconfig)], timeout=180)
            if self.network_created:
                network = json.loads(self.run(["docker", "network", "inspect", self.name]).stdout)[0]
                if network.get("Labels", {}).get(OWNER) != self.name:
                    raise RuntimeError("Refusing to remove an unowned network")
                self.run(["docker", "network", "rm", self.name])
            for tag, image_id in self.tagged.items():
                current = self.run(["docker", "image", "inspect", tag, "--format", "{{.Id}}"], check=False)
                if current.returncode == 0 and current.stdout.strip() == image_id and tag.startswith(self.name + "-"):
                    self.run(["docker", "image", "rm", tag], check=False)
            self.provenance["cleanup"] = "completed"
        except BaseException as error:
            self.provenance["cleanup"] = "failed"
            self.provenance["cleanup_error"] = self.scrub(str(error))
            if self.provenance.get("status") == "passed":
                self.provenance["status"] = "cleanup_failed"
            raise
        finally:
            shutil.rmtree(self.private, ignore_errors=True)
            self.save()


class UnitTests(unittest.TestCase):
    def test_production_template_requires_identity_and_scopes(self):
        resources = json.loads(subprocess.check_output(["ruby", "-ryaml", "-rjson", "-e",
            "puts JSON.generate(YAML.load_stream(File.read(ARGV[0])))",
            str(ROOT / "deploy/kubernetes/agentvisor-ai.yaml")], text=True))
        config = next(item for item in resources if item and item["kind"] == "ConfigMap")["data"]["agentvisor.toml"]
        self.assertIn("require_identity = true", config.splitlines())
        self.assertIn("enforce_identity_scopes = true", config.splitlines())
        cloudfoundry = (ROOT / "deploy/cloudfoundry/harness.toml").read_text().splitlines()
        self.assertIn("require_identity = true", cloudfoundry)
        self.assertIn("enforce_identity_scopes = true", cloudfoundry)

    def test_cleanup_checks_both_name_and_kind_label(self):
        node = {"Name": "/av-k8s-fixture-control-plane", "Config": {"Labels": {"io.x-k8s.kind.cluster": "av-k8s-fixture"}}}
        self.assertTrue(owned_node(node, "av-k8s-fixture"))
        self.assertFalse(owned_node(node, "someone-else"))
        altered = copy.deepcopy(node)
        altered["Config"]["Labels"] = {}
        self.assertFalse(owned_node(altered, "av-k8s-fixture"))

    def test_fixture_token_signature_and_scope(self):
        token = mint("fixture-secret", "fixture-subject", ["chat:complete"])
        header, payload, signature = token.split(".")
        self.assertEqual(signature, b64(hmac.new(b"fixture-secret", (header + "." + payload).encode(), hashlib.sha256).digest()))
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        self.assertEqual(claims["scopes"], ["chat:complete"])
        self.assertEqual(claims["iss"], ISSUER)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="agentvisor-ai:local")
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--plaintext-redis", action="store_true", help="Explicitly skip Redis TLS; record the reduced scope")
    args = parser.parse_args()
    if args.self_test:
        unittest.main(argv=[__file__])
        return
    for tool in ("kind", "kubectl", "docker", "ruby", "openssl"):
        if not shutil.which(tool):
            raise SystemExit("Required tool is missing: " + tool)
    work = args.work_dir or Path(tempfile.mkdtemp(prefix="av-kubernetes-runtime-"))
    work.mkdir(parents=True, exist_ok=True)
    work.chmod(0o700)
    print("Kubernetes staging logs: " + str(work), flush=True)
    drill = Drill(args.image, work, args.plaintext_redis)
    try:
        drill.setup()
        drill.validate()
        drill.provenance["status"] = "passed"
    except BaseException as error:
        drill.provenance["status"] = "failed"
        drill.provenance["error"] = drill.scrub(str(error))
        raise
    finally:
        drill.cleanup()
    print("PASS: %s Kubernetes staging checks; task-owned cluster and credentials removed" % len(drill.passed), flush=True)


if __name__ == "__main__":
    main()
