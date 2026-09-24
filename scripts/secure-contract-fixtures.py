#!/usr/bin/env python3
"""Isolated TLS/auth NATS and authenticated Redis Cluster contract fixtures.

Run `python3 scripts/secure-contract-fixtures.py start`, then source the printed
owner-only environment file in the shell running the Rust live contracts:

    cargo test -p av-bridge --all-features --test live_contract nats_contract
    cargo test -p av-state --features redis --test redis_contract
    cargo test -p av-harness --all-features --test revocation_redis

Run `add-kafka DIRECTORY` to add a pinned Kafka TLS/SCRAM broker to the same
environment. Then run `cargo test -p av-bridge --all-features --test live_contract
kafka_contract`. Run `check DIRECTORY` to repeat transport/topology checks, and `stop DIRECTORY`
to remove only this fixture's labelled containers and generated files. No Cargo
command is executed by this script. The six Redis processes intentionally share
one container network namespace: announced loopback ports work both between the
nodes and for host-side clients on Linux and Docker Desktop/Colima. This proves
real cluster routing and replication, not independent-host failure tolerance.
"""

from __future__ import annotations

import argparse
import binascii
import json
import os
from pathlib import Path
import secrets
import shlex
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import traceback

# Immutable NATS 2.15.0, Redis 8.2.1, and Redpanda 26.2.2 image digests.
# An absent image is pulled by digest; existing services are never used.
NATS_IMAGE = "nats:2.15.0-alpine@sha256:ac8f88a6494bffc2c2a5289a0ca61cb28a9145c11ba5677cf24265d07f46d8d4"
REDIS_IMAGE = "redis@sha256:987c376c727652f99625c7d205a1cba3cb2c53b92b0b62aade2bd48ee1593232"
KAFKA_IMAGE = "docker.redpanda.com/redpandadata/redpanda:v26.2.2@sha256:468bd13a9f2bd24794cb7fddc867c767fb1008b9a07b297b89fde48c564d7d96"
LABEL = "org.agentvisor.contract-fixture"
PREFIX = "av-contract-fixtures-"


class FixtureError(RuntimeError):
    pass


class RedisError(FixtureError):
    pass


def run(directory: Path, args: list[str], *, timeout: int = 45) -> str:
    """Keep provisioning diagnostics in an owner-only file, never echo secrets."""
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            timeout=timeout, check=False)
    with (directory / "provision.log").open("ab") as log:
        log.write(result.stdout)
    if result.returncode:
        raise FixtureError(f"{args[0]} failed; diagnostics are in {directory / 'provision.log'}")
    return result.stdout.decode(errors="replace").strip()


def private_write(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(0o600)


def save(directory: Path, state: dict) -> None:
    private_write(directory / "state.json", json.dumps(state, indent=2) + "\n")


def load(directory: Path) -> dict:
    if not directory.name.startswith(PREFIX) or directory.is_symlink():
        raise FixtureError("Refusing a directory without the fixture prefix or a symbolic link")
    state = json.loads((directory / "state.json").read_text())
    if state.get("directory") != str(directory.resolve()) or not state.get("fixture_id"):
        raise FixtureError("Fixture ownership marker does not match this directory")
    return state


def stop(directory: Path) -> None:
    state = load(directory)
    # A changed or mistyped state file cannot remove an unrelated container.
    for container in state["containers"]:
        result = subprocess.run(["docker", "inspect", "--format",
                                 '{{index .Config.Labels "' + LABEL + '"}}', container],
                                capture_output=True, text=True, timeout=30)
        if result.returncode:
            # Missing containers are harmless; a daemon failure is not proof
            # of absence and must preserve the marker for a cleanup retry.
            if "no such object" in result.stderr.lower() or "no such container" in result.stderr.lower():
                continue
            raise FixtureError("Docker inspect failed; retained fixture files for cleanup retry")
        if result.stdout.strip() != state["fixture_id"]:
            raise FixtureError("Container ownership label mismatch; refusing cleanup")
        run(directory, ["docker", "rm", "-f", "-v", container])
    shutil.rmtree(directory)


def allocate_ports(count: int) -> list[int]:
    listeners = []
    try:
        # Keep all reservations open until the complete set is known. Docker
        # still arbitrates the short bind race and startup fails safely.
        for _ in range(count):
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listeners.append(listener)
        return [listener.getsockname()[1] for listener in listeners]
    finally:
        for listener in listeners:
            listener.close()


def resp_read(stream):
    line = stream.readline(1024 * 1024)
    if not line.endswith(b"\r\n"):
        raise FixtureError("Truncated Redis protocol response")
    kind, body = line[:1], line[1:-2]
    if kind == b"+":
        return body.decode()
    if kind == b"-":
        raise RedisError(body.decode())
    if kind == b":":
        return int(body)
    if kind == b"$":
        size = int(body)
        if size == -1:
            return None
        if not 0 <= size <= 1024 * 1024:
            raise FixtureError("Unbounded Redis bulk response")
        value = stream.read(size + 2)
        if len(value) != size + 2 or not value.endswith(b"\r\n"):
            raise FixtureError("Truncated Redis bulk response")
        return value[:-2].decode()
    if kind == b"*":
        count = int(body)
        if not 0 <= count <= 20000:
            raise FixtureError("Unbounded Redis array response")
        return [resp_read(stream) for _ in range(count)]
    raise FixtureError("Unexpected Redis protocol response")


def redis(port: int, password: str | None, *args):
    def send(connection, words):
        encoded = [str(word).encode() for word in words]
        connection.sendall(b"*%d\r\n" % len(encoded) + b"".join(
            b"$%d\r\n" % len(word) + word + b"\r\n" for word in encoded))

    with socket.create_connection(("127.0.0.1", port), timeout=3) as connection:
        with connection.makefile("rb") as stream:
            if password is not None:
                send(connection, ["AUTH", password])
                resp_read(stream)
            send(connection, args)
            return resp_read(stream)


def redis_routed(ports: list[int], password: str, *args):
    port = ports[0]
    for _ in range(8):
        try:
            return redis(port, password, *args)
        except RedisError as error:
            words = str(error).split()
            if len(words) != 3 or words[0] != "MOVED":
                raise
            host, port_text = words[2].rsplit(":", 1)
            port = int(port_text)
            if host != "127.0.0.1" or port not in ports:
                raise FixtureError("Redis redirected outside the isolated fixture") from error
    raise FixtureError("Redis routing did not converge")


class Nats:
    def __init__(self, port: int, ca: Path | None, user: str | None,
                 password: str | None, *, hostname: str = "localhost"):
        self.connection = socket.create_connection(("127.0.0.1", port), timeout=3)
        try:
            # Standard NATS sends INFO before negotiating TLS. Read only that
            # line so no buffered bytes are lost when wrapping the socket.
            info = b""
            while not info.endswith(b"\r\n") and len(info) < 65536:
                byte = self.connection.recv(1)
                if not byte:
                    raise FixtureError("NATS closed before INFO")
                info += byte
            if not info.startswith(b"INFO ") or not json.loads(info[5:]).get("tls_required"):
                raise FixtureError("NATS did not require TLS")
            context = ssl.create_default_context(cafile=str(ca) if ca else None)
            self.connection = context.wrap_socket(self.connection, server_hostname=hostname)
            self.stream = self.connection.makefile("rb")
            connect = {"verbose": False, "pedantic": True, "tls_required": True}
            if user is not None:
                connect.update(user=user, **{"pass": password})
            self.connection.sendall(b"CONNECT " + json.dumps(connect).encode() + b"\r\nPING\r\n")
            self.until_pong()
        except BaseException:
            self.connection.close()
            raise

    def line(self) -> bytes:
        line = self.stream.readline(65536)
        if not line or not line.endswith(b"\r\n"):
            raise FixtureError("NATS protocol ended unexpectedly")
        if line.startswith(b"-ERR"):
            raise FixtureError("NATS rejected the connection or request")
        if line == b"PING\r\n":
            self.connection.sendall(b"PONG\r\n")
            return self.line()
        return line

    def until_pong(self) -> None:
        for _ in range(20):
            if self.line() == b"PONG\r\n":
                return
        raise FixtureError("NATS did not acknowledge the connection")

    def request(self, subject: str, value: dict) -> dict:
        inbox = "_INBOX." + secrets.token_hex(12)
        payload = json.dumps(value).encode()
        self.connection.sendall(f"SUB {inbox} 1\r\nUNSUB 1 1\r\nPUB {subject} {inbox} {len(payload)}\r\n".encode()
                                + payload + b"\r\n")
        for _ in range(20):
            line = self.line()
            if line.startswith(b"MSG "):
                size = int(line.split()[-1])
                if not 0 <= size <= 1024 * 1024:
                    raise FixtureError("Unbounded NATS message")
                payload = self.stream.read(size + 2)
                if len(payload) != size + 2 or not payload.endswith(b"\r\n"):
                    raise FixtureError("Truncated NATS message")
                response = json.loads(payload[:-2])
                if "error" in response:
                    raise FixtureError("JetStream rejected the fixture request")
                return response
        raise FixtureError("NATS did not answer request")

    def close(self) -> None:
        self.stream.close()
        self.connection.close()


def check(directory: Path) -> None:
    state = load(directory)
    credentials = json.loads((directory / "credentials.json").read_text())
    ca = directory / "nats" / "ca.crt"
    nats = Nats(state["nats_port"], ca, credentials["nats_user"], credentials["nats_password"])
    try:
        assert "memory" in nats.request("$JS.API.INFO", {})
        stream = "FIXTURE_" + secrets.token_hex(6).upper()
        subject = "fixture." + secrets.token_hex(6)
        nats.request("$JS.API.STREAM.CREATE." + stream,
                     {"name": stream, "subjects": [subject], "storage": "memory", "num_replicas": 1})
        ack = nats.request(subject, {"fixture": True})
        assert ack["stream"] == stream and ack["seq"] == 1
        assert nats.request("$JS.API.STREAM.DELETE." + stream, {})["success"]
    finally:
        nats.close()
    for ca_file, user, password, hostname in [
        (ca, None, None, "localhost"),
        (ca, credentials["nats_user"], "incorrect-fixture-password", "localhost"),
        (None, credentials["nats_user"], credentials["nats_password"], "localhost"),
        (ca, credentials["nats_user"], credentials["nats_password"], "wrong-name.invalid"),
    ]:
        try:
            rejected = Nats(state["nats_port"], ca_file, user, password, hostname=hostname)
        except (FixtureError, ssl.SSLError, OSError):
            pass
        else:
            rejected.close()
            raise FixtureError("NATS accepted an invalid trust/authentication case")
    password = credentials["redis_password"]
    ports = state["redis_ports"]
    for port in ports:
        info = redis(port, password, "CLUSTER", "INFO")
        assert "cluster_state:ok" in info and "cluster_slots_assigned:16384" in info
        try:
            redis(port, None, "PING")
        except RedisError as error:
            assert "NOAUTH" in str(error)
        else:
            raise FixtureError("Redis allowed an unauthenticated command")
    slots = redis(ports[0], password, "CLUSTER", "SLOTS")
    masters = {entry[2][2] for entry in slots}
    assert len(masters) == 3 and all(len(entry) >= 4 for entry in slots)
    assert all(node[0] == "127.0.0.1" and node[1] in ports for entry in slots for node in entry[2:])
    tag = secrets.token_hex(10)
    first, second = f"fixture:{{{tag}}}:a", f"fixture:{{{tag}}}:b"
    assert redis_routed(ports, password, "EVAL", "return {redis.call('INCRBY',KEYS[1],7),redis.call('INCRBY',KEYS[2],1)}", 2, first, second) == [7, 1]
    assert redis_routed(ports, password, "MGET", first, second) == ["7", "1"]
    other = "fixture:{" + tag + "other}:c"
    other_tag = tag + "other"
    while binascii.crc_hqx(tag.encode(), 0) % 16384 == binascii.crc_hqx(other_tag.encode(), 0) % 16384:
        other_tag += "x"
    other = "fixture:{" + other_tag + "}:c"
    try:
        redis_routed(ports, password, "EVAL", "return 1", 2, first, other)
    except RedisError as error:
        assert "CROSSSLOT" in str(error)
    else:
        raise FixtureError("Redis failed to enforce cross-slot isolation")
    assert redis_routed(ports, password, "DEL", first, second) == 2
    print("Verified NATS TLS, certificate name/trust, auth rejection, JetStream acknowledgement; Redis auth, six-node topology, slot routing and transaction isolation.")
    if state.get("kafka_container"):
        check_kafka(directory, state)


def start(parent: Path | None) -> Path:
    directory = Path(tempfile.mkdtemp(prefix=PREFIX, dir=parent)).resolve()
    directory.chmod(0o700)
    state = {"fixture_id": secrets.token_hex(12), "directory": str(directory), "containers": [],
             "images": {"nats": NATS_IMAGE, "redis": REDIS_IMAGE}}
    save(directory, state)
    try:
        for executable in ["docker", "openssl"]:
            if shutil.which(executable) is None:
                raise FixtureError(f"Required executable is missing: {executable}")
        for image in [NATS_IMAGE, REDIS_IMAGE]:
            result = subprocess.run(["docker", "image", "inspect", image], capture_output=True, timeout=30)
            if result.returncode:
                run(directory, ["docker", "pull", image], timeout=180)
        credentials = {"nats_user": "contract", "nats_password": secrets.token_hex(32),
                       "redis_password": secrets.token_hex(32)}
        private_write(directory / "credentials.json", json.dumps(credentials))
        nats_dir, redis_dir = directory / "nats", directory / "redis"
        nats_dir.mkdir(mode=0o700)
        redis_dir.mkdir(mode=0o700)
        run(directory, ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "2",
                        "-subj", "/CN=AgentVisor isolated contract CA",
                        "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", str(nats_dir / "ca.key"), "-out", str(nats_dir / "ca.crt")])
        run(directory, ["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256", "-subj", "/CN=localhost",
                        "-keyout", str(nats_dir / "server.key"), "-out", str(nats_dir / "server.csr")])
        private_write(nats_dir / "extensions.cnf", "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment\nbasicConstraints=critical,CA:FALSE\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
        run(directory, ["openssl", "x509", "-req", "-in", str(nats_dir / "server.csr"), "-CA", str(nats_dir / "ca.crt"),
                        "-CAkey", str(nats_dir / "ca.key"), "-CAcreateserial", "-out", str(nats_dir / "server.crt"),
                        "-days", "2", "-sha256", "-extfile", str(nats_dir / "extensions.cnf")])
        for path in nats_dir.iterdir():
            path.chmod(0o600)
        private_write(nats_dir / "nats.conf", f'''port: 4222
jetstream {{ store_dir: "/tmp/jetstream", max_memory_store: 64MB, max_file_store: 128MB }}
authorization {{ user: "{credentials['nats_user']}", password: "{credentials['nats_password']}" }}
tls {{ cert_file: "/fixture/server.crt", key_file: "/fixture/server.key", ca_file: "/fixture/ca.crt", timeout: 3 }}
''')
        nats_port, *redis_ports = allocate_ports(7)
        state.update(nats_port=nats_port, redis_ports=redis_ports)
        for index, port in enumerate(redis_ports):
            private_write(redis_dir / f"node-{index}.conf", f'''port {port}
bind 0.0.0.0
protected-mode yes
requirepass {credentials['redis_password']}
masterauth {credentials['redis_password']}
cluster-enabled yes
cluster-config-file /tmp/node-{index}/nodes.conf
cluster-node-timeout 3000
cluster-announce-ip 127.0.0.1
cluster-announce-port {port}
cluster-port {20000 + index}
cluster-announce-bus-port {20000 + index}
dir /tmp/node-{index}
appendonly no
save ""
maxmemory 96mb
maxmemory-policy noeviction
''')
        private_write(redis_dir / "password", credentials["redis_password"])
        private_write(redis_dir / "start.sh", "#!/bin/sh\nset -eu\n" + "\n".join(
            f"mkdir -p /tmp/node-{i}\nredis-server /fixture/node-{i}.conf &" for i in range(6)) + "\nwait\n")
        for role, image, config_dir, ports, command in [
            ("nats", NATS_IMAGE, nats_dir, [(nats_port, 4222)], ["nats-server", "-c", "/fixture/nats.conf"]),
            ("redis", REDIS_IMAGE, redis_dir, [(port, port) for port in redis_ports], ["sh", "/fixture/start.sh"]),
        ]:
            name = f"av-contract-{state['fixture_id']}-{role}"
            args = ["docker", "create", "--name", name, "--label", f"{LABEL}={state['fixture_id']}",
                    "--memory", "768m" if role == "redis" else "192m", "--cpus", "1", "--pids-limit", "128"]
            for host_port, container_port in ports:
                args += ["-p", f"127.0.0.1:{host_port}:{container_port}"]
            # Record the unique name before the Docker mutation so an
            # interrupted create remains addressable by cleanup.
            container = name
            state["containers"].append(container)
            save(directory, state)
            run(directory, args + [image] + command)
            run(directory, ["docker", "cp", str(config_dir), f"{container}:/fixture"])
            run(directory, ["docker", "start", container])
        deadline = time.monotonic() + 30
        while True:
            try:
                if all(redis(port, credentials["redis_password"], "PING") == "PONG" for port in redis_ports):
                    break
            except (OSError, FixtureError):
                if time.monotonic() >= deadline:
                    raise FixtureError("Redis nodes did not become ready")
            time.sleep(0.2)
        addresses = " ".join(f"127.0.0.1:{port}" for port in redis_ports)
        run(directory, ["docker", "exec", state["containers"][1], "sh", "-c",
                        'export REDISCLI_AUTH="$(cat /fixture/password)"; exec redis-cli --cluster create '
                        + addresses + " --cluster-replicas 1 --cluster-yes"], timeout=45)
        deadline = time.monotonic() + 45
        while not all("cluster_state:ok" in redis(port, credentials["redis_password"], "CLUSTER", "INFO") for port in redis_ports):
            if time.monotonic() >= deadline:
                raise FixtureError("Redis cluster did not become healthy")
            time.sleep(0.25)
        # Slot coverage can become healthy before replicas finish their first
        # synchronization. Do not announce a six-node fixture until every slot
        # range advertises its replica and every replica has an active link.
        while True:
            slots = redis(redis_ports[0], credentials["redis_password"], "CLUSTER", "SLOTS")
            replica_ports = {entry[3][1] for entry in slots if len(entry) >= 4}
            if len(replica_ports) == 3 and all(
                "master_link_status:up" in redis(port, credentials["redis_password"], "INFO", "replication")
                for port in replica_ports
            ):
                break
            if time.monotonic() >= deadline:
                raise FixtureError("Redis replicas did not synchronize")
            time.sleep(0.25)
        env = {
            "AV_NATS_URL": f"tls://localhost:{nats_port}",
            "AV_NATS_CA_FILE": str(nats_dir / "ca.crt"),
            "AV_NATS_USER": credentials["nats_user"], "AV_NATS_PASSWORD": credentials["nats_password"],
            "AV_REDIS_URL": ",".join(f"redis://:{credentials['redis_password']}@127.0.0.1:{port}" for port in redis_ports),
            "AV_CONTRACT_FIXTURE_DIR": str(directory),
        }
        private_write(directory / "env.sh", "# Generated local fixture credentials. Do not commit or print.\n"
                      + "\n".join(f"export {name}={shlex.quote(value)}" for name, value in env.items()) + "\n")
        check(directory)
        return directory
    except BaseException:
        # Preserve diagnostics, not live containers or credential directories.
        # The log is private because server diagnostics can include config.
        with tempfile.NamedTemporaryFile(prefix=PREFIX + "failure-", suffix=".log", delete=False) as failure:
            if (directory / "provision.log").exists():
                failure.write((directory / "provision.log").read_bytes())
            failure.write(traceback.format_exc().encode())
        print(f"Startup diagnostics: {failure.name}", file=sys.stderr)
        try:
            stop(directory)
        except Exception:
            print(f"Cleanup requires a retry: {directory}", file=sys.stderr)
        raise



def check_kafka(directory: Path, state: dict) -> None:
    port = state["kafka_port"]
    ca = directory / "nats" / "ca.crt"
    for ca_file, hostname, accepted in [(ca, "localhost", True), (None, "localhost", False),
                                         (ca, "wrong-name.invalid", False)]:
        try:
            context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
            with socket.create_connection(("127.0.0.1", port), timeout=3) as connection:
                with context.wrap_socket(connection, server_hostname=hostname):
                    pass
        except ssl.SSLError:
            if accepted:
                raise
        else:
            if not accepted:
                raise FixtureError("Kafka accepted an invalid certificate trust/name case")
    container = state["kafka_container"]
    run(directory, ["docker", "exec", container, "rpk", "cluster", "info", "--config", "/fixture/redpanda.yaml"], timeout=20)
    for config in ["wrong-password.yaml", "no-auth.yaml"]:
        result = subprocess.run(["docker", "exec", container, "rpk", "cluster", "info", "--config", "/fixture/" + config],
                                capture_output=True, timeout=20)
        if result.returncode == 0:
            raise FixtureError("Kafka accepted missing or invalid SASL credentials")
    print("Verified Kafka TLS trust/name, SCRAM-SHA-256 authentication, metadata discovery, and missing/wrong credential rejection.")


def add_kafka(directory: Path) -> None:
    """Add an independent secured broker without restarting the other fixtures.

    Redpanda bootstrap and listener configuration follow the official references:
    https://docs.redpanda.com/25.2/reference/properties/broker-properties/
    https://docs.redpanda.com/streaming/25.3/deploy/redpanda/manual/production/production-deployment/
    """
    state = load(directory)
    if state.get("kafka_container"):
        check_kafka(directory, state)
        return
    image = subprocess.run(["docker", "image", "inspect", KAFKA_IMAGE], capture_output=True, timeout=30)
    if image.returncode:
        run(directory, ["docker", "pull", KAFKA_IMAGE], timeout=180)
    config_dir = directory / "kafka"
    config_dir.mkdir(mode=0o700)
    credentials = json.loads((directory / "credentials.json").read_text())
    user, password = "contract", secrets.token_hex(32)
    port = allocate_ports(1)[0]
    container = f"av-contract-{state['fixture_id']}-kafka"
    for filename in ["server.crt", "server.key", "ca.crt"]:
        shutil.copyfile(directory / "nats" / filename, config_dir / filename)
        (config_dir / filename).chmod(0o600)
    # The CA signs only local two-day fixture certificates. Admin RPC remains
    # container-loopback-only and is never published to the host.
    config = f"""redpanda:
  data_directory: /tmp/redpanda-data
  seed_servers: []
  developer_mode: true
  rpc_server:
    address: 127.0.0.1
    port: 33145
  kafka_api:
    - name: secured
      address: 0.0.0.0
      port: {port}
  advertised_kafka_api:
    - name: secured
      address: localhost
      port: {port}
  kafka_api_tls:
    - name: secured
      enabled: true
      require_client_auth: false
      cert_file: /fixture/server.crt
      key_file: /fixture/server.key
      truststore_file: /fixture/ca.crt
  admin:
    - address: 127.0.0.1
      port: 9644
rpk:
  kafka_api:
    brokers: [localhost:{port}]
    tls:
      enabled: true
      truststore_file: /fixture/ca.crt
    sasl:
      user: {user}
      password: {password}
      mechanism: SCRAM-SHA-256
"""
    private_write(config_dir / "redpanda.yaml", config)
    private_write(config_dir / "wrong-password.yaml", config.replace(password, "incorrect-fixture-password"))
    private_write(config_dir / "no-auth.yaml", config.split("    sasl:\n")[0])
    private_write(config_dir / ".bootstrap.yaml", f"enable_sasl: true\nsuperusers: [{user}]\nenable_metrics_reporter: false\n")
    private_write(config_dir / "bootstrap-user", f"{user}:{password}:SCRAM-SHA-256")
    private_write(config_dir / "start.sh", '#!/bin/sh\nset -eu\nexport RP_BOOTSTRAP_USER="$(cat /fixture/bootstrap-user)"\n'
                  'exec /entrypoint.sh redpanda start --config /fixture/redpanda.yaml --check=false --overprovisioned --smp=1 --memory=768M --reserve-memory=0M\n')
    state["containers"].append(container)
    save(directory, state)
    try:
        run(directory, ["docker", "create", "--name", container, "--label", f"{LABEL}={state['fixture_id']}",
                        "--user", "0:0", "--memory", "1g", "--cpus", "1", "--pids-limit", "256", "--entrypoint", "/bin/sh",
                        "-p", f"127.0.0.1:{port}:{port}", KAFKA_IMAGE, "/fixture/start.sh"])
        run(directory, ["docker", "cp", str(config_dir), f"{container}:/fixture"])
        run(directory, ["docker", "start", container])
        deadline = time.monotonic() + 60
        while True:
            result = subprocess.run(["docker", "exec", container, "rpk", "cluster", "info", "--config", "/fixture/redpanda.yaml"],
                                    capture_output=True, timeout=15)
            if result.returncode == 0:
                break
            if time.monotonic() >= deadline:
                run(directory, ["docker", "logs", container])
                raise FixtureError(f"Kafka did not become ready; inspect {directory / 'provision.log'}")
            time.sleep(0.5)
        state.update(kafka_container=container, kafka_port=port)
        state.setdefault("images", {})["kafka"] = KAFKA_IMAGE
        check_kafka(directory, state)
        credentials.update(kafka_user=user, kafka_password=password)
        private_write(directory / "credentials.json", json.dumps(credentials))
        save(directory, state)
        env = {
            "AV_KAFKA_BROKER": f"localhost:{port}", "AV_KAFKA_CA_FILE": str(directory / "nats" / "ca.crt"),
            "AV_KAFKA_SASL_USERNAME": user, "AV_KAFKA_SASL_PASSWORD": password,
            "AV_KAFKA_SASL_MECHANISM": "SCRAM-SHA-256",
        }
        existing = (directory / "env.sh").read_text()
        private_write(directory / "env.sh", existing + "\n" + "\n".join(
            f"export {name}={shlex.quote(value)}" for name, value in env.items()) + "\n")
    except BaseException:
        # This name is unique and was created only by this call. Never stop
        # the other ready fixtures if this optional addition fails.
        inspected = subprocess.run(["docker", "inspect", "--format", '{{index .Config.Labels "' + LABEL + '"}}', container],
                                   capture_output=True, text=True, timeout=30)
        if inspected.returncode == 0 and inspected.stdout.strip() == state["fixture_id"]:
            run(directory, ["docker", "rm", "-f", "-v", container])
            state["containers"].remove(container)
        state.pop("kafka_container", None)
        state.pop("kafka_port", None)
        save(directory, state)
        shutil.rmtree(config_dir)
        raise

def main() -> int:
    os.umask(0o077)
    if not __debug__:
        raise SystemExit("Run without Python optimization: fixture assertions must execute")
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("start", help="Create fixtures and print the private environment path")
    create.add_argument("--parent-dir", type=Path)
    for command in ["check", "stop", "add-kafka"]:
        action = sub.add_parser(command)
        action.add_argument("directory", type=Path)
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    try:
        if args.command == "start":
            directory = start(args.parent_dir)
            print(f"Environment: {directory / 'env.sh'}")
            print(f"Cleanup: python3 scripts/secure-contract-fixtures.py stop {shlex.quote(str(directory))}")
        elif args.command == "check":
            check(args.directory.resolve())
        elif args.command == "add-kafka":
            add_kafka(args.directory.resolve())
            print(f"Updated environment: {args.directory.resolve() / 'env.sh'}")
        else:
            stop(args.directory.resolve())
            print("Removed only the requested fixture's containers and generated files.")
    except (FixtureError, OSError, ValueError, AssertionError, subprocess.TimeoutExpired) as error:
        # Do not render command arguments or connection URLs: both can hold secrets.
        if isinstance(error, ssl.SSLCertVerificationError):
            print(f"TLS certificate verification failed: {error.verify_message}", file=sys.stderr)
        elif isinstance(error, FixtureError):
            print(str(error), file=sys.stderr)
        else:
            print(f"Fixture operation failed ({type(error).__name__}); inspect its private diagnostics.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
