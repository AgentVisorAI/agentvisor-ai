#!/usr/bin/env python3
"""Isolated, authenticated Redis Cluster with verified TLS on every connection.

Usage (the Docker endpoint is explicit; normal credentials/config are retained):
  python3 scripts/redis-cluster-tls-test.py start --docker-host unix:///PATH/docker.sock
  python3 scripts/redis-cluster-tls-test.py check PRIVATE_DIRECTORY
  python3 scripts/redis-cluster-tls-test.py test PRIVATE_DIRECTORY \
    --state-bin PATH/redis_contract --tls-bin PATH/redis_tls --revocation-bin PATH/revocation_redis
  python3 scripts/redis-cluster-tls-test.py stop PRIVATE_DIRECTORY --output-dir RESULTS

No Cargo command runs here. Compile the three named test executables separately
with Redis enabled. Start prints only the private directory, never credentials.
Its env.sh can also configure direct Rust contract execution. Six Redis processes
(three primaries and three replicas) share one container network namespace so
announced loopback ports are reachable both internally and through Docker on
Linux/macOS. This proves TLS, routing and replication, not multi-host failover.
"""
from __future__ import annotations

import argparse
import binascii
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import signal
import socket
import ssl
import subprocess
import tarfile
import tempfile
import time
import unittest

SPEC = importlib.util.spec_from_file_location(
    "secure_fixtures", Path(__file__).with_name("secure-contract-fixtures.py"))
fixtures = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixtures)
ROOT = Path(__file__).resolve().parents[1]
PREFIX = "av-redis-cluster-tls-"
LABEL = "org.agentvisor.redis-cluster-tls"
IMAGE = fixtures.REDIS_IMAGE


def require(condition, message):
    if not condition:
        raise fixtures.FixtureError(message)


def client_environment(endpoint):
    require(bool(endpoint), "Set DOCKER_HOST or pass --docker-host explicitly")
    environment = dict(os.environ, DOCKER_HOST=endpoint)
    environment.pop("DOCKER_CONTEXT", None)
    return environment


def node_config(index, port, password):
    return f'''port 0
tls-port {port}
bind 0.0.0.0
protected-mode yes
tls-cert-file /fixture/node-{index}.crt
tls-key-file /fixture/node-{index}.key
tls-ca-cert-file /fixture/ca.crt
tls-auth-clients no
tls-cluster yes
tls-replication yes
tls-protocols "TLSv1.2 TLSv1.3"
requirepass {password}
masterauth {password}
cluster-enabled yes
cluster-config-file /tmp/node-{index}/nodes.conf
cluster-node-timeout 3000
cluster-announce-ip 127.0.0.1
cluster-announce-hostname localhost
cluster-preferred-endpoint-type hostname
cluster-announce-tls-port {port}
cluster-port {16000 + index}
cluster-announce-bus-port {16000 + index}
dir /tmp/node-{index}
appendonly no
save ""
maxmemory 64mb
maxmemory-policy noeviction
'''


def owned_container(value, state):
    return (value.get("Name", "").lstrip("/") == state["container"]
            and state["container"] == PREFIX + state["fixture_id"]
            and value.get("Config", {}).get("Labels", {}).get(LABEL) == state["fixture_id"])


class Cluster:
    def __init__(self, directory, docker_host=None):
        self.directory = directory.resolve()
        require(not directory.is_symlink() and directory.name.startswith(PREFIX),
                "Refusing a directory without the fixture prefix or with a symbolic link")
        self.state = json.loads((self.directory / "state.json").read_text())
        require(self.state.get("directory") == str(self.directory)
                and re.fullmatch(r"[0-9a-f]{24}", self.state.get("fixture_id", "")),
                "Fixture ownership marker does not match")
        self.environment = client_environment(docker_host or self.state["docker_host"])
        if docker_host:
            self.state["last_docker_host"] = docker_host
        self.password = (self.directory / "password").read_text()

    def save(self):
        fixtures.private_write(self.directory / "state.json", json.dumps(self.state, indent=2) + "\n")

    def scrub(self, data):
        return data.replace(self.password, "<fixture-password>")

    def run(self, command, *, timeout=45, check=True):
        try:
            result = subprocess.run(command, cwd=ROOT, env=self.environment, capture_output=True,
                                    text=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired as error:
            with (self.directory / "provision.log").open("a") as output:
                output.write(self.scrub("$ " + shlex.join(command) + "\nTIMEOUT\n"))
                for value in [error.stdout, error.stderr]:
                    if value:
                        output.write(self.scrub(value.decode(errors="replace") if isinstance(value, bytes) else value))
            raise
        with (self.directory / "provision.log").open("a") as output:
            output.write(self.scrub("$ " + shlex.join(command) + "\n" + result.stdout + result.stderr))
        if check:
            require(result.returncode == 0, "Fixture command failed; inspect private provision.log")
        return result

    def context(self, trusted=True):
        return ssl.create_default_context(cafile=str(self.directory / ("ca.crt" if trusted else "untrusted.crt")))

    def query(self, port, *words, password=True, hostname="localhost", trusted=True, before=()):
        require(port in self.state["ports"], "Refusing an endpoint outside the fixture")
        context = self.context(trusted)
        with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
            with context.wrap_socket(raw, server_hostname=hostname) as connection:
                with connection.makefile("rb") as stream:
                    def send(command):
                        parts = [str(word).encode() for word in command]
                        connection.sendall(b"*%d\r\n" % len(parts) + b"".join(
                            b"$%d\r\n" % len(part) + part + b"\r\n" for part in parts))
                        return fixtures.resp_read(stream)
                    if password is not None:
                        require(send(["AUTH", self.password if password is True else password]) == "OK",
                                "Redis authentication did not succeed")
                    for command in before:
                        send(command)
                    return send(words)

    def routed(self, port, *words):
        for _ in range(8):
            try:
                return self.query(port, *words)
            except fixtures.RedisError as error:
                fields = str(error).split()
                if len(fields) != 3 or fields[0] != "MOVED":
                    raise
                host, target = fields[2].rsplit(":", 1)
                require(host == "localhost" and int(target) in self.state["ports"],
                        "Redirect leaves the isolated TLS fixture")
                port = int(target)
                self.state["verified_tls_redirects"] = self.state.get("verified_tls_redirects", 0) + 1
        raise fixtures.FixtureError("Redis TLS routing did not converge")

    def wait(self, condition, message, timeout=60):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                if condition():
                    return
            except (OSError, fixtures.FixtureError):
                pass
            time.sleep(0.25)
        raise fixtures.FixtureError(message)

    def check(self):
        ports = self.state["ports"]
        checks = []
        for port in ports:
            info = self.query(port, "CLUSTER", "INFO")
            require("cluster_state:ok" in info and "cluster_slots_assigned:16384" in info,
                    "Cluster is not healthy with all slots assigned")
            config = self.query(port, "CONFIG", "GET", "port", "tls-port", "tls-cluster", "tls-replication")
            config = dict(zip(config[::2], config[1::2]))
            require(config == {"port": "0", "tls-port": str(port), "tls-cluster": "yes", "tls-replication": "yes"},
                    "A node enabled plaintext or disabled peer TLS")
            for credential, expected in [(None, "NOAUTH"), ("wrong-password", "WRONGPASS")]:
                try:
                    self.query(port, "PING", password=credential)
                except fixtures.RedisError as error:
                    require(expected in str(error), "Authentication failed for an unexpected reason")
                else:
                    raise fixtures.FixtureError("Redis accepted missing/invalid authentication")
            for options in [{"hostname": "127.0.0.1"}, {"trusted": False}]:
                try:
                    self.query(port, "PING", **options)
                except ssl.SSLCertVerificationError:
                    pass
                else:
                    raise fixtures.FixtureError("Redis accepted invalid certificate trust/name")
        checks += ["all six nodes enforce TLS on clients, replication and cluster links",
                   "all six nodes reject missing/wrong authentication and invalid certificate trust/name"]
        slots = self.query(ports[0], "CLUSTER", "SLOTS")
        ordered = sorted(slots, key=lambda entry: entry[0])
        next_slot = 0
        for entry in ordered:
            require(entry[0] == next_slot and entry[1] >= entry[0] and len(entry) == 4,
                    "Slot coverage is incomplete or a replica is missing")
            next_slot = entry[1] + 1
            for node in entry[2:]:
                require(node[0] == "localhost" and node[1] in ports,
                        "Advertised endpoint cannot be verified/reached by the host client")
        require(next_slot == 16384 and len({entry[2][2] for entry in slots}) == 3
                and len({entry[3][2] for entry in slots}) == 3, "Expected three primaries and three replicas")
        require(all("master_link_status:up" in self.query(entry[3][1], "INFO", "replication") for entry in slots),
                "A TLS replica is not linked to its primary")
        checks.append("three primaries and three replicas cover all slots using verified hostname endpoints")
        tag = secrets.token_hex(10)
        key, sibling = f"fixture:{{{tag}}}:a", f"fixture:{{{tag}}}:b"
        owner = next(entry for entry in slots if entry[0] <= binascii.crc_hqx(tag.encode(), 0) % 16384 <= entry[1])
        other = next(entry[2][1] for entry in slots if entry[2][1] != owner[2][1])
        self.state["verified_tls_redirects"] = 0
        try:
            require(self.routed(other, "EVAL", "return {redis.call('INCRBY',KEYS[1],7),redis.call('INCRBY',KEYS[2],1)}",
                                2, key, sibling) == [7, 1], "Same-slot Lua operation failed")
            require(self.routed(other, "MGET", key, sibling) == ["7", "1"]
                    and self.state["verified_tls_redirects"] >= 2, "Verified TLS redirects were not exercised")
            checks.append("MOVED redirects reconnect with certificate verification and preserve same-slot Lua semantics")
            self.wait(lambda: self.query(owner[3][1], "GET", key, before=[("READONLY",)]) == "7",
                      "TLS replica did not receive the primary's write")
            checks.append("a real write replicates to a replica over TLS")
            other_tag = tag + "other"
            while binascii.crc_hqx(tag.encode(), 0) % 16384 == binascii.crc_hqx(other_tag.encode(), 0) % 16384:
                other_tag += "x"
            try:
                self.routed(other, "EVAL", "return 1", 2, key, f"fixture:{{{other_tag}}}:c")
            except fixtures.RedisError as error:
                require("CROSSSLOT" in str(error), "Unexpected cross-slot failure")
            else:
                raise fixtures.FixtureError("Redis accepted a cross-slot transaction")
            checks.append("cross-slot transactions are rejected")
        finally:
            self.routed(owner[2][1], "DEL", key, sibling)
        self.state["transport_checks"] = checks
        self.save()
        print(f"PASS: {len(checks)} cluster topology/transport checks", flush=True)

    def contracts(self, binaries):
        endpoint = ",".join(f"rediss://:{self.password}@localhost:{port}" for port in self.state["ports"])
        environment = dict(self.environment, AV_REDIS_URL=endpoint, AV_REDIS_TLS_URL=endpoint,
                           AV_REDIS_TLS_WRONG_NAME_URL=endpoint.replace("localhost", "127.0.0.1"),
                           AV_REDIS_TLS_WRONG_PASSWORD_URL=endpoint.replace(self.password, "wrong-password"),
                           SSL_CERT_FILE=str(self.directory / "ca.crt"),
                           SSL_CERT_DIR=str(self.directory / "empty-trust"))
        environment.pop("AV_REDIS_TLS_UNTRUSTED_TEST", None)
        self.state["contract_results"] = []
        runs = [("state-contract", binaries["state"], None, 8, {}),
                ("tls-validation", binaries["tls"], "redis_tls_checks_certificate_name_credentials_and_insecure_flag", 1, {}),
                ("tls-untrusted", binaries["tls"], "redis_tls_rejects_untrusted_ca", 1,
                 {"SSL_CERT_FILE": str(self.directory / "untrusted.crt"), "AV_REDIS_TLS_UNTRUSTED_TEST": "1"}),
                ("revocation-contract", binaries["revocation"], None, 7, {})]
        for name, binary, test, expected, overrides in runs:
            binary = binary.resolve(strict=True)
            command = [str(binary), "--test-threads=4", "--nocapture"]
            if test:
                command += ["--exact", test]
            started = time.monotonic()
            log_path = self.directory / (name + ".log")
            with log_path.open("wb") as output:
                process = subprocess.Popen(command, cwd=ROOT, env=environment | overrides,
                                           stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
                try:
                    code = process.wait(timeout=600)
                finally:
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGTERM)
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            os.killpg(process.pid, signal.SIGKILL)
                            process.wait(timeout=5)
            output = self.scrub(log_path.read_text(errors="replace"))
            fixtures.private_write(log_path, output)
            match = re.search(r"test result: ok\. (\d+) passed; 0 failed;", output)
            passed = code == 0 and "SKIPPED" not in output and match and int(match[1]) >= expected
            self.state["contract_results"].append({"test": name, "exit_code": code,
                "passed": bool(passed), "seconds": round(time.monotonic() - started, 3),
                "binary": str(binary), "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()})
            self.save()
            require(passed, f"{name} failed, skipped, or ran too few tests; inspect its private log")
            print(f"PASS: {name}", flush=True)

    def stop(self, output_dir=None):
        inspected = self.run(["docker", "inspect", self.state["container"]], check=False)
        if inspected.returncode:
            require("no such object" in inspected.stderr.lower() or "no such container" in inspected.stderr.lower(),
                    "Cannot verify container absence; retaining fixture for cleanup retry")
        else:
            require(owned_container(json.loads(inspected.stdout)[0], self.state),
                    "Container ownership mismatch; refusing cleanup")
            logs = self.run(["docker", "logs", self.state["container"]], check=False)
            fixtures.private_write(self.directory / "redis-server.log", self.scrub(logs.stdout + logs.stderr))
            self.run(["docker", "rm", "-f", "-v", self.state["container"]])
        self.state["cleanup"] = "completed"
        self.save()
        if output_dir:
            output_dir = output_dir.resolve()
            require(output_dir != self.directory and not output_dir.is_relative_to(self.directory),
                    "Evidence directory cannot be inside the private fixture")
            output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            for log in self.directory.glob("*.log"):
                fixtures.private_write(output_dir / log.name, self.scrub(log.read_text(errors="replace")))
            fixtures.private_write(output_dir / "result.json", json.dumps(self.state, indent=2) + "\n")
        shutil.rmtree(self.directory)


def start(endpoint, failure_output_dir=None, state_file=None):
    client_environment(endpoint)
    directory = Path(tempfile.mkdtemp(prefix=PREFIX)).resolve()
    fixture_id = secrets.token_hex(12)
    state = {"directory": str(directory), "fixture_id": fixture_id, "container": PREFIX + fixture_id,
             "docker_host": endpoint, "redis_image": IMAGE, "ports": fixtures.allocate_ports(6),
             "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
             "limitations": ["Six processes in one container; no independent-host failover or production persistence validation."]}
    require(not set(state["ports"]) & set(range(16000, 16006)), "Client/bus port collision; retry fixture creation")
    fixtures.private_write(directory / "state.json", json.dumps(state))
    fixtures.private_write(directory / "password", secrets.token_hex(32))
    cluster = Cluster(directory)
    if state_file:
        fixtures.private_write(state_file, str(directory) + "\n")
    try:
        for authority in ["ca", "untrusted"]:
            cluster.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "2",
                         "-subj", f"/CN=AgentVisor cluster test {authority}", "-addext", "basicConstraints=critical,CA:TRUE",
                         "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", str(directory / f"{authority}.key"),
                         "-out", str(directory / f"{authority}.crt")])
        fixtures.private_write(directory / "extensions.cnf", "subjectAltName=DNS:localhost\n"
            "extendedKeyUsage=serverAuth,clientAuth\nkeyUsage=digitalSignature,keyEncipherment\nbasicConstraints=critical,CA:FALSE\n")
        files = ["ca.crt", "password"]
        for index, port in enumerate(state["ports"]):
            cluster.run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256", "-subj", "/CN=localhost",
                         "-keyout", str(directory / f"node-{index}.key"), "-out", str(directory / f"node-{index}.csr")])
            cluster.run(["openssl", "x509", "-req", "-in", str(directory / f"node-{index}.csr"),
                         "-CA", str(directory / "ca.crt"), "-CAkey", str(directory / "ca.key"), "-CAcreateserial",
                         "-out", str(directory / f"node-{index}.crt"), "-days", "2", "-sha256",
                         "-extfile", str(directory / "extensions.cnf")])
            fixtures.private_write(directory / f"node-{index}.conf", node_config(index, port, cluster.password))
            files += [f"node-{index}.key", f"node-{index}.crt", f"node-{index}.conf"]
        fixtures.private_write(directory / "start.sh", "#!/bin/sh\nset -eu\n" + "\n".join(
            f"mkdir -p /tmp/node-{i}\nredis-server /fixture/node-{i}.conf &" for i in range(6)) + "\nwait\n")
        files.append("start.sh")
        cluster.run(["docker", "pull", IMAGE], timeout=180)
        cluster.state["image_id"] = cluster.run(["docker", "image", "inspect", IMAGE, "--format", "{{.Id}}"]).stdout.strip()
        cluster.save()
        args = ["docker", "create", "--name", state["container"], "--label", f"{LABEL}={fixture_id}",
                # Docker copies generated secrets into the stopped container
                # before startup; a read-only root prevents that provisioning.
                "--user", "65532:65532", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                "--memory", "768m", "--cpus", "2", "--pids-limit", "128", "--tmpfs", "/tmp:rw,nosuid,noexec,size=128m,mode=1777"]
        for port in state["ports"]:
            args += ["-p", f"127.0.0.1:{port}:{port}"]
        cluster.run(args + ["--entrypoint", "sh", IMAGE, "/fixture/start.sh"])
        archive_path = directory / "fixture.tar"
        with tarfile.open(archive_path, "w") as archive:
            entry = tarfile.TarInfo("fixture")
            entry.type, entry.mode, entry.uid, entry.gid = tarfile.DIRTYPE, 0o700, 65532, 65532
            archive.addfile(entry)
            for filename in files:
                entry = archive.gettarinfo(str(directory / filename), "fixture/" + filename)
                entry.uid = entry.gid = 65532
                entry.uname = entry.gname = ""
                entry.mode = 0o600
                with (directory / filename).open("rb") as source:
                    archive.addfile(entry, source)
        with archive_path.open("rb") as source:
            copied = subprocess.run(["docker", "cp", "-a", "-", state["container"] + ":/"], env=cluster.environment,
                                    stdin=source, capture_output=True, timeout=30, check=False)
            with (directory / "provision.log").open("a") as output:
                output.write(cluster.scrub(copied.stderr.decode(errors="replace")))
            require(copied.returncode == 0, "Could not copy private Redis fixture files")
        cluster.run(["docker", "start", state["container"]])
        cluster.wait(lambda: all(cluster.query(port, "PING") == "PONG" for port in state["ports"]), "TLS nodes did not start")
        # CLUSTER MEET uses numeric node addresses. The advertised client
        # endpoint remains localhost for verified TLS redirects after bootstrap.
        addresses = " ".join(f"127.0.0.1:{port}" for port in state["ports"])
        cluster.run(["docker", "exec", state["container"], "sh", "-ec",
            'export REDISCLI_AUTH="$(cat /fixture/password)"; exec redis-cli --tls --cacert /fixture/ca.crt --sni localhost '
            '--cluster create ' + addresses + ' --cluster-replicas 1 --cluster-yes'], timeout=60)
        cluster.wait(lambda: all("cluster_state:ok" in cluster.query(port, "CLUSTER", "INFO") for port in state["ports"]),
                     "TLS cluster did not become healthy")
        cluster.wait(lambda: all(len(entry) == 4 for entry in cluster.query(state["ports"][0], "CLUSTER", "SLOTS")),
                     "TLS replicas did not join slot map")
        cluster.wait(lambda: all("master_link_status:up" in cluster.query(entry[3][1], "INFO", "replication")
                                for entry in cluster.query(state["ports"][0], "CLUSTER", "SLOTS")),
                     "TLS replicas did not synchronize")
        (directory / "empty-trust").mkdir()
        url = ",".join(f"rediss://:{cluster.password}@localhost:{port}" for port in state["ports"])
        env = {"AV_REDIS_URL": url, "AV_REDIS_TLS_URL": url,
               "AV_REDIS_TLS_WRONG_NAME_URL": url.replace("localhost", "127.0.0.1"),
               "AV_REDIS_TLS_WRONG_PASSWORD_URL": url.replace(cluster.password, "wrong-password"),
               "SSL_CERT_FILE": str(directory / "ca.crt"), "SSL_CERT_DIR": str(directory / "empty-trust")}
        fixtures.private_write(directory / "env.sh", "# Private generated credentials; do not print or commit.\nunset AV_REDIS_TLS_UNTRUSTED_TEST\n"
                               + "\n".join(f"export {name}={shlex.quote(value)}" for name, value in env.items()) + "\n")
        cluster.check()
        print("Private fixture directory: " + str(directory), flush=True)
        return directory
    except BaseException:
        evidence = failure_output_dir or Path(tempfile.mkdtemp(prefix=PREFIX + "failure-"))
        try:
            cluster.stop(evidence)
        except BaseException:
            print("Cleanup retry required for private fixture: " + str(directory), flush=True)
            raise
        if state_file:
            state_file.unlink(missing_ok=True)
        print("Startup diagnostics: " + str(evidence), flush=True)
        raise


class Tests(unittest.TestCase):
    def test_owned_cleanup_requires_exact_name_and_label(self):
        state = {"fixture_id": "a" * 24, "container": PREFIX + "a" * 24}
        value = {"Name": "/" + state["container"], "Config": {"Labels": {LABEL: state["fixture_id"]}}}
        self.assertTrue(owned_container(value, state))
        self.assertFalse(owned_container(value | {"Name": "/unrelated"}, state))
        self.assertFalse(owned_container(value | {"Config": {"Labels": {}}}, state))

    def test_tls_and_hostname_configuration(self):
        config = node_config(2, 51000, "fixture-password").splitlines()
        for required in ["port 0", "tls-port 51000", "tls-cluster yes", "tls-replication yes",
                         "cluster-announce-tls-port 51000", "cluster-announce-hostname localhost",
                         "cluster-preferred-endpoint-type hostname", "requirepass fixture-password",
                         "masterauth fixture-password"]:
            self.assertIn(required, config)
        self.assertFalse(any(line.startswith("cluster-announce-port ") for line in config))

    def test_docker_configuration_is_preserved(self):
        from unittest.mock import patch
        with patch.dict(os.environ, {"DOCKER_CONFIG": "/existing", "DOCKER_CONTEXT": "old-context"}):
            value = client_environment("unix:///task/socket")
        self.assertEqual(value["DOCKER_CONFIG"], "/existing")
        self.assertEqual(value["DOCKER_HOST"], "unix:///task/socket")
        self.assertNotIn("DOCKER_CONTEXT", value)


def main():
    os.umask(0o077)
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("start")
    create.add_argument("--docker-host", default=os.environ.get("DOCKER_HOST"))
    commands.add_parser("self-test")
    for name in ("check", "test", "stop"):
        sub = commands.add_parser(name)
        sub.add_argument("directory", type=Path)
        sub.add_argument("--docker-host", help="Explicit replacement transport to the same Docker engine")
        if name == "stop":
            sub.add_argument("--output-dir", type=Path)
        if name == "test":
            for role in ("state", "tls", "revocation"):
                sub.add_argument("--" + role + "-bin", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "self-test":
        unittest.main(argv=[__file__])
    elif args.command == "start":
        start(args.docker_host)
    else:
        cluster = Cluster(args.directory, args.docker_host)
        if args.command == "check":
            cluster.check()
        elif args.command == "test":
            cluster.check()
            cluster.contracts({role: getattr(args, role + "_bin") for role in ("state", "tls", "revocation")})
        else:
            cluster.stop(args.output_dir)
            print("Removed only the owned container and its private credentials.")


if __name__ == "__main__":
    main()
