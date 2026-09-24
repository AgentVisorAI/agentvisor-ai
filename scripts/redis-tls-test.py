#!/usr/bin/env python3
"""Test the Rust Redis backend over authenticated, certificate-verified TLS.

Creates only a labelled, task-owned Redis container on a random loopback port.
Certificates and credentials stay in a private temporary directory. Run from
the repository root. Docker, OpenSSL, Python 3 and Cargo are required.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import tarfile
import tempfile
import time

spec = importlib.util.spec_from_file_location(
    "secure_fixtures", Path(__file__).with_name("secure-contract-fixtures.py"))
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


def interrupt(*_args):
    raise KeyboardInterrupt


def cargo_contract(command, environment, log):
    process = subprocess.Popen(["cargo", "test", "--locked", *command, "--", "--nocapture"],
                               env=environment, stdout=log, stderr=subprocess.STDOUT,
                               start_new_session=True)
    try:
        return process.wait(timeout=1200)
    finally:
        if process.poll() is None:
            # Cancel only this runner's process group, including compiler/test
            # children. Leave every unrelated developer process untouched.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path,
                        help="Keep test logs and a result summary in this directory")
    args = parser.parse_args()
    os.umask(0o077)
    signal.signal(signal.SIGTERM, interrupt)
    directory = Path(tempfile.mkdtemp(prefix=fixtures.PREFIX)).resolve()
    fixture_id = secrets.token_hex(12)
    container = f"av-redis-tls-{fixture_id}"
    state = {"directory": str(directory), "fixture_id": fixture_id,
             "containers": [container]}
    fixtures.save(directory, state)
    run = lambda words, timeout=60: fixtures.run(directory, words, timeout=timeout)
    results = []
    try:
        port = fixtures.allocate_ports(1)[0]
        password = secrets.token_hex(32)
        for authority in ["ca", "untrusted"]:
            run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                 "-sha256", "-days", "2", "-subj", f"/CN=AgentVisor test {authority}",
                 "-addext", "basicConstraints=critical,CA:TRUE",
                 "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                 "-keyout", str(directory / f"{authority}.key"),
                 "-out", str(directory / f"{authority}.crt")])
        run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256",
             "-subj", "/CN=localhost", "-keyout", str(directory / "server.key"),
             "-out", str(directory / "server.csr")])
        fixtures.private_write(directory / "extensions.cnf",
                               "subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n"
                               "keyUsage=digitalSignature,keyEncipherment\n"
                               "basicConstraints=critical,CA:FALSE\n")
        run(["openssl", "x509", "-req", "-in", str(directory / "server.csr"),
             "-CA", str(directory / "ca.crt"), "-CAkey", str(directory / "ca.key"),
             "-CAcreateserial", "-out", str(directory / "server.crt"), "-days", "2",
             "-sha256", "-extfile", str(directory / "extensions.cnf")])
        fixtures.private_write(directory / "redis.conf", f"""port 0
tls-port 6379
bind 0.0.0.0
tls-cert-file /fixture/server.crt
tls-key-file /fixture/server.key
tls-ca-cert-file /fixture/ca.crt
tls-auth-clients no
requirepass {password}
save ""
appendonly no
""")
        run(["docker", "create", "--name", container, "--label",
             f"{fixtures.LABEL}={fixture_id}", "--cap-drop=ALL", "--user", "65532:65532",
             "--security-opt=no-new-privileges", "--memory", "192m", "--cpus", "1",
             "--pids-limit", "128", "--tmpfs", "/data:rw,size=16m",
             "-p", f"127.0.0.1:{port}:6379", "--entrypoint", "redis-server",
             fixtures.REDIS_IMAGE, "/fixture/redis.conf"], timeout=180)
        # Set archive ownership explicitly: Docker/Colima may preserve host
        # UIDs during copy, which makes private files unreadable to the daemon.
        with tarfile.open(directory / "fixture.tar", "w") as archive:
            entry = tarfile.TarInfo("fixture")
            entry.type, entry.mode = tarfile.DIRTYPE, 0o700
            entry.uid = entry.gid = 65532
            archive.addfile(entry)
            for filename in ["redis.conf", "server.key", "server.crt", "ca.crt"]:
                entry = archive.gettarinfo(str(directory / filename), f"fixture/{filename}")
                entry.uid = entry.gid = 65532
                entry.uname = entry.gname = ""
                entry.mode = 0o600
                with (directory / filename).open("rb") as source:
                    archive.addfile(entry, source)
        with (directory / "fixture.tar").open("rb") as source:
            copied = subprocess.run(["docker", "cp", "-a", "-", f"{container}:/"],
                                    stdin=source, capture_output=True, timeout=30, check=False)
            if copied.returncode:
                raise RuntimeError("Could not copy private Redis TLS fixture files")
        run(["docker", "start", container])
        context = ssl.create_default_context(cafile=str(directory / "ca.crt"))
        deadline = time.monotonic() + 45
        while True:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=2) as raw:
                    with context.wrap_socket(raw, server_hostname="localhost") as connection:
                        encoded = password.encode()
                        connection.sendall(b"*2\r\n$4\r\nAUTH\r\n$%d\r\n" % len(encoded)
                                           + encoded + b"\r\n")
                        with connection.makefile("rb") as stream:
                            if fixtures.resp_read(stream) != "OK":
                                raise RuntimeError("Redis TLS authentication failed")
                break
            except (OSError, ssl.SSLError) as error:
                if time.monotonic() >= deadline:
                    raise RuntimeError(f"Redis TLS fixture did not become ready ({type(error).__name__})") from None
                time.sleep(0.2)
        endpoint = f"rediss://:{password}@localhost:{port}"
        environment = dict(os.environ, CARGO_BUILD_JOBS="2", CARGO_INCREMENTAL="0",
                           SSL_CERT_FILE=str(directory / "ca.crt"),
                           SSL_CERT_DIR=str(directory / "empty-trust"),
                           AV_REDIS_URL=endpoint, AV_REDIS_TLS_URL=endpoint,
                           AV_REDIS_TLS_WRONG_NAME_URL=endpoint.replace("localhost", "127.0.0.1"),
                           AV_REDIS_TLS_WRONG_PASSWORD_URL=f"rediss://:invalid@localhost:{port}")
        (directory / "empty-trust").mkdir()
        for name, command, overrides in [
            ("state-contract", ["-p", "av-state", "--features", "redis", "--test", "redis_contract"], {}),
            ("tls-validation", ["-p", "av-state", "--features", "redis", "--test", "redis_tls",
                                "redis_tls_checks_certificate_name_credentials_and_insecure_flag"], {}),
            ("tls-untrusted", ["-p", "av-state", "--features", "redis", "--test", "redis_tls",
                               "redis_tls_rejects_untrusted_ca"],
             {"SSL_CERT_FILE": str(directory / "untrusted.crt"), "AV_REDIS_TLS_UNTRUSTED_TEST": "1"}),
            ("revocation-contract", ["-p", "av-harness", "--features", "full", "--test", "revocation_redis"], {}),
        ]:
            started = time.monotonic()
            with (directory / f"{name}.log").open("wb") as log:
                exit_code = cargo_contract(command, environment | overrides, log)
            results.append({"test": name, "exit_code": exit_code,
                            "seconds": round(time.monotonic() - started, 2)})
            print(f"{name}: {'passed' if exit_code == 0 else 'FAILED'}", flush=True)
            if exit_code:
                raise RuntimeError(f"{name} failed; inspect saved logs")
        return 0
    finally:
        try:
            with (directory / "redis-server.log").open("wb") as log:
                subprocess.run(["docker", "logs", container], stdout=log,
                               stderr=subprocess.STDOUT, timeout=30, check=False)
            if args.output_dir:
                args.output_dir.mkdir(parents=True, exist_ok=True)
                for log in directory.glob("*.log"):
                    # Test assertions intentionally do not print connection URLs.
                    shutil.copy2(log, args.output_dir / log.name)
                fixtures.private_write(args.output_dir / "results.json", json.dumps(results, indent=2) + "\n")
        finally:
            fixtures.stop(directory)



if __name__ == "__main__":
    raise SystemExit(main())
