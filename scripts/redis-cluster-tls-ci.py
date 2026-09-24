#!/usr/bin/env python3
"""Compile named Rust contracts and run the isolated Redis Cluster/TLS fixture.

CI publishes only --output-dir, which contains redacted diagnostics and provenance.
The fixture's private directory, certificates and credentials must not be uploaded.
Use --cleanup in an unconditional CI step to retry owned cleanup after interruption.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "cluster_tls_fixture", Path(__file__).with_name("redis-cluster-tls-test.py"))
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)
ROOT = Path(__file__).resolve().parents[1]
TARGETS = {"redis_contract": "state", "redis_tls": "tls", "revocation_redis": "revocation"}


def executables(output, expected):
    """Use Cargo's artifact records, never glob stale target-directory binaries."""
    found = {}
    for line in output.splitlines():
        message = json.loads(line)
        name = message.get("target", {}).get("name")
        if (message.get("reason") == "compiler-artifact" and name in expected
                and message.get("profile", {}).get("test") and message.get("executable")):
            path = Path(message["executable"]).resolve(strict=True)
            fixture.require(name not in found or found[name] == path,
                            f"Cargo reported ambiguous executables for {name}")
            found[name] = path
    fixture.require(set(found) == set(expected), "Cargo did not report every requested test executable")
    return {TARGETS[name]: path for name, path in found.items()}


def compile_contracts(output_dir):
    command = ["cargo", "test", "--locked", "--all-features", "--no-run",
               "--message-format=json", "-p", "av-state", "-p", "av-harness"]
    for name in TARGETS:
        command += ["--test", name]
    environment = dict(os.environ, CARGO_BUILD_JOBS="2", CARGO_INCREMENTAL="0")
    stdout_path = output_dir / "compile-contracts.jsonl"
    with stdout_path.open("wb") as stdout, (output_dir / "compile-contracts.log").open("wb") as stderr:
        process = subprocess.Popen(command, cwd=ROOT, env=environment, stdout=stdout,
                                   stderr=stderr, start_new_session=True)
        try:
            code = process.wait(timeout=1200)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
    fixture.require(code == 0, "Compilation failed; inspect compile-contracts.log")
    return executables(stdout_path.read_text(), TARGETS)


def cleanup(marker, output_dir):
    if not marker.exists():
        return
    directory = Path(marker.read_text().strip())
    # Cluster verifies the canonical directory marker and exact container label
    # before it removes any resource. Preserve the marker if cleanup fails.
    fixture.Cluster(directory).stop(output_dir)
    marker.unlink()


def run(endpoint, output_dir, marker):
    fixture.client_environment(endpoint)
    binaries = compile_contracts(output_dir)
    try:
        directory = fixture.start(endpoint, failure_output_dir=output_dir / "startup-failure", state_file=marker)
        cluster = fixture.Cluster(directory)
        cluster.contracts(binaries)
    finally:
        cleanup(marker, output_dir)


class Tests(unittest.TestCase):
    def test_artifact_selection_ignores_non_test_and_stale_targets(self):
        path = str(Path(__file__).resolve())
        artifact = {"reason": "compiler-artifact", "target": {"name": "redis_contract"},
                    "profile": {"test": True}, "executable": path}
        lines = [artifact | {"profile": {"test": False}, "executable": "/not-a-file"}, artifact]
        self.assertEqual(executables("\n".join(map(json.dumps, lines)), ["redis_contract"]),
                         {"state": Path(path)})
        with self.assertRaises(fixture.fixtures.FixtureError):
            executables(json.dumps(artifact), ["redis_contract", "redis_tls"])

    def test_contract_failure_still_cleans_owned_fixture(self):
        with patch.object(fixture, "start", return_value=Path("/private/owned")), \
                patch.object(fixture, "Cluster") as cluster, \
                patch(__name__ + ".compile_contracts", return_value={}), \
                patch(__name__ + ".cleanup") as clean:
            cluster.return_value.contracts.side_effect = RuntimeError("contract failure")
            with self.assertRaisesRegex(RuntimeError, "contract failure"):
                run("unix:///task/socket", Path("/diagnostics"), Path("/marker"))
            clean.assert_called_once_with(Path("/marker"), Path("/diagnostics"))

    def test_start_failure_also_retries_owned_cleanup(self):
        with patch.object(fixture, "start", side_effect=RuntimeError("startup failure")), \
                patch(__name__ + ".compile_contracts", return_value={}), \
                patch(__name__ + ".cleanup") as clean:
            with self.assertRaisesRegex(RuntimeError, "startup failure"):
                run("unix:///task/socket", Path("/diagnostics"), Path("/marker"))
            clean.assert_called_once()


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker-host", default=os.environ.get("DOCKER_HOST"))
    parser.add_argument("--output-dir", type=Path, default=Path("/tmp/agentvisor-redis-cluster-tls-results"))
    parser.add_argument("--state-file", type=Path, default=Path("/tmp/agentvisor-redis-cluster-tls-owned"))
    parser.add_argument("--cleanup", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        unittest.main(argv=[__file__])
        return
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    args.output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if args.cleanup:
        cleanup(args.state_file, args.output_dir)
    else:
        fixture.require(not args.state_file.exists(), "Previous fixture marker exists; run --cleanup first")
        run(args.docker_host, args.output_dir, args.state_file)


if __name__ == "__main__":
    main()
