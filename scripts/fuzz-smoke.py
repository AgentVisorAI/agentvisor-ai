#!/usr/bin/env python3
"""Run the existing six fuzz targets from committed seeds for 60 seconds each.

Every invocation uses a fresh writable corpus, preserving the committed seeds.
Use --prepare-only to inspect all inputs and commands without running Cargo.
Build time is additional to each target's bounded libFuzzer execution time.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import tempfile
import time

TARGETS = (
    "canonicalize_receipt_subject", "compress_invariants", "parse_provider_chunk",
    "redact_userinfo", "sse_frame_end", "parse_tool_call",
)


def positive_seconds(value: str) -> int:
    parsed = int(value)
    if not 1 <= parsed <= 3600:
        raise argparse.ArgumentTypeError("seconds must be between 1 and 3600")
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", action="append", choices=TARGETS, help="Run one target; repeat to select several")
    parser.add_argument("--seconds", type=positive_seconds, default=60, help="libFuzzer execution seconds per target (default: 60)")
    parser.add_argument("--seed", type=int, default=20260924, help="Fixed libFuzzer random seed (default: 20260924)")
    parser.add_argument("--prepare-only", action="store_true", help="Copy seeds and print commands without invoking Cargo")
    args = parser.parse_args()
    if not 1 <= args.seed <= 0xFFFFFFFF:
        parser.error("seed must be an integer from 1 through 4294967295")
    fuzz = Path(__file__).resolve().parents[1] / "fuzz"
    parent = fuzz / "corpus"
    parent.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="smoke-", dir=parent))
    artifact_root = fuzz / "artifacts" / output.name
    targets = list(dict.fromkeys(args.target or TARGETS))
    plans = []
    for target in targets:
        corpus = output / target
        artifacts = artifact_root / target
        corpus.mkdir()
        artifacts.mkdir(parents=True)
        seeds = sorted((fuzz / "seeds" / target).glob("*"))
        if not seeds or any(not seed.is_file() or seed.is_symlink() for seed in seeds):
            raise SystemExit(f"Missing or invalid committed seeds for {target}")
        manifest = []
        for source in seeds:
            data = source.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            destination = corpus / ("seed-" + digest)
            if not destination.exists():
                destination.write_bytes(data)
            manifest.append({"name": source.name, "sha256": digest, "bytes": len(data)})
        command = ["cargo", "+nightly", "fuzz", "run", target, str(corpus), "--",
                   f"-max_total_time={args.seconds}", f"-seed={args.seed}", "-timeout=10",
                   "-rss_limit_mb=2048", "-max_len=65536", f"-artifact_prefix={artifacts}/"]
        plans.append({"target": target, "seeds": manifest, "command": command})
    report = {"seconds_per_target": args.seconds, "rng_seed": args.seed,
              "working_directory": str(fuzz), "targets": plans, "prepared_only": args.prepare_only}
    report_path = output / "run.json"

    def save() -> None:
        report_path.write_text(json.dumps(report, indent=2) + "\n")

    save()
    print(f"Seed manifest and results: {report_path}", flush=True)
    print(f"Working directory: {fuzz}", flush=True)
    for plan in plans:
        print(f"{plan['target']}: {len(plan['seeds'])} committed seeds", flush=True)
        print(shlex.join(plan["command"]), flush=True)
        if args.prepare_only:
            continue
        began = time.monotonic()
        try:
            result = subprocess.run(plan["command"], cwd=fuzz, check=False)
        except (OSError, KeyboardInterrupt) as error:
            plan["error"] = type(error).__name__
            save()
            return 130 if isinstance(error, KeyboardInterrupt) else 1
        plan["elapsed_seconds"] = round(time.monotonic() - began, 3)
        plan["exit_code"] = result.returncode
        save()
        if result.returncode:
            print(f"Stopped after {plan['target']} failed; retain the corpus and crash artifacts.", flush=True)
            return result.returncode if result.returncode > 0 else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
