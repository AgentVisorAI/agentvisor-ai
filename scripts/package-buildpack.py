#!/usr/bin/env python3
"""Package buildpack/ with the sidecar binaries it launches.

The buildpack starts `avctl sidecar` beside the application, so a packaged
buildpack must carry static Linux `avctl` binaries. Pass the musl binaries
the release workflow builds:

    python3 scripts/package-buildpack.py \\
        --avctl-x86_64 target/x86_64-unknown-linux-musl/release/avctl \\
        --avctl-aarch64 target/aarch64-unknown-linux-musl/release/avctl \\
        --output dist

It writes, with SHA-256 checksum files:

- agentvisor-buildpack-<version>.zip: a Cloud Foundry classic buildpack
  (`cf create-buildpack agentvisor-buildpack <zip> 1`);
- agentvisor-buildpack-<version>.tgz: the same tree for Cloud Native
  Buildpacks (`pack buildpack package --path <tgz>`).

At least one architecture is required. The tests directory is left out, and
executable bits are kept for bin/ and vendor/.
"""
import argparse
import hashlib
import io
from pathlib import Path
import re
import sys
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
BUILDPACK = ROOT / "buildpack"
EXCLUDED = {"tests", "__pycache__", "vendor"}
ELF_MAGIC = b"\x7fELF"


def version() -> str:
    text = (BUILDPACK / "buildpack.toml").read_text()
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not match:
        raise SystemExit("buildpack.toml has no version")
    return match.group(1)


def entries(binaries: dict) -> list:
    """(archive path, bytes, mode) for every file of the package."""
    files = []
    for path in sorted(BUILDPACK.rglob("*")):
        relative = path.relative_to(BUILDPACK)
        if any(part in EXCLUDED for part in relative.parts) or not path.is_file():
            continue
        executable = relative.parts[0] == "bin"
        files.append((relative.as_posix(), path.read_bytes(), 0o755 if executable else 0o644))
    for arch, binary in sorted(binaries.items()):
        data = Path(binary).read_bytes()
        if not data.startswith(ELF_MAGIC):
            raise SystemExit(f"{binary} is not a Linux (ELF) binary; build avctl for *-unknown-linux-musl")
        files.append((f"vendor/avctl-linux-{arch}", data, 0o755))
    return files


def write_zip(path: Path, files: list) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data, mode in files:
            info = zipfile.ZipInfo(name, date_time=(2024, 1, 1, 0, 0, 0))
            info.external_attr = (0o100000 | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)


def write_tgz(path: Path, files: list) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name, data, mode in files:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = mode
            info.mtime = 1704067200
            archive.addfile(info, io.BytesIO(data))


def checksum(path: Path) -> None:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    path.with_name(path.name + ".sha256").write_text(f"{digest}  {path.name}\n")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--avctl-x86_64", help="static Linux x86_64 avctl binary")
    parser.add_argument("--avctl-aarch64", help="static Linux aarch64 avctl binary")
    parser.add_argument("--output", default="dist", help="output directory (default: dist)")
    args = parser.parse_args(argv)
    binaries = {arch: path for arch, path in (("x86_64", args.avctl_x86_64), ("aarch64", args.avctl_aarch64)) if path}
    if not binaries:
        parser.error("pass at least one of --avctl-x86_64 / --avctl-aarch64")
    files = entries(binaries)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    stem = f"agentvisor-buildpack-{version()}"
    for suffix, writer in ((".zip", write_zip), (".tgz", write_tgz)):
        target = output / (stem + suffix)
        writer(target, files)
        checksum(target)
        print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
