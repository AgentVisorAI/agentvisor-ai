#!/usr/bin/env python3
"""Run the real CNB lifecycle and classic supply contract in isolated containers.

Requires Docker and pack, or --download-pack for a checksum-verified temporary
pack installation. No foundation, registry credentials, or public service is used.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
import uuid

BUILDPACK = Path(__file__).resolve().parents[1]
PACK_VERSION = "0.40.9"
PACK_HASHES = {
    ("Linux", "x86_64"): ("linux", "dc0ee1e931cf8a106d7555a01a214864f9acb60b77adf15d69b74df4404758e9"),
    ("Linux", "aarch64"): ("linux-arm64", "091ccb213823656c727731537ef8f1000eb4dc3ec61641506653e7f9d6da0c5e"),
    ("Darwin", "x86_64"): ("macos", "bdd85a547b8d1322aa42a04ddb837cbd75630264163d41f193bacfb36b082745"),
    ("Darwin", "arm64"): ("macos-arm64", "8400318bf9a9e4aab6a1ed1e35046fecb33d0015e80a43105878913f8e18311a"),
}
ALPINE = "alpine@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6"


def write(path, content, executable=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    if executable:
        path.chmod(0o755)


def download_pack(work):
    system = (platform.system(), platform.machine())
    if system not in PACK_HASHES:
        raise RuntimeError("Unsupported platform for automatic pack download: " + repr(system))
    target, expected = PACK_HASHES[system]
    filename = "pack-v{}-{}.tgz".format(PACK_VERSION, target)
    url = "https://github.com/buildpacks/pack/releases/download/v{}/{}".format(PACK_VERSION, filename)
    archive = work / filename
    with urllib.request.urlopen(url, timeout=60) as response, archive.open("wb") as output:
        shutil.copyfileobj(response, output)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
        raise RuntimeError("Official pack release checksum did not match")
    with tarfile.open(archive) as tar:
        members = [member for member in tar if Path(member.name).name == "pack" and member.isfile()]
        if len(members) != 1:
            raise RuntimeError("Official pack archive did not contain one executable")
        with tar.extractfile(members[0]) as source, (work / "pack").open("wb") as output:
            shutil.copyfileobj(source, output)
    (work / "pack").chmod(0o700)
    return str(work / "pack")


class Lifecycle:
    def __init__(self, work, pack):
        self.work, self.pack = work, pack
        self.prefix = "av-buildpack-test-" + uuid.uuid4().hex[:12]
        self.env = dict(os.environ)
        self.images, self.volumes, self.containers = [], [], []
        self.step = 0
        # pack does not follow Docker CLI contexts on every platform.
        if not self.env.get("DOCKER_HOST"):
            self.env["DOCKER_HOST"] = self.run([
                "docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"
            ]).stdout.strip()

    def run(self, args, timeout=120, expected=0):
        self.step += 1
        result = subprocess.run(args, env=self.env, capture_output=True, text=True, timeout=timeout)
        (self.work / "{:02d}.log".format(self.step)).write_text(
            "Command: " + repr(args) + "\n" + result.stdout + result.stderr)
        passed = result.returncode == 0 if expected == 0 else result.returncode != 0
        if not passed:
            raise RuntimeError("Command failed its expected outcome: {}\n{}{}".format(
                args[:4], result.stdout, result.stderr))
        return result

    def volume_with_files(self, directory):
        volume = self.prefix + "-binding-" + str(len(self.volumes))
        self.volumes.append(volume)
        self.run(["docker", "volume", "create", volume])
        container = self.prefix + "-copy"
        self.containers.append(container)
        self.run(["docker", "create", "--name", container, "--network", "none",
                  "--mount", "type=volume,src={},dst=/binding".format(volume), self.base, "true"])
        self.run(["docker", "cp", str(directory) + "/.", container + ":/binding"])
        self.run(["docker", "rm", container])
        self.containers.remove(container)
        return volume

    def build_app(self, volume, expected=0):
        args = [self.pack, "build", self.app_image, "--builder", self.builder,
                "--path", str(self.work / "app"), "--pull-policy", "never", "--trust-builder"]
        if volume:
            args += ["--volume", volume + ":/platform/bindings:ro"]
        for kind in ("build", "launch"):
            args += ["--cache", "type={};format=volume;name={}-{}".format(kind, self.prefix, kind)]
        result = self.run(args, timeout=300, expected=expected)
        if expected and "failed to detect" not in result.stdout + result.stderr:
            raise RuntimeError("Negative binding case failed outside detection")

    def launch(self):
        container = self.prefix + "-launch"
        self.containers.append(container)
        result = self.run(["docker", "run", "--rm", "--name", container, "--network", "none", self.app_image])
        self.containers.remove(container)
        if "verified launch environment" not in result.stdout:
            raise RuntimeError("Image did not execute the fixture verification")

    def verify(self):
        self.base, self.builder, self.app_image = [self.prefix + "-" + part for part in ("base", "builder", "app")]
        self.images.extend([self.app_image, self.builder, self.base])
        self.volumes.extend([self.prefix + "-build", self.prefix + "-launch"])
        write(self.work / "base/Dockerfile", """FROM %s
RUN apk add --no-cache jq bash && addgroup -g 1000 cnb && adduser -D -u 1000 -G cnb cnb
ENV CNB_USER_ID=1000 CNB_GROUP_ID=1000 CNB_STACK_ID=io.agentvisor.test
LABEL io.buildpacks.stack.id=io.agentvisor.test
USER 1000:1000
""" % ALPINE)
        self.run(["docker", "build", "-t", self.base, str(self.work / "base")], timeout=300)
        write(self.work / "fixture/buildpack.toml", """api = "0.9"
[buildpack]
id = "io.agentvisor.fixture"
version = "0.0.1"
[[stacks]]
id = "*"
""")
        write(self.work / "fixture/bin/detect", "#!/bin/sh\nexit 0\n", True)
        write(self.work / "fixture/bin/build", """#!/bin/sh
set -eu
cat > "$CNB_LAYERS_DIR/launch.toml" <<'TOML'
[[processes]]
type = "web"
command = ["/bin/sh", "/workspace/verify.sh"]
default = true
TOML
""", True)
        write(self.work / "app/verify.sh", """#!/bin/sh
set -eu
[ "$(id -u)" = 1000 ]
jq -e 'env.AV_GATEWAY_URL == .gateway_url and env.AV_AUDIENCE == .audience and env.AV_IDENTITY_JWKS_URL == .identity_jwks_url' /workspace/expected.json >/dev/null
[ ! -e /tmp/unsafe ]
printf 'verified launch environment\\n'
""", True)
        write(self.work / "builder.toml", """description = "Isolated AgentVisor lifecycle verification"
[stack]
id = "io.agentvisor.test"
build-image = %s
run-image = %s
[lifecycle]
version = "0.21.20"
[[buildpacks]]
id = "io.agentvisor.buildpack"
version = "0.1.0"
uri = %s
[[buildpacks]]
id = "io.agentvisor.fixture"
version = "0.0.1"
uri = %s
[[order]]
[[order.group]]
id = "io.agentvisor.buildpack"
version = "0.1.0"
[[order.group]]
id = "io.agentvisor.fixture"
version = "0.0.1"
""" % tuple(json.dumps(value) for value in (self.base, self.base, str(BUILDPACK), str(self.work / "fixture"))))
        self.run([self.pack, "builder", "create", self.builder, "--config", str(self.work / "builder.toml"), "--pull-policy", "never"], timeout=300)
        values = dict(gateway_url="https://gateway.example", audience="client's $(touch /tmp/unsafe)", identity_jwks_url="https://identity.example/jwks")
        directory = self.work / "bindings/agentvisor"
        for key, value in dict(values, type="agentvisor").items():
            write(directory / key, " " + value + " \n")
        write(self.work / "app/expected.json", json.dumps(values))
        volume = self.volume_with_files(directory.parent)
        self.build_app(volume)
        self.launch()
        print("PASS: CNB detect, build, export and non-root launch; literal binding values", flush=True)
        (directory / "identity_jwks_url").unlink()
        values["identity_jwks_url"] = ""
        write(self.work / "app/expected.json", json.dumps(values))
        volume = self.volume_with_files(directory.parent)
        self.build_app(volume)
        self.launch()
        print("PASS: CNB rebuild clears removed optional metadata", flush=True)
        (directory / "audience").unlink()
        self.build_app(self.volume_with_files(directory.parent), expected=1)
        self.build_app(None, expected=1)
        print("PASS: required buildpack rejects malformed and absent bindings in detection", flush=True)
        self.classic(values)

    def classic(self, values):
        container = self.prefix + "-classic"
        self.containers.append(container)
        vcap = json.dumps({"agentvisor": [{"credentials": values}]})
        command = """set -eu
mkdir -p /tmp/app /tmp/cache /tmp/deps
if /buildpack/bin/detect /tmp/app; then exit 1; fi
/buildpack/bin/supply /tmp/app /tmp/cache /tmp/deps 0
. /tmp/deps/0/profile.d/agentvisor.sh
jq -e 'env.VCAP_SERVICES | fromjson | .agentvisor[0].credentials | env.AV_GATEWAY_URL == .gateway_url and env.AV_AUDIENCE == .audience and env.AV_IDENTITY_JWKS_URL == .identity_jwks_url' /dev/null
[ ! -e /tmp/unsafe ]
[ -z "$(ls -A /tmp/app)" ]
printf 'verified classic supply environment\\n'
""".replace("jq -e ", "jq -ne ")
        self.run(["docker", "create", "--name", container, "--network", "none", "-e", "VCAP_SERVICES=" + vcap, self.base, "sh", "-c", command])
        self.run(["docker", "cp", str(BUILDPACK), container + ":/buildpack"])
        # docker start --attach does not consistently propagate the process code.
        output = self.run(["docker", "start", "--attach", container]).stdout
        status = self.run(["docker", "inspect", "--format", "{{.State.ExitCode}}", container]).stdout.strip()
        if status != "0" or "verified classic supply environment" not in output:
            raise RuntimeError("Classic supply container failed: " + output)
        self.run(["docker", "rm", container])
        self.containers.remove(container)
        print("PASS: classic supply and generated profile run as non-root on Linux", flush=True)

    def cleanup(self):
        for kind, names in (("container", self.containers), ("image", self.images), ("volume", self.volumes)):
            for name in names:
                try:
                    self.run(["docker", kind, "rm", "-f", name], timeout=30)
                except (RuntimeError, subprocess.TimeoutExpired) as error:
                    print("Cleanup could not remove {} {}: {}".format(kind, name, error), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--download-pack", action="store_true")
    args = parser.parse_args()
    work = Path(tempfile.mkdtemp(prefix="av-buildpack-lifecycle-"))
    runner = None
    try:
        pack = download_pack(work) if args.download_pack else os.environ.get("PACK", shutil.which("pack"))
        if not pack or not shutil.which("docker"):
            raise RuntimeError("Docker and pack are required; set PACK or use --download-pack")
        runner = Lifecycle(work, pack)
        runner.verify()
        print("All lifecycle checks passed. Logs: " + str(work))
    except BaseException:
        print("Lifecycle test artifacts: " + str(work), flush=True)
        raise
    finally:
        if runner:
            runner.cleanup()


if __name__ == "__main__":
    main()
