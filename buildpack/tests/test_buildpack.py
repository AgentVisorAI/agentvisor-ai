#!/usr/bin/env python3
"""Exercise real buildpack scripts and their generated launch output."""
import json
import os
import platform
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]


class BuildpackTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="av-buildpack-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.env = dict(os.environ, SERVICE_BINDING_ROOT=str(self.work / "bindings"))
        for key in list(self.env):
            if key.startswith("CNB_") or key == "VCAP_SERVICES":
                del self.env[key]
        for name in ("app", "cache", "deps", "layers", "platform", "bindings"):
            (self.work / name).mkdir()

    def with_vendored_sidecar(self):
        """Run later scripts from a copy of the buildpack that includes a
        (fake) sidecar binary for this machine, as a packaged buildpack does."""
        copy = self.work / "buildpack"
        shutil.copytree(ROOT, copy, ignore=shutil.ignore_patterns("tests", "__pycache__", "vendor"))
        arch = {"arm64": "aarch64", "amd64": "x86_64"}.get(platform.machine(), platform.machine())
        binary = copy / "vendor" / f"avctl-linux-{arch}"
        binary.parent.mkdir()
        binary.write_text("#!/bin/sh\necho fake avctl\n")
        binary.chmod(0o755)
        self.root = copy

    def profile_values(self, *names):
        profile = self.work / "deps/0/profile.d/agentvisor.sh"
        script = '. "$1"; ' + "; ".join(f'printf "%s\\n" "${name}"' for name in names)
        result = subprocess.run(["sh", "-c", script, "sh", str(profile)], text=True, capture_output=True,
                                cwd=self.work, timeout=10, env={"PATH": os.environ["PATH"]})
        return result.stdout.splitlines()

    def run_script(self, name, args=(), cnb=False):
        env = dict(self.env)
        if cnb:
            env.update(CNB_PLATFORM_DIR=str(self.work / "platform"),
                       CNB_LAYERS_DIR=str(self.work / "layers"))
        if name == "supply" and not args:
            args = [str(self.work / n) for n in ("app", "cache", "deps")] + ["0"]
        root = getattr(self, "root", ROOT)
        return subprocess.run([str(root / "bin" / name)] + list(args), env=env,
                              text=True, capture_output=True, timeout=10)

    def vcap(self, **overrides):
        credentials = dict(gateway_url=" https://gw.example/v1 \n", audience=" client ")
        credentials.update(overrides)
        self.env["VCAP_SERVICES"] = json.dumps({"user-provided": [
            {"tags": ["agentvisor"], "credentials": credentials}]})

    def binding(self, name="one", **overrides):
        directory = self.work / "bindings" / name
        directory.mkdir()
        values = dict(type="agentvisor\n", gateway_url=" https://file.example \n", audience=" file \n")
        values.update(overrides)
        for key, value in values.items():
            (directory / key).write_text(value)
        return directory

    def test_classic_never_autoselects(self):
        self.vcap()
        self.assertEqual(self.run_script("detect", [str(self.work / "app")]).returncode, 1)

    def test_cnb_not_applicable_is_100(self):
        self.assertEqual(self.run_script("detect", cnb=True).returncode, 100)

    def test_classic_writes_only_dependency_profile_and_escapes_content(self):
        self.vcap(audience="client's $(touch NOT_ALLOWED)")
        result = self.run_script("supply")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(list((self.work / "app").iterdir()), [])
        profile = self.work / "deps/0/profile.d/agentvisor.sh"
        result = subprocess.run(["sh", "-c", '. "$1"; printf "%s\\n%s\\n%s" "$AV_GATEWAY_URL" "$AV_AUDIENCE" "$AV_IDENTITY_JWKS_URL"', "sh", str(profile)],
                                text=True, capture_output=True, cwd=self.work, timeout=10)
        self.assertEqual(result.stdout, "https://gw.example/v1\nclient's $(touch NOT_ALLOWED)\n")
        self.assertFalse((self.work / "NOT_ALLOWED").exists())

    def test_cnb_build_writes_launch_only_metadata_and_exact_values(self):
        self.binding()
        self.assertEqual(self.run_script("detect", cnb=True).returncode, 0)
        result = self.run_script("build", cnb=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        env = self.work / "layers/agentvisor/env.launch"
        self.assertEqual((env / "AV_GATEWAY_URL.override").read_text(), "https://file.example")
        self.assertEqual((env / "AV_AUDIENCE.override").read_text(), "file")
        self.assertEqual((env / "AV_IDENTITY_JWKS_URL.override").read_text(), "")
        self.assertIn("launch = true", (self.work / "layers/agentvisor.toml").read_text())
        self.assertEqual(list((self.work / "app").iterdir()), [])

    def test_vcap_precedence_and_no_match_fallback(self):
        self.binding()
        self.vcap()
        self.assertEqual(self.run_script("build", cnb=True).returncode, 0)
        env = self.work / "layers/agentvisor/env.launch/AV_GATEWAY_URL.override"
        self.assertEqual(env.read_text(), "https://gw.example/v1")
        self.env["VCAP_SERVICES"] = '{"postgres":[{"name":"agentvisor-db"}]}'
        self.assertEqual(self.run_script("build", cnb=True).returncode, 0)
        self.assertEqual(env.read_text(), "https://file.example")

    def test_malformed_vcap_never_falls_back(self):
        self.binding()
        for value in ("{", "[]", "{} {}", '{"agentvisor":{}}', '{"agentvisor":[null]}'):
            with self.subTest(value=value):
                self.env["VCAP_SERVICES"] = value
                self.assertEqual(self.run_script("detect", cnb=True).returncode, 1)
                self.assertEqual(self.run_script("supply").returncode, 1)

    def test_required_fields_reject_types_and_blank(self):
        for key in ("gateway_url", "audience"):
            for value in (None, 12, {}, [], True, " \n\t ", "x\x00y", "x\ny"):
                with self.subTest(key=key, value=value):
                    self.vcap(**{key: value})
                    self.assertNotEqual(self.run_script("supply").returncode, 0)
                    self.assertEqual(self.run_script("detect", cnb=True).returncode, 1)

    def test_optional_field_rejects_wrong_types(self):
        for value in (12, {}, [], True):
            self.vcap(identity_jwks_url=value)
            self.assertEqual(self.run_script("build", cnb=True).returncode, 1)
        for value in (None, "", " \n "):
            self.vcap(identity_jwks_url=value)
            self.assertEqual(self.run_script("build", cnb=True).returncode, 0)

    def test_ambiguity_rejected_in_both_sources(self):
        self.binding("one")
        self.binding("two")
        self.assertEqual(self.run_script("detect", cnb=True).returncode, 1)
        self.env["VCAP_SERVICES"] = json.dumps({"agentvisor": [{}, {}]})
        self.assertEqual(self.run_script("supply").returncode, 1)

    def test_type_with_embedded_nul_never_matches(self):
        self.binding(type="agent\x00visor")
        self.assertEqual(self.run_script("detect", cnb=True).returncode, 100)

    def test_whitespace_vcap_falls_through(self):
        self.env["VCAP_SERVICES"] = " \n\t "
        self.binding()
        self.assertEqual(self.run_script("detect", cnb=True).returncode, 0)

    def test_projected_symlinks_and_hidden_directories(self):
        self.binding(".hidden")
        self.assertEqual(self.run_script("detect", cnb=True).returncode, 100)
        (self.work / "bindings/projected").symlink_to(self.work / "bindings/.hidden", target_is_directory=True)
        self.assertEqual(self.run_script("detect", cnb=True).returncode, 0)
        self.assertEqual(self.run_script("supply").returncode, 0)

    def test_classic_without_sidecar_points_sdks_at_the_gateway(self):
        self.vcap(backends=["billing", "search"])
        result = self.run_script("supply")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("no sidecar binary", result.stdout)
        self.assertEqual(self.profile_values("OPENAI_BASE_URL", "OPENAI_API_BASE", "AGENTVISOR_MCP_URL",
                                             "AGENTVISOR_MCP_CONFIG", "OPENAI_API_KEY"),
                         ["https://gw.example/v1/v1", "https://gw.example/v1/v1", "https://gw.example/v1/mcp",
                          "/home/vcap/deps/0/agentvisor/mcp.json", ""])
        config = json.loads((self.work / "deps/0/agentvisor/mcp.json").read_text())
        self.assertEqual(config["mcpServers"], {
            "agentvisor": {"type": "http", "url": "https://gw.example/v1/mcp"},
            "agentvisor-billing": {"type": "http", "url": "https://gw.example/v1/mcp/billing"},
            "agentvisor-search": {"type": "http", "url": "https://gw.example/v1/mcp/search"},
        })
        self.assertFalse((self.work / "deps/0/launch.yml").exists())
        self.assertEqual(list((self.work / "app").iterdir()), [])

    def test_classic_with_sidecar_declares_it_and_routes_sdks_through_loopback(self):
        self.with_vendored_sidecar()
        self.vcap(audience="client's $(touch NOT_ALLOWED)")
        result = self.run_script("supply")
        self.assertEqual(result.returncode, 0, result.stderr)
        deps = self.work / "deps/0"
        self.assertTrue(os.access(deps / "bin/avctl", os.X_OK))
        self.assertEqual(self.profile_values("OPENAI_BASE_URL", "AGENTVISOR_MCP_URL", "OPENAI_API_KEY"),
                         ["http://127.0.0.1:8485/v1", "http://127.0.0.1:8485/mcp", "agentvisor-sidecar"])
        launch = (deps / "launch.yml").read_text()
        self.assertIn('type: "agentvisor-sidecar"', launch)
        self.assertIn('sidecar_for: ["web"]', launch)
        self.assertIn("/home/vcap/deps/0/bin/avctl sidecar --config /home/vcap/deps/0/agentvisor/sidecar.json",
                      launch)
        self.assertNotIn("client", launch, "binding values never appear on the command line")
        self.assertEqual(json.loads((deps / "agentvisor/sidecar.json").read_text()), {
            "gateway": "https://gw.example/v1", "audience": "client's $(touch NOT_ALLOWED)",
            "listen": "127.0.0.1:8485", "credential": "cf-instance"})
        self.assertFalse((self.work / "NOT_ALLOWED").exists())

    def test_an_existing_openai_key_is_kept_and_the_sidecar_can_be_disabled(self):
        self.with_vendored_sidecar()
        self.vcap(sidecar_port="9001")
        self.assertEqual(self.run_script("supply").returncode, 0)
        profile = self.work / "deps/0/profile.d/agentvisor.sh"
        result = subprocess.run(["sh", "-c", '. "$1"; printf "%s" "$OPENAI_API_KEY"', "sh", str(profile)],
                                text=True, capture_output=True, timeout=10,
                                env={"PATH": os.environ["PATH"], "OPENAI_API_KEY": "sk-real"})
        self.assertEqual(result.stdout, "sk-real")
        self.assertEqual(self.profile_values("OPENAI_BASE_URL"), ["http://127.0.0.1:9001/v1"])
        shutil.rmtree(self.work / "deps/0")
        self.vcap(sidecar=False)
        self.assertEqual(self.run_script("supply").returncode, 0)
        self.assertFalse((self.work / "deps/0/launch.yml").exists())
        self.assertEqual(self.profile_values("OPENAI_BASE_URL"), ["https://gw.example/v1/v1"])

    def test_cnb_without_an_explicit_sidecar_offers_the_process_but_uses_the_gateway(self):
        self.with_vendored_sidecar()
        self.binding()
        result = self.run_script("build", cnb=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        env = self.work / "layers/agentvisor/env.launch"
        self.assertEqual((env / "OPENAI_BASE_URL.override").read_text(), "https://file.example/v1")
        self.assertFalse((env / "OPENAI_API_KEY.default").exists())
        launch = tomllib.loads((self.work / "layers/launch.toml").read_text())
        self.assertEqual(launch["processes"][0]["type"], "agentvisor-sidecar")

    def test_cnb_sidecar_false_packages_nothing(self):
        self.with_vendored_sidecar()
        self.binding(sidecar="false")
        self.assertEqual(self.run_script("build", cnb=True).returncode, 0)
        self.assertFalse((self.work / "layers/launch.toml").exists())
        self.assertFalse((self.work / "layers/agentvisor/bin/avctl").exists())

    def test_cnb_with_sidecar_adds_a_process_type_and_launch_environment(self):
        self.with_vendored_sidecar()
        self.binding(backends="billing, search\nbilling\n", sidecar="true\n")
        result = self.run_script("build", cnb=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        layer = self.work / "layers/agentvisor"
        env = layer / "env.launch"
        self.assertEqual((env / "OPENAI_BASE_URL.override").read_text(), "http://127.0.0.1:8485/v1")
        self.assertEqual((env / "AGENTVISOR_MCP_CONFIG.override").read_text(), str(layer / "mcp.json"))
        self.assertEqual((env / "OPENAI_API_KEY.default").read_text(), "agentvisor-sidecar")
        servers = json.loads((layer / "mcp.json").read_text())["mcpServers"]
        self.assertEqual(sorted(servers), ["agentvisor", "agentvisor-billing", "agentvisor-search"])
        launch = tomllib.loads((self.work / "layers/launch.toml").read_text())
        self.assertEqual(launch["processes"][0]["type"], "agentvisor-sidecar")
        self.assertEqual(launch["processes"][0]["command"], [str(layer / "bin/avctl")])
        self.assertEqual(launch["processes"][0]["args"], ["sidecar", "--config", str(layer / "sidecar.json")])
        self.assertFalse(launch["processes"][0]["default"])
        self.assertEqual(json.loads((layer / "sidecar.json").read_text())["credential"],
                         "token-file:/var/run/secrets/agentvisor/token")

    def test_new_fields_are_validated(self):
        for field, value in (("backends", ["Bad Name"]), ("backends", [1]), ("backends", {}),
                             ("sidecar", "maybe"), ("sidecar_port", 80), ("sidecar_port", "x"),
                             ("sidecar_port", 70000)):
            with self.subTest(field=field, value=value):
                self.vcap(**{field: value})
                self.assertNotEqual(self.run_script("supply").returncode, 0)
        self.vcap(sidecar="FALSE", backends="a,b", sidecar_port=" 9000 ")
        self.assertEqual(self.run_script("supply").returncode, 0)


if __name__ == "__main__":
    unittest.main()
