#!/usr/bin/env python3
"""Exercise real buildpack scripts and their generated launch output."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
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

    def run_script(self, name, args=(), cnb=False):
        env = dict(self.env)
        if cnb:
            env.update(CNB_PLATFORM_DIR=str(self.work / "platform"),
                       CNB_LAYERS_DIR=str(self.work / "layers"))
        if name == "supply" and not args:
            args = [str(self.work / n) for n in ("app", "cache", "deps")] + ["0"]
        return subprocess.run([str(ROOT / "bin" / name)] + list(args), env=env,
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


if __name__ == "__main__":
    unittest.main()
