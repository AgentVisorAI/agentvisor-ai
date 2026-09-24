#!/usr/bin/env python3
"""Tests for scripts/package-buildpack.py, using stub ELF binaries."""
import hashlib
import importlib.util
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile

SPEC = importlib.util.spec_from_file_location("package_buildpack", Path(__file__).with_name("package-buildpack.py"))
package = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(package)


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="av-package-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)

    def stub(self, name, data=b"\x7fELF stub avctl"):
        path = self.work / name
        path.write_bytes(data)
        return str(path)

    def test_packages_include_binaries_with_exec_bits_and_exclude_tests(self):
        out = self.work / "dist"
        self.assertEqual(package.main(["--avctl-x86_64", self.stub("x"), "--avctl-aarch64", self.stub("a"),
                                       "--output", str(out)]), 0)
        version = package.version()
        zipped = out / f"agentvisor-buildpack-{version}.zip"
        with zipfile.ZipFile(zipped) as archive:
            names = archive.namelist()
            modes = {info.filename: (info.external_attr >> 16) & 0o777 for info in archive.infolist()}
        self.assertIn("bin/supply", names)
        self.assertIn("lib/outputs.sh", names)
        self.assertIn("vendor/avctl-linux-x86_64", names)
        self.assertIn("vendor/avctl-linux-aarch64", names)
        self.assertFalse(any(name.startswith("tests/") for name in names))
        self.assertEqual(modes["bin/supply"], 0o755)
        self.assertEqual(modes["vendor/avctl-linux-x86_64"], 0o755)
        self.assertEqual(modes["lib/binding.sh"], 0o644)
        with tarfile.open(out / f"agentvisor-buildpack-{version}.tgz") as archive:
            members = {member.name: member.mode for member in archive.getmembers()}
        self.assertEqual(members["bin/build"], 0o755)
        self.assertIn("buildpack.toml", members)
        digest, name = (out / f"{zipped.name}.sha256").read_text().split()
        self.assertEqual(name, zipped.name)
        self.assertEqual(digest, hashlib.sha256(zipped.read_bytes()).hexdigest())

    def test_non_linux_binaries_and_missing_binaries_are_refused(self):
        with self.assertRaises(SystemExit):
            package.main(["--avctl-x86_64", self.stub("mac", b"\xcf\xfa\xed\xfe macho"), "--output",
                          str(self.work / "dist")])
        with self.assertRaises(SystemExit):
            package.main(["--output", str(self.work / "dist")])


if __name__ == "__main__":
    unittest.main()
