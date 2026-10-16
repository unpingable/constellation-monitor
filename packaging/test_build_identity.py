"""Exercise the package identity contract with local executable fixtures."""

import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import subprocess
import tarfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "identity", Path(__file__).with_name("record-build-identity.py"))
identity = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(identity)
COMMIT = "0123456789abcdef0123456789abcdef01234567"


class PackageIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        env = patch.dict(os.environ, {"MONITOR_SOURCE_COMMIT": COMMIT,
                                     "MONITOR_BUILD_IDENTITY": "jammy-001",
                                     "CONSTELLATION_HOST_POSTURE_SOURCE_TREE_DIGEST": "sha256:"+"a"*64,
                                     "CONSTELLATION_HOST_POSTURE_CARGO_LOCK_DIGEST": "sha256:"+"b"*64})
        env.start()
        self.addCleanup(env.stop)
        self.info = {}
        for name in identity.BINARIES:
            self.info[name] = {
                "schema": "constellation.host_posture_helper.build_info.v1", "component": name, "version": "0.1.0",
                "source_commit": COMMIT, "build_id": "jammy-001",
                "rustc": "rustc 1.95.0 (fixture)", "target": "x86_64-unknown-linux-gnu",
                "debug_assertions": False,
            }
            self.write_fixture(name)
        self.info["constellation-host-posture"] = {
            "schema": "constellation.host_posture.build_info.v1", "component": "constellation-host-posture",
            "version": "0.1.0", "source_repository": "constellation-monitor", "source_commit": COMMIT,
            "source_tree_digest": "sha256:"+"a"*64, "cargo_lock_digest": "sha256:"+"b"*64,
            "toolchain_identity": "rustc 1.95.0 (fixture)", "target_triple": "x86_64-unknown-linux-gnu",
            "build_profile": "release", "enabled_features_json": "[]",
        }
        self.write_fixture("constellation-host-posture")
        for name in identity.ALIASES:
            (self.root/name).symlink_to("pulse-nq-load-support")

    def write_fixture(self, name, mutate=False):
        # Each executable is a local fixture; it reads no state or enrollment.
        program = "#!/usr/bin/env python3\nimport sys\n"
        program += "assert sys.argv[1:] == ['--build-info']\n"
        program += "from pathlib import Path\nimport json\ninfo=json.loads(" + repr(json.dumps(self.info[name])) + ")\n"
        program += "name=Path(sys.argv[0]).name\nif name in " + repr(identity.ALIASES) + ": info['component']=name\nprint(json.dumps(info))\n"
        if mutate:
            program += "from pathlib import Path\np=Path(__file__)\np.write_text(p.read_text()+'#changed\\n')\n"
        path = self.root / name
        path.write_text(program)
        path.chmod(0o755)

    def receipt(self, arch="amd64"):
        return identity.record(self.root, "0.1.0+test.1", arch)

    def test_records_exact_staged_bytes_and_complete_cohort(self):
        receipt = self.receipt()
        self.assertEqual(receipt["source_commit"], COMMIT)
        self.assertEqual(receipt["build_id"], "jammy-001")
        self.assertEqual(set(receipt["executables"]), set(identity.BINARIES) | {"constellation-host-posture"})
        for name, item in receipt["executables"].items():
            self.assertEqual(item["sha256"], hashlib.sha256((self.root/name).read_bytes()).hexdigest())

    def test_missing_or_mismatched_executable_identity_is_refused(self):
        name = identity.BINARIES[-1]
        for field, value in [("source_commit", None), ("source_commit", "f"*40),
                             ("build_id", None), ("build_id", "different-build"),
                             ("component", "another-binary"), ("schema", "other.v1"),
                             ("version", "0.9.0"), ("rustc", None),
                             ("target", "aarch64-unknown-linux-gnu"),
                             ("debug_assertions", "false")]:
            with self.subTest(field=field, value=value):
                original = self.info[name][field]
                self.info[name][field] = value
                self.write_fixture(name)
                with self.assertRaises(ValueError):
                    self.receipt()
                self.info[name][field] = original

    def test_mixed_build_profile_and_toolchain_are_refused(self):
        name = identity.BINARIES[-1]
        for field, value in [("rustc", "rustc other"), ("debug_assertions", True)]:
            with self.subTest(field=field):
                original = self.info[name][field]
                self.info[name][field] = value
                self.write_fixture(name)
                with self.assertRaisesRegex(ValueError, "inconsistent"):
                    self.receipt()
                self.info[name][field] = original

    def test_owner_stamp_and_role_aliases_must_match_the_staged_helpers(self):
        for field in ["source_commit", "toolchain_identity", "source_tree_digest", "build_profile"]:
            with self.subTest(field=field):
                old = self.info["constellation-host-posture"][field]
                self.info["constellation-host-posture"][field] = "unavailable"
                self.write_fixture("constellation-host-posture")
                with self.assertRaises(ValueError): self.receipt()
                self.info["constellation-host-posture"][field] = old
        self.write_fixture("constellation-host-posture")
        alias = self.root / identity.ALIASES[0]
        alias.unlink(); alias.symlink_to("constellation-status")
        with self.assertRaisesRegex(ValueError, "alias target"): self.receipt()

    def test_assembly_requires_explicit_expected_identity(self):
        for variable, value in [("MONITOR_SOURCE_COMMIT", ""), ("MONITOR_SOURCE_COMMIT", "HEAD"),
                                ("MONITOR_BUILD_IDENTITY", ""), ("MONITOR_BUILD_IDENTITY", "line\nbreak")]:
            with self.subTest(variable=variable, value=value), patch.dict(os.environ, {variable: value}):
                with self.assertRaises(ValueError):
                    self.receipt()

    def test_staged_content_mutation_during_probe_is_refused(self):
        self.write_fixture(identity.BINARIES[-1], mutate=True)
        with self.assertRaisesRegex(ValueError, "changed"):
            self.receipt()

    def test_package_architecture_mismatch_is_refused(self):
        with self.assertRaisesRegex(ValueError, "architecture"):
            self.receipt("arm64")

    def test_package_receipt_matches_the_actual_staged_payload(self):
        output_dir = self.root / "output"
        builder = Path(__file__).with_name("build-deb.sh")
        result = subprocess.run(["bash", str(builder), "0.1.0+test.1", "amd64",
                                 str(self.root), str(output_dir)],
                                cwd="/", capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        stem = output_dir / "constellation-host-posture_0.1.0+test.1_amd64"
        receipt = json.loads(Path(str(stem) + ".build-identity.json").read_text())
        package = Path(str(stem) + ".deb")
        tar = subprocess.run(["dpkg-deb", "--fsys-tarfile", str(package)],
                             capture_output=True, check=True).stdout
        with tarfile.open(fileobj=io.BytesIO(tar)) as payload:
            embedded = json.load(payload.extractfile(
                "./usr/share/doc/constellation-host-posture/build-identity.json"))
            self.assertEqual(embedded, receipt)
            for name, item in receipt["executables"].items():
                executable = payload.extractfile("./usr/bin/" + name).read()
                self.assertEqual(hashlib.sha256(executable).hexdigest(), item["sha256"])
        expected = hashlib.sha256(package.read_bytes()).hexdigest()
        self.assertEqual(Path(str(package) + ".sha256").read_text().split()[0], expected)

    def test_package_assembly_refuses_an_unknown_build_without_emitting_a_package(self):
        output_dir = self.root / "refused-output"
        builder = Path(__file__).with_name("build-deb.sh")
        with patch.dict(os.environ, {"MONITOR_SOURCE_COMMIT": ""}):
            result = subprocess.run(["bash", str(builder), "0.1.0+test.1", "amd64",
                                     str(self.root), str(output_dir)], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(list(output_dir.glob("*.deb")))
        self.assertFalse(list(output_dir.glob(".stage.*")))


if __name__ == "__main__":
    unittest.main()
