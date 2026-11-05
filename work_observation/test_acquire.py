"""Real files and native systemd consumer tests; fixture jobs are never product work."""
import hashlib
import datetime
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest import mock
import uuid

HERE = Path(__file__).resolve().parent
s = importlib.util.spec_from_file_location("observe", HERE / "observe.py")
module = importlib.util.module_from_spec(s)
s.loader.exec_module(module)


def write(path, value):
    path.write_text(json.dumps(value))
    path.chmod(0o644)


class AcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="work-observation-fixture-", dir=HERE.parent)
        self.root = Path(self.temp.name)
        self.trusted = self.root / "trusted"
        self.worker = self.root / "worker"
        self.trusted.mkdir()
        self.worker.mkdir()
        self.unit = "work-observation-fixture-" + uuid.uuid4().hex + ".service"
        self.now = int(time.time())
        self.verified_at = datetime.datetime.fromtimestamp(self.now, datetime.timezone.utc).isoformat()
        self.binding = {"owner": str(self.trusted / "OWNER.json"),
                        "admission": str(self.trusted / "ADMISSION-RELEASED.json"),
                        "launch": str(self.trusted / "LAUNCH.json"),
                        "verification": str(self.trusted / "verification.json"),
                        "publication": str(self.trusted / "publication.json"),
                        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                        "progress_budget": 300, "max_age": 60}
        self.owner = {"job_id": "fixture-job", "state": "accepted_not_started", "accepted_at_epoch": self.now,
                      "updated_at_epoch": self.now, "deadline_at_epoch": self.now + 600,
                      "source": {"commit": "a" * 40, "capsule_sha256": "b" * 64},
                      "native_unit": self.unit, "admission": {"state": "BLOCKED", "reason": "fixture resource hold"},
                      "native_source_paths": {"cargo_messages": str(self.worker / "cargo.jsonl")},
                      "expected_output": {"package": str(self.worker / "artifact")}}
        self.path = self.trusted / "binding.json"
        write(self.trusted / "OWNER.json", self.owner)
        write(self.path, self.binding)

    def tearDown(self):
        subprocess.run(["systemctl", "stop", self.unit], capture_output=True, timeout=5)
        subprocess.run(["systemctl", "reset-failed", self.unit], capture_output=True, timeout=5)
        self.temp.cleanup()

    def acquire(self, previous=None):
        self.assertTrue(hasattr(module, "acquire"), "bounded native source getter must exist")
        return module.acquire(self.path, previous)

    def launch(self, finish=False):
        subprocess.run(["systemd-run", "--quiet", "--unit=" + self.unit, "-p", "RemainAfterExit=yes",
                        "-p", "CPUQuota=100%", "-p", "MemoryMax=64M", "-p", "RuntimeMaxSec=60",
                        *(["/usr/bin/true"] if finish else ["/usr/bin/sleep", "45"])], check=True, capture_output=True, timeout=5)
        iid = subprocess.check_output(["systemctl", "show", self.unit, "--value", "-p", "InvocationID"], text=True).strip()
        write(self.trusted / "LAUNCH.json", {"job_id": "fixture-job", "unit": self.unit,
              "at": self.verified_at,
              "source_commit": "a" * 40, "accepted_record_sha256": hashlib.sha256((self.trusted / "OWNER.json").read_bytes()).hexdigest(),
              "invocation_id": iid, "boot_id": self.binding["boot_id"]})
        return iid

    def test_real_missing_native_unit_is_accepted_blocked_not_no_work(self):
        acquired = self.acquire()
        self.assertTrue(acquired["source_ok"], acquired["errors"])
        self.assertEqual(acquired["native"]["LoadState"], "not-found")
        self.assertEqual(acquired["admission"], "BLOCKED")
        self.assertFalse(acquired["launch_present"])

    def test_actual_native_iid_and_boot_are_bound_not_pid_or_unit_name(self):
        self.launch()
        acquired = self.acquire()
        self.assertTrue(acquired["identity_matches"], acquired["errors"])
        self.assertGreater(int(acquired["native"]["MainPID"]), 0)
        self.binding["boot_id"] = "foreign-boot"
        write(self.path, self.binding)
        self.assertFalse(self.acquire()["identity_matches"])

    def test_cargo_prefix_and_complete_records_are_measured_not_mtime(self):
        self.launch()
        cargo = self.worker / "cargo.jsonl"
        cargo.write_text('{"reason":"compiler-artifact","package_id":"fixture-package"}\n')
        first = self.acquire()
        before = module.project(first)
        self.assertEqual(first["progress"]["compiler_artifacts"], 1)
        cargo.write_text(cargo.read_text() + '{"reason":"compiler-artifact","package_id":"fixture-second"}\n{"reason":')
        second = self.acquire(before)
        self.assertTrue(second["progress"]["prefix_matches"])
        self.assertEqual(second["progress"]["compiler_artifacts"], 2)
        cargo.write_text('{"reason":"compiler-artifact","package_id":"rewritten"}\n' * 3)
        self.assertFalse(self.acquire(before)["progress"]["prefix_matches"])

    def test_worker_controlled_verified_flag_cannot_become_independent_outcome(self):
        iid = self.launch(finish=True)
        artifact = self.worker / "artifact"
        artifact.write_bytes(b"fixture artifact")
        receipt = {"job_id": "fixture-job", "verified": True, "verified_at": self.verified_at, "source_commit": "a" * 40,
                   "source_capsule_sha256": "b" * 64, "package_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                   "native_producer": {"InvocationID": iid}, "scope": "Fixture artifact equality only"}
        write(self.worker / "verification.json", receipt)
        self.binding["verification"] = str(self.worker / "verification.json")
        write(self.path, self.binding)
        self.assertNotEqual(self.acquire()["verification"], "verified")

    def test_trusted_receipt_requires_actual_artifact_hash_and_source_binding(self):
        iid = self.launch(finish=True)
        artifact = self.worker / "artifact"
        artifact.write_bytes(b"fixture artifact")
        receipt = {"job_id": "fixture-job", "verified": True, "verified_at": self.verified_at, "source_commit": "a" * 40,
                   "source_capsule_sha256": "b" * 64, "package_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                   "native_producer": {"InvocationID": iid}, "scope": "Fixture artifact equality only"}
        write(self.trusted / "verification.json", receipt)
        self.assertEqual(self.acquire()["verification"], "verified")
        artifact.write_bytes(b"different bytes")
        self.assertNotEqual(self.acquire()["verification"], "verified")

    def test_trusted_receipt_for_still_running_native_worker_is_not_final_outcome(self):
        iid = self.launch()
        artifact = self.worker / "artifact"
        artifact.write_bytes(b"fixture artifact")
        write(self.trusted / "verification.json", {"job_id": "fixture-job", "verified": True, "verified_at": self.verified_at,
              "source_commit": "a" * 40, "source_capsule_sha256": "b" * 64,
              "package_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
              "native_producer": {"InvocationID": iid}, "scope": "Fixture artifact only"})
        self.assertNotEqual(self.acquire()["verification"], "verified")

    def test_cli_uses_existing_estate_status_consumer_and_bounded_history(self):
        self.launch()
        (self.worker / "cargo.jsonl").write_text('{"reason":"compiler-artifact"}\n')
        history = self.root / "history"
        history.mkdir(mode=0o700)
        argv = ["/usr/bin/python3", "-B", str(HERE / "observe.py"), "--binding", str(self.path),
                "--history", str(history / "previous.json")]
        first = subprocess.run(argv, check=True, capture_output=True, text=True, timeout=10)
        self.assertTrue(first.stdout.strip(), "CLI must emit its observation envelope")
        doc = json.loads(first.stdout)
        self.assertEqual(doc["schema"], "project.ops.status/v1")
        self.assertEqual((history / "previous.json").stat().st_mode & 0o777, 0o600)
        time.sleep(1.05)
        with (self.worker / "cargo.jsonl").open("a") as stream:
            stream.write('{"reason":"compiler-artifact"}\n')
        second = subprocess.run(argv, check=True, capture_output=True, text=True, timeout=10)
        states = {c["id"]: c["observation"]["domain_state"] for c in json.loads(second.stdout)["concerns"]}
        self.assertEqual(states["work.progress"], "ADVANCING")

    def test_native_launch_after_held_cli_history_preserves_unbreached_progress_duty(self):
        history = self.root / "history"
        history.mkdir(mode=0o700)
        argv = ["/usr/bin/python3", "-B", str(HERE / "observe.py"), "--binding", str(self.path),
                "--history", str(history / "previous.json")]
        held = json.loads(subprocess.check_output(argv, text=True, timeout=10))
        worker = next(c["observation"] for c in held["concerns"] if c["id"] == "work.worker")
        self.assertEqual(worker["domain_state"], "ACCEPTED_NOT_STARTED")
        self.launch()
        (self.worker / "cargo.jsonl").write_text('{"reason":"compiler-artifact"}\n')
        # Reuse the real estate consumer with the same persisted held history.
        spec = importlib.util.spec_from_file_location("estate_launch", HERE.parent / "estate/constellation-estate-collect.py")
        estate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(estate)
        report = estate.evaluate({"name": "fixture-launch-observer", "runtime": {"systemd": self.unit},
                                 "status": {"kind": "project-ops-status", "argv": argv}}, 12)
        self.assertEqual(report["verdict"], "OK", report)
        after = json.loads((history / "previous.json").read_text())
        progress = next(c["observation"] for c in after["concerns"] if c["id"] == "work.progress")
        self.assertEqual(progress["domain_state"], "UNKNOWN")
        self.assertEqual(progress["local_state"], "PRESENT")
        self.assertIsNone(after["extensions"]["progress_clock"]["last_advance_at"])

    def test_missing_binding_cli_returns_required_unknown_not_empty_concerns(self):
        result = subprocess.run(["/usr/bin/python3", "-B", str(HERE / "observe.py"),
                                 "--binding", str(self.trusted / "missing.json")],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.stdout.strip(), "CLI must emit required unknown observations")
        doc = json.loads(result.stdout)
        self.assertEqual(len(doc["concerns"]), 6)
        self.assertTrue(all(c["observation"]["local_state"] == "UNKNOWN" for c in doc["concerns"]))

    def test_malformed_observer_history_returns_explicit_unknown_not_traceback(self):
        history = self.root / "history"
        history.mkdir(mode=0o700)
        previous = history / "previous.json"
        write(previous, {"schema": "project.ops.status/v1", "producer": {"id": "monitor.native-build-observation"}, "extensions": []})
        result = subprocess.run(["/usr/bin/python3", "-B", str(HERE / "observe.py"),
                                 "--binding", str(self.path), "--history", str(previous)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        doc = json.loads(result.stdout)
        self.assertTrue(all(c["observation"]["local_state"] == "UNKNOWN" for c in doc["concerns"]))

    def test_future_verifier_receipt_cannot_verify_current_artifact(self):
        iid = self.launch(finish=True)
        artifact = self.worker / "artifact"
        artifact.write_bytes(b"fixture artifact")
        write(self.trusted / "verification.json", {"job_id": "fixture-job", "verified": True,
              "source_commit": "a" * 40, "source_capsule_sha256": "b" * 64,
              "package_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
              "verified_at": "2999-01-01T00:00:00+00:00",
              "native_producer": {"InvocationID": iid}, "scope": "Fixture artifact only"})
        self.assertNotEqual(self.acquire()["verification"], "verified")

    def test_artifact_growth_during_read_cannot_verify_only_its_original_prefix(self):
        artifact = self.worker / "artifact"
        artifact.write_bytes(b"original bytes")
        real_fdopen = os.fdopen

        # Deterministic concurrent-writer boundary: real file bytes and fstat;
        # only scheduling the append relative to the bounded read is controlled.
        class GrowingReader:
            def __init__(self, stream):
                self.stream = stream

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.stream.close()

            def fileno(self):
                return self.stream.fileno()

            def read(self, count):
                with artifact.open("ab") as writer:
                    writer.write(b"concurrent trailing bytes")
                return self.stream.read(count)

        with mock.patch.object(module.os, "fdopen", side_effect=lambda *args: GrowingReader(real_fdopen(*args))):
            with self.assertRaises(ValueError):
                module.read_file(artifact, 1024)

    def estate(self):
        s = importlib.util.spec_from_file_location("estate_consumer", HERE.parent / "estate/constellation-estate-collect.py")
        estate = importlib.util.module_from_spec(s)
        s.loader.exec_module(estate)
        return estate.evaluate({"name": "fixture-work-observer", "runtime": {"systemd": self.unit},
                               "status": {"kind": "project-ops-status", "argv": ["/usr/bin/python3", "-B",
                                          str(HERE / "observe.py"), "--binding", str(self.path)]}}, 12)

    def test_existing_estate_does_not_fail_first_running_capture_before_duty_is_due(self):
        self.launch()
        (self.worker / "cargo.jsonl").write_text('{"reason":"compiler-artifact"}\n')
        report = self.estate()
        self.assertEqual(report["verdict"], "OK", report)
        raw = module.project(self.acquire())
        self.assertEqual(next(c for c in raw["concerns"] if c["id"] == "work.progress")["observation"]["domain_state"], "UNKNOWN")
        self.assertIn("UNKNOWN", next(c for c in report["concerns"] if c["id"] == "work.outcome")["reason"])

    def test_existing_estate_accepts_visible_resource_hold_before_worker_launch(self):
        self.launch()  # Separate existing runtime for this fixture observer.
        (self.trusted / "LAUNCH.json").unlink()
        self.owner["native_unit"] = "not-started-" + self.unit
        write(self.trusted / "OWNER.json", self.owner)
        report = self.estate()
        self.assertEqual(report["verdict"], "OK", report)
        self.assertIn("BLOCKED", next(c for c in report["concerns"] if c["id"] == "work.admission")["reason"])

    def test_existing_estate_does_not_fail_native_success_while_verification_not_due(self):
        self.launch(finish=True)
        report = self.estate()
        self.assertEqual(report["verdict"], "OK", report)
        self.assertIn("UNKNOWN", next(c for c in report["concerns"] if c["id"] == "work.outcome")["reason"])

    def test_existing_estate_fails_fixed_deadline_without_verified_published_result(self):
        self.owner.update(accepted_at_epoch=self.now - 10, updated_at_epoch=self.now - 10, deadline_at_epoch=self.now - 1)
        write(self.trusted / "OWNER.json", self.owner)
        self.launch(finish=True)
        report = self.estate()
        self.assertEqual(report["verdict"], "DEGRADED", report)
        self.assertIn("work.publication", report["failing"])

    def test_existing_estate_fails_explicit_unsupported_completion_claim_before_deadline(self):
        self.owner["completion_claimed"] = True
        write(self.trusted / "OWNER.json", self.owner)
        self.launch(finish=True)
        report = self.estate()
        self.assertEqual(report["verdict"], "DEGRADED", report)
        self.assertIn("work.outcome", report["failing"])

    def test_identity_uses_exact_consumed_owner_bytes_instead_of_a_second_path_read(self):
        self.launch()
        original_reader = module.read_file
        replaced = False

        def replace_after_read(path, *args, **kwargs):
            nonlocal replaced
            raw = original_reader(path, *args, **kwargs)
            if Path(path) == self.trusted / "OWNER.json" and not replaced:
                replaced = True
                replacement = dict(self.owner)
                replacement["deadline_at_epoch"] += 1
                write(self.trusted / "OWNER.json", replacement)
            return raw

        with mock.patch.object(module, "read_file", side_effect=replace_after_read):
            acquired = self.acquire()
        self.assertTrue(acquired["identity_matches"], acquired["errors"])

    def test_missing_or_writable_owner_source_is_unknown_not_empty_work(self):
        (self.trusted / "OWNER.json").chmod(0o666)
        self.assertFalse(self.acquire()["source_ok"])
        (self.trusted / "OWNER.json").unlink()
        self.assertFalse(self.acquire()["source_ok"])


if __name__ == "__main__":
    unittest.main()
