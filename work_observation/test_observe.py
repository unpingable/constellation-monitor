"""Consumer-visible projection tests; all sample sources are substitution fixtures.

These tests catch clearing an unsettled obligation from process/collector loss,
counting reads or touched files as progress, and trusting a worker's result flag.
They are not live job acceptance evidence.
"""
import copy
import importlib.util
import pathlib
import unittest

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("observe", HERE / "observe.py")
if spec.origin and pathlib.Path(spec.origin).exists():
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
else:
    module = None


def sample():
    return {
        "at": 1000, "source_ok": True, "errors": [], "sources": [],
        "owner": {"job_id": "job-1", "state": "accepted_not_started",
                  "accepted_at_epoch": 900, "deadline_at_epoch": 1200,
                  "updated_at_epoch": 900},
        "admission": "ADMITTED_AFTER_PREFLIGHT", "admission_at": 950,
        "identity": {"job_id": "job-1", "source_commit": "a" * 40,
                     "boot_id": "boot-1", "unit": "job-1.service", "invocation_id": "1" * 32},
        "launch_present": True, "identity_matches": True,
        "native": {"LoadState": "loaded", "ActiveState": "active", "SubState": "running",
                   "MainPID": "42", "InvocationID": "1" * 32, "Result": "success",
                   "ExecMainCode": "0", "ExecMainStatus": "0"},
        "progress": {"bytes": 20, "sha256": "b" * 64, "prefix_matches": True,
                     "compiler_artifacts": 2, "complete_lines": 2},
        "verification": "missing", "publication": "missing",
    }


class ProjectionTests(unittest.TestCase):
    def run_projection(self, current=None, previous=None, now=1000):
        self.assertIsNotNone(module, "read-only observation producer must exist")
        return module.project(current or sample(), previous, now)

    def states(self, result):
        return {c["id"]: c["observation"]["domain_state"] for c in result["concerns"]}

    def test_first_capture_does_not_invent_advancement(self):
        result = self.run_projection()
        self.assertEqual(self.states(result)["work.progress"], "UNKNOWN")
        self.assertEqual(self.states(result)["work.worker"], "RUNNING")
        self.assertEqual(self.states(result)["work.outcome"], "INDEPENDENT_OUTCOME_MISSING")

    def test_real_append_between_bound_captures_supports_progress(self):
        before = self.run_projection()
        current = sample()
        current["at"] = 1010
        current["progress"].update(bytes=40, sha256="c" * 64, compiler_artifacts=3, complete_lines=3)
        after = self.run_projection(current, before, 1010)
        self.assertEqual(self.states(after)["work.progress"], "ADVANCING")

    def test_reader_refresh_or_changed_mtime_does_not_extend_progress_budget(self):
        previous = self.run_projection()
        current = sample()
        current["at"] = 1010
        current["progress"].update(bytes=40, sha256="c" * 64, compiler_artifacts=3, complete_lines=3)
        previous = self.run_projection(current, previous, 1010)
        for at in (1020, 1100, 1320):
            current["at"] = at
            previous = self.run_projection(current, previous, at)
        self.assertEqual(self.states(previous)["work.progress"], "STALE_PROGRESS")

    def test_rewrite_counter_reset_or_identity_change_cannot_prove_progress(self):
        before = self.run_projection()
        for mutation in ("prefix", "reset", "identity"):
            current = sample()
            current["at"] = 1010
            current["progress"].update(bytes=40, compiler_artifacts=3, complete_lines=3, sha256="c" * 64)
            if mutation == "prefix":
                current["progress"]["prefix_matches"] = False
            elif mutation == "reset":
                current["progress"]["compiler_artifacts"] = 1
            else:
                current["identity"]["invocation_id"] = "2" * 32
            self.assertEqual(self.states(self.run_projection(current, before, 1010))["work.progress"], "UNKNOWN")

    def test_blocked_accepted_and_missing_worker_remain_distinct(self):
        current = sample()
        current["launch_present"] = False
        current["native"] = {"LoadState": "not-found"}
        current["admission"] = "BLOCKED"
        states = self.states(self.run_projection(current))
        self.assertEqual(states["work.admission"], "RESOURCE_BLOCKED")
        self.assertEqual(states["work.worker"], "ACCEPTED_NOT_STARTED")
        current["admission"] = "ADMITTED_AFTER_PREFLIGHT"
        self.assertEqual(self.states(self.run_projection(current))["work.worker"], "ACCEPTED_NOT_STARTED")
        current["launch_present"] = True
        self.assertEqual(self.states(self.run_projection(current))["work.worker"], "MISSING_BOUND_WORKER")

    def test_process_success_does_not_verify_output_or_publish(self):
        current = sample()
        current["native"].update(MainPID="0", ActiveState="active", SubState="exited", ExecMainCode="1")
        states = self.states(self.run_projection(current))
        self.assertEqual(states["work.worker"], "NATIVE_SUCCEEDED")
        self.assertEqual(states["work.outcome"], "NATIVE_SUCCESS_OUTCOME_UNKNOWN")
        self.assertEqual(next(c for c in self.run_projection(current)["concerns"] if c["id"] == "work.outcome")["observation"]["local_state"], "PRESENT")
        self.assertEqual(states["work.publication"], "RESULT_NOT_PUBLISHED")

    def test_independent_verification_and_publication_are_distinct(self):
        current = sample()
        current["verification"] = "verified"
        self.assertEqual(self.states(self.run_projection(current))["work.outcome"], "ARTIFACT_VERIFIED")
        self.assertEqual(self.states(self.run_projection(current))["work.publication"], "RESULT_NOT_PUBLISHED")
        current["publication"] = "published"
        self.assertEqual(self.states(self.run_projection(current))["work.publication"], "RESULT_PUBLISHED")

    def test_source_loss_or_substituted_worker_never_discharges_obligation(self):
        for field in ("source_ok", "identity_matches"):
            current = sample()
            current[field] = False
            states = self.states(self.run_projection(current))
            self.assertNotEqual(states["work.obligation"], "NO_ASSIGNED_WORK")
            self.assertEqual(states["work.outcome"], "UNKNOWN")

    def test_explicit_no_work_requires_fresh_source(self):
        current = sample()
        current["owner"] = {"state": "no_assigned_work", "updated_at_epoch": 990}
        self.assertEqual(self.states(self.run_projection(current))["work.obligation"], "NO_ASSIGNED_WORK")
        current["owner"]["updated_at_epoch"] = 1
        self.assertEqual(self.states(self.run_projection(current))["work.obligation"], "UNKNOWN")

    def test_old_or_future_capture_is_unknown_even_if_verified(self):
        for at in (1, 1001):
            current = sample()
            current.update(at=at, verification="verified", publication="published")
            states = self.states(self.run_projection(current))
            self.assertEqual(states["work.outcome"], "UNKNOWN")

    def test_existing_estate_consumer_accepts_full_envelope(self):
        result = self.run_projection()
        collector = HERE.parent / "estate/constellation-estate-collect.py"
        s = importlib.util.spec_from_file_location("estate", collector)
        estate = importlib.util.module_from_spec(s)
        s.loader.exec_module(estate)
        estate.validate_status(result)
        self.assertEqual(result["schema"], "project.ops.status/v1")
        self.assertTrue(all(c["required"] for c in result["concerns"]))
        self.assertTrue(all("sources" in c["observation"]["facts"] for c in result["concerns"]))


if __name__ == "__main__":
    unittest.main()
