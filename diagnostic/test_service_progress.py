import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch
import urllib.parse
import urllib.request


spec = importlib.util.spec_from_file_location("service_diagnostic", Path(__file__).with_name("constellation-diagnostic.py"))
diagnostic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnostic)
NOW = 1792454400
TIMES = list(range(NOW - 900, NOW + 1, 60))
WORK = "service_last_success_timestamp_seconds"
OBSERVATION = "service_observation_timestamp_seconds"
LABELS = {"site": "fixture-site", "service": "worker", "instance": "127.0.0.1:18080", "job": "service-worker"}
SUBJECT = "service:worker:useful-work"


def matrix(name, values):
    metric = dict(LABELS)
    if name:
        metric["__name__"] = name
    return {"status": "success", "data": {"resultType": "matrix", "result": [
        {"metric": metric, "values": [[t, str(v)] for t, v in zip(TIMES, values)]}]}}


class ServiceProgressTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.registry = {"schema": "constellation.estate_registry/v1", "site": "fixture-site", "services": [
            {"name": "worker", "role": "worker", "runtime": {"systemd": "worker.service"},
             "thresholds": {"last_success_age_seconds": 180, "metrics_observation_age_seconds": 120}}]}
        self.responses = {
            (False, WORK): matrix(WORK, [t - 5 for t in TIMES]),
            (False, OBSERVATION): matrix(OBSERVATION, [t - 1 for t in TIMES]),
            (True, WORK): matrix(None, [t - 1 for t in TIMES]),
            (True, OBSERVATION): matrix(None, [t - 1 for t in TIMES]),
        }

    def investigate(self, extra=()):
        seen = []
        responses = self.responses

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/health":
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"ok")
                    return
                seen.append(self.path)
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)["query"][0]
                family = next((name for name in (WORK, OBSERVATION) if name in query), None)
                document = responses.get((query.startswith("timestamp("), family),
                                         {"status": "success", "data": {"resultType": "matrix", "result": []}})
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps(document).encode())

            def log_message(self, *args):
                pass

        with HTTPServer(("127.0.0.1", 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            try:
                base = f"http://127.0.0.1:{server.server_port}"
                self.registry["services"][0]["health_url"] = base + "/health"
                with urllib.request.urlopen(base + "/health", timeout=3) as response:
                    self.assertEqual(response.status, 200)
                (self.root / "registry.json").write_text(json.dumps(self.registry))
                (self.root / "attention.json").write_text(json.dumps({"schema": "constellation.attention_report.v1",
                    "evaluated_at": "2026-10-20T00:00:00Z", "conditions": []}))
                record = self.root / "record.json"
                if record.exists():
                    record.unlink()
                argv = ["--registry", str(self.root / "registry.json"), "--attention", str(self.root / "attention.json"),
                        "--vm-url", base, "--service", "worker", "--instance", LABELS["instance"],
                        "--job", LABELS["job"], "--record", str(record), *extra]
                with patch.object(diagnostic.time, "time", return_value=NOW), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(diagnostic.main(argv), 0)
                return json.loads(record.read_text()), seen
            finally:
                server.shutdown()
                thread.join()

    def findings(self, result, bin_name):
        return [finding for finding in result["bins"][bin_name] if finding["subject"] == SUBJECT]

    def test_active_http_healthy_worker_with_overdue_useful_work_is_identified(self):
        self.responses[(False, WORK)] = matrix(WORK, [NOW - 900] * len(TIMES))
        def unit_reader(argv):
            return b"LoadState=loaded\nActiveState=active\nSubState=running\nResult=success\n" if argv[0] == "systemctl" else b""
        with patch.object(diagnostic, "command", side_effect=unit_reader):
            result, seen = self.investigate(["--local-readers"])
        findings = self.findings(result, "probably_wrong")
        self.assertEqual(len(findings), 1)
        self.assertIn("useful work", findings[0]["statement"].lower())
        self.assertIn("180", findings[0]["statement"])
        self.assertFalse(self.findings(result, "checked_not_wrong_within_scope"))
        self.assertEqual(len(seen), 4)
        sources = {source["id"]: source for source in result["sources"]}
        for identity in findings[0]["evidence"]:
            self.assertIn("sha256", sources[identity])

    def test_fresh_advancing_work_is_scoped_progress_with_exact_queries(self):
        result, seen = self.investigate()
        self.assertEqual(len(self.findings(result, "checked_not_wrong_within_scope")), 1)
        self.assertFalse(self.findings(result, "probably_wrong"))
        self.assertEqual(result["asked"]["mode"], "service")
        self.assertEqual(len(seen), 4)
        for path in seen:
            url = urllib.parse.urlsplit(path)
            self.assertEqual(url.path, "/api/v1/query_range")
            params = urllib.parse.parse_qs(url.query)
            for key, value in LABELS.items():
                self.assertIn(key + "=" + json.dumps(value), params["query"][0])
            self.assertEqual(params["start"], [str(NOW - 900)])
            self.assertEqual(params["end"], [str(NOW)])

    def test_missing_stale_future_and_incomplete_observations_remain_unknown(self):
        cases = []
        empty = matrix(OBSERVATION, [])
        cases.append(((False, OBSERVATION), empty))
        cases.append(((False, OBSERVATION), matrix(OBSERVATION, [t - 600 for t in TIMES])))
        cases.append(((False, WORK), matrix(WORK, [t + 60 for t in TIMES])))
        cases.append(((True, WORK), matrix(None, [t - 600 for t in TIMES])))
        cases.append(((True, OBSERVATION), matrix(None, [t + 60 for t in TIMES])))
        cases.append(((False, WORK), matrix(WORK, ["NaN"] * len(TIMES))))
        boolean = matrix(WORK, [t - 5 for t in TIMES])
        for pair in boolean["data"]["result"][0]["values"]:
            pair[1] = True
        cases.append(((False, WORK), boolean))
        gapped = matrix(WORK, [t - 5 for t in TIMES])
        gapped["data"]["result"][0]["values"][3:8] = []
        cases.append(((False, WORK), gapped))
        for key, document in cases:
            old = self.responses[key]
            self.responses[key] = document
            with self.subTest(key=key, document=document):
                result, _ = self.investigate()
                self.assertTrue(self.findings(result, "unknown"))
                self.assertFalse(self.findings(result, "checked_not_wrong_within_scope"))
                self.assertFalse(self.findings(result, "probably_wrong"))
            self.responses[key] = old

    def test_wrong_target_duplicate_series_and_reset_are_unknown(self):
        original = self.responses[(False, WORK)]
        for label in LABELS:
            wrong = json.loads(json.dumps(original))
            wrong["data"]["result"][0]["metric"][label] = "other"
            self.responses[(False, WORK)] = wrong
            result, _ = self.investigate()
            self.assertTrue(self.findings(result, "unknown"), label)
            self.assertFalse(self.findings(result, "probably_wrong"), label)
        duplicate = json.loads(json.dumps(original))
        duplicate["data"]["result"] *= 2
        reset = matrix(WORK, [t - 5 for t in TIMES])
        reset["data"]["result"][0]["values"][8][1] = "0"
        for document in (duplicate, reset):
            self.responses[(False, WORK)] = document
            result, _ = self.investigate()
            self.assertTrue(self.findings(result, "unknown"))
            self.assertFalse(self.findings(result, "checked_not_wrong_within_scope"))

    def test_quiet_window_inside_authored_budget_is_not_a_stall_claim(self):
        self.registry["services"][0]["thresholds"]["last_success_age_seconds"] = 1800
        self.responses[(False, WORK)] = matrix(WORK, [NOW - 900] * len(TIMES))
        result, _ = self.investigate()
        self.assertTrue(self.findings(result, "unknown"))
        self.assertFalse(self.findings(result, "probably_wrong"))
        self.assertFalse(self.findings(result, "checked_not_wrong_within_scope"))

    def test_fractionally_future_application_timestamp_is_not_current_evidence(self):
        with self.assertRaises(ValueError):
            diagnostic.service_history(matrix(WORK, [t + 0.5 for t in TIMES]), LABELS, NOW, 900, WORK)

    def test_missing_or_unsupported_declared_limits_are_unknown_without_metric_queries(self):
        for limits in ({}, {"last_success_age_seconds": True, "metrics_observation_age_seconds": 120},
                       {"last_success_age_seconds": 180, "metrics_observation_age_seconds": -1}):
            self.registry["services"][0]["thresholds"] = limits
            result, seen = self.investigate()
            self.assertTrue(self.findings(result, "unknown"))
            self.assertEqual(seen, [])

    def test_local_context_is_limited_to_the_selected_service(self):
        self.registry["services"].insert(0, {"name": "unrelated", "runtime": {"systemd": "unrelated.service"}})
        commands = []
        def reader(argv):
            commands.append(argv)
            return b"ActiveState=active\n" if argv[0] == "systemctl" else b""
        with patch.object(diagnostic, "command", side_effect=reader):
            result, _ = self.investigate(["--local-readers"])
        self.assertTrue(self.findings(result, "checked_not_wrong_within_scope"))
        self.assertEqual([argv[-1] for argv in commands if argv[0] == "systemctl"], ["worker.service"])


if __name__ == "__main__":
    unittest.main()
