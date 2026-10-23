import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("diagnostic", Path(__file__).with_name("constellation-diagnostic.py"))
diagnostic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnostic)
NOW = 1792454400


def matrix(value, times=None):
    return {"status": "success", "data": {"resultType": "matrix", "result": [
        {"metric": {}, "values": [[t, str(value)] for t in (times if times is not None else range(NOW - 900, NOW + 1, 60))]}]}}


class DiagnosticTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.write("registry.json", {"schema": "constellation.estate_registry/v1", "site": "fixture-site", "services": []})
        self.write("attention.json", {"schema": "constellation.attention_report.v1", "evaluated_at": "2026-10-20T00:00:00Z", "conditions": []})
        for name in diagnostic.QUERIES:
            fixture = Path(__file__).parent / "fixtures" / "swap-occupied" / (name + ".json")
            self.write(name + ".json", json.loads(fixture.read_text()))

    def write(self, name, document):
        (self.root / name).write_text(json.dumps(document))

    def run_diagnostic(self, extra=()):
        argv = ["--registry", str(self.root / "registry.json"), "--attention", str(self.root / "attention.json"),
                "--metrics-fixture", str(self.root), "--instance", "fixture:9100", "--job", "node",
                "--record", str(self.root / "record.json"), *extra]
        with patch.object(diagnostic.time, "time", return_value=NOW), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(diagnostic.main(argv), 0)
        return json.loads((self.root / "record.json").read_text())

    def test_swap_occupied_without_paging_or_psi_is_not_pressure(self):
        result = self.run_diagnostic()
        finding = result["bins"]["checked_not_wrong_within_scope"][0]
        self.assertIn("not pressure", finding["statement"])
        self.assertEqual(len(finding["evidence"]), len(diagnostic.QUERIES))
        self.assertEqual(set(result["bins"]), set(diagnostic.BINS))
        self.assertEqual(result["asked"]["mode"], "host-sweep")
        self.assertTrue(all("sha256" in s for s in result["sources"]))
        self.assertEqual((self.root / "record.json").stat().st_mode & 0o777, 0o600)

    def test_insufficient_history_cannot_clear(self):
        self.write("memory_psi_ratio.json", matrix(0, []))
        result = self.run_diagnostic(["--condition", "host.memory_pressure"])
        self.assertFalse(result["bins"]["checked_not_wrong_within_scope"])
        self.assertTrue(any("insufficient history" in f["statement"] for f in result["bins"]["unknown"]))

    def test_gaps_stale_future_and_nan_cannot_clear(self):
        cases = [matrix(0, [NOW - 900, NOW]), matrix(0, range(NOW - 1800, NOW - 900, 60)),
                 matrix(0, range(NOW - 840, NOW + 61, 60)), matrix("NaN")]
        for document in cases:
            with self.subTest(document=document):
                with self.assertRaises(ValueError):
                    diagnostic.history(document, NOW, 900)

    def test_paging_is_a_symptom_not_root_cause(self):
        self.write("paging_pages_per_second.json", matrix(10))
        result = self.run_diagnostic()
        self.assertEqual(result["bins"]["probably_wrong"][0]["subject"], "host.memory_pressure")
        self.assertFalse(result["bins"]["wrong"])

    def test_missing_metric_is_unknown(self):
        (self.root / "memory_psi_ratio.json").unlink()
        result = self.run_diagnostic()
        self.assertTrue(result["bins"]["unknown"])
        self.assertFalse(result["bins"]["checked_not_wrong_within_scope"])

    def test_attention_delivery_failure_is_named_independently_of_conditions(self):
        for code, exit_class in [(4, "delivery_failed"), (4, "delivery_partial"), (4, "intent_log_unwritable"), (3, "input_error")]:
            with self.subTest(exit_class=exit_class):
                delivery_class = "clean" if exit_class == "intent_log_unwritable" else "delivery_partial"
                outcome = "accepted" if delivery_class == "clean" else "failed"
                self.write("attention.json", {"schema": "constellation.attention_report.v1", "evaluated_at": "2026-10-20T00:00:00Z",
                                             "conditions": [], "exit_code": code, "exit_class": exit_class,
                                             "delivery_class": delivery_class, "delivery": {"operations": {"outcome": outcome, "last_attempt_at": "2026-10-20T00:00:00Z"}, "page": {"outcome": "accepted", "last_attempt_at": "2026-10-19T00:00:00Z"}}})
                result = self.run_diagnostic()
                finding = next(f for f in result["bins"]["probably_wrong"] if f["subject"].startswith("attention."))
                self.assertIn(exit_class, finding["statement"])
                self.assertIn(delivery_class, finding["statement"])
                self.assertIn("operations", finding["statement"])
                self.assertIn("last_attempt_at", finding["statement"])
                self.assertIn(outcome, finding["statement"])
                self.assertFalse(result["bins"]["wrong"])
                (self.root / "record.json").unlink()

    def test_attention_pending_present_does_not_clear(self):
        self.write("attention.json", {"schema": "constellation.attention_report.v1", "evaluated_at": "2026-10-20T00:00:00Z",
                                     "conditions": [{"id": "site:test", "active": False, "observation": "present"}]})
        result = self.run_diagnostic(["--condition", "site:test"])
        self.assertEqual(len(result["bins"]["probably_wrong"]), 1)
        self.assertFalse(result["bins"]["checked_not_wrong_within_scope"])

    def test_attention_stale_active_is_unknown(self):
        self.write("attention.json", {"schema": "constellation.attention_report.v1", "evaluated_at": "2026-10-19T00:00:00Z",
                                     "conditions": [{"id": "site:test", "active": True, "observation": "present"}]})
        result = self.run_diagnostic(["--condition", "site:test"])
        self.assertFalse(result["bins"]["wrong"])
        self.assertTrue(any("stale" in f["statement"] for f in result["bins"]["unknown"]))

    def test_attention_active_clear_unknown_and_removed_remain_distinct(self):
        self.write("attention.json", {"schema": "constellation.attention_report.v1", "evaluated_at": "2026-10-20T00:00:00Z",
                                     "conditions": [{"id": state, "active": True, "observation": state}
                                                    for state in ("present", "clear", "unknown", "removed")]})
        result = self.run_diagnostic()
        self.assertEqual([f["subject"] for f in result["bins"]["wrong"]], ["present"])
        self.assertIn("clear", [f["subject"] for f in result["bins"]["checked_not_wrong_within_scope"]])
        self.assertTrue({"unknown", "removed"}.issubset({f["subject"] for f in result["bins"]["unknown"]}))

    def test_incident_inspection_is_history_not_current_health(self):
        self.write("incidents.json", {"schema": "constellation.incidents.inspection/v1", "read_at": "2026-10-20T00:00:00Z",
                                     "incidents": [{"incident": {"id": "inc-fixture", "key": "fixture", "state": "open"}}]})
        result = self.run_diagnostic(["--condition", "fixture", "--incidents", str(self.root / "incidents.json")])
        self.assertEqual(result["bins"]["probably_wrong"][0]["subject"], "inc-fixture")
        self.assertFalse(result["bins"]["checked_not_wrong_within_scope"])

    def test_no_registry_command_is_executed(self):
        self.write("registry.json", {"schema": "constellation.estate_registry/v1", "services": [
            {"name": "fixture", "runtime": {"systemd": "bad;touch.service"}, "status": {"argv": ["false"]}}]})
        with patch.object(diagnostic, "command", side_effect=AssertionError("command executed")):
            self.run_diagnostic(["--local-readers"])

    def test_record_is_exclusive(self):
        self.run_diagnostic()
        original = (self.root / "record.json").read_bytes()
        with self.assertRaises(SystemExit) as result:
            self.run_diagnostic()
        self.assertEqual(result.exception.code, 3)
        self.assertEqual((self.root / "record.json").read_bytes(), original)

    def test_oversize_source_is_unknown(self):
        (self.root / "registry.json").write_bytes(b"x" * (diagnostic.LIMIT + 1))
        result = self.run_diagnostic()
        self.assertTrue(any("limit" in f["statement"] for f in result["bins"]["unknown"]))

    def test_subprocess_timeout_and_capture_limit(self):
        with self.assertRaises(ValueError):
            diagnostic.command([sys.executable, "-c", "import time; time.sleep(10)"], timeout=0.05)
        with self.assertRaises(ValueError):
            diagnostic.command([sys.executable, "-c", "import sys; sys.stdout.write('x'*2000000)"], timeout=3)

    def test_external_vm_rejected_before_network(self):
        for url in ("http://example.com", "http://192.0.2.1:8428", "http://user:pass@127.0.0.1:8428", "https://127.0.0.1:8428"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                diagnostic.vm_query(url, "up", NOW, 900)

    def test_loopback_vm_query_range_contract(self):
        seen = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps(matrix(0)).encode())

            def log_message(self, *args):
                pass

        with HTTPServer(("127.0.0.1", 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            try:
                data = diagnostic.vm_query(f"http://127.0.0.1:{server.server_port}", "sum(up)", NOW, 900)
                self.assertEqual(diagnostic.history(json.loads(data), NOW, 900), [0] * 16)
                self.assertIn("/api/v1/query_range?query=sum%28up%29", seen[0])
            finally:
                server.shutdown()
                thread.join()

    def test_old_underlying_samples_do_not_clear(self):
        self.write("metric_source_age_seconds.json", matrix(600))
        result = self.run_diagnostic()
        self.assertFalse(result["bins"]["checked_not_wrong_within_scope"])

    def test_missing_constituent_family_cannot_clear(self):
        doc = json.loads((self.root / "required_families.json").read_text())
        doc["data"]["result"].pop()
        self.write("required_families.json", doc)
        result = self.run_diagnostic()
        self.assertFalse(result["bins"]["checked_not_wrong_within_scope"])
        self.assertTrue(any("family missing" in f["statement"] for f in result["bins"]["unknown"]))

    def test_mixed_target_or_duplicate_site_cannot_clear(self):
        original = json.loads((self.root / "required_families.json").read_text())
        for label, value in (("instance", "other:9100"), ("job", "other"), ("site", "other-site")):
            doc = json.loads(json.dumps(original))
            doc["data"]["result"][0]["metric"][label] = value
            with self.subTest(label=label), self.assertRaises(ValueError):
                diagnostic.required_families(doc, "fixture:9100", "node", "fixture-site", NOW, 900)
        doc = json.loads(json.dumps(original))
        extra = json.loads(json.dumps(doc["data"]["result"][0]))
        extra["metric"]["site"] = "other-site"
        doc["data"]["result"].append(extra)
        self.write("required_families.json", doc)
        result = self.run_diagnostic()
        self.assertFalse(result["bins"]["checked_not_wrong_within_scope"])

    def test_all_queries_pin_target_without_changing_metric_names(self):
        for query in diagnostic.QUERIES.values():
            selected = diagnostic.target_query(query, 'a"b:9100', "node", "fixture-site")
            self.assertIn('instance="a\\"b:9100",job="node"', selected)
            self.assertIn('site="fixture-site"', selected)

    def test_missing_registry_site_or_wrong_only_site_cannot_clear(self):
        doc = json.loads((self.root / "required_families.json").read_text())
        for row in doc["data"]["result"]:
            row["metric"]["site"] = "wrong-only-site"
        with self.assertRaises(ValueError):
            diagnostic.required_families(doc, "fixture:9100", "node", "fixture-site", NOW, 900)
        self.write("registry.json", {"schema": "constellation.estate_registry/v1", "services": []})
        result = self.run_diagnostic()
        self.assertFalse(result["bins"]["checked_not_wrong_within_scope"])
        self.assertTrue(any("site identity" in f["statement"] for f in result["bins"]["unknown"]))


if __name__ == "__main__":
    unittest.main()
