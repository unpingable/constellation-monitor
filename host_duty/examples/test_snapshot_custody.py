"""Caller checks around native NQ custody; no native NQ execution here."""
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

HERE = Path(__file__).resolve().parent
VECTOR = json.loads((HERE.parent / "fixtures/host-duty-row-custody-v1.json").read_text())


def recipe():
    path = HERE / "snapshot_custody.py"
    assert path.exists(), "Missing optional snapshot-custody preparation/inspection recipe"
    spec = importlib.util.spec_from_file_location("snapshot_custody_example", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def snapshot(tmp_path, name="reachable", empty=False):
    case = next(case for case in VECTOR["cases"] if case["name"] == name)
    path = tmp_path / "latest.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE host_duty_observations (schema TEXT,host_id TEXT,instance_id TEXT,boot_id TEXT,source_observed_at REAL,source_state TEXT,source_sha256 TEXT,source_detail TEXT,telemetry_json TEXT,exported_at REAL)")
        if not empty:
            connection.execute("INSERT INTO host_duty_observations VALUES (?,?,?,?,?,?,?,?,?,?)", case["values"])
    path.chmod(0o444)
    return path, case


def retained(expected, case):
    installed = {"result":"installed", "reference":"fatbot-custody", "definition_digest":"sha256:"+"b"*64}
    binding = {"definition_digest":installed["definition_digest"],
        "target_reference":expected["snapshot_path"],
        "source_identity":expected["definition"]["source_identity"],
        "currentness_seconds":60,
        "source_observed_at_assertion":"1970-01-01T00:16:45.500000+00:00"}
    # This complete boundary fixture represents NQ's already verified output;
    # the caller does not duplicate NQ claim/digest verification.
    result = {"evaluation_id":"capture-a", "outcome":"passed", "indeterminate":False,
        "row_evidence_inspection":{"state":"valid", "payload_sha256":"sha256:"+"c"*64, "rows":1, "columns":10},
        "detail":{"binding":binding, "read_attempted_at":"1970-01-01T00:16:46Z",
            "row_evidence":{"schema":"nq.saved-check-row-evidence/v1", "evaluation_id":"capture-a",
                "binding":binding, "outcome":"passed", "read_attempted_at":"1970-01-01T00:16:46Z",
                "payload_sha256":"sha256:"+"c"*64,
                "payload":{"schema":"nq.saved-check-selected-rows/v1", "columns":VECTOR["columns"], "rows":[case["selected_row"]]}}}}
    seal_fixture(result)
    return installed, result


def seal_fixture(result):
    payload = result["detail"]["row_evidence"]["payload"]
    # The public literal uses ASCII strings and no JSON numeric values; this
    # constructs a faithful fixture, not a caller-side custody verifier.
    digest = "sha256:"+hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    result["detail"]["row_evidence"]["payload_sha256"] = digest
    result["row_evidence_inspection"]["payload_sha256"] = digest


@pytest.mark.parametrize("name", ["reachable", "unreachable", "unknown", "missing"])
def test_prepared_assertion_is_publication_and_native_retained_tuple_confirms_only_custody(tmp_path, name):
    module = recipe()
    path, case = snapshot(tmp_path, name)
    expected = module.prepare(path, "fatbot", "machine-a", "fatbot-custody", "capture-a")
    assert expected["values"][9] == 1005.5
    assert "publication_assertion" not in expected and "selected_row" not in expected
    assert expected["definition"]["source_identity"] == "constellation.host_duty_observation.v1/fatbot/machine-a"
    assert expected["definition"]["row_evidence"] == "selected_rows_v1"
    installed, result = retained(expected, case)
    inspection = module.inspect_result(expected, installed, result)
    assert inspection["disposition"] == "custody_confirmed"
    assert inspection["observer_testimony"]["source_observed_at"] == case["values"][4]
    assert inspection["observer_testimony"]["source_state"] == name
    assert inspection["observer_testimony"]["exported_at"] == 1005.5


@pytest.mark.parametrize("changed", ["publication", "state", "instance"])
def test_atomic_generation_or_tuple_change_is_indeterminate_even_with_native_pass(tmp_path, changed):
    module = recipe()
    path, case = snapshot(tmp_path)
    expected = module.prepare(path, "fatbot", "machine-a", "fatbot-custody", "capture-a")
    installed, result = retained(expected, case)
    result = deepcopy(result)
    row = result["detail"]["row_evidence"]["payload"]["rows"][0]
    index, replacement = {"publication":(9,{"type":"real","value":"408f740000000000"}),
        "state":(5,{"type":"text","value":"unknown"}),
        "instance":(2,{"type":"text","value":"machine-b"})}[changed]
    row[index] = replacement
    seal_fixture(result)
    inspection = module.inspect_result(expected, installed, result)
    assert inspection["disposition"] == "indeterminate"
    assert inspection["reason"] == "publication_tuple_mismatch"
    assert inspection["nq_outcome"] == "passed"


def test_missing_snapshot_row_refuses_preparation_without_inventing_source_time(tmp_path):
    module = recipe()
    path, _ = snapshot(tmp_path, empty=True)
    with pytest.raises(ValueError, match="singleton"):
        module.prepare(path, "fatbot", "machine-a", "fatbot-custody", "capture-a")


def test_missing_retained_rows_or_absent_native_evidence_remain_indeterminate(tmp_path):
    module = recipe()
    path, case = snapshot(tmp_path)
    expected = module.prepare(path, "fatbot", "machine-a", "fatbot-custody", "capture-a")
    installed, result = retained(expected, case)
    result["detail"]["row_evidence"]["payload"]["rows"] = []
    assert module.inspect_result(expected, installed, result)["disposition"] == "indeterminate"
    result["row_evidence_inspection"] = {"state":"absent", "reason":"capture_not_established"}
    result["outcome"] = "refused"
    result["detail"]["refusal_reason"] = "row_evidence_terminal_detail_limit"
    assert module.inspect_result(expected, installed, result)["disposition"] == "indeterminate"


def test_different_retained_request_binding_is_indeterminate(tmp_path):
    module = recipe()
    path, case = snapshot(tmp_path)
    expected = module.prepare(path, "fatbot", "machine-a", "fatbot-custody", "capture-a")
    installed, result = retained(expected, case)
    result["detail"]["binding"]["source_observed_at_assertion"] = "1970-01-01T00:16:40.250000+00:00"
    assert module.inspect_result(expected, installed, result)["disposition"] == "indeterminate"


def test_real_cli_prepares_receipts_and_exits_nonzero_for_generation_mismatch(tmp_path):
    module = recipe()
    path, case = snapshot(tmp_path, "missing")
    directory = tmp_path / "occurrence"
    command = [sys.executable, "-I", str(HERE/"snapshot_custody.py")]
    prepared = subprocess.run([*command, "prepare", "--snapshot", str(path), "--host", "fatbot",
        "--instance", "machine-a", "--reference", "fatbot-custody", "--evaluation-id", "capture-a",
        "--directory", str(directory)], capture_output=True, text=True, timeout=5)
    assert prepared.returncode == 0, prepared.stderr
    assert json.loads(prepared.stdout)["disposition"] == "prepared"
    expected = json.loads((directory/"expected.json").read_text())
    assert expected["values"][4] is None
    installed, result = retained(expected, case)
    result["detail"]["row_evidence"]["payload"]["rows"][0][9] = {"type":"real", "value":"408f740000000000"}
    seal_fixture(result)
    (directory/"install.json").write_text(json.dumps(installed))
    (directory/"result.json").write_text(json.dumps(result))
    inspected = subprocess.run([*command, "inspect", "--expected", str(directory/"expected.json"),
        "--install", str(directory/"install.json"), "--result", str(directory/"result.json")],
        capture_output=True, text=True, timeout=5)
    assert inspected.returncode == 3
    assert json.loads(inspected.stdout)["disposition"] == "indeterminate"
    assert (directory/"expected.json").stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("drift", ["time", "state", "both"])
def test_changed_caller_values_cannot_render_invented_testimony_from_valid_null_row(tmp_path, drift):
    module = recipe()
    path, case = snapshot(tmp_path, "missing")
    expected = module.prepare(path, "fatbot", "machine-a", "fatbot-custody", "capture-a")
    installed, result = retained(expected, case)
    if drift in {"time", "both"}:
        expected["values"][4] = 99.0
    if drift in {"state", "both"}:
        expected["values"][5] = "reachable"
    inspection = module.inspect_result(expected, installed, result)
    assert inspection["disposition"] == "indeterminate"
    assert inspection["reason"] == "publication_tuple_mismatch"
    assert "observer_testimony" not in inspection


def test_cached_wrong_assertion_echoed_by_native_binding_cannot_refresh_old_publication(tmp_path):
    module = recipe()
    path, case = snapshot(tmp_path, "missing")
    expected = module.prepare(path, "fatbot", "machine-a", "fatbot-custody", "capture-a")
    installed, result = retained(expected, case)
    expected["publication_assertion"] = "2026-11-22T00:00:00Z"
    result["detail"]["binding"]["source_observed_at_assertion"] = expected["publication_assertion"]
    result["detail"]["read_attempted_at"] = "2026-11-22T00:00:01Z"
    result["detail"]["row_evidence"]["read_attempted_at"] = result["detail"]["read_attempted_at"]
    inspection = module.inspect_result(expected, installed, result)
    assert inspection["disposition"] == "indeterminate"
    assert inspection["reason"] == "retained_request_binding_mismatch"
    assert "observer_testimony" not in inspection
