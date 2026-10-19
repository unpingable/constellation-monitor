"""Producer tests: the metric_alerts document is the shared vector, identity is policy identity, failures are refused."""
import copy, importlib.util, json, os, pathlib, subprocess, sys

import pytest

HERE = pathlib.Path(__file__).parent
spec = importlib.util.spec_from_file_location("mac", HERE / "metric-alerts-collect.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
VECTOR = json.loads((HERE / "fixtures/vmalert-rules-runtime-v1.json").read_bytes())


def test_document_matches_the_shared_vector():
    declared = VECTOR["document"]["declared_policy_sha256"]
    assert m.document(VECTOR["api"], VECTOR["site"], VECTOR["generated_at"], declared) == VECTOR["document"]
    assert VECTOR["document"]["schema"] == "constellation.metric_alerts/v1"
    assert VECTOR["document"]["policy_matches_declared"] is True


def test_policy_identity_ignores_runtime_state_but_not_definitions():
    api = copy.deepcopy(VECTOR["api"])
    swap = next(r for g in api["data"]["groups"] for r in g["rules"] if r["name"] == "HostSwapExhausted")
    swap["state"], swap["alerts"], swap["health"] = "inactive", [], "err"
    doc = m.document(api, "crow", VECTOR["generated_at"], VECTOR["document"]["declared_policy_sha256"])
    assert doc["policy_sha256"] == VECTOR["document"]["policy_sha256"]
    assert doc["policy_matches_declared"] is True
    assert doc["counts"]["firing"] == VECTOR["document"]["counts"]["firing"] - 1
    swap["query"] = "vector(0)"
    doc = m.document(api, "crow", VECTOR["generated_at"], VECTOR["document"]["declared_policy_sha256"])
    assert doc["policy_sha256"] != VECTOR["document"]["policy_sha256"]
    assert doc["policy_matches_declared"] is False


def test_without_a_declared_policy_the_comparison_is_absent():
    doc = m.document(VECTOR["api"], "crow", VECTOR["generated_at"])
    assert doc["declared_policy_sha256"] is None and doc["policy_matches_declared"] is None


def test_declared_policy_file_identity_is_the_registry_pin(tmp_path):
    policy = m._collector().vmalert_policy(VECTOR["api"])
    path = tmp_path / "declared-vmalert-policy.json"
    path.write_text(json.dumps(policy, indent=2, sort_keys=True))  # formatting must not matter
    assert m.declared_sha256(path) == VECTOR["document"]["declared_policy_sha256"]
    path.write_text(json.dumps({"schema": "other", "groups": []}))
    with pytest.raises(ValueError):
        m.declared_sha256(path)


def test_unsuccessful_or_empty_api_answers_are_refused():
    for bad in [{"status": "error"}, {"status": "success", "data": {"groups": []}}]:
        with pytest.raises((ValueError, KeyError)):
            m.document(bad, "crow", VECTOR["generated_at"])


def test_instances_are_bounded_and_counted():
    api = copy.deepcopy(VECTOR["api"])
    swap = next(r for g in api["data"]["groups"] for r in g["rules"] if r["name"] == "HostSwapExhausted")
    one = swap["alerts"][0]
    swap["alerts"] = [dict(one, labels=dict(one["labels"], instance="h%d" % i)) for i in range(50)]
    doc = m.document(api, "crow", VECTOR["generated_at"])
    rule = next(r for r in doc["rules"] if r["name"] == "HostSwapExhausted")
    assert rule["instance_count"] == 50 and len(rule["instances"]) == m.INSTANCE_LIMIT


def test_main_writes_atomically_and_reports_an_unreadable_source(tmp_path, monkeypatch):
    out = tmp_path / "state" / "metric-alerts.json"
    monkeypatch.setattr(m, "read_api", lambda url, timeout: copy.deepcopy(VECTOR["api"]))
    assert m.main(["--site", "crow", "--out", str(out)]) == 0
    doc = json.loads(out.read_bytes())
    assert doc["schema"] == "constellation.metric_alerts/v1" and doc["counts"] == VECTOR["document"]["counts"]
    assert not [p for p in out.parent.iterdir() if p.name.startswith(".metric-alerts-")]
    before = out.read_bytes()

    def boom(url, timeout):
        raise OSError("connection refused")
    monkeypatch.setattr(m, "read_api", boom)
    assert m.main(["--site", "crow", "--out", str(out)]) == 1
    assert out.read_bytes() == before  # the last good document is never replaced by an empty one
