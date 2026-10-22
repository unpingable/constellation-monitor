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


@pytest.mark.parametrize("case", VECTOR["value_code_cases"], ids=lambda c: c["name"])
def test_value_codes_match_the_shared_vector_and_are_admitted(case):
    api = copy.deepcopy(VECTOR["api"])
    api["data"]["groups"] = [api["data"]["groups"][0]]
    api["data"]["groups"][0]["rules"] = [case["api_rule"]]
    doc = m.document(api, "collector-site", VECTOR["generated_at"])
    assert doc["site"] == "collector-site", "an instance's site is not the collector site"
    assert doc["rules"] == [case["document_rule"]]
    policy = m._collector().vmalert_policy(api)
    rows = m.check_targets(policy, ["labelwatch"])
    assert len(rows) == 1 and rows[0]["admitted"], rows


def test_value_code_summary_includes_pending_and_truncated_instances():
    api = copy.deepcopy(VECTOR["api"])
    rule = next(r for g in api["data"]["groups"] for r in g["rules"] if r["name"] == "HostSwapExhausted")
    rule["labels"].update(VECTOR["value_code_marker"])
    one = rule["alerts"][0]
    rule["alerts"] = [dict(one, value="1", labels=dict(one["labels"], site="crow", instance=str(i))) for i in range(40)]
    rule["alerts"].extend([dict(one, state="pending", value="2", labels=dict(one["labels"], site="testbed")),
                           dict(one, state="firing", value="4", labels=dict(one["labels"], site="crow")),
                           dict(one, state="inactive", value="3")])
    doc = m.document(api, "collector-site", VECTOR["generated_at"])
    out = next(r for r in doc["rules"] if r["name"] == "HostSwapExhausted")
    assert len(out["instances"]) == 32 and out["instance_count"] == 43
    assert out["value_code_counts"] == [
        dict(site="crow", state="firing", value="1", count=40),
        dict(site="crow", state="firing", value="4", count=1),
        dict(site="testbed", state="pending", value="2", count=1)]


@pytest.mark.parametrize("prefix", ["", "Host swap coverage: "])
def test_check_targets_cli_accepts_the_value_code_marker(tmp_path, capsys, prefix):
    policy = m._collector().vmalert_policy(copy.deepcopy(VECTOR["api"]))
    for group in policy["groups"]:
        for rule in group["rules"]:
            rule["labels"].update(VECTOR["value_code_marker"])
            rule["annotations"]["summary"] = prefix + "evidence code={{ $value }} (present)"
    path = tmp_path / "declared.json"
    path.write_text(json.dumps(policy))
    assert m.main(["--check-targets", "--declared", str(path), "--key-site", "labelwatch"]) == 0
    assert json.loads(capsys.readouterr().out)["rejected"] == 0


@pytest.mark.parametrize("summary", [None, "", "threshold met"])
@pytest.mark.parametrize("attention", ["true", "false"])
def test_check_targets_rejects_a_labelled_rule_without_summary_code(tmp_path, capsys, summary, attention):
    policy = m._collector().vmalert_policy(copy.deepcopy(VECTOR["api"]))
    rule = policy["groups"][0]["rules"][0]
    rule["labels"].update(VECTOR["value_code_marker"], attention=attention)
    rule["annotations"] = {"description": "evidence code={{ $value }} (present)"}
    if summary is not None:
        rule["annotations"]["summary"] = summary
    path = tmp_path / "declared.json"
    path.write_text(json.dumps(policy))
    assert m.main(["--check-targets", "--declared", str(path)]) == 1
    captured = capsys.readouterr()
    assert json.loads(captured.out)["rejected"] == 1
    assert "summary must contain evidence code=" in captured.err
    assert "rule_rejected:" + rule["name"] in captured.err


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


def test_a_rule_vmalert_has_not_evaluated_yet_has_no_last_evaluation():
    api = copy.deepcopy(VECTOR["api"])
    swap = next(r for g in api["data"]["groups"] for r in g["rules"] if r["name"] == "HostSwapExhausted")
    swap["lastEvaluation"] = "0001-01-01T00:00:00Z"
    doc = m.document(api, "crow", VECTOR["generated_at"])
    rule = next(r for r in doc["rules"] if r["name"] == "HostSwapExhausted")
    assert rule["last_evaluation"] is None   # the reader then says "has no valid last_evaluation" (indeterminate), not a huge age


TARGETS = json.loads((HERE / "fixtures/metric-alert-targets-v1.json").read_bytes())


def test_admission_matches_the_shared_target_vector():
    """The evaluator's inputs.rs tests the same vector: both sides derive and refuse the same targets."""
    for case in TARGETS["cases"]:
        verdict = m.admit(case["alert"], [case["site"]] if case["site"] else None)
        admitted = not verdict["rejected"]
        target = verdict["keyed"][0][1] if admitted else verdict["rejected"][0][1]
        assert (admitted, target, len(target.encode())) == (case["admitted"], case["target"], case["bytes"]), case
    for group in TARGETS["collisions"]:
        policy = {"groups": [{"name": "g", "rules": [{"name": n, "labels": {"attention": "true"}} for n in group["alerts"]]}]}
        rows = m.check_targets(policy)
        assert [r["rule"] for r in rows if r["admitted"]] == group["admitted"], group
        assert all(r["rejected"][-1]["target"] == group["target"] for r in rows), rows


def _declared(tmp_path, names):
    rule = {"annotations": {"summary": "x"}, "duration_seconds": 300, "keep_firing_for_seconds": 0,
            "labels": {"attention": "true", "severity": "warn"}, "query": "vector(1)"}
    policy = {"schema": "constellation.vmalert_policy/v1",
              "groups": [{"file": "service.rules.yml", "interval_seconds": 30, "name": "service",
                          "rules": [dict(rule, name=n) for n in names] + [dict(rule, name="NotOptedInAtAllWithAVeryLongAlertName", labels={})]}]}
    path = tmp_path / "declared-vmalert-policy.json"
    path.write_text(json.dumps(policy))
    return path


def test_check_targets_refuses_a_49_byte_derived_target(tmp_path, capsys):
    fits = "Z" + "z" * 41 + "Z"   # a 44-byte alert token
    path = _declared(tmp_path, ["HostSwapExhausted", fits])
    assert m.main(["--check-targets", "--declared", str(path), "--key-site", "cro"]) == 0   # 44 + 1 + 3 = 48
    capsys.readouterr()
    assert m.main(["--check-targets", "--declared", str(path), "--key-site", "crow"]) == 1   # 44 + 1 + 4 = 49
    captured = capsys.readouterr()
    out = json.loads(captured.out)
    assert out["rejected"] == 1 and out["sites"] == ["crow"]
    bad = next(r for r in out["rules"] if not r["admitted"])
    assert bad["rule"] == fits and bad["bytes"] == 49 and bad["targets"] == [], bad
    assert bad["rejected"][0]["site"] == "crow" and "is 49 bytes" in bad["rejected"][0]["reason"], bad
    assert "rule_rejected:" + fits + " (crow)" in captured.err
    assert next(r for r in out["rules"] if r["rule"] == "HostSwapExhausted")["targets"] == ["host-swap-exhausted.crow"]
    assert [r["rule"] for r in out["rules"]] == ["HostSwapExhausted", fits], "only attention-labelled rules are admitted"


def test_check_targets_names_the_real_p3_rule_on_the_testbed(tmp_path, capsys):
    """The 2026-10-22 testbed drill: ServiceMetricsObservationNeedsAttention keyed by site testbed is 51 bytes."""
    path = _declared(tmp_path, ["ServiceMetricsObservationNeedsAttention", "ServiceLastSuccessNeedsAttention",
                                "HostMetricsAcquisitionNeedsAttention"])
    assert m.main(["--check-targets", "--declared", str(path), "--key-site", "testbed"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert [(r["rule"], r["admitted"], r["bytes"]) for r in out["rules"]] == [
        ("ServiceMetricsObservationNeedsAttention", False, 51),
        ("ServiceLastSuccessNeedsAttention", True, 44),
        ("HostMetricsAcquisitionNeedsAttention", True, 48)]


def test_check_targets_refuses_two_rules_with_one_target(tmp_path, capsys):
    path = _declared(tmp_path, ["HostSwapExhausted", "host-swap-exhausted"])
    assert m.main(["--check-targets", "--declared", str(path)]) == 1
    out = json.loads(capsys.readouterr().out)
    assert [r["admitted"] for r in out["rules"]] == [False, False], "both, not the first one in order"
    assert out["rules"][1]["rejected"][0]["reason"] == 'derived target "host-swap-exhausted" is shared by alerts "HostSwapExhausted", "host-swap-exhausted"'


def test_check_targets_refuses_only_the_site_that_overflows(tmp_path, capsys):
    path = _declared(tmp_path, ["HostMetricsAcquisitionNeedsAttention"])
    assert m.main(["--check-targets", "--declared", str(path), "--key-site", "testbed", "--key-site", "labelwatch"]) == 1
    row = json.loads(capsys.readouterr().out)["rules"][0]
    assert row["targets"] == ["host-metrics-acquisition-needs-attention.testbed"]
    assert [(r["site"], r["bytes"]) for r in row["rejected"]] == [("labelwatch", 51)]


def test_check_targets_needs_the_declared_policy():
    with pytest.raises(SystemExit):
        m.main(["--check-targets"])
