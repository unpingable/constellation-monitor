"""Collector tests: declared contracts must be acquired, coverage includes timers and contracts."""
import importlib.util, json, os, pathlib, sys

HERE = pathlib.Path(__file__).parent
spec = importlib.util.spec_from_file_location("collect", HERE / "constellation-estate-collect.py")
c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)

CONCERNS = """schema = "project.concerns/v1"
project = "demo"

[[concerns]]
id = "demo.ingest.progress"   # comment
question = "q/v1"
required = true

[[concerns]]
id = "demo.optional.thing"
required = false

[[concerns]]
id = "demo.output.fresh"
required = true
"""


def fake_run(table):
    def run(argv, timeout, user=None, cwd=None, env=None, limit=1 << 20):
        key = " ".join(argv)
        for prefix, (rc, out) in table.items():
            if key.startswith(prefix):
                return rc, out.encode(), ""
        raise AssertionError("unexpected argv: " + key)
    return run


def test_parse_concerns_reads_required_ids(tmp_path):
    p = tmp_path / "concerns.toml"; p.write_text(CONCERNS)
    assert c.parse_concerns(str(p)) == ["demo.ingest.progress", "demo.output.fresh"]


def test_parse_concerns_refuses_an_unreadable_contract(tmp_path):
    p = tmp_path / "concerns.toml"; p.write_text('schema = "x"\n')
    try:
        c.parse_concerns(str(p))
    except ValueError:
        return
    raise AssertionError("an empty contract must not read as satisfied")


def test_declared_but_not_acquired_concern_degrades(tmp_path, monkeypatch):
    p = tmp_path / "concerns.toml"; p.write_text(CONCERNS)
    status = {"schema": "project.ops.status/v1", "concerns": [
        {"id": "demo.ingest.progress", "required": True, "observation": {"local_state": "PRESENT", "reason": "ok"}}]}
    monkeypatch.setattr(c, "run", fake_run({
        "systemctl show demo.service": (0, "ActiveState=active\nSubState=running\n"),
        "producer": (0, json.dumps(status))}))
    svc = {"name": "demo", "runtime": {"systemd": "demo.service"},
           "status": {"kind": "project-ops-status", "argv": ["producer"]}, "contract": {"concerns": str(p)}}
    out = c.evaluate(svc, 10)
    assert out["verdict"] == "DEGRADED", out
    assert "demo.output.fresh" in out["failing"]
    missing = [x for x in out["concerns"] if x["id"] == "demo.output.fresh"][0]
    assert missing["state"] == "MISSING_REQUIRED_OBSERVATION"


def test_failed_timer_run_degrades_and_ok_status_is_honoured(monkeypatch):
    table = {
        "systemctl show demo.service": (0, "ActiveState=active\nSubState=running\n"),
        "systemctl show demo-job.timer": (0, "ActiveState=active\nUnit=demo-job.service\nLastTriggerUSec=Tue\n"),
        "systemctl show demo-job.service": (0, "Result=exit-code\nExecMainStatus=3\nActiveState=failed\n")}
    monkeypatch.setattr(c, "run", fake_run(table))
    svc = {"name": "demo", "runtime": {"systemd": "demo.service"}, "timers": ["demo-job.timer"]}
    assert c.evaluate(svc, 10)["verdict"] == "DEGRADED"
    svc["timers"] = [{"unit": "demo-job.timer", "ok_status": [0, 3]}]
    assert c.evaluate(svc, 10)["verdict"] == "OK"


def test_coverage_names_unregistered_timers_and_unacquired_contracts(tmp_path, monkeypatch):
    (tmp_path / ".ops").mkdir(); (tmp_path / ".ops" / "concerns.toml").write_text(CONCERNS)
    monkeypatch.setattr(c, "run", fake_run({
        "systemctl list-units --type=timer": (0, "demo-job.timer loaded active waiting x\nstray.timer loaded active waiting y\napt-daily.timer loaded active waiting z\n"),
        "systemctl list-unit-files": (0, "demo.service enabled enabled\n"),
        "systemctl list-units --type=service": (0, ""),
        "docker ps": (0, ""),
        "systemctl show demo.service -p WorkingDirectory": (0, "WorkingDirectory=%s\n" % tmp_path)}))
    reg = {"services": [{"name": "demo", "runtime": {"systemd": "demo.service"}, "timers": ["demo-job.timer"]}],
           "unsupervised": {"timer": [{"match": "apt-*", "reason": "base"}]}}
    assert c.coverage(reg, 10) == ["contract:demo:%s/.ops" % tmp_path, "timer:stray.timer"]
    reg["services"][0]["contract"] = {"waived": "old architecture"}
    assert c.coverage(reg, 10) == ["timer:stray.timer"]


def test_contract_drift_against_the_pinned_digest_degrades(tmp_path, monkeypatch):
    import hashlib
    p = tmp_path / "concerns.toml"; p.write_text(CONCERNS)
    pinned = "sha256:" + hashlib.sha256(CONCERNS.encode()).hexdigest()
    status = {"schema": "project.ops.status/v1", "concerns": [
        {"id": cid, "required": True, "observation": {"local_state": "PRESENT", "reason": "ok"}}
        for cid in ("demo.ingest.progress", "demo.output.fresh")]}
    monkeypatch.setattr(c, "run", fake_run({
        "systemctl show demo.service": (0, "ActiveState=active\nSubState=running\n"),
        "producer": (0, json.dumps(status))}))
    svc = {"name": "demo", "runtime": {"systemd": "demo.service"},
           "status": {"kind": "project-ops-status", "argv": ["producer"]}, "contract": {"concerns": str(p), "sha256": pinned}}
    assert c.evaluate(svc, 10)["verdict"] == "OK"
    p.write_text(CONCERNS + "\n# edited on the host\n")
    out = c.evaluate(svc, 10)
    assert out["verdict"] == "DEGRADED" and "contract.revision" in out["failing"], out


def test_definition_drift_is_detected_per_kind(tmp_path, monkeypatch):
    import hashlib
    f = tmp_path / "attention.toml"; f.write_text("x = 1\n")
    good = "sha256:" + hashlib.sha256(b"x = 1\n").hexdigest()
    monkeypatch.setattr(c, "run", fake_run({
        "/usr/bin/constellation-attention check-config": (0, json.dumps({"attention_policy_digest": "sha256:" + "a" * 64})),
        "/usr/bin/nq --config /etc/nq/ops.toml --json saved-check inspect sc.one": (0, json.dumps({"definition_digest": "sha256:" + "b" * 64})),
        "/usr/bin/nq --config /etc/nq/ops.toml --json saved-check inspect sc.gone": (1, "")}))
    reg = {"definitions": [
        {"id": "cfg", "kind": "file", "path": str(f), "digest": good, "owner": "constellation"},
        {"id": "policy", "kind": "attention-policy", "config": str(f), "digest": "sha256:" + "a" * 64},
        {"id": "sc.one", "kind": "nq-saved-check", "nq_config": "/etc/nq/ops.toml", "reference": "sc.one", "digest": "sha256:" + "b" * 64},
        {"id": "sc.gone", "kind": "nq-saved-check", "nq_config": "/etc/nq/ops.toml", "reference": "sc.gone", "digest": "sha256:" + "c" * 64}]}
    states = {x["id"]: x["state"] for x in c.definitions(reg, 10)}
    assert states == {"definition.cfg": "PRESENT", "definition.policy": "PRESENT",
                      "definition.sc.one": "PRESENT", "definition.sc.gone": "UNKNOWN"}
    f.write_text("x = 2\n")   # edited on the host, outside review
    reg["definitions"][1]["digest"] = "sha256:" + "f" * 64   # a policy that is not the one deployed
    out = {x["id"]: x for x in c.definitions(reg, 10)}
    assert out["definition.cfg"]["state"] == "DEGRADED" and "drift" in out["definition.cfg"]["reason"]
    assert out["definition.policy"]["state"] == "DEGRADED"


def test_coverage_on_a_host_without_docker(monkeypatch):
    """No Docker and no declared containers means no containers, not a failed inventory (found by cartography #94)."""
    monkeypatch.setattr(c.shutil, "which", lambda *a, **k: None)
    monkeypatch.setattr(c, "run", fake_run({
        "systemctl list-units --type=timer": (0, ""),
        "systemctl list-unit-files": (0, "demo.service enabled enabled\n"),
        "systemctl list-units --type=service": (0, ""),
        "systemctl show demo.service -p WorkingDirectory": (0, "WorkingDirectory=/\n")}))
    reg = {"services": [{"name": "demo", "runtime": {"systemd": "demo.service"}}], "unsupervised": {}}
    assert c.coverage(reg, 10) == []
    reg["services"].append({"name": "box", "runtime": {"docker": "box"}})
    try:
        c.coverage(reg, 10)
    except AssertionError as e:  # a declared container still requires `docker ps` to answer
        assert "docker ps" in str(e)
    else:
        raise AssertionError("coverage ignored a declared container on a host without docker")


def test_report_pins_the_registry_bytes_actually_read(tmp_path, monkeypatch):
    """A later pathname replacement must not re-label an earlier collection."""
    import hashlib
    registry = tmp_path / "registry.json"
    report = tmp_path / "estate.json"
    original = b'{"schema":"constellation.estate_registry/v1","site":"fixture","services":[]}'
    registry.write_bytes(original)

    def coverage(reg, timeout):
        registry.write_bytes(original + b'\n')
        return []

    monkeypatch.setattr(c, "coverage", coverage)
    assert c.main(["--registry", str(registry), "--output", str(report)]) == 0
    doc = json.loads(report.read_bytes())
    assert doc["registry_sha256"] == hashlib.sha256(original).hexdigest()
    assert doc["registry_sha256"] != hashlib.sha256(registry.read_bytes()).hexdigest()


def test_release_observation_golden(monkeypatch, tmp_path):
    fixture = HERE / "fixtures" / "definition-release"
    registry = fixture / "registry.json"
    report = tmp_path / "estate.json"
    monkeypatch.setattr(c.time, "time", lambda: 1002)
    monkeypatch.setattr(c, "coverage", lambda *args: [])
    monkeypatch.setattr(c, "deployed_digest", lambda d, timeout: d["digest"])
    assert c.main(["--registry", str(registry), "--output", str(report)]) == 0
    assert json.loads(report.read_bytes()) == json.loads((fixture / "report.json").read_bytes())
