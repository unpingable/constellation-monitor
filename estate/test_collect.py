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
