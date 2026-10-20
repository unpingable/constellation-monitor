"""Collector tests: declared contracts must be acquired, coverage includes timers and contracts."""
import importlib.util, json, os, pathlib, sys, time

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


def test_admission_inspection_uses_owner_verification_and_preserves_unknown(monkeypatch):
    vector = json.loads((HERE / "fixtures" / "watcher-inspection-v1.json").read_bytes())
    definition = {"id": "nq.fixture.admission", "kind": "nq-watcher-admission", "owner": "nq-owner",
                  "nq_config": "/fixture/nq.toml", "instance_id": vector["instance_id"],
                  "program": "/fixture/nq", "digest": vector["binding_digest"]}
    reg = {"definitions": [definition]}
    monkeypatch.setattr(c, "run", fake_run({"/fixture/nq --config /fixture/nq.toml --json watcher inspect": (0, json.dumps(vector))}))
    assert c.definitions(reg, 5)[0]["state"] == "PRESENT"
    definition["digest"] = "sha256:" + "d" * 64
    assert c.definitions(reg, 5)[0]["state"] == "DEGRADED"
    for doc in [dict(vector, schema="unsupported"), dict(vector, instance_id="other"), dict(vector, binding_digest="unknown")]:
        monkeypatch.setattr(c, "run", fake_run({"/fixture/nq --config": (0, json.dumps(doc))}))
        assert c.definitions(reg, 5)[0]["state"] == "UNKNOWN"
    monkeypatch.setattr(c, "run", fake_run({"/fixture/nq --config": (2, "old CLI has no inspect command")}))
    assert c.definitions(reg, 5)[0]["state"] == "UNKNOWN"


def test_unavailable_required_definition_is_an_operator_visible_supervision_failure(tmp_path, monkeypatch):
    registry = tmp_path / "registry.json"
    output = tmp_path / "estate.json"
    registry.write_text(json.dumps({"schema":"constellation.estate_registry/v1", "site":"fixture", "services":[],
        "definitions":[{"id":"missing-admission", "kind":"file", "path":str(tmp_path / "missing.json"),
                        "owner":"operator", "digest":"sha256:" + "a" * 64}]}))
    monkeypatch.setattr(c, "coverage", lambda *args: [])
    assert c.main(["--registry", str(registry), "--output", str(output)]) == 0
    doc = json.loads(output.read_bytes())
    service = next(s for s in doc["services"] if s["name"] == "estate-definitions")
    assert service["concerns"][0]["state"] == "UNKNOWN"
    assert service["verdict"] == "DEGRADED"
    assert service["failing"] == ["definition.missing-admission"]


def test_definition_only_collection_makes_no_workload_coverage_claim(tmp_path, monkeypatch):
    path = tmp_path / "rule.yml"; path.write_text("known rule\n")
    registry = tmp_path / "registry.json"; report = tmp_path / "report.json"
    registry.write_text(json.dumps({"schema":"constellation.estate_registry/v1", "site":"crow", "services":[],
        "definitions":[{"id":"crow.rules", "kind":"file", "path":str(path), "owner":"operator",
                        "digest":"sha256:" + c.hashlib.sha256(path.read_bytes()).hexdigest()}]}))
    def forbidden(*args):
        raise AssertionError("definition-only collection must not inspect workloads")
    monkeypatch.setattr(c, "coverage", forbidden)
    monkeypatch.setattr(c, "evaluate", forbidden)
    assert c.main(["--registry",str(registry),"--output",str(report),"--definitions-only"]) == 0
    doc = json.loads(report.read_bytes())
    assert doc["scope"] == "definitions-only" and len(doc["services"]) == 1
    assert doc["services"][0]["verdict"] == "OK"
    path.unlink()
    c.main(["--registry",str(registry),"--output",str(report),"--definitions-only"])
    doc = json.loads(report.read_bytes())
    assert doc["services"][0]["verdict"] == "DEGRADED"
    assert doc["services"][0]["concerns"][0]["state"] == "UNKNOWN"


def test_vmalert_loaded_policy_matches_shared_declared_vector():
    import copy
    import pytest
    vector = json.loads((HERE / "fixtures/vmalert-policy-v1.json").read_bytes())
    assert c.vmalert_policy(vector["api"]) == vector["policy"]
    runtime = copy.deepcopy(vector["api"])
    runtime["data"]["groups"][0]["rules"][0]["state"] = "firing"
    assert c.vmalert_policy(runtime) == vector["policy"]  # firing is not definition identity
    runtime["data"]["groups"][0]["rules"][0]["query"] = "vector(0)"
    assert c.vmalert_policy(runtime) != vector["policy"]
    for bad in [{"status":"error"}, {"status":"success","data":{"groups":[]}}]:
        with pytest.raises(ValueError):
            c.vmalert_policy(bad)


def test_an_observation_past_its_own_validity_is_stale_even_when_the_producer_says_present(monkeypatch):
    import json as _json
    doc = {"schema": "project.ops.status/v1", "concerns": [
        {"id": "a.fresh", "required": True, "observation": {"local_state": "PRESENT", "reason": "ok", "observed_at": "2099-01-01T00:00:00Z", "valid_for_seconds": 60}},
        {"id": "a.old", "required": True, "observation": {"local_state": "PRESENT", "reason": "ok", "observed_at": "2020-01-01T00:00:00Z", "valid_for_seconds": 60}},
        {"id": "a.nodate", "required": True, "observation": {"local_state": "PRESENT", "reason": "ok"}}]}
    monkeypatch.setattr(c, "run", lambda argv, timeout, user=None, cwd=None, env=None, limit=1 << 20: (0, _json.dumps(doc).encode(), ""))
    concerns, err = c.project_status({"argv": ["x"]}, 5)
    assert err is None
    by = {x["id"]: x for x in concerns}
    assert by["a.fresh"]["state"] == "PRESENT" and by["a.nodate"]["state"] == "PRESENT"
    assert by["a.old"]["state"] == "STALE" and "exceeds its 60s validity" in by["a.old"]["reason"]
    assert by["a.old"]["observed_at"] == "2020-01-01T00:00:00Z"


def test_declared_file_probes_emit_geometry_and_age_without_sqlite_sidecars(tmp_path):
    import sqlite3
    db = tmp_path / "store.sqlite"
    connection = sqlite3.connect(db)
    connection.execute("CREATE TABLE records (x TEXT)")
    connection.commit()
    connection.close()
    wal = tmp_path / "store.sqlite-wal"
    wal.write_bytes(b"wal fixture")
    output = tmp_path / "output.json"; output.write_text("{}")
    backup = tmp_path / "backup.sqlite"; backup.write_bytes(b"backup")
    before = set(tmp_path.iterdir())
    reg = {"services": [{"name": "demo", "runtime": {"systemd": "demo.service"}, "probes": {
        "stores": [{"name": "main", "path": str(db)}],
        "outputs": [{"name": "report", "path": str(output)}],
        "backups": [{"name": "daily", "path": str(backup)}]}}]}
    specs = c.probe_specs(reg)
    entries = c.collect_probes(specs, str(tmp_path / "state.json"), 2)
    metrics = c.render_probes(specs, entries)
    assert 'service_store_bytes{service="demo",store="main"} ' in metrics
    assert 'service_store_wal_bytes{service="demo",store="main"} 11' in metrics
    assert 'service_store_freelist_pages{service="demo",store="main"} 0' in metrics
    assert 'service_filesystem_avail_bytes{service="demo",store="main"} ' in metrics
    assert 'service_filesystem_avail_inodes{service="demo",store="main"} ' in metrics
    assert 'service_output_age_seconds{service="demo",output="report"} ' in metrics
    assert 'service_backup_created_timestamp_seconds{service="demo",backup="daily"} ' in metrics
    assert set(tmp_path.iterdir()) - before == {tmp_path / "state.json"}
    assert not (tmp_path / "store.sqlite-shm").exists()


def test_hung_file_probe_does_not_delay_other_probe_or_clear_missing(tmp_path):
    blocked = tmp_path / "blocked.sqlite"
    os.mkfifo(blocked)
    good = tmp_path / "good.json"; good.write_text("good")
    missing = tmp_path / "missing.json"
    specs = [("demo", "store", "blocked", str(blocked), "sqlite"),
             ("demo", "output", "good", str(good), "output_mtime"),
             ("demo", "output", "missing", str(missing), "output_mtime")]
    started = time.monotonic()
    entries = c.collect_probes(specs, str(tmp_path / "state.json"), 0.25, workers=3)
    assert time.monotonic() - started < 3
    assert entries[c.probe_key(specs[0])]["success"] is False
    assert entries[c.probe_key(specs[1])]["success"] is True
    assert entries[c.probe_key(specs[2])]["success"] is False
    metrics = c.render_probes(specs, entries)
    assert 'service_probe_success{service="demo",output="good",probe="output_mtime"} 1' in metrics
    assert 'service_probe_success{service="demo",output="missing",probe="output_mtime"} 0' in metrics
    assert 'service_output_age_seconds{service="demo",output="missing"}' not in metrics


def test_slow_probe_retains_observation_time_then_reports_failure(tmp_path):
    import sqlite3
    db = tmp_path / "store.sqlite"
    cx = sqlite3.connect(db); cx.execute("CREATE TABLE x (v)"); cx.close()
    spec = ("demo", "store", "main", str(db), "sqlite")
    state = str(tmp_path / "state.json")
    first = c.collect_probes([spec], state, 2, slow_seconds=600)
    observed = first[c.probe_key(spec)]["observed_at"]
    db.unlink()
    skipped = c.collect_probes([spec], state, 2, slow_seconds=600)
    assert skipped[c.probe_key(spec)]["observed_at"] == observed
    assert 'service_probe_observed_timestamp_seconds{service="demo",store="main",probe="sqlite"} ' in c.render_probes([spec], skipped)
    due = c.collect_probes([spec], state, 2, slow_seconds=0)
    assert due[c.probe_key(spec)]["success"] is False
    assert due[c.probe_key(spec)]["observed_at"] == observed
    assert 'service_store_bytes{service="demo",store="main"}' not in c.render_probes([spec], due)


def test_command_output_capture_is_bounded_while_draining_both_pipes():
    code = "import os; os.write(1,b'x'*2000000); os.write(2,b'y'*2000000+b'end')"
    rc, out, err = c.run([sys.executable, "-c", code], 4, limit=128)
    assert rc == 0 and out == b"x" * 128 and len(err) == 2000 and err.endswith("end")


def test_filesystem_probe_uses_declared_path(monkeypatch):
    class Stat:
        f_bavail = 2
        f_frsize = 4096
        f_favail = 3
    seen = []
    monkeypatch.setattr(c.os, "statvfs", lambda path: (seen.append(path), Stat())[1])
    assert c.probe_worker("filesystem", "/a/link-to-store") == {
        "filesystem_avail_bytes": 8192, "filesystem_avail_inodes": 3}
    assert seen == ["/a/link-to-store"]


def test_main_publishes_probes_before_concurrent_service_checks(tmp_path, monkeypatch):
    import threading
    output = tmp_path / "output.json"; output.write_text("{}")
    textfiles = tmp_path / "textfiles"; textfiles.mkdir()
    report = tmp_path / "estate.json"
    registry = tmp_path / "registry.json"
    registry.write_text(json.dumps({"schema": "constellation.estate_registry/v1", "services": [
        {"name": name, "runtime": {"systemd": name + ".service"},
         "probes": {"outputs": [{"name": "report", "path": str(output)}]}}
        for name in ("one", "two")]}))
    barrier = threading.Barrier(2)

    def evaluate(svc, timeout):
        assert 'service_output_age_seconds{service="one",output="report"}' in (textfiles / "constellation-estate.prom").read_text()
        barrier.wait(timeout=2)
        return {"name": svc["name"], "verdict": "OK", "reason": "fixture", "concerns": []}

    monkeypatch.setattr(c, "evaluate", evaluate)
    monkeypatch.setattr(c, "coverage", lambda *args: [])
    assert c.main(["--registry", str(registry), "--output", str(report),
                   "--textfile-dir", str(textfiles)]) == 0
    assert [s["name"] for s in json.loads(report.read_text())["services"][:2]] == ["one", "two"]
    registry.write_text(json.dumps({"schema": "constellation.estate_registry/v1", "services": []}))
    assert c.main(["--registry", str(registry), "--output", str(report),
                   "--textfile-dir", str(textfiles)]) == 0
    assert "service_output_age_seconds{" not in (textfiles / "constellation-estate.prom").read_text()
