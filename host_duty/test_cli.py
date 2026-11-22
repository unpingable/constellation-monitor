"""Operator CLI behavior through actual processes and the persisted ledger."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def run(database, *args):
    result = subprocess.run([sys.executable, "-m", "host_duty.cli", "--database", str(database), *args],
        capture_output=True, text=True, timeout=5,
        env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    return result


def checked(database, *args):
    result = run(database, *args)
    assert result.returncode == 0, "CLI behavior missing: " + result.stderr
    return json.loads(result.stdout)


@pytest.mark.parametrize("damage", ["missing", "corrupt"])
def test_status_failure_emits_all_unknown_and_never_creates_database(tmp_path, damage):
    database = tmp_path / "ledger.sqlite"
    if damage == "corrupt":
        database.write_bytes(b"not a sqlite ledger")
        database.chmod(0o600)
    doc = checked(database, "--status", "--host", "fatbot")
    assert doc["schema"] == "project.ops.status/v1"
    assert {c["id"] for c in doc["concerns"]} == {"duty.availability", "duty.observation", "duty.deadline"}
    assert {c["observation"]["local_state"] for c in doc["concerns"]} == {"UNKNOWN"}
    if damage == "missing":
        assert not database.exists()
    else:
        assert database.read_bytes() == b"not a sqlite ledger"


def test_init_register_assign_and_claim_do_not_discharge_work(tmp_path):
    database = tmp_path / "ledger.sqlite"
    checked(database, "init")
    assert database.stat().st_mode & 0o777 == 0o600
    checked(database, "register", "fatbot", "machine-a")
    checked(database, "assign", "duty-a", "build-a", "fatbot", "--deadline", str(time.time() + 3600))
    checked(database, "observe-claim", "fatbot", "machine-a", "--reason", "operator recorded host shutdown claim")
    state = checked(database, "list", "--host", "fatbot")
    assert state["duties"][0]["disposition"] is None
    assert state["hosts"][0]["instance_id"] == "machine-a"
    doc = checked(database, "status", "fatbot")
    availability = next(c for c in doc["concerns"] if c["id"] == "duty.availability")
    assert availability["observation"]["facts"]["availability_required"] is True
    events = checked(database, "events", "--limit", "10")
    assert len(events["events"]) >= 3


def test_release_completed_needs_explicit_confirmation_and_evidence(tmp_path):
    database = tmp_path / "ledger.sqlite"
    checked(database, "init")
    checked(database, "register", "fatbot", "machine-a")
    checked(database, "assign", "duty-a", "build-a", "fatbot", "--deadline", str(time.time() + 3600))
    args = ("release", "duty-a", "completed", "--reason", "operator inspected retained result")
    assert run(database, *args).returncode != 0
    assert run(database, *args, "--evidence-sha256", "a" * 64).returncode != 0
    assert run(database, *args, "--confirm-completed").returncode != 0
    state = checked(database, "list")
    assert state["duties"][0]["disposition"] is None
    checked(database, *args, "--evidence-sha256", "a" * 64, "--confirm-completed")
    state = checked(database, "list")
    assert state["duties"][0]["evidence_kind"] == "operator_attestation"
    assert state["duties"][0]["disposition"] == "completed"


def test_atomic_transfer_release_and_replace_from_cli(tmp_path):
    database = tmp_path / "ledger.sqlite"
    checked(database, "init")
    checked(database, "register", "fatbot", "machine-a")
    checked(database, "register", "gojira", "machine-b")
    deadline = str(time.time() + 3600)
    checked(database, "assign", "duty-a", "build-a", "fatbot", "--deadline", deadline)
    checked(database, "transfer", "duty-a", "duty-b", "gojira", "--deadline", deadline, "--reason", "move build")
    checked(database, "replace", "fatbot", "machine-c", "--reason", "replacement VM")
    checked(database, "release", "duty-b", "cancelled", "--reason", "owner cancelled")
    state = checked(database, "list")
    assert [d["work_id"] for d in state["duties"]] == ["build-a", "build-a"]
    assert [d["disposition"] for d in state["duties"]] == ["transferred", "cancelled"]


def test_cli_rejects_relative_database_and_arbitrary_observation_time(tmp_path):
    assert run("relative.sqlite", "init").returncode != 0
    database = tmp_path / "ledger.sqlite"
    checked(database, "init")
    checked(database, "register", "fatbot", "machine-a")
    assert run(database, "status", "fatbot", "--at", "1000").returncode != 0
    assert run(database, "observe-claim", "fatbot", "machine-a", "--state", "reachable", "--reason", "claim").returncode != 0


def test_collect_uses_explicit_config_and_never_initializes(tmp_path):
    config = tmp_path / "probe.json"
    database = tmp_path / "missing.sqlite"
    config.write_text(json.dumps({"schema":"constellation.host_duty_probe_config.v1", "database":str(database),
        "targets":[{"host_id":"fatbot", "instance_id":"a", "address":"127.0.0.1", "port":22,
            "argv":[sys.executable, "-m", "host_duty.sample"], "machine_identity_sha256":"a"*64}]}))
    config.chmod(0o600)
    result = subprocess.run([sys.executable, "-m", "host_duty.cli", "collect", "--config", str(config)],
        capture_output=True, text=True, timeout=5)
    assert result.returncode != 0
    assert "collect refused" in result.stderr
    assert not database.exists()
