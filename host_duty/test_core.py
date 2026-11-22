"""Behavioral duty tests: observation must never discharge an obligation."""
import hashlib
import importlib.util
from pathlib import Path
import sqlite3
import sys
import os
import time
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from host_duty.core import Ledger, Refused


def concerns(document):
    return {item["id"]: item["observation"] for item in document["concerns"]}


@pytest.fixture
def setup(tmp_path):
    clock = [1000]
    try:
        ledger = Ledger.create(tmp_path / "duty.sqlite", clock=lambda: clock[0])
    except NotImplementedError:
        pytest.fail("Missing behavior: an off-host duty ledger must persist explicit commitments")
    ledger.register("fatbot", "machine-a")
    yield ledger, clock, tmp_path / "duty.sqlite"
    ledger.close()


def assign(ledger, **kw):
    return ledger.assign(kw.get("duty", "duty-1"), kw.get("work", "build-1"),
                         kw.get("host", "fatbot"), kw.get("deadline", 2000))


def test_registered_offline_and_online_idle_have_no_uptime_obligation(tmp_path):
    clock = [1000]
    try:
        ledger = Ledger.create(tmp_path / "duty.sqlite", clock=lambda: clock[0])
    except NotImplementedError:
        pytest.fail("Missing behavior: registering an idle host must not create an uptime obligation")
    ledger.register("fatbot", "machine-a")
    assert ledger.report("fatbot")["availability_required"] is False
    ledger.observe("fatbot", "machine-a", "reachable", boot_id="boot-a")
    assert ledger.report("fatbot")["state"] == "online_idle"
    clock[0] += 1
    ledger.observe("fatbot", "machine-a", "unreachable")
    report = ledger.report("fatbot")
    assert report["state"] == "registered_offline"
    assert report["availability_required"] is False


def test_missing_host_on_duty_is_a_failure_after_declared_grace(setup):
    ledger, clock, _ = setup
    assign(ledger)
    clock[0] += 31
    ledger.observe("fatbot", "machine-a", "unreachable")
    report = ledger.report("fatbot")
    assert report["state"] == "missing_on_duty"
    assert report["availability_required"] is True
    assert report["duties"][0]["disposition"] is None


def test_shutdown_claim_does_not_release_duty_or_refresh_reachability(setup):
    ledger, clock, _ = setup
    assign(ledger)
    ledger.observe("fatbot", "machine-a", "reachable", boot_id="boot-a")
    clock[0] += 100
    ledger.shutdown_claim("fatbot", "machine-a", "going offline")
    report = ledger.report("fatbot")
    assert report["availability_required"] is True
    assert report["presence"] == "stale"
    assert report["duties"][0]["disposition"] is None


@pytest.mark.parametrize("disposition", ["cancelled", "released", "completed"])
def test_only_explicit_operator_disposition_ends_availability_duty(setup, disposition):
    ledger, clock, _ = setup
    assign(ledger)
    evidence = hashlib.sha256(b"independently inspected build artifact").hexdigest()
    ledger.release("duty-1", disposition, "operator checked the outcome", evidence_sha256=evidence)
    clock[0] += 100
    ledger.observe("fatbot", "machine-a", "unreachable")
    assert ledger.report("fatbot")["availability_required"] is False
    assert ledger.duties()[0]["disposition"] == disposition
    if disposition == "completed":
        assert ledger.duties()[0]["evidence_kind"] == "operator_attestation"


def test_completion_requires_evidence_and_is_not_inferred_from_claim(setup):
    ledger, _, _ = setup
    assign(ledger)
    with pytest.raises(Refused):
        ledger.release("duty-1", "completed", "worker said success")
    assert ledger.report("fatbot")["availability_required"] is True


def test_expiry_is_overdue_outstanding_and_never_success(setup):
    ledger, clock, _ = setup
    assign(ledger, deadline=1100)
    clock[0] = 1100
    report = ledger.report("fatbot")
    assert report["overdue"] is True
    assert report["availability_required"] is True
    assert report["duties"][0]["disposition"] is None


def test_boot_change_preserves_duty_and_retired_boot_cannot_become_current(setup):
    ledger, clock, _ = setup
    assign(ledger)
    ledger.observe("fatbot", "machine-a", "reachable", boot_id="boot-a")
    clock[0] += 5
    ledger.observe("fatbot", "machine-a", "reachable", boot_id="boot-b")
    assert ledger.report("fatbot")["availability_required"] is True
    assert ledger.report("fatbot")["boot_id"] == "boot-b"
    clock[0] += 1
    with pytest.raises(Refused):
        ledger.observe("fatbot", "machine-a", "reachable", boot_id="boot-a")
    assert ledger.report("fatbot")["boot_id"] == "boot-b"


def test_replacement_requires_old_duty_disposition_and_old_instance_refuses(setup):
    ledger, clock, _ = setup
    assign(ledger)
    with pytest.raises(Refused):
        ledger.replace("fatbot", "machine-b", "new VM")
    ledger.release("duty-1", "released", "work remains open for reassignment")
    ledger.replace("fatbot", "machine-b", "new VM")
    with pytest.raises(Refused):
        ledger.observe("fatbot", "machine-a", "reachable", boot_id="boot-old")
    assert ledger.report("fatbot")["instance_id"] == "machine-b"
    assert ledger.report("fatbot")["availability_required"] is False


def test_transfer_keeps_work_identity_and_old_host_no_longer_required(setup):
    ledger, _, _ = setup
    ledger.register("gojira", "machine-b")
    assign(ledger)
    ledger.transfer("duty-1", "duty-2", "gojira", 2100, "moving the build")
    assert ledger.report("fatbot")["availability_required"] is False
    assert ledger.report("gojira")["availability_required"] is True
    duties = ledger.duties()
    assert [d["work_id"] for d in duties] == ["build-1", "build-1"]
    assert duties[0]["disposition"] == "transferred"


def test_failed_transfer_is_atomic_and_repeat_settled_operation_refuses(setup):
    ledger, _, _ = setup
    assign(ledger)
    with pytest.raises(Refused):
        ledger.transfer("duty-1", "duty-2", "not-enrolled", 2100, "moving")
    assert ledger.report("fatbot")["availability_required"] is True
    ledger.release("duty-1", "cancelled", "operator cancellation")
    count = len(ledger.events())
    with pytest.raises(Refused):
        ledger.release("duty-1", "cancelled", "operator cancellation")
    assert len(ledger.events()) == count


def test_persisted_duty_and_history_survive_observer_process_reopen(setup):
    ledger, clock, path = setup
    assign(ledger)
    ledger.observe("fatbot", "machine-a", "reachable", boot_id="boot-a")
    with Ledger(path, readonly=True, clock=lambda: clock[0]) as reopened:
        assert reopened.report("fatbot")["availability_required"] is True
        assert reopened.report("fatbot")["boot_id"] == "boot-a"
        assert any(e["kind"] == "assigned" for e in reopened.events())


def test_old_or_future_sample_cannot_refresh_head(setup):
    ledger, clock, _ = setup
    ledger.observe("fatbot", "machine-a", "reachable", boot_id="boot-a")
    clock[0] += 10
    with pytest.raises(Refused):
        ledger.observe("fatbot", "machine-a", "reachable", boot_id="boot-a", observed_at=999)
    with pytest.raises(Refused):
        ledger.observe("fatbot", "machine-a", "reachable", boot_id="boot-a", observed_at=2000)
    assert ledger.report("fatbot")["observation_age_seconds"] == 10


def test_observation_loss_is_unknown_not_missing_or_recovered(setup):
    ledger, clock, _ = setup
    assign(ledger)
    ledger.observe("fatbot", "machine-a", "reachable", boot_id="boot-a")
    clock[0] += 61
    report = ledger.report("fatbot")
    assert report["presence"] == "stale"
    assert report["state"] == "observation_unknown"
    assert report["availability_required"] is True


def test_missing_ledger_is_not_implicitly_initialized(tmp_path):
    with pytest.raises((Refused, OSError)):
        Ledger(tmp_path / "absent.sqlite", readonly=True)
    assert not (tmp_path / "absent.sqlite").exists()


def test_concurrent_writer_refuses_without_losing_duty(setup):
    ledger, _, path = setup
    assign(ledger)
    other = sqlite3.connect(path)
    other.execute("BEGIN IMMEDIATE")
    try:
        with pytest.raises(Refused, match="busy|locked"):
            ledger.release("duty-1", "cancelled", "another writer is busy")
    finally:
        other.rollback()
        other.close()
    assert ledger.report("fatbot")["availability_required"] is True


def test_duplicate_assignment_never_adds_second_active_host_for_one_work(setup):
    ledger, _, _ = setup
    ledger.register("gojira", "machine-b")
    assign(ledger)
    with pytest.raises(Refused):
        assign(ledger, duty="duplicate", host="gojira")
    assert len([d for d in ledger.duties() if d["disposition"] is None]) == 1


def test_duplicate_sample_and_clock_regression_cannot_create_current_health(setup):
    from host_duty.core import status_document
    ledger, clock, _ = setup
    assign(ledger)
    ledger.observe("fatbot", "machine-a", "reachable", boot_id="boot-a")
    with pytest.raises(Refused):
        ledger.observe("fatbot", "machine-a", "reachable", boot_id="boot-a")
    clock[0] = 999
    with pytest.raises(Refused, match="clock"):
        ledger.shutdown_claim("fatbot", "machine-a", "claim with regressed clock")
    assert {c["local_state"] for c in concerns(status_document(ledger, "fatbot")).values()} == {"UNKNOWN"}


def test_status_preserves_source_time_and_distinguishes_observation_gap(setup):
    from host_duty.core import status_document
    ledger, clock, _ = setup
    assign(ledger)
    ledger.observe("fatbot", "machine-a", "reachable", boot_id="boot-a")
    clock[0] = 1040
    first = concerns(status_document(ledger, "fatbot"))
    assert first["duty.availability"]["observed_at"] == "1970-01-01T00:16:40+00:00"
    assert first["duty.availability"]["valid_for_seconds"] == 60
    clock[0] = 1061
    gap = concerns(status_document(ledger, "fatbot"))
    assert gap["duty.availability"]["local_state"] == "UNKNOWN"
    assert gap["duty.observation"]["local_state"] == "ABSENT"
    assert gap["duty.deadline"]["local_state"] == "PRESENT"
    ledger.observe("fatbot", "machine-a", "unreachable")
    lost = concerns(status_document(ledger, "fatbot"))
    assert lost["duty.availability"]["local_state"] == "ABSENT"
    assert lost["duty.observation"]["local_state"] == "PRESENT"


def test_idle_status_is_conditional_and_overdue_deadline_is_failure(setup):
    from host_duty.core import status_document
    ledger, clock, _ = setup
    idle = concerns(status_document(ledger, "fatbot"))
    assert idle["duty.availability"]["local_state"] == "PRESENT"
    assert idle["duty.availability"]["domain_state"] == "NOT_REQUIRED"
    assert ledger.report("fatbot")["presence"] == "unknown"
    assign(ledger, deadline=1010)
    clock[0] = 1010
    on_duty = concerns(status_document(ledger, "fatbot"))
    assert on_duty["duty.availability"]["domain_state"] == "WITHIN_GRACE"
    assert on_duty["duty.observation"]["local_state"] == "PRESENT"
    assert on_duty["duty.observation"]["domain_state"] == "WITHIN_GRACE"
    assert on_duty["duty.deadline"]["local_state"] == "ABSENT"
    assert ledger.report("fatbot")["availability_required"] is True


def test_transfer_rolls_back_predecessor_if_successor_insert_fails(setup):
    ledger, _, path = setup
    ledger.register("gojira", "machine-b")
    assign(ledger)
    db = sqlite3.connect(path)
    db.execute("CREATE TRIGGER reject_successor BEFORE INSERT ON duties WHEN NEW.duty_id='duty-2' BEGIN SELECT RAISE(ABORT, 'fixture insertion refusal'); END")
    db.commit()
    db.close()
    count = len(ledger.events())
    with pytest.raises(Refused):
        ledger.transfer("duty-1", "duty-2", "gojira", 2100, "move")
    assert ledger.report("fatbot")["availability_required"] is True
    assert ledger.report("gojira")["availability_required"] is False
    assert len(ledger.events()) == count


def test_release_leaves_work_reassignable_and_terminal_outcome_does_not(setup):
    ledger, _, _ = setup
    assign(ledger)
    ledger.release("duty-1", "released", "needs another host")
    assign(ledger, duty="duty-2")
    ledger.release("duty-2", "completed", "operator inspected", evidence_sha256="a" * 64)
    with pytest.raises(Refused):
        assign(ledger, duty="duty-3")


@pytest.mark.parametrize("telemetry", [{"value":float("nan")}, {"value":float("inf")}, {"value":"x"*65536}, []])
def test_malformed_or_unbounded_telemetry_refuses_without_refreshing(setup, telemetry):
    ledger, clock, _ = setup
    ledger.observe("fatbot", "machine-a", "reachable", boot_id="boot-a")
    clock[0] = 1010
    with pytest.raises(Refused):
        ledger.observe("fatbot", "machine-a", "reachable", boot_id="boot-a", telemetry=telemetry)
    assert ledger.report("fatbot")["observation_age_seconds"] == 10


def test_bounded_history_does_not_forget_retired_boots(setup):
    ledger, clock, path = setup
    ledger.observe("fatbot", "machine-a", "reachable", boot_id="boot-a")
    for i in range(260):
        clock[0] += 1
        ledger.observe("fatbot", "machine-a", "reachable", boot_id="boot-b")
    db = sqlite3.connect(path)
    assert db.execute("SELECT COUNT(*) FROM observations WHERE host_id='fatbot'").fetchone()[0] == 256
    db.close()
    clock[0] += 1
    with pytest.raises(Refused):
        ledger.observe("fatbot", "machine-a", "reachable", boot_id="boot-a")
    assert len([e for e in ledger.events(256) if e["kind"] == "boot_changed"]) == 1


def test_readonly_unknown_schema_and_corrupt_state_never_reinitialize(tmp_path):
    path = tmp_path / "invalid.sqlite"
    path.write_bytes(b"invalid SQLite")
    path.chmod(0o600)
    with pytest.raises(Refused):
        Ledger(path, readonly=True)
    assert path.read_bytes() == b"invalid SQLite"
    path.unlink()
    db = sqlite3.connect(path)
    db.execute("PRAGMA user_version=99")
    db.close()
    path.chmod(0o600)
    with pytest.raises(Refused, match="schema"):
        Ledger(path)


def test_database_custody_rejects_symlink_hardlink_mode_and_writable_parent(setup):
    ledger, clock, path = setup
    alias = path.with_name("alias.sqlite")
    alias.symlink_to(path)
    with pytest.raises(Refused):
        Ledger(alias)
    alias.unlink()
    os.link(path, alias)
    with pytest.raises(Refused):
        Ledger(path)
    alias.unlink()
    path.chmod(0o644)
    with pytest.raises(Refused):
        Ledger(path)
    path.chmod(0o600)
    path.parent.chmod(0o777)
    try:
        with pytest.raises(Refused):
            Ledger(path)
    finally:
        path.parent.chmod(0o700)


def test_invalid_ids_and_reasons_never_reach_sql_or_mutate(setup):
    ledger, _, _ = setup
    before = len(ledger.events())
    for host in ("x'*; DROP TABLE hosts;", "x"*49, "båd", "", "two hosts"):
        with pytest.raises(Refused):
            ledger.register(host, "valid-instance")
    assign(ledger)
    with pytest.raises(Refused):
        ledger.release("duty-1", "completed", "", evidence_sha256="a"*64)
    with pytest.raises(Refused):
        ledger.shutdown_claim("fatbot", "machine-a", "x"*1001)
    assert len(ledger.events()) == before + 1


def test_events_limit_and_readonly_mutations_are_refused(setup):
    ledger, clock, path = setup
    with Ledger(path, clock=lambda: clock[0], readonly=True) as reader:
        with pytest.raises(Refused):
            reader.assign("new", "new-work", "fatbot", 2000)
    for limit in (0, -1, 257, True):
        with pytest.raises(Refused):
            ledger.events(limit)
    assert len(ledger.events(1)) == 1


def test_clock_regression_after_read_is_detected_without_a_later_write(setup):
    from host_duty.core import status_document
    ledger, clock, _ = setup
    assign(ledger)
    clock[0] = 1200
    assert ledger.report("fatbot")["at"] == 1200
    clock[0] = 1199
    assert {c["local_state"] for c in concerns(status_document(ledger, "fatbot")).values()} == {"UNKNOWN"}
    with pytest.raises(Refused, match="clock"):
        ledger.release("duty-1", "released", "clock not restored")


def test_missing_ledger_unknown_survives_estate_status_normalization(tmp_path):
    import json
    from host_duty.core import unknown_document
    spec = importlib.util.spec_from_file_location("duty_estate_collect", Path(__file__).resolve().parents[1] / "estate/constellation-estate-collect.py")
    estate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(estate)
    document = unknown_document("fatbot", "ledger missing")
    producer = tmp_path / "producer.py"
    producer.write_text("print(" + repr(json.dumps(document)) + ")\n")
    observations, error = estate.project_status({"argv":[sys.executable, str(producer)]}, 2)
    assert error is None
    assert {o["state"] for o in observations} == {"UNKNOWN"}


def test_first_sample_is_not_a_reboot_and_retired_instance_stays_retired(setup):
    ledger, clock, _ = setup
    ledger.observe("fatbot", "machine-a", "reachable", boot_id="boot-a")
    assert not any(e["kind"] == "boot_changed" for e in ledger.events())
    clock[0] += 1
    ledger.replace("fatbot", "machine-b", "new machine")
    with pytest.raises(Refused):
        ledger.replace("fatbot", "machine-a", "old instance cannot return")
    assert ledger.report("fatbot")["boot_id"] is None
    assert ledger.report("fatbot")["presence"] == "unknown"


def test_numeric_limits_refuse_huge_integers_without_refreshing(setup):
    ledger, _, _ = setup
    for bad in (float("nan"), float("inf"), -1, True, 10**400):
        with pytest.raises(Refused):
            assign(ledger, deadline=bad)
        with pytest.raises(Refused):
            ledger.observe("fatbot", "machine-a", "reachable", observed_at=bad)
    assert ledger.report("fatbot")["availability_required"] is False
    assert ledger.report("fatbot")["presence"] == "unknown"


def test_host_and_active_duty_capacity_refusals_are_atomic(setup):
    ledger, _, _ = setup
    for i in range(64):
        assign(ledger, duty="duty-" + str(i), work="work-" + str(i))
    with pytest.raises(Refused, match="64"):
        assign(ledger, duty="duty-overflow", work="work-overflow")
    assert len(ledger.report("fatbot")["duties"]) == 64
    for i in range(255):
        ledger.register("host-" + str(i), "instance-" + str(i))
    with pytest.raises(Refused, match="256"):
        ledger.register("host-overflow", "instance-overflow")
    assert len(ledger.hosts()) == 256


def test_observations_preserve_outstanding_set_across_bounded_transitions(setup):
    ledger, clock, _ = setup
    assign(ledger)
    for i, (state, boot) in enumerate([("reachable", "boot-a"), ("unreachable", None), ("unknown", None), ("reachable", "boot-b")]):
        clock[0] = 1001 + i * 100
        ledger.observe("fatbot", "machine-a", state, boot_id=boot)
        ledger.shutdown_claim("fatbot", "machine-a", "bounded transition claim")
        assert [(d["duty_id"], d["work_id"], d["disposition"]) for d in ledger.report("fatbot")["duties"]] == [("duty-1", "build-1", None)]


def test_new_assignment_never_renews_old_outstanding_duty_grace(setup):
    from host_duty.core import status_document
    ledger, clock, path = setup
    assign(ledger)
    clock[0] = 1031
    assign(ledger, duty="new-duty", work="new-work")
    ledger.shutdown_claim("fatbot", "machine-a", "still no observer source")
    with Ledger(path, clock=lambda: clock[0], readonly=True) as reopened:
        report = reopened.report("fatbot")
        assert report["in_grace"] is False
        assert [d["assigned_at"] for d in report["duties"]] == [1000, 1031]
        projected = concerns(status_document(reopened, "fatbot"))
        assert projected["duty.availability"]["local_state"] == "UNKNOWN"
        assert projected["duty.observation"]["local_state"] == "ABSENT"


@pytest.mark.parametrize("kind", ["deadline", "grace"])
@pytest.mark.parametrize("query_at,want", [(200.5, "PRESENT"), (200.5000004, "PRESENT"),
    (200.5000006, "PRESENT"), (200.9999998, "UNKNOWN")])
def test_serialized_positive_confirmation_expires_before_known_transition(tmp_path, kind, query_at, want):
    """Keeping the old positive at the transition would hide an already due duty."""
    import json
    from host_duty.core import status_document
    clock = [200]
    with Ledger.create(tmp_path / "duty.sqlite", clock=lambda: clock[0]) as ledger:
        ledger.register("fatbot", "machine-a")
        ledger.assign("later", "work-later", "fatbot", 205)
        ledger.assign("first-due", "work-first", "fatbot", 201)
        clock[0] = query_at
        document = status_document(ledger, "fatbot", grace_seconds=1)
        selected = ["duty.deadline"] if kind == "deadline" else ["duty.availability", "duty.observation"]
        for name in selected:
            observation = concerns(document)[name]
            assert observation["local_state"] == want
            if want == "PRESENT":
                assert 0 < observation["valid_for_seconds"] <= 201 - query_at
        clock[0] = 201
        due = concerns(status_document(ledger, "fatbot", grace_seconds=1))
        assert due["duty.deadline"]["local_state"] == "ABSENT"
        assert due["duty.availability"]["local_state"] == "UNKNOWN"
        assert due["duty.observation"]["local_state"] == "ABSENT"

    spec = importlib.util.spec_from_file_location("duty_estate_boundary", Path(__file__).resolve().parents[1] / "estate/constellation-estate-collect.py")
    estate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(estate)
    producer = tmp_path / "producer.py"
    producer.write_text("print(" + repr(json.dumps(document, allow_nan=False)) + ")\n")
    # Keep the real process runner's monotonic clock, while controlling the
    # actual consumer's wall clock over the same serialized old document.
    for acquired_at in (201, 201.5):
        estate.time = SimpleNamespace(time=lambda: acquired_at, monotonic=time.monotonic)
        normalized, error = estate.project_status({"argv":[sys.executable, str(producer)]}, 2)
        assert error is None
        states = {item["id"]: item["state"] for item in normalized}
        for name in selected:
            assert states[name] in ("STALE", "UNKNOWN")
